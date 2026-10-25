// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package zds

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/ztunnel/membership"
	"github.com/cilium/cilium/pkg/ztunnel/pb"
)

func captureFixture() (membership.Reference, *pb.WorkloadBinding, []byte) {
	ref := membership.Reference{Key: membership.Key{ClusterID: 1, NamespaceUID: "ns-uid", PodUID: "pod-uid"},
		Incarnation: 3, Epoch: "registry-epoch"}
	live := bytes.Repeat([]byte{7}, 32)
	binding := &pb.WorkloadBinding{Version: 1, SourceEpoch: ref.Epoch, ClusterId: 1, NamespaceUid: "ns-uid",
		PodUid: "pod-uid", EndpointId: 9, Incarnation: 3, CaptureGeneration: 5, ProxyEpoch: live}
	return ref, binding, live
}

// Verification is read-only and passes only for an ADD that the live ztunnel
// execution acknowledged for exactly this incarnation and capture generation.
func TestVerifyCaptureRequiresTheLiveExecutionAndExactGeneration(t *testing.T) {
	s := strictCleanupServer(t)
	ep := liveManagedEndpoint(t, 9, "pod-uid", "/ns")
	ref, binding, live := captureFixture()

	require.ErrorContains(t, s.VerifyCapture(ep, ref, 5), "no ztunnel execution")
	s.setLiveProxyEpoch(live)
	require.ErrorContains(t, s.VerifyCapture(ep, ref, 5), "no acknowledged ADD")
	s.drainBindings = map[endpointIncarnation]*pb.WorkloadBinding{{id: 9, uid: "pod-uid", netnsPath: "/ns"}: binding}
	require.NoError(t, s.VerifyCapture(ep, ref, 5))
	require.ErrorContains(t, s.VerifyCapture(ep, ref, 6), "capture generation", "a newer capture generation is not yet acknowledged")
	other := ref
	other.Incarnation++
	require.Error(t, s.VerifyCapture(ep, other, 5), "another incarnation cannot reuse this acknowledgment")
	require.ErrorContains(t, s.VerifyCapture(ep, ref, 0), "unset")

	restarted := bytes.Repeat([]byte{8}, 32)
	s.setLiveProxyEpoch(restarted)
	require.ErrorContains(t, s.VerifyCapture(ep, ref, 5), "earlier ztunnel execution")
	s.clearLiveProxyEpoch(live)
	require.ErrorContains(t, s.VerifyCapture(ep, ref, 5), "earlier ztunnel execution",
		"an ended earlier connection cannot clear its successor")
	s.clearLiveProxyEpoch(restarted)
	require.ErrorContains(t, s.VerifyCapture(ep, ref, 5), "no ztunnel execution")
	require.True(t, proto.Equal(binding, s.drainBindings[endpointIncarnation{id: 9, uid: "pod-uid", netnsPath: "/ns"}]),
		"verification never changes retained state")
}

// A ztunnel restart (stale binding) or an agent restart (no binding) must not
// fail the initial snapshot: those endpoints are left out, and the snapshot
// completes so admission can re-capture them over this connection.
func TestInitialSnapshotLeavesOutUnreplayableStrictEndpoints(t *testing.T) {
	s := strictCleanupServer(t)
	stale := liveManagedEndpoint(t, 9, "pod-uid", "/ns-stale")
	missing := liveManagedEndpoint(t, 10, "other-pod-uid", "/ns-missing")
	s.endpointCache[9] = stale
	s.endpointCache[10] = missing
	_, binding, _ := captureFixture()
	s.drainBindings = map[endpointIncarnation]*pb.WorkloadBinding{{id: 9, uid: "pod-uid", netnsPath: "/ns-stale"}: binding}

	conn, peer := zdsSocketPair(t)
	conn.proxyEpoch = bytes.Repeat([]byte{8}, 32)
	sent := make(chan *pb.WorkloadRequest, 4)
	go func() {
		defer close(sent)
		if err := peer.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			return
		}
		var request pb.WorkloadRequest
		if err := (&ztunnelConn{conn: peer}).readMsg(&request); err != nil {
			return
		}
		sent <- &request
		_, _ = peer.Write([]byte{0x0a, 0x00})
	}()
	require.NoError(t, s.sendInitialSnapshot(conn), "unreplayable endpoints cannot fail the snapshot")
	first, ok := <-sent
	require.True(t, ok)
	require.NotNil(t, first.GetSnapshotSent(), "no ADD is replayed into a different or unknown execution")
}
