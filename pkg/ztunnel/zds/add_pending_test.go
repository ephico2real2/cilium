// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package zds

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/ztunnel/membership"
	"github.com/cilium/cilium/pkg/ztunnel/pb"
)

func pendingADDRequest(ref membership.Reference) *pb.WorkloadRequest {
	b := drainTestBinding(ref)
	return &pb.WorkloadRequest{Payload: &pb.WorkloadRequest_Add{Add: &pb.AddWorkload{Uid: b.PodUid, Binding: b}}}
}

func TestNativePendingADDOutlivesCanceledProducerUntilConsumerCompletion(t *testing.T) {
	s, ep, registry, ref, generation := recoveryFixture(t, 0)
	ctx, cancel := context.WithCancel(t.Context())
	sent := make(chan error, 1)
	go func() {
		sent <- s.sendUpdateAndWaitForAck(ctx, zdsUpdate{request: pendingADDRequest(ref), netnsPath: "/removed-sandbox", errCh: make(chan error, 1)})
	}()
	queued := receiveCleanupUpdate(t, s)
	require.NotNil(t, queued.policyPending)
	cancel()
	require.ErrorIs(t, <-sent, context.Canceled)
	// Neither ACK cache nor pre-wire index exists: the actual consumer has not
	// run yet. Returning to the producer must not turn this interval into absence.
	require.Empty(t, s.drainBindings)
	require.Empty(t, s.policyADDAttempts)
	ownership, err := s.ObservePolicyOwnership(9, "pod-uid", "/removed-sandbox")
	require.NoError(t, err)
	require.Equal(t, PolicyOwnershipRetained, ownership)
	for _, correlation := range []struct {
		id        uint16
		uid, path string
	}{{9, "", ""}, {0, "pod-uid", ""}, {0, "", "/removed-sandbox"}} {
		ownership, err = s.ObservePolicyOwnership(correlation.id, correlation.uid, correlation.path)
		require.NoError(t, err)
		require.Equal(t, PolicyOwnershipRetained, ownership)
	}
	drainCtx, drainCancel := context.WithTimeout(t.Context(), time.Second)
	defer drainCancel()
	drained := startRecoveryDrain(s, drainCtx, ep, ref, generation)
	// A queued request whose context expired cannot write or fabricate a drain.
	// Running the real consumer resolves its pending marker synchronously.
	conn, peer := zdsSocketPair(t)
	require.NoError(t, s.processUpdate(t.Context(), conn, queued))
	require.NoError(t, peer.SetReadDeadline(time.Now().Add(10*time.Millisecond)))
	require.Error(t, (&ztunnelConn{conn: peer}).readMsg(&pb.WorkloadRequest{}))
	result := <-drained
	require.ErrorContains(t, result.err, "missing retained original ADD")
	require.Nil(t, result.receipt)
	require.Empty(t, s.updates)
	require.Empty(t, s.policyADDPending)
	state, ok := registry.Get(ref)
	require.True(t, ok)
	require.True(t, state.Draining)
	require.False(t, state.DrainCompleted)
}

func TestNativePendingADDUnqueuedCancellationReleasesOnlyItsMarker(t *testing.T) {
	s, _, _, ref, _ := recoveryFixture(t, 0)
	s.updates = make(chan zdsUpdate) // No consumer; cancellation cannot enqueue.
	unrelated, err := s.beginPendingPolicyADD(pendingADDRequest(ref), "/different-path")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	pending, err := s.beginPendingPolicyADD(pendingADDRequest(ref), "/removed-sandbox")
	require.NoError(t, err)
	// Finish is idempotent. Its pointer token cannot delete the unrelated marker.
	s.finishPendingPolicyADD(pending)
	s.finishPendingPolicyADD(pending)
	require.Len(t, s.policyADDPending, 1)
	sent := make(chan error, 1)
	go func() {
		sent <- s.sendUpdateAndWaitForAck(ctx, zdsUpdate{request: pendingADDRequest(ref), netnsPath: "/removed-sandbox", errCh: make(chan error, 1)})
	}()
	require.Eventually(t, func() bool {
		s.endpointCacheMutex.Lock()
		defer s.endpointCacheMutex.Unlock()
		return len(s.policyADDPending) == 2
	}, time.Second, time.Millisecond)
	cancel()
	require.ErrorIs(t, <-sent, context.Canceled)
	require.Len(t, s.policyADDPending, 1)
	s.finishPendingPolicyADD(unrelated)
	require.Empty(t, s.policyADDPending)
}

func TestNativePendingADDCorrelationAndCapacityAreRestrictive(t *testing.T) {
	s, _, _, ref, _ := recoveryFixture(t, 0)
	for _, name := range []string{"uid", "namespace", "epoch", "generation", "inode", "path", "proxy-epoch"} {
		t.Run(name, func(t *testing.T) {
			req := pendingADDRequest(ref)
			path := "/removed-sandbox"
			switch name {
			case "uid":
				req.GetAdd().Uid = "different"
			case "namespace":
				req.GetAdd().Binding.NamespaceUid = ""
			case "epoch":
				req.GetAdd().Binding.SourceEpoch = ""
			case "generation":
				req.GetAdd().Binding.CaptureGeneration = 0
			case "inode":
				req.GetAdd().Binding.NetnsIno = 0
			case "path":
				path = ""
			case "proxy-epoch":
				req.GetAdd().Binding.ProxyEpoch = []byte{1}
			}
			pending, err := s.beginPendingPolicyADD(req, path)
			require.Error(t, err)
			require.Nil(t, pending)
			require.Empty(t, s.policyADDPending)
		})
	}
	for range maxPolicyADDAttempts {
		_, err := s.beginPendingPolicyADD(pendingADDRequest(ref), "/removed-sandbox")
		require.NoError(t, err)
	}
	require.Len(t, s.policyADDPending, maxPolicyADDAttempts)
	pending, err := s.beginPendingPolicyADD(pendingADDRequest(ref), "/removed-sandbox")
	require.ErrorContains(t, err, "capacity")
	require.Nil(t, pending)
}

func TestNativePendingADDJoinsLateACKCallbackBeforeChoosingDrainOwner(t *testing.T) {
	// The actual processor has received a successful ADD ACK while its caller
	// is canceled. The queue marker must survive until the callback finishes.
	path := "/proc/self/ns/net"
	registry := membership.NewRegistry(1)
	ref, err := registry.Require("namespace-uid", "pod-uid", 9, path)
	require.NoError(t, err)
	generation, ok := registry.BeginDrain(ref)
	require.True(t, ok)
	s := strictCleanupServer(t)
	ep := liveManagedEndpoint(t, 9, "pod-uid", path)
	ns, err := netns.OpenPinned(path)
	require.NoError(t, err)
	defer ns.Close()
	binding, err := bindingForCapture(WithCaptureReference(t.Context(), ref, 1), ep, ns)
	require.NoError(t, err)
	binding.ProxyEpoch = bytes.Repeat([]byte{3}, 32)
	request := pendingADDRequest(ref)
	request.GetAdd().Binding = binding
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	sent := make(chan error, 1)
	go func() {
		sent <- s.sendUpdateAndWaitForAck(ctx, zdsUpdate{request: request, netnsPath: path, errCh: make(chan error, 1), onAck: func() {
			close(entered)
			<-release
			s.endpointCacheMutex.Lock()
			key := endpointIncarnation{id: 9, uid: "pod-uid", netnsPath: path}
			s.drainBindings = map[endpointIncarnation]*pb.WorkloadBinding{key: proto.Clone(binding).(*pb.WorkloadBinding)}
			s.pruneAcknowledgedPolicyHistoryLocked(key, binding)
			s.endpointCacheMutex.Unlock()
		}})
	}()
	update := receiveCleanupUpdate(t, s)
	conn, peer := zdsSocketPair(t)
	conn.proxyEpoch = bytes.Clone(binding.ProxyEpoch)
	processed := make(chan error, 1)
	go func() { processed <- s.processUpdate(t.Context(), conn, update) }()
	require.NoError(t, peer.SetReadDeadline(time.Now().Add(time.Second)))
	var data [2048]byte
	oob := make([]byte, unix.CmsgSpace(4))
	n, on, flags, _, err := peer.ReadMsgUnix(data[:], oob)
	require.NoError(t, err)
	require.Zero(t, flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC))
	actualADD := &pb.WorkloadRequest{}
	require.NoError(t, proto.Unmarshal(data[:n], actualADD))
	require.True(t, proto.Equal(binding, actualADD.GetAdd().GetBinding()))
	messages, err := unix.ParseSocketControlMessage(oob[:on])
	require.NoError(t, err)
	descriptors := 0
	for _, message := range messages {
		fds, err := unix.ParseUnixRights(&message)
		require.NoError(t, err)
		for _, fd := range fds {
			descriptors++
			require.NoError(t, unix.Close(fd))
		}
	}
	require.Equal(t, 1, descriptors)
	ack, err := proto.Marshal(&pb.WorkloadResponse{Payload: &pb.WorkloadResponse_Ack{Ack: &pb.Ack{}}})
	require.NoError(t, err)
	_, err = peer.Write(ack)
	require.NoError(t, err)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("ACK callback was not reached")
	}
	cancel()
	require.ErrorIs(t, <-sent, context.Canceled)
	require.Len(t, s.policyADDPending, 1)
	drainCtx, drainCancel := context.WithTimeout(t.Context(), time.Second)
	defer drainCancel()
	drained := startRecoveryDrain(s, drainCtx, ep, ref, generation)
	close(release)
	require.NoError(t, <-processed)
	actual, err := exchangeRecoveryDrain(t, s, receiveCleanupUpdate(t, s), bytes.Clone(binding.ProxyEpoch), recoveryResponse)
	require.NoError(t, err)
	require.True(t, proto.Equal(binding, actual.Binding))
	result := <-drained
	require.NoError(t, result.err)
	require.NoError(t, result.receipt.Retire(registry, ref, generation))
	require.Empty(t, s.policyADDPending)
	require.Empty(t, s.policyADDAttempts)
	require.Empty(t, s.policyADDHistory)
	require.Empty(t, s.drainBindings)
}
