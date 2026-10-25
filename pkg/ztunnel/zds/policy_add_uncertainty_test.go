// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package zds

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/ztunnel/membership"
	"github.com/cilium/cilium/pkg/ztunnel/pb"
)

func TestPolicyADDUncertaintySurvivesLostACKAndZeroedRegistry(t *testing.T) {
	path := "/proc/self/ns/net"
	ep := acknowledgedView(9, "pod-uid", path)
	r := membership.NewRegistry(1)
	ref, err := r.Require("ns-uid", ep.K8sUID, 9, path)
	require.NoError(t, err)
	generation, ok := r.BeginZDS(ref)
	require.True(t, ok)
	ns, err := netns.OpenPinned(path)
	require.NoError(t, err)
	defer ns.Close()
	binding, err := bindingForCapture(WithCaptureReference(t.Context(), ref, generation), ep, ns)
	require.NoError(t, err)
	binding.ProxyEpoch = bytes.Repeat([]byte{3}, 32)
	s := strictCleanupServer(t)
	conn, peer := zdsSocketPair(t)
	conn.proxyEpoch = bytes.Clone(binding.ProxyEpoch)
	add, err := endpointToWorkload(ep)
	require.NoError(t, err)
	add.Binding = binding
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- s.processUpdate(ctx, conn, zdsUpdate{ctx: ctx, netnsPath: path, request: &pb.WorkloadRequest{Payload: &pb.WorkloadRequest_Add{Add: add}}})
	}()
	require.NoError(t, peer.SetReadDeadline(time.Now().Add(time.Second)))
	var data [2048]byte
	oob := make([]byte, unix.CmsgSpace(4))
	n, on, flags, _, err := peer.ReadMsgUnix(data[:], oob)
	require.NoError(t, err)
	require.Zero(t, flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC))
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
	actual := &pb.WorkloadRequest{}
	require.NoError(t, proto.Unmarshal(data[:n], actual))
	require.NotNil(t, actual.GetAdd())
	// Peer received the real ADD+held FD, then the ACK is lost. No onAck cache
	// callback ran, so those maps cannot establish that the proxy never started.
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
	require.Empty(t, s.endpointCache)
	require.Empty(t, s.drainBindings)
	require.True(t, r.InvalidateCaptureGeneration(ref, generation))
	state, exists := r.Get(ref)
	require.True(t, exists)
	require.Zero(t, state.ZDSGeneration)
	ownership, err := s.ObservePolicyOwnership(9, ep.K8sUID, path)
	require.NoError(t, err)
	require.Equal(t, PolicyOwnershipRetained, ownership)
	// The same execution can now prove actual native drain using the recorded
	// pre-write binding. This does not fabricate an acknowledged ADD.
	owner := liveManagedEndpoint(t, 9, ep.K8sUID, path)
	drainGeneration, ok := r.BeginDrain(ref)
	require.True(t, ok)
	drainCtx, drainCancel := context.WithTimeout(t.Context(), time.Second)
	defer drainCancel()
	drained := startRecoveryDrain(s, drainCtx, owner, ref, drainGeneration)
	request, processErr := exchangeRecoveryDrain(t, s, receiveCleanupUpdate(t, s), bytes.Repeat([]byte{3}, 32), func(request *pb.DrainWorkload) *pb.WorkloadResponse {
		return recoveryResponse(request)
	})
	require.NoError(t, processErr)
	require.True(t, proto.Equal(binding, request.Binding))
	result := <-drained
	require.NoError(t, result.err)
	require.NotNil(t, result.receipt)
	require.Empty(t, s.drainBindings, "uncertain ADD must not become an ADD ACK")
	require.NoError(t, result.receipt.ConfirmPolicyQuarantine(r, ref, drainGeneration))
	require.True(t, owner.SetState(endpoint.StateDisconnecting, "delete drained owner"))
	require.True(t, owner.SetState(endpoint.StateDisconnected, "delete complete"))
	require.NoError(t, result.receipt.Retire(r, ref, drainGeneration))
	require.Empty(t, s.policyADDAttempts)
	require.Empty(t, s.policyADDHistory)
	ownership, err = s.ObservePolicyOwnership(9, ep.K8sUID, path)
	require.NoError(t, err)
	require.Equal(t, PolicyOwnershipAbsent, ownership)

}
func TestPolicyADDAttemptBoundAndDefensiveCopy(t *testing.T) {
	s := strictCleanupServer(t)
	r := membership.NewRegistry(1)
	ref, err := r.Require("ns-uid", "pod-uid", 9, "/ns")
	require.NoError(t, err)
	binding := drainTestBinding(ref)
	request := func(b *pb.WorkloadBinding) *pb.WorkloadRequest {
		return &pb.WorkloadRequest{Payload: &pb.WorkloadRequest_Add{Add: &pb.AddWorkload{Uid: b.PodUid, Binding: b}}}
	}
	for i := range maxPolicyADDAttempts {
		b := proto.Clone(binding).(*pb.WorkloadBinding)
		b.PodUid = fmt.Sprintf("pod-%d", i)
		b.EndpointId = uint32(i + 1)
		require.NoError(t, s.recordPolicyADDAttempt(request(b), fmt.Sprintf("/ns/%d", i)))
	}
	require.Len(t, s.policyADDAttempts, maxPolicyADDAttempts)
	overflow := proto.Clone(binding).(*pb.WorkloadBinding)
	overflow.PodUid = "overflow"
	overflow.EndpointId = 5000
	require.ErrorContains(t, s.recordPolicyADDAttempt(request(overflow), "/ns/overflow"), "capacity")
	key := endpointIncarnation{id: 1, uid: "pod-0", netnsPath: "/ns/0"}
	refreshed := proto.Clone(s.policyADDAttempts[key]).(*pb.WorkloadBinding)
	refreshed.CaptureGeneration++
	require.NoError(t, s.recordPolicyADDAttempt(request(refreshed), key.netnsPath))
	recorded := proto.Clone(refreshed)
	refreshed.CaptureGeneration++
	require.True(t, proto.Equal(recorded, s.policyADDAttempts[key]))
	require.Len(t, s.policyADDAttempts, maxPolicyADDAttempts)
}
