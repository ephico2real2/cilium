// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package zds

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/ztunnel/membership"
	"github.com/cilium/cilium/pkg/ztunnel/pb"
)

func TestLivePolicyDrainRequiresExactNativeReceiptAndRetainsQuarantine(t *testing.T) {
	for _, name := range []string{"valid", "generic-ack", "nack", "wrong-nonce", "namespace", "pod", "source-epoch", "incarnation", "capture-generation", "endpoint", "cluster", "version", "device", "sandbox", "drain-generation", "proxy-epoch", "disconnect"} {
		t.Run(name, func(t *testing.T) {
			registry := membership.NewRegistry(1)
			ref, err := registry.Require("namespace-uid", "pod-uid", 9, "/removed-sandbox")
			require.NoError(t, err)
			generation, ok := registry.BeginDrain(ref)
			require.True(t, ok)
			s := strictCleanupServer(t)
			ep := liveManagedEndpoint(t, 9, "pod-uid", "/removed-sandbox")
			key, err := incarnation(ep)
			require.NoError(t, err)
			s.drainBindings = map[endpointIncarnation]*pb.WorkloadBinding{key: drainTestBinding(ref)}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			type result struct {
				receipt *DrainReceipt
				err     error
			}
			done := make(chan result, 1)
			go func() { r, e := s.DrainLiveEndpointForPolicyContext(ctx, ep, ref, generation); done <- result{r, e} }()
			update := receiveCleanupUpdate(t, s)
			require.Empty(t, update.netnsPath)
			conn, peer := zdsSocketPair(t)
			conn.proxyEpoch = bytes.Repeat([]byte{3}, 32)
			processDone := make(chan error, 1)
			go func() { processDone <- s.processUpdate(ctx, conn, update) }()
			wire := &pb.WorkloadRequest{}
			require.NoError(t, (&ztunnelConn{conn: peer}).readMsg(wire))
			req := wire.GetDrain()
			require.NotNil(t, req)
			response := &pb.WorkloadResponse{Payload: &pb.WorkloadResponse_Drained{Drained: &pb.WorkloadDrained{Binding: proto.Clone(req.Binding).(*pb.WorkloadBinding), DrainGeneration: req.DrainGeneration, Nonce: bytes.Clone(req.Nonce)}}}
			got := response.GetDrained()
			switch name {
			case "generic-ack":
				response = &pb.WorkloadResponse{Payload: &pb.WorkloadResponse_Ack{Ack: &pb.Ack{}}}
			case "nack":
				response = &pb.WorkloadResponse{Payload: &pb.WorkloadResponse_Ack{Ack: &pb.Ack{Error: "denied"}}}
			case "wrong-nonce":
				got.Nonce[0] ^= 1
			case "namespace":
				got.Binding.NamespaceUid = "replacement"
			case "pod":
				got.Binding.PodUid = "replacement"
			case "source-epoch":
				got.Binding.SourceEpoch = "replacement"
			case "incarnation":
				got.Binding.Incarnation++
			case "capture-generation":
				got.Binding.CaptureGeneration++
			case "endpoint":
				got.Binding.EndpointId++
			case "cluster":
				got.Binding.ClusterId++
			case "version":
				got.Binding.Version++
			case "device":
				got.Binding.NetnsDev++
			case "sandbox":
				got.Binding.NetnsIno++
			case "drain-generation":
				got.DrainGeneration++
			case "proxy-epoch":
				got.Binding.ProxyEpoch[0] ^= 1
			}
			if name == "disconnect" {
				require.NoError(t, peer.Close())
			} else {
				raw, e := proto.Marshal(response)
				require.NoError(t, e)
				_, e = peer.Write(raw)
				require.NoError(t, e)
			}
			processErr := <-processDone
			r := <-done
			if name == "valid" {
				require.NoError(t, processErr)
				require.NoError(t, r.err)
				require.NoError(t, r.receipt.ConfirmPolicyQuarantine(registry, ref, generation))
				state, exists := registry.Get(ref)
				require.True(t, exists)
				require.True(t, state.Draining)
				require.True(t, state.DrainCompleted)
				require.False(t, state.ReadyForAddress())
				require.False(t, state.Active())
				require.NotEmpty(t, s.drainBindings, "policy quarantine cannot forget original ADD ownership")
				require.True(t, ep.IsAlive(), "no endpoint deletion or capture removal")
				successor := proto.Clone(s.drainBindings[key]).(*pb.WorkloadBinding)
				successor.Incarnation++
				require.NoError(t, s.recordPolicyADDAttempt(&pb.WorkloadRequest{Payload: &pb.WorkloadRequest_Add{Add: &pb.AddWorkload{Uid: successor.PodUid, Binding: successor}}}, "/removed-sandbox"))

				_, err := registry.Require(ref.Key.NamespaceUID, ref.Key.PodUID, 9, "/removed-sandbox")
				require.Error(t, err, "same incarnation cannot be silently re-enrolled")
				require.True(t, ep.SetState(endpoint.StateDisconnecting, "actual deletion begins"))
				require.True(t, ep.SetState(endpoint.StateDisconnected, "actual deletion completes"))
				require.NoError(t, r.receipt.Retire(registry, ref, generation), "later deletion can retire exact owner")
				require.True(t, proto.Equal(successor, s.policyADDAttempts[key]), "old receipt cannot erase successor send uncertainty")

			} else {
				require.Error(t, processErr)
				require.Error(t, r.err)
				require.Nil(t, r.receipt)
				state, exists := registry.Get(ref)
				require.True(t, exists)
				require.True(t, state.Draining)
				require.False(t, state.DrainCompleted)
			}
		})
	}
}
func TestLivePolicyDrainRejectsRestartAndTimeoutAndRecoversOriginalExecution(t *testing.T) {
	registry := membership.NewRegistry(1)
	ref, err := registry.Require("namespace-uid", "pod-uid", 9, "/removed-sandbox")
	require.NoError(t, err)
	generation, _ := registry.BeginDrain(ref)
	s := strictCleanupServer(t)
	ep := liveManagedEndpoint(t, 9, "pod-uid", "/removed-sandbox")
	key, _ := incarnation(ep)
	s.drainBindings = map[endpointIncarnation]*pb.WorkloadBinding{key: drainTestBinding(ref)}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	_, err = s.DrainLiveEndpointForPolicyContext(ctx, ep, ref, generation)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	// An expired queued request is dropped without transmitting to a new stream.
	update := <-s.updates
	conn, peer := zdsSocketPair(t)
	require.NoError(t, s.processUpdate(t.Context(), conn, update))
	require.NoError(t, peer.SetReadDeadline(time.Now().Add(10*time.Millisecond)))
	require.Error(t, (&ztunnelConn{conn: peer}).readMsg(&pb.WorkloadRequest{}))
	// A new proxy epoch cannot prove closure of original-execution flows.
	conn2, _ := zdsSocketPair(t)
	conn2.proxyEpoch = bytes.Repeat([]byte{8}, 32)
	require.ErrorContains(t, conn2.sendDrain(&pb.DrainWorkload{Binding: drainTestBinding(ref), DrainGeneration: generation, Nonce: bytes.Repeat([]byte{4}, 32)}), "proxy execution")
	state, ok := registry.Get(ref)
	require.True(t, ok)
	require.False(t, state.DrainCompleted)
}

func TestLivePolicyDrainDelayedReceiptCannotCompleteNewRequestAndFreshRetryRecovers(t *testing.T) {
	registry := membership.NewRegistry(1)
	ref, err := registry.Require("namespace-uid", "pod-uid", 9, "/removed-sandbox")
	require.NoError(t, err)
	generation, _ := registry.BeginDrain(ref)
	s := strictCleanupServer(t)
	ep := liveManagedEndpoint(t, 9, "pod-uid", "/removed-sandbox")
	key, _ := incarnation(ep)
	s.drainBindings = map[endpointIncarnation]*pb.WorkloadBinding{key: drainTestBinding(ref)}
	var priorNonce []byte
	for attempt := range 3 {
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		type result struct {
			receipt *DrainReceipt
			err     error
		}
		done := make(chan result, 1)
		go func() { r, e := s.DrainLiveEndpointForPolicyContext(ctx, ep, ref, generation); done <- result{r, e} }()
		update := receiveCleanupUpdate(t, s)
		conn, peer := zdsSocketPair(t)
		conn.proxyEpoch = bytes.Repeat([]byte{3}, 32)
		processed := make(chan error, 1)
		go func() { processed <- s.processUpdate(ctx, conn, update) }()
		wire := &pb.WorkloadRequest{}
		require.NoError(t, (&ztunnelConn{conn: peer}).readMsg(wire))
		request := wire.GetDrain()
		require.NotNil(t, request)
		if attempt == 0 {
			priorNonce = bytes.Clone(request.Nonce)
			cancel()
			require.ErrorIs(t, <-processed, context.Canceled)
			r := <-done
			require.ErrorIs(t, r.err, context.Canceled)
			require.Nil(t, r.receipt)
		} else {
			nonce := request.Nonce
			if attempt == 1 {
				nonce = priorNonce
				require.NotEqual(t, nonce, request.Nonce)
			}
			raw, e := proto.Marshal(&pb.WorkloadResponse{Payload: &pb.WorkloadResponse_Drained{Drained: &pb.WorkloadDrained{Binding: request.Binding, DrainGeneration: request.DrainGeneration, Nonce: nonce}}})
			require.NoError(t, e)
			_, e = peer.Write(raw)
			require.NoError(t, e)
			pe := <-processed
			r := <-done
			if attempt == 1 {
				require.Error(t, pe)
				require.Error(t, r.err)
				require.Nil(t, r.receipt)
			} else {
				require.NoError(t, pe)
				require.NoError(t, r.err)
				wrong := ref
				wrong.Incarnation++
				require.Error(t, r.receipt.ConfirmPolicyQuarantine(registry, wrong, generation))
				state, exists := registry.Get(ref)
				require.True(t, exists)
				require.False(t, state.DrainCompleted)
				require.NoError(t, r.receipt.ConfirmPolicyQuarantine(registry, ref, generation))
				require.NotEmpty(t, s.drainBindings)
			}
		}
		cancel()
	}
	_, ok := registry.Get(ref)
	require.True(t, ok)
	state, _ := registry.Get(ref)
	require.True(t, state.Draining)
	require.True(t, state.DrainCompleted)
}
