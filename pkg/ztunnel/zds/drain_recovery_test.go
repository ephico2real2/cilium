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

type recoveryDrainResult struct {
	receipt *DrainReceipt
	err     error
}

func startRecoveryDrain(s *Server, ctx context.Context, ep *endpoint.Endpoint, ref membership.Reference, generation uint64) <-chan recoveryDrainResult {
	done := make(chan recoveryDrainResult, 1)
	go func() {
		receipt, err := s.DrainLiveEndpointForPolicyContext(ctx, ep, ref, generation)
		done <- recoveryDrainResult{receipt, err}
	}()
	return done
}
func recoveryResponse(request *pb.DrainWorkload) *pb.WorkloadResponse {
	return &pb.WorkloadResponse{Payload: &pb.WorkloadResponse_Drained{Drained: &pb.WorkloadDrained{
		Binding: proto.Clone(request.Binding).(*pb.WorkloadBinding), DrainGeneration: request.DrainGeneration, Nonce: bytes.Clone(request.Nonce)}}}
}

// Actual native Go processor and Unix seqpacket transport. The peer fixture
// simulates typed responses; real Rust task/flow drain tests remain separate.
func exchangeRecoveryDrain(t *testing.T, s *Server, update zdsUpdate, epoch []byte, respond func(*pb.DrainWorkload) *pb.WorkloadResponse) (*pb.DrainWorkload, error) {
	t.Helper()
	conn, peer := zdsSocketPair(t)
	conn.proxyEpoch = bytes.Clone(epoch)
	processed := make(chan error, 1)
	go func() { processed <- s.processUpdate(t.Context(), conn, update) }()
	require.NoError(t, peer.SetReadDeadline(time.Now().Add(time.Second)))
	wire := &pb.WorkloadRequest{}
	require.NoError(t, (&ztunnelConn{conn: peer}).readMsg(wire))
	request := wire.GetDrain()
	require.NotNil(t, request)
	raw, err := proto.Marshal(respond(request))
	require.NoError(t, err)
	_, err = peer.Write(raw)
	require.NoError(t, err)
	return request, <-processed
}
func recoveryFixture(t *testing.T, count int) (*Server, *endpoint.Endpoint, *membership.Registry, membership.Reference, uint64) {
	t.Helper()
	r := membership.NewRegistry(1)
	ref, err := r.Require("namespace-uid", "pod-uid", 9, "/removed-sandbox")
	require.NoError(t, err)
	generation, ok := r.BeginDrain(ref)
	require.True(t, ok)
	s := strictCleanupServer(t)
	for i := 1; i <= count; i++ {
		b := drainTestBinding(ref)
		b.CaptureGeneration = uint64(i)
		require.NoError(t, s.recordPolicyADDAttempt(&pb.WorkloadRequest{Payload: &pb.WorkloadRequest_Add{Add: &pb.AddWorkload{Uid: b.PodUid, Binding: b}}}, "/removed-sandbox"))
	}
	return s, liveManagedEndpoint(t, 9, "pod-uid", "/removed-sandbox"), r, ref, generation
}
func TestNativeDrainFindsIntermediateUnACKedOwnerWithoutErasingHistory(t *testing.T) {
	s, ep, r, ref, generation := recoveryFixture(t, 3)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	done := startRecoveryDrain(s, ctx, ep, ref, generation)
	var previous []byte
	for _, wanted := range []uint64{3, 2} {
		request, err := exchangeRecoveryDrain(t, s, receiveCleanupUpdate(t, s), bytes.Repeat([]byte{3}, 32), func(request *pb.DrainWorkload) *pb.WorkloadResponse {
			require.Equal(t, wanted, request.Binding.CaptureGeneration)
			if wanted == 3 {
				return &pb.WorkloadResponse{Payload: &pb.WorkloadResponse_Ack{Ack: &pb.Ack{Error: "no such exact original owner"}}}
			}
			return recoveryResponse(request)
		})
		if wanted == 3 {
			require.ErrorIs(t, err, errNativeDrainNACK)
			previous = bytes.Clone(request.Nonce)
		} else {
			require.NoError(t, err)
			require.NotEqual(t, previous, request.Nonce)
		}
	}
	result := <-done
	require.NoError(t, result.err)
	require.Empty(t, s.drainBindings)
	require.Len(t, s.policyADDHistory[endpointIncarnation{id: 9, uid: "pod-uid", netnsPath: "/removed-sandbox"}], 3)
	require.NoError(t, result.receipt.Retire(r, ref, generation))
	require.Empty(t, s.policyADDAttempts)
	require.Empty(t, s.policyADDHistory)
}
func TestNativeDrainNACKNeverBecomesAbsenceAndFreshRetryRecovers(t *testing.T) {
	s, ep, r, ref, generation := recoveryFixture(t, 2)
	for trial := range 2 {
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		done := startRecoveryDrain(s, ctx, ep, ref, generation)
		for _, wanted := range []uint64{2, 1} {
			_, err := exchangeRecoveryDrain(t, s, receiveCleanupUpdate(t, s), bytes.Repeat([]byte{3}, 32), func(request *pb.DrainWorkload) *pb.WorkloadResponse {
				require.Equal(t, wanted, request.Binding.CaptureGeneration)
				if trial == 1 && wanted == 1 {
					return recoveryResponse(request)
				}
				return &pb.WorkloadResponse{Payload: &pb.WorkloadResponse_Ack{Ack: &pb.Ack{Error: "unknown owner"}}}
			})
			if trial == 1 && wanted == 1 {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, errNativeDrainNACK)
			}
		}
		result := <-done
		cancel()
		if trial == 0 {
			require.Error(t, result.err)
			require.Nil(t, result.receipt)
			state, ok := r.Get(ref)
			require.True(t, ok)
			require.True(t, state.Draining)
			require.False(t, state.DrainCompleted)
			require.NotEmpty(t, s.policyADDAttempts)
		} else {
			require.NoError(t, result.err)
			require.NoError(t, result.receipt.Retire(r, ref, generation))
		}
	}
}
func TestNativeDrainProtocolMismatchAndRestartCannotUseOlderCandidate(t *testing.T) {
	for _, name := range []string{"generic-ack", "wrong-nonce", "wrong-generation", "wrong-binding", "proxy-restart"} {
		t.Run(name, func(t *testing.T) {
			s, ep, r, ref, generation := recoveryFixture(t, 2)
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			done := startRecoveryDrain(s, ctx, ep, ref, generation)
			update := receiveCleanupUpdate(t, s)
			if name == "proxy-restart" {
				conn, peer := zdsSocketPair(t)
				conn.proxyEpoch = bytes.Repeat([]byte{8}, 32)
				require.ErrorContains(t, s.processUpdate(ctx, conn, update), "proxy execution")
				require.NoError(t, peer.SetReadDeadline(time.Now().Add(10*time.Millisecond)))
				require.Error(t, (&ztunnelConn{conn: peer}).readMsg(&pb.WorkloadRequest{}))
			} else {
				_, err := exchangeRecoveryDrain(t, s, update, bytes.Repeat([]byte{3}, 32), func(request *pb.DrainWorkload) *pb.WorkloadResponse {
					if name == "generic-ack" {
						return &pb.WorkloadResponse{Payload: &pb.WorkloadResponse_Ack{Ack: &pb.Ack{}}}
					}
					response := recoveryResponse(request)
					receipt := response.GetDrained()
					switch name {
					case "wrong-nonce":
						receipt.Nonce[0] ^= 1
					case "wrong-generation":
						receipt.DrainGeneration++
					case "wrong-binding":
						receipt.Binding.Incarnation++
					}
					return response
				})
				require.Error(t, err)
			}
			result := <-done
			require.Error(t, result.err)
			require.Nil(t, result.receipt)
			require.Empty(t, s.updates, "protocol errors cannot select another candidate")
			state, ok := r.Get(ref)
			require.True(t, ok)
			require.False(t, state.DrainCompleted)
			require.NotEmpty(t, s.policyADDAttempts)
		})
	}
}
func TestNativeDrainRejectsConflictingReferenceSandboxAndEpochBeforeQueueing(t *testing.T) {
	for _, name := range []string{"namespace", "pod", "source-epoch", "cluster", "incarnation", "endpoint", "device", "inode", "proxy-epoch", "nil", "missing"} {
		t.Run(name, func(t *testing.T) {
			s, ep, r, ref, generation := recoveryFixture(t, 1)
			key := endpointIncarnation{id: 9, uid: "pod-uid", netnsPath: "/removed-sandbox"}
			corrupt := proto.Clone(s.policyADDAttempts[key]).(*pb.WorkloadBinding)
			switch name {
			case "namespace":
				corrupt.NamespaceUid = "foreign"
			case "pod":
				corrupt.PodUid = "foreign"
			case "source-epoch":
				corrupt.SourceEpoch = "foreign"
			case "cluster":
				corrupt.ClusterId++
			case "incarnation":
				corrupt.Incarnation++
			case "endpoint":
				corrupt.EndpointId++
			case "device":
				corrupt.NetnsDev++
			case "inode":
				corrupt.NetnsIno++
			case "proxy-epoch":
				corrupt.ProxyEpoch = bytes.Repeat([]byte{7}, 32)
			}
			// Keep the original history: a conflicting latest tuple must not be ignored.
			s.policyADDAttempts[key] = corrupt
			if name == "nil" {
				s.policyADDAttempts[key] = nil
			}
			if name == "missing" {
				delete(s.policyADDAttempts, key)
				delete(s.policyADDHistory, key)
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			receipt, err := s.DrainLiveEndpointForPolicyContext(ctx, ep, ref, generation)
			require.Error(t, err)
			require.Nil(t, receipt)
			require.Empty(t, s.updates)
			state, ok := r.Get(ref)
			require.True(t, ok)
			require.True(t, state.Draining)
			require.False(t, state.DrainCompleted)
		})
	}
}
func TestNativeADDHistoryBoundAndACKPruningPreserveSuccessor(t *testing.T) {
	s, _, _, ref, _ := recoveryFixture(t, maxPolicyADDHistory)
	key := endpointIncarnation{id: 9, uid: "pod-uid", netnsPath: "/removed-sandbox"}
	latest := proto.Clone(s.policyADDAttempts[key]).(*pb.WorkloadBinding)
	overflow := proto.Clone(latest).(*pb.WorkloadBinding)
	overflow.CaptureGeneration++
	request := func(b *pb.WorkloadBinding) *pb.WorkloadRequest {
		return &pb.WorkloadRequest{Payload: &pb.WorkloadRequest_Add{Add: &pb.AddWorkload{Uid: b.PodUid, Binding: b}}}
	}
	require.ErrorContains(t, s.recordPolicyADDAttempt(request(overflow), key.netnsPath), "history capacity")
	require.True(t, proto.Equal(latest, s.policyADDAttempts[key]))
	require.Len(t, s.policyADDHistory[key], maxPolicyADDHistory)
	s.endpointCacheMutex.Lock()
	s.drainBindings = map[endpointIncarnation]*pb.WorkloadBinding{key: proto.Clone(latest).(*pb.WorkloadBinding)}
	s.pruneAcknowledgedPolicyHistoryLocked(key, latest)
	s.endpointCacheMutex.Unlock()
	require.Empty(t, s.policyADDHistory[key])
	require.NoError(t, s.recordPolicyADDAttempt(request(overflow), key.netnsPath))
	s.endpointCacheMutex.Lock()
	selection, err := s.originalDrainCandidatesLocked(key, ref)
	s.endpointCacheMutex.Unlock()
	require.NoError(t, err)
	successor := proto.Clone(overflow).(*pb.WorkloadBinding)
	successor.Incarnation++
	require.NoError(t, s.recordPolicyADDAttempt(request(successor), key.netnsPath))
	s.forgetOriginalDrainCandidates(key, selection)
	require.Empty(t, s.drainBindings)
	require.True(t, proto.Equal(successor, s.policyADDAttempts[key]))
	require.Len(t, s.policyADDHistory[key], 1)
	require.True(t, proto.Equal(successor, s.policyADDHistory[key][0]))
}
func TestNativeADDHistoryCapturesAllUnACKedGenerations(t *testing.T) {
	s, _, _, ref, _ := recoveryFixture(t, 3)
	key := endpointIncarnation{id: 9, uid: "pod-uid", netnsPath: "/removed-sandbox"}
	s.endpointCacheMutex.Lock()
	selection, err := s.originalDrainCandidatesLocked(key, ref)
	s.endpointCacheMutex.Unlock()
	require.NoError(t, err)
	require.Len(t, selection, 3)
	for i, b := range selection {
		require.Equal(t, uint64(3-i), b.CaptureGeneration)
	}
	selection[0].PodUid = "mutated returned copy"
	require.Equal(t, "pod-uid", s.policyADDAttempts[key].PodUid)
	require.Len(t, s.policyADDHistory[key], 3)
}

func TestNativeUnACKedDrainCancellationRetainsHistoryAndFreshRetryRecovers(t *testing.T) {
	s, ep, registry, ref, generation := recoveryFixture(t, 2)
	ctx, cancel := context.WithCancel(t.Context())
	drained := startRecoveryDrain(s, ctx, ep, ref, generation)
	update := receiveCleanupUpdate(t, s)
	conn, peer := zdsSocketPair(t)
	conn.proxyEpoch = bytes.Repeat([]byte{3}, 32)
	processed := make(chan error, 1)
	go func() { processed <- s.processUpdate(t.Context(), conn, update) }()
	require.NoError(t, peer.SetReadDeadline(time.Now().Add(time.Second)))
	wire := &pb.WorkloadRequest{}
	require.NoError(t, (&ztunnelConn{conn: peer}).readMsg(wire))
	require.Equal(t, uint64(2), wire.GetDrain().Binding.CaptureGeneration)
	cancel() // No response: no typed receipt, even if the real peer did drain.
	require.ErrorIs(t, <-processed, context.Canceled)
	result := <-drained
	require.ErrorIs(t, result.err, context.Canceled)
	require.Nil(t, result.receipt)
	require.Empty(t, s.updates, "cancellation cannot select another candidate")
	require.Len(t, s.policyADDHistory[endpointIncarnation{id: 9, uid: "pod-uid", netnsPath: "/removed-sandbox"}], 2)
	state, ok := registry.Get(ref)
	require.True(t, ok)
	require.False(t, state.DrainCompleted)
	// Same original execution and drain generation can return the exact receipt
	// on an explicit retry. The native owner itself must make drain idempotent.
	retryCtx, retryCancel := context.WithTimeout(t.Context(), time.Second)
	defer retryCancel()
	retry := startRecoveryDrain(s, retryCtx, ep, ref, generation)
	_, err := exchangeRecoveryDrain(t, s, receiveCleanupUpdate(t, s), bytes.Repeat([]byte{3}, 32), recoveryResponse)
	require.NoError(t, err)
	result = <-retry
	require.NoError(t, result.err)
	require.NoError(t, result.receipt.Retire(registry, ref, generation))
	require.Empty(t, s.policyADDHistory)
	require.Empty(t, s.policyADDAttempts)
}

func TestNativeHistoryCapacityFailureIsAtomicWithInconsistentLatest(t *testing.T) {
	s, _, _, _, _ := recoveryFixture(t, maxPolicyADDHistory)
	key := endpointIncarnation{id: 9, uid: "pod-uid", netnsPath: "/removed-sandbox"}
	old := proto.Clone(s.policyADDAttempts[key]).(*pb.WorkloadBinding)
	old.CaptureGeneration++
	s.policyADDAttempts[key] = old // A conflicting compatibility marker must not grow history to nine.
	req := &pb.WorkloadRequest{Payload: &pb.WorkloadRequest_Add{Add: &pb.AddWorkload{Uid: old.PodUid, Binding: s.policyADDHistory[key][0]}}}
	require.ErrorContains(t, s.recordPolicyADDAttempt(req, key.netnsPath), "capacity")
	require.Len(t, s.policyADDHistory[key], maxPolicyADDHistory)
	require.True(t, proto.Equal(old, s.policyADDAttempts[key]))
}
