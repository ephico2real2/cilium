// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package zds

import (
	"bytes"
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/ztunnel/membership"
	"github.com/cilium/cilium/pkg/ztunnel/pb"
)

// answerADD reads one ADD (closing its sandbox FD) and answers it.
func answerADD(t *testing.T, peer *net.UnixConn, nackError string) {
	t.Helper()
	require.NoError(t, peer.SetReadDeadline(time.Now().Add(time.Second)))
	var data [2048]byte
	oob := make([]byte, unix.CmsgSpace(4))
	_, on, _, _, err := peer.ReadMsgUnix(data[:], oob)
	require.NoError(t, err)
	messages, err := unix.ParseSocketControlMessage(oob[:on])
	require.NoError(t, err)
	for _, message := range messages {
		fds, err := unix.ParseUnixRights(&message)
		require.NoError(t, err)
		for _, fd := range fds {
			require.NoError(t, unix.Close(fd))
		}
	}
	response, err := proto.Marshal(&pb.WorkloadResponse{Payload: &pb.WorkloadResponse_Ack{Ack: &pb.Ack{Error: nackError}}})
	require.NoError(t, err)
	_, err = peer.Write(response)
	require.NoError(t, err)
}

type refusedADDFixture struct {
	s        *Server
	conn     *ztunnelConn
	peer     *net.UnixConn
	registry *membership.Registry
	ref      membership.Reference
	path     string
}

func newRefusedADDFixture(t *testing.T) *refusedADDFixture {
	path := "/proc/self/ns/net"
	ep := acknowledgedView(9, "pod-uid", path)
	registry := membership.NewRegistry(1)
	ref, err := registry.Require("ns-uid", ep.K8sUID, 9, path)
	require.NoError(t, err)
	conn, peer := zdsSocketPair(t)
	conn.proxyEpoch = bytes.Repeat([]byte{3}, 32)
	return &refusedADDFixture{s: strictCleanupServer(t), conn: conn, peer: peer, registry: registry, ref: ref, path: path}
}

// send runs one bound ADD of a fresh capture generation through the real
// update path, with the peer answering nackError ("" is a success ACK).
func (f *refusedADDFixture) send(t *testing.T, nackError string) (*pb.WorkloadBinding, error) {
	t.Helper()
	generation, ok := f.registry.BeginZDS(f.ref)
	require.True(t, ok)
	ns, err := netns.OpenPinned(f.path)
	require.NoError(t, err)
	defer ns.Close()
	ep := acknowledgedView(9, "pod-uid", f.path)
	binding, err := bindingForCapture(WithCaptureReference(t.Context(), f.ref, generation), ep, ns)
	require.NoError(t, err)
	binding.ProxyEpoch = bytes.Clone(f.conn.proxyEpoch)
	add, err := endpointToWorkload(ep)
	require.NoError(t, err)
	add.Binding = binding
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- f.s.processUpdate(ctx, f.conn, zdsUpdate{ctx: ctx, netnsPath: f.path, request: &pb.WorkloadRequest{Payload: &pb.WorkloadRequest_Add{Add: add}}})
	}()
	answerADD(t, f.peer, nackError)
	return proto.Clone(binding).(*pb.WorkloadBinding), <-done
}

// The order seen after an agent restart: ztunnel refuses re-admission ADDs,
// each with a new capture generation. A refusal installs nothing, so it is
// not uncertainty; more refusals than the history bound still leave the next
// ADD sendable, and its ACK makes it the acknowledged owner.
func TestRefusedBoundADDsNeverExhaustUncertaintyHistory(t *testing.T) {
	f := newRefusedADDFixture(t)
	for range maxPolicyADDHistory + 4 {
		_, err := f.send(t, "old workload must complete its exact drain before replacement")
		require.ErrorIs(t, err, errZDSNACK)
		require.NotErrorIs(t, err, errZDSRequestRejected, "a refused ADD was transmitted")
		require.Empty(t, f.s.policyADDHistory, "a refused binding is not uncertain")
		require.Empty(t, f.s.policyADDAttempts)
	}
	_, err := f.send(t, "")
	require.NoError(t, err, "the endpoint can still be admitted after many refusals")
}

// Only a refusal is forgotten: a send whose answer never arrives stays
// uncertain, and a refusal never removes the acknowledged owner marker.
func TestRefusedADDKeepsUncertainAndAcknowledgedBindings(t *testing.T) {
	f := newRefusedADDFixture(t)
	acknowledged, err := f.send(t, "")
	require.NoError(t, err)
	key := endpointIncarnation{id: 9, uid: "pod-uid", netnsPath: f.path}
	// What the enrollment's onAck does: record the owner, prune its history.
	f.s.endpointCacheMutex.Lock()
	f.s.drainBindings = map[endpointIncarnation]*pb.WorkloadBinding{key: proto.Clone(acknowledged).(*pb.WorkloadBinding)}
	f.s.pruneAcknowledgedPolicyHistoryLocked(key, acknowledged)
	// Distinct from the refused ADD, which takes the next capture generation.
	uncertain := proto.Clone(acknowledged).(*pb.WorkloadBinding)
	uncertain.CaptureGeneration += 100
	require.NoError(t, f.s.appendPolicyADDHistoryLocked(key, uncertain))
	f.s.endpointCacheMutex.Unlock()

	refused, err := f.send(t, "denied")
	require.ErrorIs(t, err, errZDSNACK)
	require.True(t, bindingIn(f.s.policyADDHistory[key], uncertain), "the unanswered send stays uncertain")
	require.False(t, bindingIn(f.s.policyADDHistory[key], refused), "the refused send is not uncertain")
	require.True(t, proto.Equal(uncertain, f.s.policyADDAttempts[key]))
	require.True(t, proto.Equal(acknowledged, f.s.drainBindings[key]), "the acknowledged owner stays")

	f.s.forgetRefusedADD(&pb.WorkloadRequest{Payload: &pb.WorkloadRequest_Add{Add: &pb.AddWorkload{Binding: acknowledged}}}, f.path)
	require.True(t, proto.Equal(acknowledged, f.s.drainBindings[key]), "a refusal of the acknowledged binding is not a drain")
	require.NotNil(t, refused)
}
