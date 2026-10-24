// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package zds

import (
	"context"
	"testing"

	"github.com/cilium/hive/hivetest"
	goiptables "github.com/coreos/go-iptables/iptables"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
	inpodiptables "github.com/cilium/cilium/pkg/ztunnel/iptables"
	"github.com/cilium/cilium/pkg/ztunnel/pb"
)

func TestPrivilegedZDSReenrollmentRepairsCaptureAfterDelNack(t *testing.T) {
	server := setupZDSTestSuite(t)
	server.SeedInitialSnapshot()
	conn, client := dialZDSClient(t)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	sendHello(t, conn)
	expectSnapshotAndAck(t, client, conn, "")
	ep, cleanup := createTestEndpoint(t, "reenroll-after-nack", 37)
	defer cleanup()
	result := make(chan error, 1)
	ack := func(message string) {
		t.Helper()
		data, err := proto.Marshal(&pb.WorkloadResponse{
			Payload: &pb.WorkloadResponse_Ack{Ack: &pb.Ack{Error: message}},
		})
		require.NoError(t, err)
		_, err = conn.Write(data)
		require.NoError(t, err)
	}
	capturePresent := func() bool {
		t.Helper()
		ns, err := netns.OpenPinned(ep.GetContainerNetnsPath())
		require.NoError(t, err)
		defer ns.Close()
		present := false
		require.NoError(t, ns.Do(func() error {
			var ipt *goiptables.IPTables
			var err error
			if option.Config.EnableIPv4 {
				ipt, err = goiptables.New()
			} else {
				ipt, err = goiptables.NewWithProtocol(goiptables.ProtocolIPv6)
			}
			if err != nil {
				return err
			}
			exists, err := ipt.ChainExists("nat", inpodiptables.InpodPreroutingChain)
			if err != nil {
				return err
			}
			if !exists {
				return nil
			}
			present, err = ipt.Exists("nat", "PREROUTING", "-j", inpodiptables.InpodPreroutingChain)
			return err
		}))
		return present
	}
	go func() { result <- server.EnrollEndpoint(ep) }()
	request := &pb.WorkloadRequest{}
	require.NoError(t, client.readMsg(request))
	require.NotNil(t, request.GetAdd())
	ack("")
	require.NoError(t, <-result)
	require.True(t, capturePresent())

	go func() { result <- server.DisenrollEndpoint(ep) }()
	request = &pb.WorkloadRequest{}
	require.NoError(t, client.readMsg(request))
	require.NotNil(t, request.GetDel())
	ack("injected deletion refusal")
	require.ErrorContains(t, <-result, "injected deletion refusal")
	require.False(t, capturePresent()) // documents current DEL-before-cleanup gate
	server.endpointCacheMutex.Lock()
	cached := server.endpointCache[ep.GetID16()]
	server.endpointCacheMutex.Unlock()
	require.Same(t, ep, cached)

	// NACK retires the connection. Reconnect, but do not seed/replay this
	// cached endpoint: invoke the actual processUpdate path with a socketpair
	// so a cached fast-return cannot be hidden by snapshot repair.
	// Use a distinct, non-serving server with the retained observed cache.
	// The original fixture's lifecycle still owns its live listener/handler.
	// No reconnect snapshot can repair capture and hide the fast-return bug.
	server = &Server{
		logger: hivetest.Logger(t), metrics: NewMetrics(),
		updates:       make(chan zdsUpdate, 1),
		endpointCache: map[uint16]*endpoint.Endpoint{ep.GetID16(): ep},
	}
	connection, peer := zdsSocketPair(t)
	require.NoError(t, peer.SetDeadline(time.Now().Add(2*time.Second)))
	reenrolled := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		reenrolled <- server.EnrollEndpointContext(ctx, ep)
	}()
	var update zdsUpdate
	select {
	case update = <-server.updates:
	case err := <-reenrolled:
		t.Fatalf("Reenrollment returned without fresh ADD/ACK: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Reenrollment did not enqueue a fresh ADD")
	}
	require.NotNil(t, update.request.GetAdd())
	require.True(t, capturePresent())
	processed := make(chan error, 1)
	go func() { processed <- server.processUpdate(context.Background(), connection, update) }()
	request = &pb.WorkloadRequest{}
	require.NoError(t, (&ztunnelConn{conn: peer}).readMsg(request))
	require.Equal(t, ep.K8sUID, request.GetAdd().Uid)
	_, err := peer.Write([]byte{0x0a, 0x00})
	require.NoError(t, err)
	require.NoError(t, <-processed)
	require.NoError(t, <-reenrolled)
}
