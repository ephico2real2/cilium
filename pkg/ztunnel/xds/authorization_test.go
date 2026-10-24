// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	k8stypes "k8s.io/apimachinery/pkg/types"

	slimmetav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/ztunnel/pb/security"
)

const authorizationTestNode = "ztunnel~10.0.0.1~ztunnel.test~test.svc.cluster.local"

func testAuthorization(name string, port uint32) *security.Authorization {
	return &security.Authorization{
		Name: name, Namespace: "orders", Scope: security.Scope_WORKLOAD_SELECTOR,
		Action: security.Action_ALLOW,
		Rules: []*security.Rule{{Clauses: []*security.Clause{{Matches: []*security.Match{{
			Principals:       []*security.StringMatch{{MatchType: &security.StringMatch_Exact{Exact: "spiffe://cluster-a.example/ns/clients/sa/pos"}}},
			DestinationPorts: []uint32{port},
		}}}}}},
	}
}

func applyAuthorization(t *testing.T, p *AuthorizationPolicies, name string, port uint32) uint64 {
	t.Helper()
	version, changed, err := p.Apply(map[string]*security.Authorization{"orders/" + name: testAuthorization(name, port)}, nil)
	require.NoError(t, err)
	require.True(t, changed)
	return version
}

type authorizationTestPeer struct {
	stream    v3.AggregatedDiscoveryService_DeltaAggregatedResourcesClient
	responses chan *v3.DeltaDiscoveryResponse
	errors    chan error
	cancel    context.CancelFunc
}

func newAuthorizationPeer(t *testing.T, conn *grpc.ClientConn) *authorizationTestPeer {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	stream, err := v3.NewAggregatedDiscoveryServiceClient(conn).DeltaAggregatedResources(ctx)
	require.NoError(t, err)
	p := &authorizationTestPeer{stream: stream, responses: make(chan *v3.DeltaDiscoveryResponse, 16), errors: make(chan error, 1), cancel: cancel}
	t.Cleanup(cancel)
	go func() {
		for {
			resp, err := stream.Recv()
			if err != nil {
				p.errors <- err
				return
			}
			select {
			case p.responses <- resp:
			case <-ctx.Done():
				return
			}
		}
	}()
	return p
}

func (p *authorizationTestPeer) send(t *testing.T, req *v3.DeltaDiscoveryRequest) {
	t.Helper()
	require.NoError(t, p.stream.Send(req))
}

func (p *authorizationTestPeer) receive(t *testing.T) *v3.DeltaDiscoveryResponse {
	t.Helper()
	select {
	case resp := <-p.responses:
		return resp
	case err := <-p.errors:
		t.Fatalf("ADS receive: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for ADS response")
	}
	return nil
}

func (p *authorizationTestPeer) noResponse(t *testing.T) {
	t.Helper()
	select {
	case resp := <-p.responses:
		t.Fatalf("unexpected ADS response: %v", resp)
	case err := <-p.errors:
		t.Fatalf("unexpected ADS close: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
}

func (p *authorizationTestPeer) closed(t *testing.T) {
	t.Helper()
	select {
	case <-p.errors:
	case resp := <-p.responses:
		t.Fatalf("unexpected response before close: %v", resp)
	case <-time.After(3 * time.Second):
		t.Fatal("invalid ADS request did not close stream")
	}
}

func subscribeAuthorization() *v3.DeltaDiscoveryRequest {
	return &v3.DeltaDiscoveryRequest{TypeUrl: xdsTypeURLAuthorization, Node: &corev3.Node{Id: authorizationTestNode}}
}

func (p *authorizationTestPeer) ack(t *testing.T, resp *v3.DeltaDiscoveryResponse) {
	p.send(t, &v3.DeltaDiscoveryRequest{TypeUrl: resp.TypeUrl, ResponseNonce: resp.Nonce})
}

func testAuthorizationServer(t *testing.T) (*Server, *grpc.ClientConn) {
	return testAuthorizationServerMode(t, false)
}

func testAuthorizationServerMode(t *testing.T, addresses bool) (*Server, *grpc.ClientConn) {
	t.Helper()
	log := slog.New(slog.DiscardHandler)
	metrics := NewMetrics()
	metrics.Enable()
	server := newServer(log, nil, nil, nil, nil, 8, metrics)
	listener := bufconn.Listen(1024 * 1024)
	grpcServer := grpc.NewServer()
	var handler v3.AggregatedDiscoveryServiceServer = server
	if addresses {
		handler = &multiplexAuthorizationTestServer{Server: server}
	}
	v3.RegisterAggregatedDiscoveryServiceServer(grpcServer, handler)
	go func() { _ = grpcServer.Serve(listener) }()
	conn, err := grpc.NewClient("passthrough:///ztunnel-authorization", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close(); grpcServer.Stop(); _ = listener.Close() })
	return server, conn
}

func requireAuthorization(t *testing.T, resp *v3.DeltaDiscoveryResponse, name string, port uint32) {
	t.Helper()
	require.Equal(t, xdsTypeURLAuthorization, resp.TypeUrl)
	require.NotEmpty(t, resp.Nonce)
	require.NotEqual(t, "0", resp.Nonce)
	require.Len(t, resp.Resources, 1)
	resource := resp.Resources[0]
	require.Equal(t, "orders/"+name, resource.Name)
	require.NotEmpty(t, resource.Version)
	require.Equal(t, xdsTypeURLAuthorization, resource.Resource.TypeUrl)
	var policy security.Authorization
	require.NoError(t, resource.Resource.UnmarshalTo(&policy))
	require.True(t, proto.Equal(testAuthorization(name, port), &policy))
}

func TestAuthorizationApplyAtomicAndImmutable(t *testing.T) {
	s, conn := testAuthorizationServer(t)
	policy := testAuthorization("pos", 80)
	version, changed, err := s.authorizations.Apply(map[string]*security.Authorization{"orders/pos": policy}, nil)
	require.NoError(t, err)
	require.True(t, changed)
	unchanged, changed, err := s.authorizations.Apply(map[string]*security.Authorization{"orders/pos": policy}, nil)
	require.NoError(t, err)
	require.False(t, changed)
	require.Equal(t, version, unchanged)
	policy.Rules[0].Clauses[0].Matches[0].DestinationPorts[0] = 81
	badWire := testAuthorization("bad-wire", 80)
	badWire.Rules[0].Clauses[0].Matches[0].Principals[0].MatchType = &security.StringMatch_Exact{Exact: string([]byte{0xff})}
	for _, batch := range []map[string]*security.Authorization{
		{"orders/valid": testAuthorization("valid", 80), "bad": testAuthorization("bad", 80)},
		{"orders/nil": nil},
		{"orders/bad-wire": badWire},
		{"orders/wrong": testAuthorization("other", 80)},
		{"orders/scope": {Name: "scope", Namespace: "orders", Scope: security.Scope(42)}},
		{"orders/action": {Name: "action", Namespace: "orders", Action: security.Action(42)}},
		{"/empty": {Name: "empty", Scope: security.Scope_NAMESPACE}},
	} {
		_, _, err := s.authorizations.Apply(batch, nil)
		require.Error(t, err)
	}
	_, _, err = s.authorizations.Apply(map[string]*security.Authorization{"orders/pos": testAuthorization("pos", 80)}, []string{"orders/pos"})
	require.Error(t, err)
	_, _, err = s.authorizations.Apply(nil, []string{"orders/"})
	require.Error(t, err)
	current, changed, err := s.authorizations.Apply(nil, nil)
	require.NoError(t, err)
	require.False(t, changed)
	require.Equal(t, version, current)
	peer := newAuthorizationPeer(t, conn)
	peer.send(t, subscribeAuthorization())
	requireAuthorization(t, peer.receive(t), "pos", 80)
}

func TestAuthorizationDeltaLifecycle(t *testing.T) {
	s, conn := testAuthorizationServer(t)
	peer := newAuthorizationPeer(t, conn)
	peer.send(t, subscribeAuthorization())
	empty := peer.receive(t)
	require.Equal(t, xdsTypeURLAuthorization, empty.TypeUrl)
	require.NotEmpty(t, empty.Nonce)
	require.NotEqual(t, "0", empty.Nonce)
	require.Empty(t, empty.Resources)
	peer.ack(t, empty)
	version := applyAuthorization(t, s.authorizations, "pos", 80)
	first := peer.receive(t)
	requireAuthorization(t, first, "pos", 80)
	require.Equal(t, fmt.Sprint(version), first.Resources[0].Version)
	peer.ack(t, first)
	version = applyAuthorization(t, s.authorizations, "pos", 81)
	updated := peer.receive(t)
	requireAuthorization(t, updated, "pos", 81)
	require.Equal(t, fmt.Sprint(version), updated.Resources[0].Version)
	require.NotEqual(t, first.Nonce, updated.Nonce)
	peer.ack(t, updated)
	_, changed, err := s.authorizations.Apply(nil, []string{"orders/pos"})
	require.NoError(t, err)
	require.True(t, changed)
	removed := peer.receive(t)
	require.Empty(t, removed.Resources)
	require.Equal(t, []string{"orders/pos"}, removed.RemovedResources)
	peer.ack(t, removed)
	peer.noResponse(t)
	require.Eventually(t, func() bool { return testutil.ToFloat64(s.metrics.AuthorizationEvents.WithLabelValues("ack")) == 4 }, time.Second, time.Millisecond)
}

func TestAuthorizationNamedSubscriptions(t *testing.T) {
	s, conn := testAuthorizationServer(t)
	applyAuthorization(t, s.authorizations, "one", 80)
	applyAuthorization(t, s.authorizations, "two", 80)
	peer := newAuthorizationPeer(t, conn)
	req := subscribeAuthorization()
	req.ResourceNamesSubscribe = []string{"orders/one"}
	peer.send(t, req)
	first := peer.receive(t)
	requireAuthorization(t, first, "one", 80)
	peer.send(t, &v3.DeltaDiscoveryRequest{TypeUrl: xdsTypeURLAuthorization, ResponseNonce: first.Nonce, ResourceNamesSubscribe: []string{"orders/two"}, ResourceNamesUnsubscribe: []string{"orders/one"}})
	two := peer.receive(t)
	requireAuthorization(t, two, "two", 80)
	peer.ack(t, two)
	applyAuthorization(t, s.authorizations, "one", 81)
	peer.noResponse(t)
	applyAuthorization(t, s.authorizations, "two", 82)
	requireAuthorization(t, peer.receive(t), "two", 82)
}

func TestAuthorizationNACKAndStaleACK(t *testing.T) {
	s, conn := testAuthorizationServer(t)
	applyAuthorization(t, s.authorizations, "pos", 80)
	peer := newAuthorizationPeer(t, conn)
	peer.send(t, subscribeAuthorization())
	first := peer.receive(t)
	peer.send(t, &v3.DeltaDiscoveryRequest{TypeUrl: xdsTypeURLAuthorization, ResponseNonce: first.Nonce, ErrorDetail: &status.Status{Code: 3, Message: "rejected policy"}})
	peer.noResponse(t)
	require.Eventually(t, func() bool { return testutil.ToFloat64(s.metrics.AuthorizationEvents.WithLabelValues("nack")) == 1 }, time.Second, time.Millisecond)
	require.Zero(t, testutil.ToFloat64(s.metrics.AuthorizationEvents.WithLabelValues("ack")))
	require.Zero(t, testutil.ToFloat64(s.metrics.EnrollmentFailures.WithLabelValues("nack_received")))
	applyAuthorization(t, s.authorizations, "pos", 81)
	updated := peer.receive(t)
	requireAuthorization(t, updated, "pos", 81)
	peer.ack(t, first)
	peer.noResponse(t)
	require.Zero(t, testutil.ToFloat64(s.metrics.AuthorizationEvents.WithLabelValues("ack")))
	peer.ack(t, updated)
	peer.noResponse(t)
	require.Equal(t, float64(1), testutil.ToFloat64(s.metrics.AuthorizationEvents.WithLabelValues("ack")))
}

func TestAuthorizationReconnectRemovesStaleResources(t *testing.T) {
	s, conn := testAuthorizationServer(t)
	version := applyAuthorization(t, s.authorizations, "current", 80)
	peer := newAuthorizationPeer(t, conn)
	req := subscribeAuthorization()
	req.InitialResourceVersions = map[string]string{"orders/current": fmt.Sprint(version), "orders/deleted": "9999"}
	peer.send(t, req)
	resp := peer.receive(t)
	requireAuthorization(t, resp, "current", 80)
	require.Equal(t, []string{"orders/deleted"}, resp.RemovedResources)
	peer.ack(t, resp)
	peer.cancel()
	_, _, err := s.authorizations.Apply(map[string]*security.Authorization{"orders/new": testAuthorization("new", 81)}, []string{"orders/current"})
	require.NoError(t, err)
	peer = newAuthorizationPeer(t, conn)
	req = subscribeAuthorization()
	req.InitialResourceVersions = map[string]string{"orders/current": "9999"}
	peer.send(t, req)
	resp = peer.receive(t)
	requireAuthorization(t, resp, "new", 81)
	require.Equal(t, []string{"orders/current"}, resp.RemovedResources)
}

func TestAuthorizationStreamsHaveIndependentACKState(t *testing.T) {
	s, conn := testAuthorizationServer(t)
	applyAuthorization(t, s.authorizations, "pos", 80)
	one, two := newAuthorizationPeer(t, conn), newAuthorizationPeer(t, conn)
	one.send(t, subscribeAuthorization())
	two.send(t, subscribeAuthorization())
	firstOne, firstTwo := one.receive(t), two.receive(t)
	one.ack(t, firstOne)
	applyAuthorization(t, s.authorizations, "pos", 81)
	requireAuthorization(t, one.receive(t), "pos", 81)
	two.noResponse(t)
	two.ack(t, firstTwo)
	requireAuthorization(t, two.receive(t), "pos", 81)
}

func TestAuthorizationRejectsInvalidAcknowledgments(t *testing.T) {
	for name, request := range map[string]func(string) *v3.DeltaDiscoveryRequest{
		"Address cannot ACK Authorization": func(nonce string) *v3.DeltaDiscoveryRequest {
			return &v3.DeltaDiscoveryRequest{TypeUrl: xdsTypeURLAddress, ResponseNonce: nonce}
		},
		"invalid nonce": func(string) *v3.DeltaDiscoveryRequest {
			return &v3.DeltaDiscoveryRequest{TypeUrl: xdsTypeURLAuthorization, ResponseNonce: "address-uuid"}
		},
		"error without nonce": func(string) *v3.DeltaDiscoveryRequest {
			return &v3.DeltaDiscoveryRequest{TypeUrl: xdsTypeURLAuthorization, ErrorDetail: &status.Status{Code: 3}}
		},
		"changed node": func(nonce string) *v3.DeltaDiscoveryRequest {
			return &v3.DeltaDiscoveryRequest{TypeUrl: xdsTypeURLAuthorization, ResponseNonce: nonce, Node: &corev3.Node{Id: "ztunnel~10.0.0.2~other.test~test.svc.cluster.local"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, conn := testAuthorizationServer(t)
			peer := newAuthorizationPeer(t, conn)
			peer.send(t, subscribeAuthorization())
			resp := peer.receive(t)
			peer.send(t, request(resp.Nonce))
			peer.closed(t)
			require.Zero(t, testutil.ToFloat64(s.metrics.AuthorizationEvents.WithLabelValues("ack")))
		})
	}
}

// Replace only the CEP source for the mixed-type test; the stream processor,
// authorization store, shared delta server and gRPC transport remain real.
type multiplexAuthorizationTestServer struct{ *Server }

func (s *multiplexAuthorizationTestServer) DeltaAggregatedResources(stream v3.AggregatedDiscoveryService_DeltaAggregatedResourcesServer) error {
	sp := NewStreamProcessor(&StreamProcessorParams{
		Stream: stream, StreamRecv: make(chan *v3.DeltaDiscoveryRequest, 1),
		EndpointEventRecv: s.endpointEventChan, Log: s.log, Metrics: s.metrics,
		Authorizations: s.authorizations,
	})
	sp.endpointSource = &MockEndpointEventSource{}
	return sp.Start()
}

func TestAuthorizationAndAddressShareADS(t *testing.T) {
	s, conn := testAuthorizationServerMode(t, true)
	applyAuthorization(t, s.authorizations, "pos", 80)
	peer := newAuthorizationPeer(t, conn)
	peer.send(t, &v3.DeltaDiscoveryRequest{TypeUrl: xdsTypeURLAddress, Node: &corev3.Node{Id: authorizationTestNode}})
	address := peer.receive(t)
	require.Equal(t, xdsTypeURLAddress, address.TypeUrl)
	peer.ack(t, address)
	// Node is only sent on the first ADS request, not on each resource type.
	peer.send(t, &v3.DeltaDiscoveryRequest{TypeUrl: xdsTypeURLAuthorization})
	authorization := peer.receive(t)
	requireAuthorization(t, authorization, "pos", 80)
	peer.ack(t, authorization)

	cep := makeCEP("shop", "orders", "10.0.0.5")
	cep.OwnerReferences = []slimmetav1.OwnerReference{{Kind: "Pod", UID: k8stypes.UID("shop-pod-uid")}}
	go func() { s.endpointEventChan <- &EndpointEvent{Type: CREATE, CiliumEndpoint: cep} }()
	applyAuthorization(t, s.authorizations, "pos", 81)
	seen := map[string]bool{}
	for range 2 {
		resp := peer.receive(t)
		seen[resp.TypeUrl] = true
		if resp.TypeUrl == xdsTypeURLAuthorization {
			requireAuthorization(t, resp, "pos", 81)
		} else {
			require.Equal(t, xdsTypeURLAddress, resp.TypeUrl)
			require.Len(t, resp.Resources, 1)
			require.Equal(t, "shop-pod-uid", resp.Resources[0].Name)
		}
		peer.ack(t, resp)
	}
	require.Len(t, seen, 2)
	peer.noResponse(t)
}

func TestAuthorizationCannotACKAddress(t *testing.T) {
	s, conn := testAuthorizationServerMode(t, true)
	peer := newAuthorizationPeer(t, conn)
	peer.send(t, &v3.DeltaDiscoveryRequest{TypeUrl: xdsTypeURLAddress, Node: &corev3.Node{Id: authorizationTestNode}})
	address := peer.receive(t)
	peer.send(t, &v3.DeltaDiscoveryRequest{TypeUrl: xdsTypeURLAuthorization, ResponseNonce: address.Nonce})
	peer.closed(t)
	require.Zero(t, testutil.ToFloat64(s.metrics.AuthorizationEvents.WithLabelValues("ack")))
}

func TestAuthorizationSendFailureTerminatesStream(t *testing.T) {
	ctx := t.Context()
	requests := make(chan *v3.DeltaDiscoveryRequest, 1)
	requests <- subscribeAuthorization()
	stream := &MockStream{}
	stream.OnContext = func() context.Context { return ctx }
	stream._Recv = func() (*v3.DeltaDiscoveryRequest, error) {
		select {
		case req := <-requests:
			return req, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	writeError := errors.New("test ADS write failure")
	stream.OnSendMsg = func(any) error { return writeError }
	metrics := NewMetrics()
	metrics.Enable()
	sp := NewStreamProcessor(&StreamProcessorParams{Stream: stream, StreamRecv: make(chan *v3.DeltaDiscoveryRequest, 1), EndpointEventRecv: make(chan *EndpointEvent), Log: slog.New(slog.DiscardHandler), Metrics: metrics})
	done := make(chan error, 1)
	go func() { done <- sp.Start() }()
	select {
	case err := <-done:
		require.ErrorIs(t, err, writeError)
	case <-time.After(time.Second):
		t.Fatal("write error did not close ADS stream")
	}
	require.Equal(t, float64(1), testutil.ToFloat64(metrics.AuthorizationEvents.WithLabelValues("send_failed")))
}
