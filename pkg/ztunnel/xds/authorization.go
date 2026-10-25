// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/protobuf/proto"

	envoyxds "github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/ztunnel/pb/security"
)

// AuthorizationPolicies contains the desired authorization resources for the
// local ztunnel. It transports compiled policies; it does not compile Cilium
// policy, enroll workloads, or establish that traffic is protected.
//
// Resources are keyed by namespace/name, as in the pinned proxy. A future
// compiler must preserve incarnation and effective-policy semantics in its
// names and workload references. Callers must not publish a broader SA allow
// in place of a label-specific Cilium policy.
type AuthorizationPolicies struct {
	quarantineMu lock.Mutex
	cache        *envoyxds.Cache
	server       *envoyxds.Server
}

// NewAuthorizationPolicies creates an empty, agent-local desired policy store.
func NewAuthorizationPolicies(log *slog.Logger, metrics *Metrics) *AuthorizationPolicies {
	if metrics == nil {
		metrics = NewMetrics()
	}
	cache := envoyxds.NewCache(log)
	m := authorizationMetrics{metrics}
	return &AuthorizationPolicies{
		cache: cache,
		server: envoyxds.NewServer(log, map[string]*envoyxds.ResourceTypeConfiguration{
			xdsTypeURLAuthorization: {Source: cache, AckObserver: authorizationACKMetrics{m}},
		}, nil, m),
	}
}

// Apply atomically publishes a validated batch. It clones protobufs before
// caching them so later caller mutations cannot change an unversioned policy.
// Versions are local to this agent process, not persistent admission epochs.
// A reconnect replays current resources and removes stale client-held names.
func (p *AuthorizationPolicies) Apply(upserts map[string]*security.Authorization, removals []string) (uint64, bool, error) {
	resources := make(map[string]proto.Message, len(upserts))
	for name, policy := range upserts {
		if policy == nil {
			return 0, false, fmt.Errorf("nil authorization %q", name)
		}
		if err := validateAuthorizationName(name); err != nil {
			return 0, false, err
		}
		if name != policy.Namespace+"/"+policy.Name {
			return 0, false, fmt.Errorf("authorization key %q does not match namespace/name", name)
		}
		if _, ok := security.Scope_name[int32(policy.Scope)]; !ok {
			return 0, false, fmt.Errorf("authorization %q has unknown scope", name)
		}
		if policy.Scope != security.Scope_GLOBAL && policy.Namespace == "" {
			return 0, false, fmt.Errorf("authorization %q requires a namespace", name)
		}
		if _, ok := security.Action_name[int32(policy.Action)]; !ok {
			return 0, false, fmt.Errorf("authorization %q has unknown action", name)
		}
		cloned := proto.Clone(policy)
		if _, err := proto.Marshal(cloned); err != nil {
			return 0, false, fmt.Errorf("authorization %q cannot be encoded: %w", name, err)
		}
		resources[name] = cloned
	}
	for _, name := range removals {
		if err := validateAuthorizationName(name); err != nil {
			return 0, false, err
		}
		if _, ok := upserts[name]; ok {
			return 0, false, fmt.Errorf("authorization %q is both upserted and removed", name)
		}
	}
	version, changed, _ := p.cache.TX(xdsTypeURLAuthorization, resources, removals)
	return version, changed, nil
}

func validateAuthorizationName(name string) error {
	parts := strings.Split(name, "/")
	if len(parts) != 2 || parts[1] == "" || strings.ContainsAny(name, "\x00\r\n\t ") {
		return fmt.Errorf("invalid authorization namespace/name %q", name)
	}
	return nil
}

// authorizationDeltaStream demultiplexes only Authorization requests into the
// shared delta engine. Address ACKs never enter its per-type nonce state.
type authorizationDeltaStream struct {
	ctx      context.Context
	requests <-chan *v3.DeltaDiscoveryRequest
	stream   *serializedDeltaStream
	metrics  *Metrics
}

func (s *authorizationDeltaStream) Recv() (*v3.DeltaDiscoveryRequest, error) {
	select {
	case req := <-s.requests:
		return req, nil
	case <-s.ctx.Done():
		authorizationMetrics{s.metrics}.IncreaseCancel(xdsTypeURLAuthorization)
		return nil, s.ctx.Err()
	}
}

func (s *authorizationDeltaStream) Send(resp *v3.DeltaDiscoveryResponse) error {
	err := s.stream.SendMsg(resp)
	if err != nil {
		s.metrics.AuthorizationEvents.WithLabelValues("send_failed").Inc()
	}
	return err
}

// gRPC permits a reader and writer concurrently, but not concurrent writers.
// The legacy Address handler and the Authorization engine share this lock.
type serializedDeltaStream struct {
	v3.AggregatedDiscoveryService_DeltaAggregatedResourcesServer
	ctx context.Context
	mu  lock.Mutex
}

func (s *serializedDeltaStream) Context() context.Context { return s.ctx }

func (s *serializedDeltaStream) Send(resp *v3.DeltaDiscoveryResponse) error {
	return s.SendMsg(resp)
}

func (s *serializedDeltaStream) SendMsg(message any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.AggregatedDiscoveryService_DeltaAggregatedResourcesServer.SendMsg(message)
}

// authorizationACKMetrics observes protocol acknowledgments only. It exposes
// no readiness state, completion callback, or admission decision.
type authorizationACKMetrics struct{ authorizationMetrics }

func (m authorizationACKMetrics) HandleResourceVersionAck(_ string, _, _ uint64, nack bool, _ string, typeURL string, _ []string) {
	if !nack {
		m.IncreaseACK(typeURL)
	}
}

func (authorizationACKMetrics) MarkRestorePending()                             {}
func (authorizationACKMetrics) MarkRestoreCompleted()                           {}
func (authorizationACKMetrics) WaitForFirstAck(context.Context, string, string) {}

type authorizationMetrics struct{ *Metrics }

func (m authorizationMetrics) IncreaseACK(string) {
	m.AuthorizationEvents.WithLabelValues("ack").Inc()
}

func (m authorizationMetrics) IncreaseNACK(string) {
	m.AuthorizationEvents.WithLabelValues("nack").Inc()
}

func (m authorizationMetrics) IncreaseCancel(string) {
	m.AuthorizationEvents.WithLabelValues("cancel").Inc()
}
