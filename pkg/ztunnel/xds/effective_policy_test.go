// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/netip"
	"slices"
	"testing"
	"time"

	v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/status"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/policy"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/ztunnel/membership"
	"github.com/cilium/cilium/pkg/ztunnel/pb/security"
)

var ownerCluster = cmtypes.ClusterInfo{ID: 1, Name: "cmtc-a", MaxConnectedClusters: 255}

const (
	ingress = 0
	egress  = 1
	tcp     = 6
)

type l4Entry struct {
	dir, proto, prefix uint8
	id                 uint32
	port               uint16
	deny               bool
}

// l4Snapshot builds a native snapshot through the production bounded decoder.
func l4Snapshot(t *testing.T, entries ...l4Entry) *policy.ZtunnelL4Snapshot {
	t.Helper()
	slices.SortFunc(entries, func(a, b l4Entry) int {
		for _, d := range []int{int(a.dir) - int(b.dir), int(a.proto) - int(b.proto), int(a.port) - int(b.port), int(a.prefix) - int(b.prefix)} {
			if d != 0 {
				return d
			}
		}
		switch {
		case a.id < b.id:
			return -1
		case a.id > b.id:
			return 1
		}
		return 0
	})
	body := []byte("CL4SNAP1")
	body = binary.BigEndian.AppendUint32(body, ownerCluster.ID)
	body = binary.BigEndian.AppendUint32(body, ownerCluster.MaxConnectedClusters)
	body = append(body, byte(len(ownerCluster.Name)))
	body = append(body, ownerCluster.Name...)
	body = binary.BigEndian.AppendUint64(body, 1)
	body = binary.BigEndian.AppendUint64(body, 1)
	body = binary.BigEndian.AppendUint32(body, uint32(len(entries)))
	for _, e := range entries {
		precedence := policyTypes.AllowEntry().Precedence
		if e.deny {
			precedence = policyTypes.DenyEntry().Precedence
		}
		body = append(body, e.dir, e.proto, e.prefix, 0)
		body = binary.BigEndian.AppendUint32(body, e.id)
		body = binary.BigEndian.AppendUint16(body, e.port)
		body = binary.BigEndian.AppendUint16(body, 0)
		body = binary.BigEndian.AppendUint32(body, uint32(precedence))
		body = binary.BigEndian.AppendUint32(body, 0)
	}
	sum := sha256.Sum256(body)
	snapshot, err := policy.DecodeNativeZtunnelL4(slog.New(slog.DiscardHandler), policy.NativeZtunnelL4Expectation{
		Owner: ownerCluster, PolicyRevision: 1, SelectorRevision: 1, Digest: hex.EncodeToString(sum[:])}, append(body, sum[:]...))
	require.NoError(t, err)
	return snapshot
}

// allowAll is what a distilled map contains when every peer is allowed in
// one direction: one allow entry per aggregate identity (mapstate
// allowAllIdentities), not an identity-0 wildcard.
func allowAll(dir uint8) []l4Entry {
	out := make([]l4Entry, 0, len(policy.AllAggregates))
	for _, nid := range policy.AllAggregates {
		out = append(out, l4Entry{dir: dir, id: uint32(nid)})
	}
	return out
}

func entries(groups ...[]l4Entry) []l4Entry {
	var out []l4Entry
	for _, g := range groups {
		out = append(out, g...)
	}
	return out
}

func one(e l4Entry) []l4Entry { return []l4Entry{e} }

type fakeWorkload struct {
	podUID        string
	candidate     endpoint.ZtunnelReleaseCandidate
	err           error
	quarantined   bool
	releaseErr    error
	receipts      []endpoint.ZtunnelAdmissionReceipt
	regenerations []*regeneration.ExternalRegenerationMetadata
}

func (w *fakeWorkload) GetK8sPodUID() string { return w.podUID }
func (w *fakeWorkload) SnapshotZtunnelReleaseCandidate() (endpoint.ZtunnelReleaseCandidate, error) {
	return w.candidate, w.err
}
func (w *fakeWorkload) IsZtunnelQuarantined() bool { return w.quarantined }
func (w *fakeWorkload) ReleaseZtunnelQuarantine(r endpoint.ZtunnelAdmissionReceipt) error {
	w.receipts = append(w.receipts, r)
	if w.releaseErr != nil {
		return w.releaseErr
	}
	w.quarantined = false
	return nil
}
func (w *fakeWorkload) RegenerateIfAlive(m *regeneration.ExternalRegenerationMetadata) <-chan bool {
	w.regenerations = append(w.regenerations, m)
	ch := make(chan bool, 1)
	ch <- true
	return ch
}

type fakeLookup map[uint16]*fakeWorkload

func (l fakeLookup) lookup(id uint16) policyWorkload {
	if w, ok := l[id]; ok {
		return w
	}
	return nil
}

type ownerFixture struct {
	t         *testing.T
	registry  *membership.Registry
	policies  *AuthorizationPolicies
	owner     *effectivePolicyOwner
	workloads fakeLookup
	refs      map[string]membership.Reference
}

func newOwnerFixture(t *testing.T) *ownerFixture {
	f := &ownerFixture{t: t, registry: membership.NewRegistry(ownerCluster.ID), workloads: fakeLookup{}, refs: map[string]membership.Reference{}}
	metrics := NewMetrics()
	f.policies = NewAuthorizationPolicies(slog.New(slog.DiscardHandler), metrics)
	f.owner = newEffectivePolicyOwner(slog.New(slog.DiscardHandler), f.registry, f.workloads, f.policies, ownerCluster, "cmtc-a.mesh.example", metrics)
	return f
}

// capture registers one Required, captured, ZDS-acknowledged incarnation and
// its endpoint with the given realized policy.
func (f *ownerFixture) capture(name string, epid uint16, podUID, ip string, idn uint32, snapshot *policy.ZtunnelL4Snapshot) *fakeWorkload {
	t := f.t
	ref, err := f.registry.Require(remoteNamespaceUID, podUID, epid, "/run/netns/"+name)
	require.NoError(t, err)
	zds, ok := f.registry.BeginZDS(ref)
	require.True(t, ok)
	require.True(t, f.registry.MarkCaptured(ref, zds))
	require.True(t, f.registry.AcknowledgeZDS(ref, zds))
	pub, ok := f.registry.Publication(ref)
	require.True(t, ok)
	w := &fakeWorkload{podUID: podUID, quarantined: true, candidate: endpoint.ZtunnelReleaseCandidate{
		Binding:       endpoint.ZtunnelPolicyBinding{RequiredObserved: true, EndpointID: epid, NamespaceUID: remoteNamespaceUID, PodUID: podUID},
		Membership:    endpoint.ZtunnelMembership{Version: pub.Version, Revision: pub.Revision, Epoch: pub.Epoch, Generation: pub.Generation, State: pub.State, NamespaceUID: remoteNamespaceUID},
		HasMembership: true,
		Subject: policy.ZtunnelPolicySubject{EndpointID: epid, Namespace: "orders", NamespaceUID: remoteNamespaceUID, PodUID: podUID,
			ServiceAccount: name, NumericIdentity: identity.NumericIdentity(1<<16 | idn), Addresses: []netip.Addr{netip.MustParseAddr(ip)}, Policy: snapshot},
		PolicyRevision: 1, PolicyDigest: snapshot.Digest()}}
	f.workloads[epid] = w
	f.refs[podUID] = ref
	return w
}

// bindAndAcknowledgeAddress is what the stream does: bind the per-incarnation
// key, then publish and acknowledge the workload Address on its generation.
func (f *ownerFixture) bindAndAcknowledgeAddress(generation uint64, podUIDs ...string) {
	t := f.t
	for _, podUID := range podUIDs {
		deny, err := quarantineAuthorization("orders", remoteNamespaceUID, podUID)
		require.NoError(t, err)
		require.NoError(t, f.policies.applyQuarantines(map[string]*security.Authorization{deny.Namespace + "/" + deny.Name: deny}, nil))
		version, ok := f.registry.PublishAddress(f.refs[podUID], generation)
		require.True(t, ok)
		require.True(t, f.registry.AcknowledgeAddress(f.refs[podUID], generation, version))
	}
}

func (f *ownerFixture) effective(podUID string) *security.Authorization {
	key, err := effectivePolicyKey("orders", remoteNamespaceUID, podUID)
	require.NoError(f.t, err)
	got := f.policies.cache.GetResources(xdsTypeURLAuthorization, 0, []string{key})
	require.NotNil(f.t, got)
	require.Len(f.t, got.VersionedResources, 1)
	return got.VersionedResources[0].Resource.(*security.Authorization)
}

func (f *ownerFixture) cacheVersion() uint64 {
	return f.policies.cache.GetResources(xdsTypeURLAuthorization, 0, nil).Version
}

const (
	podD = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
	podS = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
	podX = "ffffffff-ffff-4fff-8fff-ffffffffffff"
)

// Compile, publish, require the ztunnel ACK of exactly that version on the
// current stream, then release with a receipt bound to the candidate.
func TestEffectivePolicyIsCompiledAcknowledgedAndThenReleases(t *testing.T) {
	f := newOwnerFixture(t)
	d := f.capture("api", 10, podD, "10.0.0.20", 300, l4Snapshot(t, entries(allowAll(ingress), allowAll(egress))...))
	s := f.capture("web", 11, podS, "10.0.0.21", 301, l4Snapshot(t, entries(allowAll(ingress), allowAll(egress))...))
	generation := f.owner.beginStream()
	f.bindAndAcknowledgeAddress(generation, podD, podS)
	require.Equal(t, security.Action_DENY, f.effective(podD).Action, "bound content starts as the DENY quarantine")

	f.owner.reconcile()
	allow := f.effective(podD)
	require.Equal(t, security.Action_ALLOW, allow.Action)
	require.Len(t, allow.Rules, 1, "one rule per permitted source workload")
	match := allow.Rules[0].Clauses[0].Matches[0]
	require.Equal(t, "cmtc-a.mesh.example/ns/orders/sa/web", match.Principals[0].GetExact())
	require.Equal(t, netip.MustParseAddr("10.0.0.21").AsSlice(), match.SourceIps[0].Address)
	require.Equal(t, netip.MustParseAddr("10.0.0.20").AsSlice(), match.DestinationIps[0].Address)
	require.Empty(t, match.DestinationPorts, "both maps allow every port")
	state, _ := f.registry.Get(f.refs[podD])
	require.NotZero(t, state.PolicyVersion)
	require.False(t, state.PolicyAcked)
	require.Empty(t, d.receipts, "no release before ztunnel acknowledges the policy")

	// An ACK of an older stream's generation does not count.
	f.owner.observeAuthorizationAck(generation-1, f.cacheVersion())
	f.owner.reconcile()
	require.Empty(t, d.receipts)

	f.owner.observeAuthorizationAck(generation, f.cacheVersion())
	f.owner.reconcile()
	state, _ = f.registry.Get(f.refs[podD])
	require.True(t, state.Active())
	require.Len(t, d.receipts, 1)
	receipt := d.receipts[0]
	require.Equal(t, d.candidate.Binding, receipt.Binding)
	require.Equal(t, d.candidate.Membership, receipt.Membership)
	require.Equal(t, d.candidate.PolicyDigest, receipt.PolicyDigest)
	require.NotZero(t, receipt.AuthorizationVersion)
	require.Len(t, d.regenerations, 1)
	require.Equal(t, regeneration.RegenerateWithDatapath, d.regenerations[0].RegenerationLevel)
	require.Len(t, s.receipts, 1, "the source is a destination too and is released the same way")

	f.owner.reconcile()
	require.Len(t, d.receipts, 1, "a released workload is not released again")
}

// The destination's ingress AND each source's egress decide the ports.
func TestEffectivePolicyIntersectsDestinationIngressAndSourceEgress(t *testing.T) {
	f := newOwnerFixture(t)
	f.capture("api", 10, podD, "10.0.0.20", 300, l4Snapshot(t, entries(
		one(l4Entry{dir: ingress, proto: tcp, prefix: 16, id: 1<<16 | 301, port: 8080}),
		one(l4Entry{dir: ingress, proto: tcp, prefix: 16, id: 1<<16 | 302, port: 8080}), allowAll(egress))...))
	f.capture("web", 11, podS, "10.0.0.21", 301, l4Snapshot(t, entries(allowAll(ingress), allowAll(egress))...))
	f.capture("batch", 12, podX, "10.0.0.22", 302, l4Snapshot(t, entries(allowAll(ingress),
		one(l4Entry{dir: egress, id: 1<<16 | 300, deny: true}), allowAll(egress))...))
	generation := f.owner.beginStream()
	f.bindAndAcknowledgeAddress(generation, podD, podS, podX)
	f.owner.reconcile()

	allow := f.effective(podD)
	require.Len(t, allow.Rules, 1, "the source whose egress denies the destination gets no rule")
	match := allow.Rules[0].Clauses[0].Matches[0]
	require.Equal(t, "cmtc-a.mesh.example/ns/orders/sa/web", match.Principals[0].GetExact())
	require.Equal(t, []uint32{8080}, match.DestinationPorts, "only the port the destination admits")
}

func TestEffectivePolicyFailsClosed(t *testing.T) {
	t.Run("compile failure keeps DENY and publishes no evidence", func(t *testing.T) {
		f := newOwnerFixture(t)
		d := f.capture("api", 10, podD, "10.0.0.20", 300, l4Snapshot(t, entries(allowAll(ingress), allowAll(egress))...))
		// A subject claiming another cluster's identity cannot be compiled.
		d.candidate.Subject.NumericIdentity = identity.NumericIdentity(2<<16 | 300)
		generation := f.owner.beginStream()
		f.bindAndAcknowledgeAddress(generation, podD)
		f.owner.reconcile()
		f.owner.observeAuthorizationAck(generation, f.cacheVersion())
		f.owner.reconcile()
		require.Equal(t, security.Action_DENY, f.effective(podD).Action)
		state, _ := f.registry.Get(f.refs[podD])
		require.Zero(t, state.PolicyVersion)
		require.Empty(t, d.receipts)
	})
	t.Run("unacknowledged Address publishes nothing", func(t *testing.T) {
		f := newOwnerFixture(t)
		d := f.capture("api", 10, podD, "10.0.0.20", 300, l4Snapshot(t, entries(allowAll(ingress), allowAll(egress))...))
		f.owner.beginStream()
		deny, _ := quarantineAuthorization("orders", remoteNamespaceUID, podD)
		require.NoError(t, f.policies.applyQuarantines(map[string]*security.Authorization{deny.Namespace + "/" + deny.Name: deny}, nil))
		f.owner.reconcile()
		require.Equal(t, security.Action_DENY, f.effective(podD).Action)
		require.Empty(t, d.receipts)
	})
	t.Run("unbound workload gets no orphan ALLOW", func(t *testing.T) {
		f := newOwnerFixture(t)
		f.capture("api", 10, podD, "10.0.0.20", 300, l4Snapshot(t, entries(allowAll(ingress), allowAll(egress))...))
		generation := f.owner.beginStream()
		version, ok := f.registry.PublishAddress(f.refs[podD], generation)
		require.True(t, ok)
		require.True(t, f.registry.AcknowledgeAddress(f.refs[podD], generation, version))
		f.owner.reconcile()
		require.Empty(t, f.policies.cache.GetResources(xdsTypeURLAuthorization, 0, nil).VersionedResources)
	})
	t.Run("membership not published by the endpoint", func(t *testing.T) {
		f := newOwnerFixture(t)
		d := f.capture("api", 10, podD, "10.0.0.20", 300, l4Snapshot(t, entries(allowAll(ingress), allowAll(egress))...))
		d.candidate.Membership.Generation++
		generation := f.owner.beginStream()
		f.bindAndAcknowledgeAddress(generation, podD)
		f.owner.reconcile()
		require.Equal(t, security.Action_DENY, f.effective(podD).Action)
	})
	t.Run("unrealized policy", func(t *testing.T) {
		f := newOwnerFixture(t)
		d := f.capture("api", 10, podD, "10.0.0.20", 300, l4Snapshot(t, entries(allowAll(ingress), allowAll(egress))...))
		d.err = errors.New("endpoint native policy is not current and realized")
		generation := f.owner.beginStream()
		f.bindAndAcknowledgeAddress(generation, podD)
		f.owner.reconcile()
		require.Equal(t, security.Action_DENY, f.effective(podD).Action)
	})
}

// A refused release is retried; a new stream invalidates the old ACK.
func TestEffectivePolicyReleaseRetryAndStreamReset(t *testing.T) {
	f := newOwnerFixture(t)
	d := f.capture("api", 10, podD, "10.0.0.20", 300, l4Snapshot(t, entries(allowAll(ingress), allowAll(egress))...))
	d.releaseErr = errors.New("native policy drain is pending")
	generation := f.owner.beginStream()
	f.bindAndAcknowledgeAddress(generation, podD)
	f.owner.reconcile()
	f.owner.observeAuthorizationAck(generation, f.cacheVersion())
	f.owner.reconcile()
	require.Len(t, d.receipts, 1)
	require.True(t, d.quarantined)

	// ztunnel reconnects before the release succeeds: everything restarts.
	next := f.owner.beginStream()
	d.releaseErr = nil
	f.owner.reconcile()
	require.Len(t, d.receipts, 1, "the previous stream's ACKs cannot release")
	f.bindAndAcknowledgeAddress(next, podD)
	f.owner.reconcile()
	f.owner.observeAuthorizationAck(next, f.cacheVersion())
	f.owner.reconcile()
	require.Len(t, d.receipts, 2)
	require.False(t, d.quarantined)
}

// A plan acknowledged on a stream that has since closed, with no newer
// stream yet, cannot release: that ztunnel session no longer exists. A late
// ACK from the closed stream is ignored, and the next stream releases only on
// its own acknowledgments.
func TestEffectivePolicyEndedStreamCannotRelease(t *testing.T) {
	f := newOwnerFixture(t)
	d := f.capture("api", 10, podD, "10.0.0.20", 300, l4Snapshot(t, entries(allowAll(ingress), allowAll(egress))...))
	d.releaseErr = errors.New("native policy drain is pending")
	generation := f.owner.beginStream()
	f.bindAndAcknowledgeAddress(generation, podD)
	f.owner.reconcile()
	f.owner.observeAuthorizationAck(generation, f.cacheVersion())
	f.owner.reconcile()
	require.Len(t, d.receipts, 1)
	require.True(t, d.quarantined)

	f.owner.endStream(generation)
	d.releaseErr = nil
	f.owner.observeAuthorizationAck(generation, f.cacheVersion())
	f.owner.reconcile()
	require.Len(t, d.receipts, 1, "an ended stream's acknowledgments cannot release")
	require.True(t, d.quarantined)
	state, _ := f.registry.Get(f.refs[podD])
	require.False(t, state.Active())

	next := f.owner.beginStream()
	f.owner.reconcile()
	require.Len(t, d.receipts, 1, "a new stream releases only on its own acknowledgments")
	f.bindAndAcknowledgeAddress(next, podD)
	f.owner.reconcile()
	f.owner.observeAuthorizationAck(next, f.cacheVersion())
	f.owner.reconcile()
	require.Len(t, d.receipts, 2)
	require.False(t, d.quarantined)
}

// The real stream loop ends the ADS generation it began when the ztunnel
// connection closes, so the owner and the registry hold no live stream.
func TestStreamCloseEndsItsADSGeneration(t *testing.T) {
	f := newOwnerFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	requests := make(chan *v3.DeltaDiscoveryRequest, 1)
	stream := &MockStream{}
	stream.OnContext = func() context.Context { return ctx }
	stream.OnSendMsg = func(any) error { return nil }
	stream._Recv = func() (*v3.DeltaDiscoveryRequest, error) {
		select {
		case r := <-requests:
			return r, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	sp := NewStreamProcessor(&StreamProcessorParams{NodeNames: fixtureNodeNames(t), Stream: stream,
		StreamRecv: make(chan *v3.DeltaDiscoveryRequest, 1), EndpointEventRecv: make(chan *EndpointEvent),
		Log: slog.New(slog.DiscardHandler), Metrics: NewMetrics(), PolicyOwner: f.owner})
	sp.endpointSource = &MockEndpointEventSource{initial: EndpointEventCollection{}}
	done := make(chan error, 1)
	go func() { done <- sp.Start() }()
	requests <- &v3.DeltaDiscoveryRequest{TypeUrl: xdsTypeURLAddress}
	require.Eventually(t, func() bool { return f.registry.ADSGeneration() != 0 }, 5*time.Second, 10*time.Millisecond)

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("stream did not close")
	}
	require.Zero(t, f.registry.ADSGeneration(), "the closed stream is still the registry's current stream")
	f.owner.mu.Lock()
	defer f.owner.mu.Unlock()
	require.Zero(t, f.owner.generation, "the closed stream is still the owner's current stream")
}

// Stream hooks: an Address version is acknowledged only by the ACK of the
// response that carried it, and Authorization ACKs are attributed per stream.
func TestStreamEvidenceHooksAttributeAcknowledgments(t *testing.T) {
	f := newOwnerFixture(t)
	f.capture("api", 10, podD, "10.0.0.20", 300, l4Snapshot(t, entries(allowAll(ingress), allowAll(egress))...))
	stream := &MockStream{}
	var sent []*v3.DeltaDiscoveryResponse
	stream.OnSendMsg = func(m any) error { sent = append(sent, m.(*v3.DeltaDiscoveryResponse)); return nil }
	sp := &StreamProcessor{stream: stream, policyOwner: f.owner, metrics: NewMetrics(), expectedNonce: map[string]struct{}{},
		log: slog.New(slog.DiscardHandler)}
	sp.adsGeneration = f.owner.beginStream()

	response := &v3.DeltaDiscoveryResponse{TypeUrl: xdsTypeURLAddress, Nonce: "n1", Resources: []*v3.Resource{{Name: podD}, {Name: "not-captured"}}}
	sp.recordAddressEvidence(response)
	state, _ := f.registry.Get(f.refs[podD])
	require.NotZero(t, state.AddressVersion)
	require.False(t, state.AddressAcked)
	sp.acknowledgeAddressEvidence("other-nonce")
	state, _ = f.registry.Get(f.refs[podD])
	require.False(t, state.AddressAcked, "another response's ACK does not acknowledge this Address")
	sp.acknowledgeAddressEvidence("n1")
	state, _ = f.registry.Get(f.refs[podD])
	require.True(t, state.AddressAcked)

	// A renewed capture generation resets Address evidence; the evidence tick
	// re-sends the unchanged resource and binds a new version.
	ref := f.refs[podD]
	zds, ok := f.registry.BeginZDS(ref)
	require.True(t, ok)
	require.True(t, f.registry.MarkCaptured(ref, zds))
	require.True(t, f.registry.AcknowledgeZDS(ref, zds))
	require.NoError(t, sp.refreshAddressEvidence())
	require.Len(t, sent, 1)
	require.Equal(t, []string{podD}, names(sent[0].Resources))
	state, _ = f.registry.Get(ref)
	require.NotZero(t, state.AddressVersion)
	require.NoError(t, sp.refreshAddressEvidence())
	require.Len(t, sent, 1, "a pending version is not re-sent")

	// Authorization: only an ACK of a response sent on this stream counts.
	sp.recordAuthorizationSend(&v3.DeltaDiscoveryResponse{Nonce: "a1", SystemVersionInfo: "7"})
	sp.recordAuthorizationSend(&v3.DeltaDiscoveryResponse{Nonce: "a2", SystemVersionInfo: "9"})
	sp.observeAuthorizationRequest(&v3.DeltaDiscoveryRequest{ResponseNonce: "a2", ErrorDetail: &status.Status{Message: "bad policy"}})
	require.Zero(t, f.owner.acked, "a NACK is not an acknowledgment")
	sp.observeAuthorizationRequest(&v3.DeltaDiscoveryRequest{ResponseNonce: "unknown"})
	require.Zero(t, f.owner.acked)
	sp.observeAuthorizationRequest(&v3.DeltaDiscoveryRequest{ResponseNonce: "a1"})
	require.Equal(t, uint64(7), f.owner.acked)
}

// The order seen after an agent restart: ztunnel subscribes to Address while
// the restored workload is still quarantined and not yet required, and the
// workload is re-admitted afterwards. The evidence tick publishes its Address
// on the open stream, ztunnel's ACK of that response counts, and the workload
// is released without a reconnect.
func TestWorkloadAdmittedAfterStreamBeganIsPublishedAndReleased(t *testing.T) {
	f := newOwnerFixture(t)
	stream := &MockStream{}
	var sent []*v3.DeltaDiscoveryResponse
	stream.OnSendMsg = func(m any) error { sent = append(sent, m.(*v3.DeltaDiscoveryResponse)); return nil }
	sp := &StreamProcessor{stream: stream, policyOwner: f.owner, metrics: NewMetrics(), expectedNonce: map[string]struct{}{},
		log: slog.New(slog.DiscardHandler)}
	sp.adsGeneration = f.owner.beginStream()
	sp.recordAddressEvidence(&v3.DeltaDiscoveryResponse{TypeUrl: xdsTypeURLAddress, Nonce: "snapshot", Resources: []*v3.Resource{{Name: podD}}})
	require.Empty(t, sp.addressEvidence, "a workload that is not yet required has no Address evidence")

	d := f.capture("api", 10, podD, "10.0.0.20", 300, l4Snapshot(t, entries(allowAll(ingress), allowAll(egress))...))
	deny, err := quarantineAuthorization("orders", remoteNamespaceUID, podD)
	require.NoError(t, err)
	require.NoError(t, f.policies.applyQuarantines(map[string]*security.Authorization{deny.Namespace + "/" + deny.Name: deny}, nil))

	require.NoError(t, sp.refreshAddressEvidence())
	require.Len(t, sent, 1)
	require.Equal(t, []string{podD}, names(sent[0].Resources))
	sp.acknowledgeAddressEvidence(sent[0].Nonce)
	state, _ := f.registry.Get(f.refs[podD])
	require.True(t, state.AddressAcked, "the ACK of the evidence response acknowledges the Address on the open stream")

	f.owner.reconcile()
	f.owner.observeAuthorizationAck(sp.adsGeneration, f.cacheVersion())
	f.owner.reconcile()
	require.Len(t, d.receipts, 1)
	require.False(t, d.quarantined)
	require.Equal(t, security.Action_ALLOW, f.effective(podD).Action)

	// A newer stream drops the evidence; the replaced stream re-sends nothing.
	f.owner.beginStream()
	require.NoError(t, sp.refreshAddressEvidence())
	require.Len(t, sent, 1, "a replaced stream sends no Address evidence")
}

// The endpoint fence quarantines a released workload whose enforced content
// changed. The owner compiles the new content, publishes it, and releases the
// same incarnation again once ztunnel acknowledges it.
func TestEffectivePolicyContentChangeRepublishesAndReleasesTheSameIncarnation(t *testing.T) {
	f := newOwnerFixture(t)
	d := f.capture("api", 10, podD, "10.0.0.20", 300, l4Snapshot(t, entries(allowAll(ingress), allowAll(egress))...))
	f.capture("web", 11, podS, "10.0.0.21", 301, l4Snapshot(t, entries(allowAll(ingress), allowAll(egress))...))
	generation := f.owner.beginStream()
	f.bindAndAcknowledgeAddress(generation, podD, podS)
	f.owner.reconcile()
	f.owner.observeAuthorizationAck(generation, f.cacheVersion())
	f.owner.reconcile()
	require.Len(t, d.receipts, 1)
	released := f.cacheVersion()

	// The destination now admits only 8080: the fence quarantined it.
	narrowed := l4Snapshot(t, entries(one(l4Entry{dir: ingress, proto: tcp, prefix: 16, id: 1<<16 | 301, port: 8080}), allowAll(egress))...)
	d.candidate.Subject.Policy, d.candidate.PolicyDigest = narrowed, narrowed.ContentDigest()
	d.quarantined = true

	f.owner.reconcile()
	require.Equal(t, []uint32{8080}, f.effective(podD).Rules[0].Clauses[0].Matches[0].DestinationPorts)
	require.Greater(t, f.cacheVersion(), released)
	require.Len(t, d.receipts, 1, "no release before ztunnel acknowledges the new content")
	f.owner.observeAuthorizationAck(generation, f.cacheVersion())
	f.owner.reconcile()
	require.Len(t, d.receipts, 2, "the same incarnation is released again")
	require.Equal(t, narrowed.ContentDigest(), d.receipts[1].PolicyDigest)
	require.False(t, d.quarantined)
	require.Equal(t, f.refs[podD], mustCurrentRef(t, f, podD), "no new incarnation was needed")
}

// A caller whose egress narrowed is released only after every released
// destination's plan reflects its new policy: ztunnel enforces caller policy
// only at the destination.
func TestEffectivePolicyCallerReleaseWaitsForDependentPlans(t *testing.T) {
	f := newOwnerFixture(t)
	caller := f.capture("api", 10, podD, "10.0.0.20", 300, l4Snapshot(t, entries(allowAll(ingress), allowAll(egress))...))
	destination := f.capture("web", 11, podS, "10.0.0.21", 301, l4Snapshot(t, entries(allowAll(ingress), allowAll(egress))...))
	generation := f.owner.beginStream()
	f.bindAndAcknowledgeAddress(generation, podD, podS)
	f.owner.reconcile()
	f.owner.observeAuthorizationAck(generation, f.cacheVersion())
	f.owner.reconcile()
	require.Len(t, caller.receipts, 1)
	require.Len(t, destination.receipts, 1)
	before := f.cacheVersion()

	// The caller may now reach the destination only on 8080: fenced.
	narrowed := l4Snapshot(t, entries(allowAll(ingress), one(l4Entry{dir: egress, proto: tcp, prefix: 16, id: 1<<16 | 301, port: 8080}))...)
	caller.candidate.Subject.Policy, caller.candidate.PolicyDigest = narrowed, narrowed.ContentDigest()
	caller.quarantined = true

	f.owner.reconcile()
	require.Equal(t, []uint32{8080}, f.effective(podS).Rules[0].Clauses[0].Matches[0].DestinationPorts,
		"the destination plan is recompiled with the caller's narrowed egress")
	require.Greater(t, f.cacheVersion(), before)
	state, _ := f.registry.Get(f.refs[podD])
	require.True(t, state.Active(), "the caller's own plan is unchanged and stays acknowledged")
	require.Len(t, caller.receipts, 1, "the destination still enforces the earlier ALLOW for the caller")
	require.True(t, caller.quarantined)

	f.owner.observeAuthorizationAck(generation, f.cacheVersion())
	f.owner.reconcile()
	require.Len(t, caller.receipts, 2, "released once the destination acknowledged the narrowed plan")
	require.False(t, caller.quarantined)
}

func mustCurrentRef(t *testing.T, f *ownerFixture, podUID string) membership.Reference {
	t.Helper()
	ref, _, ok := f.registry.CurrentForPodUID(podUID)
	require.True(t, ok)
	return ref
}

type countingHandler struct {
	slog.Handler
	messages map[string]int
}

func (h *countingHandler) Handle(_ context.Context, r slog.Record) error {
	h.messages[r.Message]++
	return nil
}
func (h *countingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *countingHandler) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h *countingHandler) WithGroup(string) slog.Handler            { return h }

// Why a Required workload is not an effective-policy destination is logged
// when the reason changes, not on every reconcile.
func TestEffectivePolicyLogsIneligibilityOncePerReason(t *testing.T) {
	f := newOwnerFixture(t)
	h := &countingHandler{messages: map[string]int{}}
	f.owner.log = slog.New(h)
	d := f.capture("api", 10, podD, "10.0.0.20", 300, l4Snapshot(t, entries(allowAll(ingress), allowAll(egress))...))
	d.err = errors.New("endpoint native policy is not current and realized")
	generation := f.owner.beginStream()
	f.bindAndAcknowledgeAddress(generation, podD)
	const ineligible = "Required workload is not an effective ztunnel policy destination"
	f.owner.reconcile()
	f.owner.reconcile()
	f.owner.reconcile()
	require.Equal(t, 1, h.messages[ineligible])
	d.err = errors.New("native selector updates are pending")
	f.owner.reconcile()
	require.Equal(t, 2, h.messages[ineligible], "a new reason is logged")
	d.err = nil
	f.owner.reconcile()
	require.Equal(t, 1, h.messages["Required workload is now an effective ztunnel policy destination"])
}
