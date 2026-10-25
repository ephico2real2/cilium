// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"context"
	"log/slog"
	"net/netip"
	"slices"
	"testing"

	v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/ztunnel/pb"
	remote "github.com/cilium/cilium/pkg/ztunnel/remote_workload"
)

const (
	remoteNamespaceUID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	remotePodUID       = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	remotePodUID2      = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
)

func closed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func remoteWorkload(podUID, node, ip string) remote.Workload {
	return remote.Workload{Key: remote.WorkloadKey{ClusterID: 2, NamespaceUID: remoteNamespaceUID, PodUID: podUID},
		Namespace: "orders", NodeName: node, PodName: "api", ServiceAccount: "api", Identity: 2<<16 | 300,
		MembershipEpoch: "epoch-b", MembershipGeneration: 3, MembershipState: "captured",
		Addresses: []netip.Addr{netip.MustParseAddr(ip)}}
}

func remoteSnapshot(now time.Time, generation uint64, workloads ...remote.Workload) remote.Snapshot {
	return remote.Snapshot{ClusterName: "cmtc-b", ClusterID: 2, Generation: generation, SessionEpoch: 1,
		SourceMembershipSessionEpoch: 1, PeerIdentityEpoch: 1, Valid: true,
		SourceMembershipLeaseValidUntil: now.Add(time.Minute), PeerCertificateNotAfter: now.Add(time.Hour),
		PeerHeartbeatAt: now, Workloads: workloads}
}

func trustedB(now time.Time) remoteTrustView {
	return remoteTrustView{valid: true, sequence: 7, until: now.Add(time.Hour), peers: map[string]string{"cmtc-b": "cmtc-b.mesh.example"}}
}

func decodeAddress(t *testing.T, encoded []byte) *pb.Workload {
	t.Helper()
	address := new(pb.Address)
	require.NoError(t, proto.Unmarshal(encoded, address))
	return address.GetWorkload()
}

func TestProjectRemoteSnapshotBindsApprovedIdentityAndIncarnation(t *testing.T) {
	now := time.Now()
	p := projectRemoteSnapshot(remoteSnapshot(now, 1, remoteWorkload(remotePodUID, "cmtc-b-worker", "10.2.0.10")),
		"cmtc-b.mesh.example", now.Add(time.Hour), map[string]bool{"worker-a": true}, now)
	require.NoError(t, p.err)
	name := "cilium/remote/2/" + remoteNamespaceUID + "/" + remotePodUID
	require.Contains(t, p.resources, name)
	w := decodeAddress(t, p.resources[name])
	require.Equal(t, name, w.Uid, "the remote resource never reuses a local Pod-UID name")
	require.Equal(t, "cmtc-b.mesh.example", w.TrustDomain, "trust domain from the issuer profile")
	require.Equal(t, "cmtc-b", w.ClusterId)
	require.Equal(t, "cmtc-b-worker", w.Node)
	require.Equal(t, "api", w.ServiceAccount)
	require.Equal(t, pb.TunnelProtocol_HBONE, w.TunnelProtocol)
	require.Equal(t, [][]byte{netip.MustParseAddr("10.2.0.10").AsSlice()}, w.Addresses)
	require.Empty(t, w.AuthorizationPolicies, "inbound policy of a remote workload is enforced by its own ztunnel")
	require.True(t, p.until.Equal(now.Add(time.Minute)), "the earliest authority deadline (membership lease) bounds the projection")

	again := projectRemoteSnapshot(remoteSnapshot(now, 1, remoteWorkload(remotePodUID, "cmtc-b-worker", "10.2.0.10")),
		"cmtc-b.mesh.example", now.Add(time.Hour), nil, now)
	require.Equal(t, p.resources, again.resources, "encoding is deterministic")
}

func TestProjectRemoteSnapshotFailsClosed(t *testing.T) {
	now := time.Now()
	for name, mutate := range map[string]func(*remote.Snapshot, *string, *time.Time, map[string]bool){
		"invalid snapshot": func(s *remote.Snapshot, _ *string, _ *time.Time, _ map[string]bool) { s.Valid = false },
		"no cluster ID":    func(s *remote.Snapshot, _ *string, _ *time.Time, _ map[string]bool) { s.ClusterID = 0 },
		"bad cluster name": func(s *remote.Snapshot, _ *string, _ *time.Time, _ map[string]bool) { s.ClusterName = "CMTC_B" },
		"no session epoch": func(s *remote.Snapshot, _ *string, _ *time.Time, _ map[string]bool) {
			s.SourceMembershipSessionEpoch = 0
		},
		"no peer epoch":    func(s *remote.Snapshot, _ *string, _ *time.Time, _ map[string]bool) { s.PeerIdentityEpoch = 0 },
		"bad trust domain": func(_ *remote.Snapshot, d *string, _ *time.Time, _ map[string]bool) { *d = "Not A Domain" },
		"lease expired": func(s *remote.Snapshot, _ *string, _ *time.Time, _ map[string]bool) {
			s.SourceMembershipLeaseValidUntil = now
		},
		"certificate expired": func(s *remote.Snapshot, _ *string, _ *time.Time, _ map[string]bool) {
			s.PeerCertificateNotAfter = now.Add(-time.Second)
		},
		"heartbeat stale": func(s *remote.Snapshot, _ *string, _ *time.Time, _ map[string]bool) {
			s.PeerHeartbeatAt = now.Add(-3 * time.Minute)
		},
		"no heartbeat":  func(s *remote.Snapshot, _ *string, _ *time.Time, _ map[string]bool) { s.PeerHeartbeatAt = time.Time{} },
		"trust expired": func(_ *remote.Snapshot, _ *string, u *time.Time, _ map[string]bool) { *u = now },
		"key of another cluster": func(s *remote.Snapshot, _ *string, _ *time.Time, _ map[string]bool) {
			s.Workloads[0].Key.ClusterID = 3
		},
		"noncanonical pod UID": func(s *remote.Snapshot, _ *string, _ *time.Time, _ map[string]bool) {
			s.Workloads[0].Key.PodUID = "BBBBBBBB-BBBB-4BBB-8BBB-BBBBBBBBBBBB"
		},
		"not captured": func(s *remote.Snapshot, _ *string, _ *time.Time, _ map[string]bool) {
			s.Workloads[0].MembershipState = "required"
		},
		"no membership generation": func(s *remote.Snapshot, _ *string, _ *time.Time, _ map[string]bool) {
			s.Workloads[0].MembershipGeneration = 0
		},
		"local node name": func(s *remote.Snapshot, _ *string, _ *time.Time, nodes map[string]bool) {
			nodes[s.Workloads[0].NodeName] = true
		},
		"noncanonical namespace": func(s *remote.Snapshot, _ *string, _ *time.Time, _ map[string]bool) {
			s.Workloads[0].Namespace = "Orders"
		},
		"no address": func(s *remote.Snapshot, _ *string, _ *time.Time, _ map[string]bool) { s.Workloads[0].Addresses = nil },
		"loopback address": func(s *remote.Snapshot, _ *string, _ *time.Time, _ map[string]bool) {
			s.Workloads[0].Addresses = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
		},
		"two addresses of one family": func(s *remote.Snapshot, _ *string, _ *time.Time, _ map[string]bool) {
			s.Workloads[0].Addresses = append(s.Workloads[0].Addresses, netip.MustParseAddr("10.2.0.11"))
		},
		"address with two owners": func(s *remote.Snapshot, _ *string, _ *time.Time, _ map[string]bool) {
			s.Workloads = append(s.Workloads, remoteWorkload(remotePodUID2, "cmtc-b-worker", "10.2.0.10"))
		},
		"duplicate incarnation": func(s *remote.Snapshot, _ *string, _ *time.Time, _ map[string]bool) {
			s.Workloads = append(s.Workloads, remoteWorkload(remotePodUID, "cmtc-b-worker", "10.2.0.12"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := remoteSnapshot(now, 1, remoteWorkload(remotePodUID, "cmtc-b-worker", "10.2.0.10"))
			domain, until, nodes := "cmtc-b.mesh.example", now.Add(time.Hour), map[string]bool{}
			mutate(&s, &domain, &until, nodes)
			p := projectRemoteSnapshot(s, domain, until, nodes, now)
			require.Error(t, p.err)
			require.Empty(t, p.resources, "a refused peer projects nothing")
		})
	}
}

func TestProjectRemotePeersWithdrawsEveryCollidingOwner(t *testing.T) {
	now := time.Now()
	trust := remoteTrustView{valid: true, until: now.Add(time.Hour), peers: map[string]string{"cmtc-b": "cmtc-b.mesh.example", "cmtc-c": "cmtc-c.mesh.example"}}
	c := remoteSnapshot(now, 1, remoteWorkload(remotePodUID, "cmtc-c-worker", "10.2.0.10"))
	c.ClusterName, c.ClusterID = "cmtc-c", 3
	c.Workloads[0].Key.ClusterID = 3
	views := map[string]remote.PeerSnapshotView{
		"cmtc-b": {Snapshot: remoteSnapshot(now, 1, remoteWorkload(remotePodUID, "cmtc-b-worker", "10.2.0.10"))},
		"cmtc-c": {Snapshot: c},
	}
	out := projectRemotePeers(views, trust, nil, nil, now)
	require.Error(t, out["cmtc-b"].err, "two peers claim one address: neither is trusted")
	require.Error(t, out["cmtc-c"].err)

	views["cmtc-c"].Snapshot.Workloads[0].Addresses[0] = netip.MustParseAddr("10.3.0.10")
	out = projectRemotePeers(views, trust, nil, map[netip.Addr]string{netip.MustParseAddr("10.2.0.10"): "local-pod"}, now)
	require.ErrorContains(t, out["cmtc-b"].err, "collides", "a remote address owned by a local workload withdraws the peer")
	require.NoError(t, out["cmtc-c"].err)

	untrusted := map[string]remote.PeerSnapshotView{"cmtc-d": {Snapshot: remoteSnapshot(now, 1, remoteWorkload(remotePodUID, "cmtc-d-worker", "10.4.0.10"))}}
	out = projectRemotePeers(untrusted, trust, nil, nil, now)
	require.ErrorContains(t, out["cmtc-d"].err, "approves no trust domain", "no domain is ever derived for an unapproved peer")
}

func TestPlanRemoteWithdrawsAndRequiresAFreshStreamToRecover(t *testing.T) {
	now := time.Now()
	trust := trustedB(now)
	st := newRemoteStreamState()
	views := map[string]remote.PeerSnapshotView{"cmtc-b": {Fence: 1, WriterEpoch: 1,
		Snapshot: remoteSnapshot(now, 1, remoteWorkload(remotePodUID, "cmtc-b-worker", "10.2.0.10"))}}
	d, err := st.planRemote(views, trust, nil, nil, now)
	require.NoError(t, err)
	require.Len(t, d.upserts, 1)
	require.Equal(t, "projected", d.events["cmtc-b"])
	st.commit(d)

	d, err = st.planRemote(views, trust, nil, nil, now)
	require.NoError(t, err)
	require.True(t, d.empty(), "an unchanged view publishes nothing")

	// A second workload appears, then the first one is deleted.
	views["cmtc-b"] = remote.PeerSnapshotView{Fence: 1, WriterEpoch: 1, Snapshot: remoteSnapshot(now, 2,
		remoteWorkload(remotePodUID, "cmtc-b-worker", "10.2.0.10"), remoteWorkload(remotePodUID2, "cmtc-b-worker", "10.2.0.11"))}
	d, err = st.planRemote(views, trust, nil, nil, now)
	require.NoError(t, err)
	require.Len(t, d.upserts, 1)
	st.commit(d)
	views["cmtc-b"] = remote.PeerSnapshotView{Fence: 1, WriterEpoch: 1, Snapshot: remoteSnapshot(now, 3,
		remoteWorkload(remotePodUID2, "cmtc-b-worker", "10.2.0.11"))}
	d, err = st.planRemote(views, trust, nil, nil, now)
	require.NoError(t, err)
	require.Equal(t, []string{"cilium/remote/2/" + remoteNamespaceUID + "/" + remotePodUID}, d.removals)
	st.commit(d)

	// Invalidation: withdraw everything of the peer.
	views["cmtc-b"] = remote.PeerSnapshotView{Fence: 2, WriterEpoch: 1, Snapshot: remote.Snapshot{ClusterName: "cmtc-b", Reason: "peer lost"}}
	d, err = st.planRemote(views, trust, nil, nil, now)
	require.NoError(t, err)
	require.Equal(t, []string{"cilium/remote/2/" + remoteNamespaceUID + "/" + remotePodUID2}, d.removals)
	st.commit(d)
	require.True(t, st.peers["cmtc-b"].withdrawn)

	// Valid again: recovery is refused on this stream.
	views["cmtc-b"] = remote.PeerSnapshotView{Fence: 2, WriterEpoch: 1, Snapshot: remoteSnapshot(now, 4,
		remoteWorkload(remotePodUID2, "cmtc-b-worker", "10.2.0.11"))}
	_, err = st.planRemote(views, trust, nil, nil, now)
	require.ErrorIs(t, err, errRemoteRecovery)

	// A fresh stream projects the recovered view.
	fresh := newRemoteStreamState()
	d, err = fresh.planRemote(views, trust, nil, nil, now)
	require.NoError(t, err)
	require.Len(t, d.upserts, 1)
}

func TestPlanRemoteCoalescedInvalidationAfterPublicationResetsTheStream(t *testing.T) {
	now := time.Now()
	trust := trustedB(now)
	st := newRemoteStreamState()
	views := map[string]remote.PeerSnapshotView{"cmtc-b": {Fence: 1, WriterEpoch: 1,
		Snapshot: remoteSnapshot(now, 1, remoteWorkload(remotePodUID, "cmtc-b-worker", "10.2.0.10"))}}
	d, err := st.planRemote(views, trust, nil, nil, now)
	require.NoError(t, err)
	st.commit(d)

	// Invalid -> valid happened before this stream looked again.
	views["cmtc-b"] = remote.PeerSnapshotView{Fence: 2, WriterEpoch: 1, Snapshot: remoteSnapshot(now, 3,
		remoteWorkload(remotePodUID, "cmtc-b-worker", "10.2.0.10"))}
	d, err = st.planRemote(views, trust, nil, nil, now)
	require.ErrorIs(t, err, errRemoteRecovery)
	require.Equal(t, []string{"cilium/remote/2/" + remoteNamespaceUID + "/" + remotePodUID}, d.removals,
		"the crossed view is withdrawn before the stream ends")

	// A replaced observer (new writer epoch) is treated the same way.
	st = newRemoteStreamState()
	views["cmtc-b"] = remote.PeerSnapshotView{Fence: 2, WriterEpoch: 1, Snapshot: remoteSnapshot(now, 3,
		remoteWorkload(remotePodUID, "cmtc-b-worker", "10.2.0.10"))}
	d, err = st.planRemote(views, trust, nil, nil, now)
	require.NoError(t, err)
	st.commit(d)
	views["cmtc-b"] = remote.PeerSnapshotView{Fence: 3, WriterEpoch: 2, Snapshot: remoteSnapshot(now, 1,
		remoteWorkload(remotePodUID, "cmtc-b-worker", "10.2.0.10"))}
	_, err = st.planRemote(views, trust, nil, nil, now)
	require.ErrorIs(t, err, errRemoteRecovery)
}

func TestPlanRemotePeerInvalidAtStreamStartProjectsWhenValid(t *testing.T) {
	now := time.Now()
	trust := trustedB(now)
	st := newRemoteStreamState()
	views := map[string]remote.PeerSnapshotView{"cmtc-b": {Fence: 4, WriterEpoch: 1, Snapshot: remote.Snapshot{ClusterName: "cmtc-b"}}}
	d, err := st.planRemote(views, trust, nil, nil, now)
	require.NoError(t, err)
	require.True(t, d.empty())
	st.commit(d)
	views["cmtc-b"] = remote.PeerSnapshotView{Fence: 5, WriterEpoch: 1, Snapshot: remoteSnapshot(now, 2,
		remoteWorkload(remotePodUID, "cmtc-b-worker", "10.2.0.10"))}
	d, err = st.planRemote(views, trust, nil, nil, now)
	require.NoError(t, err, "nothing was published on this stream, so nothing stale can be carried")
	require.Len(t, d.upserts, 1)
}

// streamFixture is a strict stream with one local workload on node worker-a
// and remote projection from a real PeerSnapshotStore.
type streamFixture struct {
	sp     *StreamProcessor
	store  *remote.PeerSnapshotStore
	writer remote.SnapshotSink
	trust  *remoteTrustAuthority
	mu     lock.Mutex
	sent   []*v3.DeltaDiscoveryResponse
}

func newStreamFixture(t *testing.T, now time.Time) *streamFixture {
	t.Helper()
	f := &streamFixture{store: remote.NewPeerSnapshotStore()}
	f.writer = f.store.NewWriter("cmtc-b")
	f.trust = &remoteTrustAuthority{log: slog.New(slog.DiscardHandler), changed: make(chan struct{}), clock: time.Now}
	f.trust.publish(trustedB(now))
	stream := &MockStream{}
	stream.OnContext = func() context.Context { return context.Background() }
	stream.OnSendMsg = func(message any) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.sent = append(f.sent, message.(*v3.DeltaDiscoveryResponse))
		return nil
	}
	f.sp = &StreamProcessor{nodeNames: fixtureNodeNames(t), stream: stream, metrics: NewMetrics(),
		expectedNonce: make(map[string]struct{}), log: slog.New(slog.DiscardHandler),
		trustDomain: "cmtc-a.mesh.example", clusterName: "cmtc-a", requireMTLS: true,
		remotePeers: f.store, remoteTrust: f.trust}
	return f
}

func (f *streamFixture) last() *v3.DeltaDiscoveryResponse {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.sent) == 0 {
		return nil
	}
	return f.sent[len(f.sent)-1]
}

func (f *streamFixture) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sent)
}

func names(resources []*v3.Resource) []string {
	out := make([]string, 0, len(resources))
	for _, r := range resources {
		out = append(out, r.Name)
	}
	slices.Sort(out)
	return out
}

const remoteName = "cilium/remote/2/" + remoteNamespaceUID + "/" + remotePodUID

func TestStrictInitialSnapshotMergesLocalAndRemoteWorkloads(t *testing.T) {
	now := time.Now()
	f := newStreamFixture(t, now)
	f.writer.PublishRemoteWorkloadSnapshot(remoteSnapshot(now, 1, remoteWorkload(remotePodUID, "cmtc-b-worker", "10.2.0.10")))
	f.sp.endpointSource = &MockEndpointEventSource{initial: EndpointEventCollection{{Type: CREATE,
		CiliumEndpoint: makeStrictCEP("api", "orders", "pod-local", "10.0.0.20")}}}
	stale := "cilium/remote/2/" + remoteNamespaceUID + "/" + remotePodUID2
	require.NoError(t, f.sp.handleAddressTypeURL(&v3.DeltaDiscoveryRequest{TypeUrl: xdsTypeURLAddress,
		InitialResourceVersions: map[string]string{remoteName: "v1", stale: "v1", "pod-gone": "v1"}}))
	response := f.last()
	require.Equal(t, []string{remoteName, "pod-local"}, names(response.Resources), "one complete local + remote snapshot")
	require.ElementsMatch(t, []string{stale, "pod-gone"}, response.RemovedResources, "strict initial removals run once on the merge")
	require.Contains(t, f.sp.expectedNonce, response.Nonce)
	require.Equal(t, "pod-local", f.sp.localAddresses[netip.MustParseAddr("10.0.0.20")])
	require.NotNil(t, f.sp.remoteTimer(), "the earliest authority deadline is scheduled")

	// A local update does not remove the remote workload.
	events := make(chan *EndpointEvent, 1)
	f.sp.endpointRecv = events
	require.NoError(t, f.sp.handleEPEvent(&EndpointEvent{Type: CREATE, CiliumEndpoint: makeStrictCEP("web", "orders", "pod-web", "10.0.0.21")}))
	require.NotContains(t, f.last().RemovedResources, remoteName)
	require.Len(t, f.sp.remote.peers["cmtc-b"].published, 1)
}

func TestRemoteInvalidationWithdrawsAndRecoveryNeedsAFreshStream(t *testing.T) {
	now := time.Now()
	f := newStreamFixture(t, now)
	f.writer.PublishRemoteWorkloadSnapshot(remoteSnapshot(now, 1, remoteWorkload(remotePodUID, "cmtc-b-worker", "10.2.0.10")))
	f.sp.endpointSource = &MockEndpointEventSource{initial: EndpointEventCollection{}}
	require.NoError(t, f.sp.handleAddressTypeURL(&v3.DeltaDiscoveryRequest{TypeUrl: xdsTypeURLAddress}))
	require.Equal(t, []string{remoteName}, names(f.last().Resources))

	f.writer.PublishRemoteWorkloadSnapshot(remote.Snapshot{ClusterName: "cmtc-b", ClusterID: 2, Generation: 2, Reason: "origin lost"})
	require.True(t, closed(f.sp.remoteViewWatch()))
	require.NoError(t, f.sp.syncRemote(now))
	require.Equal(t, []string{remoteName}, f.last().RemovedResources, "withdrawn at once, stream kept")

	f.writer.PublishRemoteWorkloadSnapshot(remoteSnapshot(now, 3, remoteWorkload(remotePodUID, "cmtc-b-worker", "10.2.0.10")))
	sent := f.count()
	require.ErrorIs(t, f.sp.syncRemote(now), errRemoteRecovery)
	require.Equal(t, sent, f.count(), "the recovered view is not re-added on this stream")

	// The next stream starts from a complete merged snapshot.
	g := newStreamFixture(t, now)
	g.store, g.sp.remotePeers = f.store, f.store
	g.sp.endpointSource = &MockEndpointEventSource{initial: EndpointEventCollection{}}
	require.NoError(t, g.sp.handleAddressTypeURL(&v3.DeltaDiscoveryRequest{TypeUrl: xdsTypeURLAddress}))
	require.Equal(t, []string{remoteName}, names(g.last().Resources))
}

func TestRemoteTrustLossWithdrawsWithoutDiscoveryEvent(t *testing.T) {
	now := time.Now()
	f := newStreamFixture(t, now)
	f.writer.PublishRemoteWorkloadSnapshot(remoteSnapshot(now, 1, remoteWorkload(remotePodUID, "cmtc-b-worker", "10.2.0.10")))
	f.sp.endpointSource = &MockEndpointEventSource{initial: EndpointEventCollection{}}
	require.NoError(t, f.sp.handleAddressTypeURL(&v3.DeltaDiscoveryRequest{TypeUrl: xdsTypeURLAddress}))

	f.trust.publish(remoteTrustView{reason: "issuer profile withdrawn"})
	require.True(t, closed(f.sp.remoteTrustWatch()))
	require.NoError(t, f.sp.syncRemote(now))
	require.Equal(t, []string{remoteName}, f.last().RemovedResources)
}

func TestRemoteDeadlineWithdrawsWithoutAnyWatchEvent(t *testing.T) {
	now := time.Now()
	f := newStreamFixture(t, now)
	s := remoteSnapshot(now, 1, remoteWorkload(remotePodUID, "cmtc-b-worker", "10.2.0.10"))
	s.SourceMembershipLeaseValidUntil = now.Add(50 * time.Millisecond)
	f.writer.PublishRemoteWorkloadSnapshot(s)
	f.sp.endpointSource = &MockEndpointEventSource{initial: EndpointEventCollection{}}
	require.NoError(t, f.sp.handleAddressTypeURL(&v3.DeltaDiscoveryRequest{TypeUrl: xdsTypeURLAddress}))
	require.Equal(t, []string{remoteName}, names(f.last().Resources))

	select {
	case <-f.sp.remoteTimer():
	case <-time.After(5 * time.Second):
		t.Fatal("the lease deadline timer did not fire")
	}
	require.False(t, closed(f.sp.remoteViewWatch()), "no discovery event happened")
	require.NoError(t, f.sp.syncRemote(time.Now()))
	require.Equal(t, []string{remoteName}, f.last().RemovedResources, "an expired lease withdraws the peer")
}

func TestLocalWorkloadCollisionWithdrawsRemotePeerInTheSameResponse(t *testing.T) {
	now := time.Now()
	f := newStreamFixture(t, now)
	f.writer.PublishRemoteWorkloadSnapshot(remoteSnapshot(now, 1, remoteWorkload(remotePodUID, "cmtc-b-worker", "10.2.0.10")))
	f.sp.endpointSource = &MockEndpointEventSource{initial: EndpointEventCollection{}}
	require.NoError(t, f.sp.handleAddressTypeURL(&v3.DeltaDiscoveryRequest{TypeUrl: xdsTypeURLAddress}))

	f.sp.endpointRecv = make(chan *EndpointEvent, 1)
	require.NoError(t, f.sp.handleEPEvent(&EndpointEvent{Type: CREATE, CiliumEndpoint: makeStrictCEP("dup", "orders", "pod-dup", "10.2.0.10")}))
	response := f.last()
	require.Equal(t, []string{"pod-dup"}, names(response.Resources))
	require.Equal(t, []string{remoteName}, response.RemovedResources, "the remote owner of a local address is withdrawn in the same response")
	require.True(t, f.sp.remote.peers["cmtc-b"].withdrawn)
}

func TestRemoteNodeNameCollisionIsRefused(t *testing.T) {
	now := time.Now()
	f := newStreamFixture(t, now)
	f.writer.PublishRemoteWorkloadSnapshot(remoteSnapshot(now, 1, remoteWorkload(remotePodUID, "worker-a", "10.2.0.10")))
	f.sp.endpointSource = &MockEndpointEventSource{initial: EndpointEventCollection{}}
	require.NoError(t, f.sp.handleAddressTypeURL(&v3.DeltaDiscoveryRequest{TypeUrl: xdsTypeURLAddress}))
	require.Empty(t, f.last().Resources, "a remote workload on a node name that exists locally is not projected")
}

// The real Start loop reacts to a store change with no endpoint event.
func TestStartLoopPublishesRemoteChanges(t *testing.T) {
	now := time.Now()
	f := newStreamFixture(t, now)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	requests := make(chan *v3.DeltaDiscoveryRequest, 4)
	stream := f.sp.stream.(*MockStream)
	stream.OnContext = func() context.Context { return ctx }
	stream._Recv = func() (*v3.DeltaDiscoveryRequest, error) {
		select {
		case r := <-requests:
			return r, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	f.sp.streamRecv = make(chan *v3.DeltaDiscoveryRequest, 1)
	f.sp.endpointRecv = make(chan *EndpointEvent)
	f.sp.endpointSource = &MockEndpointEventSource{initial: EndpointEventCollection{}}
	done := make(chan error, 1)
	go func() { done <- f.sp.Start() }()
	requests <- &v3.DeltaDiscoveryRequest{TypeUrl: xdsTypeURLAddress}
	require.Eventually(t, func() bool { return f.count() == 1 }, 5*time.Second, 10*time.Millisecond)
	require.Empty(t, f.last().Resources, "no valid peer yet")

	f.writer.PublishRemoteWorkloadSnapshot(remoteSnapshot(now, 1, remoteWorkload(remotePodUID, "cmtc-b-worker", "10.2.0.10")))
	require.Eventually(t, func() bool { return f.count() == 2 }, 5*time.Second, 10*time.Millisecond)
	require.Equal(t, []string{remoteName}, names(f.last().Resources))

	f.writer.PublishRemoteWorkloadSnapshot(remote.Snapshot{ClusterName: "cmtc-b", ClusterID: 2, Generation: 2})
	require.Eventually(t, func() bool { return f.count() == 3 }, 5*time.Second, 10*time.Millisecond)
	require.Equal(t, []string{remoteName}, f.last().RemovedResources)

	f.writer.PublishRemoteWorkloadSnapshot(remoteSnapshot(now, 3, remoteWorkload(remotePodUID, "cmtc-b-worker", "10.2.0.10")))
	select {
	case err := <-done:
		require.ErrorIs(t, err, errRemoteRecovery, "recovery ends the stream; ztunnel reconnects for a fresh snapshot")
	case <-time.After(5 * time.Second):
		t.Fatal("stream did not end on remote recovery")
	}
}
