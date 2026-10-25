// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"context"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/ztunnel/membership"
	"github.com/cilium/cilium/pkg/ztunnel/pb/security"
	remote "github.com/cilium/cilium/pkg/ztunnel/remote_workload"
)

var peerCluster = cmtypes.ClusterInfo{ID: 2, Name: "cmtc-b", MaxConnectedClusters: 255}

const (
	podC        = "c0c0c0c0-c0c0-4c0c-8c0c-c0c0c0c0c0c0" // same cluster, other node
	podP        = "a0a0a0a0-a0a0-4a0a-8a0a-a0a0a0a0a0a0" // peer cluster
	clusterIDn  = 1<<16 | 310
	peerIDn     = 2<<16 | 320
	clusterAddr = "10.0.1.30"
	peerAddr    = "10.2.0.40"
)

type addressOwner struct {
	id     identity.NumericIdentity
	podUID string
}

type fakeAddresses map[netip.Addr]addressOwner

func (f fakeAddresses) workloadAt(ip netip.Addr) (identity.NumericIdentity, string, bool) {
	owner, ok := f[ip]
	return owner.id, owner.podUID, ok
}

func envelope(owner cmtypes.ClusterInfo, e ...l4Entry) *membership.SourceEgressPolicy {
	wire, digest := l4Wire(owner, e...)
	return &membership.SourceEgressPolicy{Version: membership.SourceEgressPolicyVersion, PolicyRevision: 1, SelectorRevision: 1,
		Digest: digest, Wire: wire}
}

func sourceWorkload(cluster uint32, podUID, node, ip, sa string, id identity.NumericIdentity, policy *membership.SourceEgressPolicy) remote.Workload {
	return remote.Workload{Key: remote.WorkloadKey{ClusterID: cluster, NamespaceUID: remoteNamespaceUID, PodUID: podUID},
		Namespace: "orders", NodeName: node, PodName: sa, ServiceAccount: sa, Identity: id,
		MembershipEpoch: "epoch-" + node, MembershipGeneration: 2, MembershipState: "captured",
		Addresses: []netip.Addr{netip.MustParseAddr(ip)}, EndpointID: 77, EgressPolicy: policy}
}

type sourceFixture struct {
	*ownerFixture
	now       time.Time
	cluster   *remote.LocalSourceMailbox
	peers     *remote.PeerSnapshotStore
	peerSink  remote.SnapshotSink
	peerGen   uint64
	trust     *remoteTrustAuthority
	addresses fakeAddresses
}

// newSourceFixture has one captured destination D on this node, a source C on
// another node of this cluster and a source P in cluster cmtc-b. All policies
// allow every peer; the ipcache agrees with both sources.
func newSourceFixture(t *testing.T) *sourceFixture {
	f := &sourceFixture{ownerFixture: newOwnerFixture(t), now: time.Now(), peers: remote.NewPeerSnapshotStore(),
		addresses: fakeAddresses{
			netip.MustParseAddr(clusterAddr): {id: clusterIDn, podUID: podC},
			netip.MustParseAddr(peerAddr):    {id: peerIDn, podUID: podP},
		}}
	f.cluster = &remote.LocalSourceMailbox{SnapshotMailbox: remote.NewSnapshotMailbox()}
	f.peerSink = f.peers.NewWriter("cmtc-b")
	f.trust = &remoteTrustAuthority{view: trustedB(f.now), changed: make(chan struct{})}
	f.owner.clock = func() time.Time { return f.now }
	f.owner.sources = externalSources{cluster: f.cluster, peers: f.peers, trust: f.trust, nodes: fixtureNodeNames(t), addresses: f.addresses}
	f.capture("api", 10, podD, "10.0.0.20", 300, l4Snapshot(t, entries(allowAll(ingress), allowAll(egress))...))
	f.publishCluster(sourceWorkload(1, podC, "worker-b", clusterAddr, "web", clusterIDn, envelope(ownerCluster, allowAll(egress)...)))
	f.publishPeer(sourceWorkload(2, podP, "cmtc-b-worker", peerAddr, "client", peerIDn, envelope(peerCluster, allowAll(egress)...)))
	generation := f.owner.beginStream()
	f.bindAndAcknowledgeAddress(generation, podD)
	return f
}

func (f *sourceFixture) publishCluster(workloads ...remote.Workload) {
	f.cluster.PublishRemoteWorkloadSnapshot(remote.Snapshot{ClusterName: ownerCluster.Name, ClusterID: ownerCluster.ID, Valid: true,
		SourceMembershipLeaseValidUntil: f.now.Add(30 * time.Second), Workloads: workloads})
}

func (f *sourceFixture) publishPeer(workloads ...remote.Workload) {
	f.peerGen++
	f.peerSink.PublishRemoteWorkloadSnapshot(remoteSnapshot(f.now, f.peerGen, workloads...))
}

// principals returns the caller principal of every rule of D's plan.
func (f *sourceFixture) principals() []string {
	var out []string
	for _, rule := range f.effective(podD).Rules {
		out = append(out, rule.Clauses[0].Matches[0].Principals[0].GetExact())
	}
	return out
}

func TestEffectivePolicyAdmitsCallersOfOtherNodesAndClusters(t *testing.T) {
	f := newSourceFixture(t)
	f.owner.reconcile()
	allow := f.effective(podD)
	require.Equal(t, security.Action_ALLOW, allow.Action)
	require.ElementsMatch(t, []string{"cmtc-a.mesh.example/ns/orders/sa/web", "cmtc-b.mesh.example/ns/orders/sa/client"}, f.principals(),
		"the same-cluster caller binds the local trust domain, the peer caller the domain the issuer profile approves")
	for _, rule := range allow.Rules {
		match := rule.Clauses[0].Matches[0]
		require.Len(t, match.SourceIps, 1)
		require.Contains(t, [][]byte{netip.MustParseAddr(clusterAddr).AsSlice(), netip.MustParseAddr(peerAddr).AsSlice()}, match.SourceIps[0].Address)
		require.Equal(t, netip.MustParseAddr("10.0.0.20").AsSlice(), match.DestinationIps[0].Address)
	}
	require.Equal(t, 1, f.owner.sourceCounts[sourceOriginCluster])
	require.Equal(t, 1, f.owner.sourceCounts[sourceOriginPeer])
	require.Empty(t, f.owner.refusedSources)
}

// Each check alone leaves its source out of the plan; the other source and
// the destination's plan are unaffected.
func TestEffectivePolicyRefusesAnExternalCallerThatFailsAnyCheck(t *testing.T) {
	peer := func(mutate func(*remote.Workload)) remote.Workload {
		w := sourceWorkload(2, podP, "cmtc-b-worker", peerAddr, "client", peerIDn, envelope(peerCluster, allowAll(egress)...))
		mutate(&w)
		return w
	}
	for name, setup := range map[string]func(f *sourceFixture){
		"no ipcache entry": func(f *sourceFixture) { delete(f.addresses, netip.MustParseAddr(peerAddr)) },
		"ipcache identity": func(f *sourceFixture) {
			f.addresses[netip.MustParseAddr(peerAddr)] = addressOwner{id: peerIDn + 1, podUID: podP}
		},
		"ipcache Pod UID": func(f *sourceFixture) {
			f.addresses[netip.MustParseAddr(peerAddr)] = addressOwner{id: peerIDn, podUID: podX}
		},
		"no egress policy": func(f *sourceFixture) { f.publishPeer(peer(func(w *remote.Workload) { w.EgressPolicy = nil })) },
		"policy of other owner": func(f *sourceFixture) {
			f.publishPeer(peer(func(w *remote.Workload) { w.EgressPolicy = envelope(ownerCluster, allowAll(egress)...) }))
		},
		"not captured": func(f *sourceFixture) {
			f.publishPeer(peer(func(w *remote.Workload) { w.MembershipState = "withdrawn" }))
		},
		"tampered wire":          func(f *sourceFixture) { f.publishPeer(peer(func(w *remote.Workload) { w.EgressPolicy.Wire[20] ^= 1 })) },
		"trust domain withdrawn": func(f *sourceFixture) { f.trust.publish(remoteTrustView{reason: "profile withdrawn"}) },
		"peer invalidated": func(f *sourceFixture) {
			f.peerSink.PublishRemoteWorkloadSnapshot(remote.Snapshot{ClusterName: "cmtc-b", ClusterID: 2, Reason: "watch lost"})
		},
		"peer lease expired": func(f *sourceFixture) { f.now = f.now.Add(2 * time.Minute) },
	} {
		t.Run(name, func(t *testing.T) {
			f := newSourceFixture(t)
			setup(f)
			if name == "peer lease expired" {
				// Keep the same-cluster lease and the trust view current.
				f.publishCluster(sourceWorkload(1, podC, "worker-b", clusterAddr, "web", clusterIDn, envelope(ownerCluster, allowAll(egress)...)))
				f.trust.publish(trustedB(f.now))
			}
			f.owner.reconcile()
			require.Equal(t, security.Action_ALLOW, f.effective(podD).Action, "a refused source never fails the destination's plan")
			require.Equal(t, []string{"cmtc-a.mesh.example/ns/orders/sa/web"}, f.principals())
			require.Zero(t, f.owner.sourceCounts[sourceOriginPeer])
			require.NotEmpty(t, f.owner.refusedSources)
		})
	}
}

func TestEffectivePolicyRefusesStaleOrForeignClusterLeases(t *testing.T) {
	for name, publish := range map[string]func(f *sourceFixture){
		"expired": func(f *sourceFixture) {
			f.cluster.PublishRemoteWorkloadSnapshot(remote.Snapshot{ClusterName: ownerCluster.Name, ClusterID: ownerCluster.ID, Valid: true,
				SourceMembershipLeaseValidUntil: f.now, Workloads: []remote.Workload{sourceWorkload(1, podC, "worker-b", clusterAddr, "web", clusterIDn,
					envelope(ownerCluster, allowAll(egress)...))}})
		},
		"invalid": func(f *sourceFixture) {
			f.cluster.PublishRemoteWorkloadSnapshot(remote.Snapshot{ClusterName: ownerCluster.Name, ClusterID: ownerCluster.ID, Reason: "watch lost"})
		},
		"another cluster": func(f *sourceFixture) {
			f.cluster.PublishRemoteWorkloadSnapshot(remote.Snapshot{ClusterName: "cmtc-b", ClusterID: 2, Valid: true,
				SourceMembershipLeaseValidUntil: f.now.Add(time.Minute)})
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newSourceFixture(t)
			publish(f)
			f.owner.reconcile()
			require.Equal(t, []string{"cmtc-b.mesh.example/ns/orders/sa/client"}, f.principals())
			require.Contains(t, f.owner.refusedSources, sourceOriginCluster)
		})
	}
}

// A conflicting claim would make CompileZtunnelTCP fail the whole plan; it
// is refused instead, so no external source can deny a destination's callers.
func TestEffectivePolicyRefusesConflictingExternalClaims(t *testing.T) {
	t.Run("address of a local workload", func(t *testing.T) {
		f := newSourceFixture(t)
		f.addresses[netip.MustParseAddr("10.0.0.20")] = addressOwner{id: peerIDn, podUID: podP}
		f.publishPeer(sourceWorkload(2, podP, "cmtc-b-worker", "10.0.0.20", "client", peerIDn, envelope(peerCluster, allowAll(egress)...)))
		f.owner.reconcile()
		require.Equal(t, []string{"cmtc-a.mesh.example/ns/orders/sa/web"}, f.principals())
	})
	t.Run("incarnation of a local workload", func(t *testing.T) {
		f := newSourceFixture(t)
		f.addresses[netip.MustParseAddr(clusterAddr)] = addressOwner{id: clusterIDn, podUID: podD}
		f.publishCluster(sourceWorkload(1, podD, "worker-b", clusterAddr, "web", clusterIDn, envelope(ownerCluster, allowAll(egress)...)))
		f.owner.reconcile()
		require.Equal(t, []string{"cmtc-b.mesh.example/ns/orders/sa/client"}, f.principals())
	})
	t.Run("one address claimed by two external sources", func(t *testing.T) {
		// The ipcache has one owner per address, so both claims pass only if
		// the entry changes between two lookups of one reconcile.
		a := policySubjectFor(t, 1, podC, ownerCluster, clusterIDn, peerAddr)
		b := policySubjectFor(t, 2, podP, peerCluster, peerIDn, peerAddr)
		out := sourceAdmission{refused: map[string]string{}}
		kept := withoutConflicts(&out, ownerCluster, "cmtc-a.mesh.example", nil,
			[]sourcedSubject{{origin: sourceOriginCluster, subject: a}, {origin: sourceOriginPeer, subject: b}})
		require.Empty(t, kept, "neither claimant of the address is admitted")
		require.Len(t, out.refused, 2)
	})
	t.Run("one cluster ID with two names", func(t *testing.T) {
		a := policySubjectFor(t, 2, podC, peerCluster, peerIDn, clusterAddr)
		b := policySubjectFor(t, 2, podP, peerCluster, peerIDn, peerAddr)
		b.ClusterName = "cmtc-c"
		out := sourceAdmission{refused: map[string]string{}}
		require.Empty(t, withoutConflicts(&out, ownerCluster, "cmtc-a.mesh.example", nil,
			[]sourcedSubject{{origin: sourceOriginPeer, subject: a}, {origin: sourceOriginPeer, subject: b}}))
	})
}

// policySubjectFor is an external source subject with a decoded allow-all
// egress policy of owner.
func policySubjectFor(t *testing.T, cluster uint32, podUID string, owner cmtypes.ClusterInfo, id identity.NumericIdentity, ip string) policy.ZtunnelPolicySubject {
	t.Helper()
	e := envelope(owner, allowAll(egress)...)
	snapshot, err := policy.DecodeNativeZtunnelL4(slog.New(slog.DiscardHandler), policy.NativeZtunnelL4Expectation{Owner: owner,
		PolicyRevision: 1, SelectorRevision: 1, Digest: e.Digest}, e.Wire)
	require.NoError(t, err)
	return policy.ZtunnelPolicySubject{ClusterID: cluster, EndpointID: 77, ClusterName: owner.Name, TrustDomain: owner.Name + ".mesh.example",
		Namespace: "orders", NamespaceUID: remoteNamespaceUID, PodUID: podUID, ServiceAccount: "web", NumericIdentity: id,
		Addresses: []netip.Addr{netip.MustParseAddr(ip)}, Policy: snapshot}
}

// Narrowing a source's egress republishes the destination's plan without the
// port, and the new version needs a new ztunnel ACK.
func TestEffectivePolicyRepublishesWhenAnExternalSourceNarrows(t *testing.T) {
	f := newSourceFixture(t)
	f.owner.reconcile()
	before := f.cacheVersion()
	f.owner.observeAuthorizationAck(f.owner.generation, before)
	f.owner.reconcile()
	state, _ := f.registry.Get(f.refs[podD])
	require.True(t, state.PolicyAcked)

	f.publishPeer(sourceWorkload(2, podP, "cmtc-b-worker", peerAddr, "client", peerIDn,
		envelope(peerCluster, l4Entry{dir: egress, proto: tcp, prefix: 16, id: 1<<16 | 300, port: 8080})))
	f.owner.reconcile()
	require.Greater(t, f.cacheVersion(), before)
	state, _ = f.registry.Get(f.refs[podD])
	require.False(t, state.PolicyAcked, "the narrowed plan is not acknowledged yet")
	for _, rule := range f.effective(podD).Rules {
		match := rule.Clauses[0].Matches[0]
		if match.Principals[0].GetExact() == "cmtc-b.mesh.example/ns/orders/sa/client" {
			require.Equal(t, []uint32{8080}, match.DestinationPorts)
			return
		}
	}
	t.Fatal("the narrowed peer source is missing from the plan")
}

func TestEffectivePolicyWithoutAddressViewAdmitsOnlyLocalCallers(t *testing.T) {
	f := newSourceFixture(t)
	f.owner.sources.addresses = nil
	f.owner.reconcile()
	require.Equal(t, security.Action_ALLOW, f.effective(podD).Action)
	require.Empty(t, f.principals())
}

func TestEffectivePolicyDecodesEachEgressPolicyOnce(t *testing.T) {
	f := newSourceFixture(t)
	f.owner.reconcile()
	require.Len(t, f.owner.decoded, 2)
	first := make(map[decodeKey]decodeResult, len(f.owner.decoded))
	for k, v := range f.owner.decoded {
		first[k] = v
	}
	f.owner.reconcile()
	for k, v := range f.owner.decoded {
		require.Same(t, first[k].snapshot, v.snapshot, "an unchanged envelope is not decoded again")
	}
	f.publishPeer()
	f.owner.reconcile()
	require.Len(t, f.owner.decoded, 1, "a withdrawn source's decoded policy is dropped")
}

func TestEffectivePolicySourceChangesKickTheOwner(t *testing.T) {
	f := newSourceFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err := f.cluster.Wait(ctx) // the fixture's own publication
	require.NoError(t, err)
	kicks := make(chan struct{}, 8)
	f.owner.sources.watch(ctx, func() { kicks <- struct{}{} })
	for name, change := range map[string]func(){
		"same-cluster leases": func() { f.publishCluster() },
		"peer snapshot":       func() { f.publishPeer() },
		"trust view":          func() { f.trust.publish(remoteTrustView{reason: "profile withdrawn"}) },
	} {
		change()
		select {
		case <-kicks:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s change did not kick the owner", name)
		}
		require.Empty(t, kicks, "one change kicks once")
	}
}
