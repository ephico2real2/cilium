// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/identity"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
)

func ztunnelTestPolicy(t *testing.T, entries map[Key]MapStateEntry) *EndpointPolicy {
	t.Helper()
	logger := hivetest.Logger(t)
	p := &EndpointPolicy{SelectorPolicy: &selectorPolicy{Revision: 7, L4Policy: NewL4Policy(7)},
		PolicyOwner: DummyOwner{logger: logger}, selectors: policyTypes.MockSelectorSnapshot(),
		policyMapState: newMapState(logger, MapStateSizes{}, allFeatures, cmtypes.ClusterInfo{ID: 1, Name: "cluster-a", MaxConnectedClusters: 255})}
	for key, value := range entries {
		p.policyMapState.upsert(key, NewMapStateEntry(value))
	}
	return p
}
func ztunnelTestSubject(t *testing.T, endpoint uint16, id identity.NumericIdentity, uid, ip string, entries map[Key]MapStateEntry) ZtunnelPolicySubject {
	t.Helper()
	snapshot, err := ztunnelTestPolicy(t, entries).SnapshotZtunnelL4(7)
	require.NoError(t, err)
	return ZtunnelPolicySubject{ClusterID: 1, EndpointID: endpoint, ClusterName: "cluster-a", TrustDomain: "cluster-a.mesh", Namespace: "orders",
		NamespaceUID: "11111111-1111-4111-8111-111111111111", PodUID: uid, ServiceAccount: "api", NumericIdentity: id, Addresses: []netip.Addr{netip.MustParseAddr(ip)}, Policy: snapshot}
}
func TestZtunnelNativeSnapshotImmutableAndRevisionFailures(t *testing.T) {
	id := identity.NumericIdentity(1<<16 | 1000)
	key := IngressKey().WithIdentity(id).WithTCPPort(8080)
	p := ztunnelTestPolicy(t, map[Key]MapStateEntry{key: policyTypes.AllowEntry()})
	snapshot, err := p.SnapshotZtunnelL4(7)
	require.NoError(t, err)
	require.True(t, snapshot.permits(id, 8080, true))
	p.policyMapState.upsert(key, NewMapStateEntry(policyTypes.DenyEntry()))
	require.True(t, snapshot.permits(id, 8080, true), "immutable snapshot cannot follow the mutable native map")
	next, err := p.SnapshotZtunnelL4(7)
	require.NoError(t, err)
	require.False(t, next.permits(id, 8080, true))
	require.NotEqual(t, snapshot.Digest(), next.Digest())
	_, err = p.SnapshotZtunnelL4(8)
	require.Error(t, err)
	p.selectors.Revision = 0
	_, err = p.SnapshotZtunnelL4(7)
	require.Error(t, err)
	p.selectors = policyTypes.MockSelectorSnapshot()
	p.policyMapChanges.changes = append(p.policyMapChanges.changes, mapChange{})
	_, err = p.SnapshotZtunnelL4(7)
	require.Error(t, err)
	p.policyMapChanges.changes = nil
	p.PolicyOwner = nil
	_, err = p.SnapshotZtunnelL4(7)
	require.Error(t, err)
}
func TestZtunnelNativeCompilerRequiresBothDirectionsAndExactSource(t *testing.T) {
	info := cmtypes.ClusterInfo{ID: 1, Name: "cluster-a", MaxConnectedClusters: 255}
	sourceID := identity.NumericIdentity(1<<16 | 1000)
	otherID := identity.NumericIdentity(1<<16 | 1001)
	destinationID := identity.NumericIdentity(1<<16 | 1002)
	dst := ztunnelTestSubject(t, 1, destinationID, "22222222-2222-4222-8222-222222222222", "10.1.2.3", map[Key]MapStateEntry{
		IngressKey().WithIdentity(sourceID).WithTCPPort(8080):  policyTypes.AllowEntry(),
		IngressKey().WithIdentity(sourceID).WithTCPPort(31337): policyTypes.AllowEntry(),
	})
	src := ztunnelTestSubject(t, 2, sourceID, "33333333-3333-4333-8333-333333333333", "10.1.2.4", map[Key]MapStateEntry{
		EgressKey().WithIdentity(destinationID).WithTCPPort(8080):  policyTypes.AllowEntry(),
		EgressKey().WithIdentity(destinationID).WithTCPPort(31337): policyTypes.DenyEntry(),
	})
	other := ztunnelTestSubject(t, 3, otherID, "44444444-4444-4444-8444-444444444444", "10.1.2.5", map[Key]MapStateEntry{EgressKey().WithIdentity(identity.ReservedIdentityAggregateCluster): policyTypes.AllowEntry()})
	plan, err := CompileZtunnelTCP(info, dst, []ZtunnelPolicySubject{src, other})
	require.NoError(t, err)
	require.Len(t, plan.ReviewAuthorization.Rules, 1)
	rule := plan.ReviewAuthorization.Rules[0]
	require.Len(t, rule.Clauses, 1)
	require.Len(t, rule.Clauses[0].Matches, 1)
	match := rule.Clauses[0].Matches[0]
	require.Equal(t, []uint32{8080}, match.DestinationPorts)
	require.Equal(t, "cluster-a.mesh/ns/orders/sa/api", match.Principals[0].GetExact())
	require.Equal(t, src.Addresses[0].AsSlice(), match.SourceIps[0].Address)
	require.Equal(t, dst.Addresses[0].AsSlice(), match.DestinationIps[0].Address)
	require.NotEmpty(t, plan.Digest)
	// Same SA does not turn the unselected numeric identity into an allow.
	denied, err := CompileZtunnelTCP(info, dst, []ZtunnelPolicySubject{other})
	require.NoError(t, err)
	require.Empty(t, denied.ReviewAuthorization.Rules)
	// An unknown egress snapshot cannot reuse the ingress allow.
	src.Policy = nil
	_, err = CompileZtunnelTCP(info, dst, []ZtunnelPolicySubject{src})
	require.Error(t, err)
}
func TestZtunnelNativeCompilerAllPortsAndAmbiguousIncarnation(t *testing.T) {
	info := cmtypes.ClusterInfo{ID: 1, Name: "cluster-a", MaxConnectedClusters: 255}
	dst := ztunnelTestSubject(t, 1, 1<<16|1000, "22222222-2222-4222-8222-222222222222", "10.1.2.3", map[Key]MapStateEntry{IngressKey().WithIdentity(identity.ReservedIdentityAggregateCluster): policyTypes.AllowEntry()})
	src := ztunnelTestSubject(t, 2, 1<<16|1001, "33333333-3333-4333-8333-333333333333", "10.1.2.4", map[Key]MapStateEntry{EgressKey().WithIdentity(identity.ReservedIdentityAggregateCluster): policyTypes.AllowEntry()})
	plan, err := CompileZtunnelTCP(info, dst, []ZtunnelPolicySubject{src})
	require.NoError(t, err)
	require.Len(t, plan.ReviewAuthorization.Rules, 1)
	require.Empty(t, plan.ReviewAuthorization.Rules[0].Clauses[0].Matches[0].DestinationPorts, "all TCP ports have no port predicate")
	_, err = CompileZtunnelTCP(info, dst, []ZtunnelPolicySubject{src, src})
	require.Error(t, err)
	other := src
	other.PodUID = "44444444-4444-4444-8444-444444444444"
	_, err = CompileZtunnelTCP(info, dst, []ZtunnelPolicySubject{src, other})
	require.Error(t, err)
	src.ClusterID = 2
	_, err = CompileZtunnelTCP(info, dst, []ZtunnelPolicySubject{src})
	require.Error(t, err)
}
func TestZtunnelNativeSnapshotRejectsProxyAndUnsupportedEntries(t *testing.T) {
	key := IngressKey().WithTCPPort(80)
	for _, entry := range []MapStateEntry{policyTypes.AllowEntry().WithProxyPort(15000), policyTypes.InvalidEntry()} {
		p := ztunnelTestPolicy(t, map[Key]MapStateEntry{key: entry})
		_, err := p.SnapshotZtunnelL4(7)
		require.Error(t, err)
	}
}

func TestZtunnelNativeLookupUsesRealAggregateBucketsAndProtocol(t *testing.T) {
	local := identity.NumericIdentity(1<<16 | 1000)
	remote := identity.NumericIdentity(2<<16 | 1000)
	tests := []struct {
		name                    string
		key                     Key
		localAllow, remoteAllow bool
	}{
		{"identity-zero-is-not-a-global-wildcard", IngressKey(), false, false},
		{"local-cluster-aggregate", IngressKey().WithIdentity(identity.ReservedIdentityAggregateCluster), true, false},
		{"clustermesh-aggregate", IngressKey().WithIdentity(identity.ReservedIdentityAggregateClusterMesh), false, true},
		{"udp-only-does-not-allow-tcp", IngressKey().WithIdentity(identity.ReservedIdentityAggregateCluster).WithUDPPort(8080), false, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p := ztunnelTestPolicy(t, map[Key]MapStateEntry{test.key: policyTypes.AllowEntry()})
			snapshot, err := p.SnapshotZtunnelL4(7)
			require.NoError(t, err)
			for _, port := range []uint16{1, 80, 8080, 31337, 65535} {
				require.Equal(t, test.localAllow, snapshot.permits(local, port, true), "local TCP/%d", port)
				require.Equal(t, test.remoteAllow, snapshot.permits(remote, port, true), "remote TCP/%d", port)
				require.False(t, snapshot.permits(local, port, false), "ingress cannot authorize egress")
			}
		})
	}
	// This is the ACTUAL native distillation path for disabled directions:
	// it expands every aggregate. No compiler-specific wildcard shortcut.
	p := ztunnelTestPolicy(t, nil)
	p.policyMapState.allowAllIdentities(true, true)
	snapshot, err := p.SnapshotZtunnelL4(7)
	require.NoError(t, err)
	for _, id := range []identity.NumericIdentity{local, remote} {
		for _, port := range []uint16{1, 80, 8080, 31337, 65535} {
			require.True(t, snapshot.permits(id, port, true))
			require.True(t, snapshot.permits(id, port, false))
		}
	}
}

func TestZtunnelNativeCompilerRejectsSnapshotFromAnotherCluster(t *testing.T) {
	info := cmtypes.ClusterInfo{ID: 1, Name: "cluster-a", MaxConnectedClusters: 255}
	dst := ztunnelTestSubject(t, 1, 1<<16|1000, "22222222-2222-4222-8222-222222222222", "10.1.2.3", map[Key]MapStateEntry{IngressKey().WithIdentity(identity.ReservedIdentityAggregateClusterMesh): policyTypes.AllowEntry()})
	src := ztunnelTestSubject(t, 2, 2<<16|1000, "33333333-3333-4333-8333-333333333333", "10.2.2.4", map[Key]MapStateEntry{EgressKey().WithIdentity(identity.ReservedIdentityAggregateCluster): policyTypes.AllowEntry()})
	// Identity and declared cluster B agree, but its map was actually built
	// for cluster A. Without a snapshot binding check, destination identity A
	// matches the local aggregate in the mislabeled source map and is allowed.
	src.ClusterID = 2
	src.ClusterName = "cluster-b"
	src.TrustDomain = "cluster-b.mesh"
	_, err := CompileZtunnelTCP(info, dst, []ZtunnelPolicySubject{src})
	require.ErrorContains(t, err, "snapshot cluster binding")
	// Build the real source-owned cluster B map. A destination in cluster A
	// belongs to its ClusterMesh aggregate, not its local-cluster aggregate.
	sourcePolicy := ztunnelTestPolicy(t, nil)
	sourcePolicy.policyMapState.clusterInfo = cmtypes.ClusterInfo{ID: 2, Name: "cluster-b", MaxConnectedClusters: 255}
	sourcePolicy.policyMapState.upsert(EgressKey().WithIdentity(identity.ReservedIdentityAggregateClusterMesh), NewMapStateEntry(policyTypes.AllowEntry()))
	src.Policy, err = sourcePolicy.SnapshotZtunnelL4(7)
	require.NoError(t, err)
	plan, err := CompileZtunnelTCP(info, dst, []ZtunnelPolicySubject{src})
	require.NoError(t, err)
	require.Len(t, plan.ReviewAuthorization.Rules, 1)
	require.Empty(t, plan.ReviewAuthorization.Rules[0].Clauses[0].Matches[0].DestinationPorts)
}
