// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"fmt"
	"log/slog"
	"net/netip"
	"testing"

	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"
	apimachineryTypes "k8s.io/apimachinery/pkg/types"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodetypes "github.com/cilium/cilium/pkg/node/types"
)

var testLocalCluster = cmtypes.ClusterInfo{Name: "cmtc-a", ID: 1}

type testNodeRow struct {
	name, cluster string
	clusterID     uint32
	addresses     []string
	internal      []string // CiliumInternalIP addresses (cluster-scoped index)
}

// testNodeTable is a real native node table, written the way Cilium's node
// discovery writes it. registerInitializer leaves it unsynchronized.
func testNodeTable(t testing.TB, registerInitializer bool, rows ...testNodeRow) (*statedb.DB, statedb.RWTable[*node.Node]) {
	db := statedb.New()
	nodes, err := node.NewNodeTable(db)
	require.NoError(t, err)
	txn := db.WriteTxn(nodes)
	if registerInitializer {
		nodes.RegisterInitializer(txn, "test")
	}
	for _, row := range rows {
		n := &node.Node{Node: nodetypes.Node{Name: row.name, Cluster: row.cluster, ClusterID: row.clusterID}}
		for _, a := range row.addresses {
			n.IPAddresses = append(n.IPAddresses, nodetypes.NewAddress(addressing.NodeInternalIP, netip.MustParseAddr(a)))
		}
		for _, a := range row.internal {
			n.IPAddresses = append(n.IPAddresses, nodetypes.NewAddress(addressing.NodeCiliumInternalIP, netip.MustParseAddr(a)))
		}
		_, _, err := nodes.Insert(txn, n)
		require.NoError(t, err)
	}
	txn.Commit()
	return db, nodes
}

// fixtureNodeNames is the native node discovery used by tests whose subject
// is not node naming. Each name differs from its address.
func fixtureNodeNames(t testing.TB) nodeNameResolver {
	db, nodes := testNodeTable(t, false,
		testNodeRow{name: "worker-a", cluster: "cmtc-a", clusterID: 1, addresses: []string{"10.0.0.1"}},
		testNodeRow{name: "test-node", cluster: "cmtc-a", clusterID: 1, addresses: []string{"10.1.1.10"}},
		testNodeRow{name: "remove-node", cluster: "cmtc-a", clusterID: 1, addresses: []string{"10.2.1.10"}},
		testNodeRow{name: "create-node-1", cluster: "cmtc-a", clusterID: 1, addresses: []string{"100.1.1.10"}},
		testNodeRow{name: "create-node-2", cluster: "cmtc-a", clusterID: 1, addresses: []string{"100.1.1.20"}},
		testNodeRow{name: "test-node-1", cluster: "cmtc-a", clusterID: 1, addresses: []string{"10.3.3.1"}},
		testNodeRow{name: "test-node-2", cluster: "cmtc-a", clusterID: 1, addresses: []string{"10.3.3.2"}},
		testNodeRow{name: "test-node-3", cluster: "cmtc-a", clusterID: 1, addresses: []string{"10.3.3.3"}},
	)
	names, err := newNativeNodeNames(db, nodes, testLocalCluster)
	require.NoError(t, err)
	return names
}

// panicTB lets gRPC test servers (which have no *testing.T) build the same
// real native fixture; any setup failure panics the test binary.
type panicTB struct{ testing.TB }

func (panicTB) Helper()                           {}
func (panicTB) Errorf(format string, args ...any) { panic(fmt.Sprintf(format, args...)) }
func (panicTB) FailNow()                          { panic("fixture setup failed") }

func mustFixtureNodeNames() nodeNameResolver { return fixtureNodeNames(panicTB{}) }

func nodeTestEvent(uid, nodeIP string) *EndpointEvent {
	return &EndpointEvent{Type: CREATE, CiliumEndpoint: &types.CiliumEndpoint{
		ObjectMeta: slim_metav1.ObjectMeta{Name: "api", Namespace: "orders",
			OwnerReferences: []slim_metav1.OwnerReference{{Kind: "Pod", UID: apimachineryTypes.UID(uid)}}},
		Networking:     &v2.EndpointNetworking{Addressing: v2.AddressPairList{{IPV4: "10.10.1.33"}}, NodeIP: nodeIP},
		ServiceAccount: "api",
	}}
}

// Mirrors the live kind APIs: names are not addresses, and each cluster has
// its own nodes (cmtc-a-worker 172.18.0.2, cmtc-b-worker 172.18.0.5).
func TestNativeNodeNameUsesKubernetesNameNotAddress(t *testing.T) {
	db, nodes := testNodeTable(t, false,
		testNodeRow{name: "cmtc-a-control-plane", cluster: "cmtc-a", clusterID: 1, addresses: []string{"172.18.0.3"}, internal: []string{"10.10.0.249"}},
		testNodeRow{name: "cmtc-a-worker", cluster: "cmtc-a", clusterID: 1, addresses: []string{"172.18.0.2"}, internal: []string{"10.10.1.147"}},
		testNodeRow{name: "cmtc-b-worker", cluster: "cmtc-b", clusterID: 2, addresses: []string{"172.18.0.5"}, internal: []string{"10.20.1.171"}},
	)
	names, err := newNativeNodeNames(db, nodes, testLocalCluster)
	require.NoError(t, err)

	event := nodeTestEvent("11111111-1111-4111-8111-111111111111", "172.18.0.2")
	bound, pairs, watch, err := names.bind(EndpointEventCollection{event})
	require.NoError(t, err)
	require.NotNil(t, watch)
	require.Equal(t, "cmtc-a-worker", bound[0].NodeName)
	require.NotEqual(t, bound[0].Networking.NodeIP, bound[0].NodeName, "the node name is never the node IP")
	require.Empty(t, event.NodeName, "input events are not mutated")
	require.Equal(t, map[netip.Addr]string{netip.MustParseAddr("172.18.0.2"): "cmtc-a-worker"}, pairs)

	address, err := bound[0].ToXDSAddress()
	require.NoError(t, err)
	require.Equal(t, "cmtc-a-worker", address.GetWorkload().Node)

	// A remote-cluster node address is never resolved by the local stream.
	_, _, _, err = names.bind(EndpointEventCollection{nodeTestEvent("22222222-2222-4222-8222-222222222222", "172.18.0.5")})
	require.ErrorContains(t, err, "no Kubernetes node name")
}

func TestNativeNodeNameDeniesMissingAmbiguousUnsyncedAndInvalid(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rows  []testNodeRow
		init  bool
		ip    string
		error string
	}{
		{name: "missing node", ip: "172.18.0.2", error: "no Kubernetes node name"},
		{name: "empty node name", rows: []testNodeRow{{name: "", cluster: "cmtc-a", clusterID: 1, addresses: []string{"172.18.0.2"}}},
			ip: "172.18.0.2", error: "no Kubernetes node name"},
		{name: "same cluster name, other cluster ID", rows: []testNodeRow{{name: "cmtc-a-worker", cluster: "cmtc-a", clusterID: 7, addresses: []string{"172.18.0.2"}}},
			ip: "172.18.0.2", error: "no Kubernetes node name"},
		{name: "ambiguous address", rows: []testNodeRow{
			{name: "cmtc-a-worker", cluster: "cmtc-a", clusterID: 1, addresses: []string{"172.18.0.2"}},
			{name: "cmtc-a-other", cluster: "cmtc-a", clusterID: 1, addresses: []string{"172.18.0.2"}},
		}, ip: "172.18.0.2", error: "more than one Kubernetes node"},
		{name: "not synchronized", rows: []testNodeRow{{name: "cmtc-a-worker", cluster: "cmtc-a", clusterID: 1, addresses: []string{"172.18.0.2"}}},
			init: true, ip: "172.18.0.2", error: "has not synchronized"},
		{name: "invalid node address", rows: []testNodeRow{{name: "cmtc-a-worker", cluster: "cmtc-a", clusterID: 1, addresses: []string{"172.18.0.2"}}},
			ip: "cmtc-a-worker", error: "invalid node address"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, nodes := testNodeTable(t, tc.init, tc.rows...)
			names, err := newNativeNodeNames(db, nodes, testLocalCluster)
			require.NoError(t, err)
			bound, _, _, err := names.bind(EndpointEventCollection{nodeTestEvent("11111111-1111-4111-8111-111111111111", tc.ip)})
			require.ErrorContains(t, err, tc.error)
			require.Nil(t, bound)
		})
	}
	_, err := newNativeNodeNames(nil, nil, testLocalCluster)
	require.Error(t, err)

	// Without the resolver an Address response fails closed; there is no
	// NodeIP fallback.
	sp := &StreamProcessor{log: slog.New(slog.DiscardHandler)}
	_, err = sp.addressResponse(EndpointEventCollection{nodeTestEvent("11111111-1111-4111-8111-111111111111", "10.0.0.1")})
	require.ErrorContains(t, err, "node discovery is not configured")
	unbound := nodeTestEvent("11111111-1111-4111-8111-111111111111", "10.0.0.1")
	_, err = unbound.ToXDSAddress()
	require.ErrorContains(t, err, "missing Kubernetes node name")
}

// Repeated node names in two clusters stay separate: each stream resolves only
// its own cluster's rows, and removal of one cluster's node is never covered by
// the other cluster's identical name/address.
func TestNativeNodeNameRepeatedNamesInDifferentClusters(t *testing.T) {
	db, nodes := testNodeTable(t, false,
		testNodeRow{name: "worker-shared", cluster: "cmtc-a", clusterID: 1, addresses: []string{"192.0.2.1"}},
		testNodeRow{name: "worker-shared", cluster: "cmtc-b", clusterID: 2, addresses: []string{"192.0.2.1"}},
	)
	event := nodeTestEvent("11111111-1111-4111-8111-111111111111", "192.0.2.1")
	for _, cluster := range []cmtypes.ClusterInfo{{Name: "cmtc-a", ID: 1}, {Name: "cmtc-b", ID: 2}} {
		names, err := newNativeNodeNames(db, nodes, cluster)
		require.NoError(t, err)
		bound, _, _, err := names.bind(EndpointEventCollection{event})
		require.NoError(t, err, cluster.Name)
		require.Equal(t, "worker-shared", bound[0].NodeName)
	}
	txn := db.WriteTxn(nodes)
	_, _, err := nodes.Delete(txn, &node.Node{Node: nodetypes.Node{Name: "worker-shared", Cluster: "cmtc-a"}})
	require.NoError(t, err)
	txn.Commit()
	names, err := newNativeNodeNames(db, nodes, testLocalCluster)
	require.NoError(t, err)
	_, _, _, err = names.bind(EndpointEventCollection{event})
	require.ErrorContains(t, err, "no Kubernetes node name", "cmtc-b's identical row must not substitute")
}

// A node-only change (no endpoint event) must invalidate the active stream;
// unrelated node writes re-arm the watch without closing it.
func TestNativeNodeNameWatchInvalidatesStreamOnNodeChange(t *testing.T) {
	db, nodes := testNodeTable(t, false,
		testNodeRow{name: "cmtc-a-worker", cluster: "cmtc-a", clusterID: 1, addresses: []string{"172.18.0.2"}},
		testNodeRow{name: "cmtc-a-control-plane", cluster: "cmtc-a", clusterID: 1, addresses: []string{"172.18.0.3"}},
	)
	names, err := newNativeNodeNames(db, nodes, testLocalCluster)
	require.NoError(t, err)
	sp := &StreamProcessor{log: slog.New(slog.DiscardHandler), nodeNames: names}
	bound, err := sp.bindNodeNames(EndpointEventCollection{nodeTestEvent("11111111-1111-4111-8111-111111111111", "172.18.0.2")})
	require.NoError(t, err)
	require.Equal(t, "cmtc-a-worker", bound[0].NodeName)
	watch := sp.nodeNameWatch
	require.NotNil(t, watch)

	// Unrelated node write: watch fires, binding unchanged, stream survives.
	txn := db.WriteTxn(nodes)
	_, _, err = nodes.Insert(txn, &node.Node{Node: nodetypes.Node{Name: "cmtc-a-extra", Cluster: "cmtc-a", ClusterID: 1,
		IPAddresses: []nodetypes.Address{nodetypes.NewAddress(addressing.NodeInternalIP, netip.MustParseAddr("172.18.0.9"))}}})
	require.NoError(t, err)
	txn.Commit()
	<-watch
	require.NoError(t, sp.revalidateNodeNames())
	require.NotEqual(t, watch, sp.nodeNameWatch, "watch is re-armed from the new read")

	// The bound node disappears without any CEP event: the stream must end.
	watch = sp.nodeNameWatch
	txn = db.WriteTxn(nodes)
	_, _, err = nodes.Delete(txn, &node.Node{Node: nodetypes.Node{Name: "cmtc-a-worker", Cluster: "cmtc-a"}})
	require.NoError(t, err)
	txn.Commit()
	<-watch
	require.ErrorContains(t, sp.revalidateNodeNames(), "Kubernetes node binding changed")

	// A name change for an address already published is refused at bind time.
	db2, nodes2 := testNodeTable(t, false, testNodeRow{name: "renamed", cluster: "cmtc-a", clusterID: 1, addresses: []string{"172.18.0.3"}})
	names2, err := newNativeNodeNames(db2, nodes2, testLocalCluster)
	require.NoError(t, err)
	sp.nodeNames = names2
	sp.boundNodeNames = map[netip.Addr]string{netip.MustParseAddr("172.18.0.3"): "cmtc-a-control-plane"}
	_, err = sp.bindNodeNames(EndpointEventCollection{nodeTestEvent("33333333-3333-4333-8333-333333333333", "172.18.0.3")})
	require.ErrorContains(t, err, "was published as")
}

// REMOVED events name only the Pod UID; they must work after the node is gone.
func TestNativeNodeNameRemovalNeedsNoNode(t *testing.T) {
	db, nodes := testNodeTable(t, false)
	names, err := newNativeNodeNames(db, nodes, testLocalCluster)
	require.NoError(t, err)
	removed := &EndpointEvent{Type: REMOVED, CiliumEndpoint: nodeTestEvent("11111111-1111-4111-8111-111111111111", "172.18.0.2").CiliumEndpoint}
	sourceError := &EndpointEvent{Err: errInvalidWorkloadData}
	bound, _, _, err := names.bind(EndpointEventCollection{removed, sourceError})
	require.NoError(t, err)
	require.Same(t, removed, bound[0])
	require.Same(t, sourceError, bound[1], "source rejections reach the strict converter unchanged")
	_, err = bound.toValidatedDeltaDiscoveryResponse("mesh.example.com", "cmtc-a")
	require.ErrorContains(t, err, "endpoint source rejected workload data", "and still fail the batch")
}

// fixtureBound binds through the real native fixture for converter-focused
// tests. If binding rejects the batch, the events pass through unchanged so
// the converter's own validation error stays the subject of the test.
func fixtureBound(t testing.TB, collection EndpointEventCollection) EndpointEventCollection {
	bound, _, _, err := fixtureNodeNames(t).bind(collection)
	if err != nil {
		return collection
	}
	return bound
}
