// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"testing"

	"github.com/cilium/statedb"
	v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/cilium/cilium/pkg/ztunnel/pb"
	"github.com/cilium/cilium/pkg/ztunnel/pb/security"
	"github.com/cilium/cilium/pkg/ztunnel/table"
)

func TestNativeQuarantineDeliveredOverADSAndBoundToIncarnation(t *testing.T) {
	server, conn := testAuthorizationServer(t)
	db := statedb.New()
	tbl, err := table.NewEnrolledNamespacesTable(db)
	require.NoError(t, err)
	nsUID := "11111111-1111-4111-8111-111111111111"
	podUID := "22222222-2222-4222-8222-222222222222"
	tx := db.WriteTxn(tbl)
	_, _, err = tbl.Insert(tx, &table.EnrolledNamespace{Name: "orders", UID: nsUID})
	require.NoError(t, err)
	tx.Commit()
	sp := &StreamProcessor{nodeNames: fixtureNodeNames(t), db: db, enrolledNamespaceTable: tbl, authorizations: server.authorizations, log: server.log}
	wire, err := anypb.New(&pb.Address{Type: &pb.Address_Workload{Workload: &pb.Workload{Uid: podUID, Namespace: "orders"}}})
	require.NoError(t, err)
	response := &v3.DeltaDiscoveryResponse{TypeUrl: xdsTypeURLAddress, Resources: []*v3.Resource{{Name: podUID, Resource: wire}}}
	require.NoError(t, sp.bindEffectiveQuarantine(response))
	var address pb.Address
	require.NoError(t, response.Resources[0].Resource.UnmarshalTo(&address))
	expected, err := quarantineAuthorization("orders", nsUID, podUID)
	require.NoError(t, err)
	key := "orders/" + expected.Name
	require.Equal(t, []string{key}, address.GetWorkload().AuthorizationPolicies)
	peer := newAuthorizationPeer(t, conn)
	peer.send(t, subscribeAuthorization())
	delivered := peer.receive(t)
	require.Len(t, delivered.Resources, 1)
	require.Equal(t, key, delivered.Resources[0].Name)
	var policy security.Authorization
	require.NoError(t, delivered.Resources[0].Resource.UnmarshalTo(&policy))
	require.Equal(t, security.Action_DENY, policy.Action)
	require.Equal(t, security.Scope_WORKLOAD_SELECTOR, policy.Scope)
	require.False(t, policy.DryRun)
	require.Len(t, policy.Rules, 1)
	require.Empty(t, policy.Rules[0].Clauses, "one zero-clause rule is an unconditional DENY")
	peer.ack(t, delivered)
	// The removed Address removes its exact policy, while a recreated namespace
	// gets a distinct binding even if the namespace name and address are reused.
	require.NoError(t, sp.bindEffectiveQuarantine(&v3.DeltaDiscoveryResponse{RemovedResources: []string{podUID}}))
	removed := peer.receive(t)
	require.Equal(t, []string{key}, removed.RemovedResources)
	peer.ack(t, removed)
	next, err := quarantineAuthorization("orders", "33333333-3333-4333-8333-333333333333", podUID)
	require.NoError(t, err)
	require.NotEqual(t, expected.Name, next.Name)
	_, err = quarantineAuthorization("orders", "", podUID)
	require.Error(t, err)
	_, err = quarantineAuthorization("orders", nsUID, "not-a-uid")
	require.Error(t, err)
}

func TestNativeQuarantineMissingNamespaceNeverPublishesOrphanAllow(t *testing.T) {
	server, _ := testAuthorizationServer(t)
	db := statedb.New()
	tbl, err := table.NewEnrolledNamespacesTable(db)
	require.NoError(t, err)
	sp := &StreamProcessor{nodeNames: fixtureNodeNames(t), db: db, enrolledNamespaceTable: tbl, authorizations: server.authorizations, log: server.log}
	wire, err := anypb.New(&pb.Address{Type: &pb.Address_Workload{Workload: &pb.Workload{Uid: "22222222-2222-4222-8222-222222222222", Namespace: "orders"}}})
	require.NoError(t, err)
	require.Error(t, sp.bindEffectiveQuarantine(&v3.DeltaDiscoveryResponse{Resources: []*v3.Resource{{Name: "pod", Resource: wire}}}))
	current := server.authorizations.cache.GetResources(xdsTypeURLAuthorization, 0, nil)
	require.Empty(t, current.VersionedResources)
}
