// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package remote_workload

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
)

type recordingSink struct{ snapshots []Snapshot }

func (s *recordingSink) PublishRemoteWorkloadSnapshot(snapshot Snapshot) {
	s.snapshots = append(s.snapshots, snapshot)
}

type fakePeerEvidence struct {
	name                string
	id                  uint32
	identityEpoch       uint64
	spki, profile       [32]byte
	notAfter, heartbeat time.Time
}

func (e fakePeerEvidence) ClusterName() string            { return e.name }
func (e fakePeerEvidence) ClusterID() uint32              { return e.id }
func (e fakePeerEvidence) IdentityEpoch() uint64          { return e.identityEpoch }
func (e fakePeerEvidence) CertificateNotAfter() time.Time { return e.notAfter }
func (e fakePeerEvidence) LastHeartbeat() time.Time       { return e.heartbeat }
func (e fakePeerEvidence) SPKIHash() [32]byte             { return e.spki }
func (e fakePeerEvidence) ProfileID() [32]byte            { return e.profile }
func (e fakePeerEvidence) Validate(now time.Time) error {
	if e.name == "" || e.id == 0 || e.identityEpoch == 0 || e.spki == [32]byte{} || e.profile == [32]byte{} || !now.Before(e.notAfter) {
		return fmt.Errorf("fake peer evidence unavailable")
	}
	if e.heartbeat.IsZero() || e.heartbeat.After(now) || now.Sub(e.heartbeat) > 2*kvstore.HeartbeatWriteInterval {
		return fmt.Errorf("fake peer heartbeat stale")
	}
	return nil
}

type fakePeerEvidenceProvider struct {
	evidence kvstore.RemotePeerEvidence
	err      error
}

func (p *fakePeerEvidenceProvider) CurrentRemotePeerEvidence() (kvstore.RemotePeerEvidence, error) {
	return p.evidence, p.err
}

func newTestInventory(t *testing.T) (*Inventory, *recordingSink) {
	t.Helper()
	sink := &recordingSink{}
	clusterInfo := cmtypes.ClusterInfo{ID: 1, Name: "cluster-alpha", MaxConnectedClusters: 255}
	peer := fakePeerEvidence{name: "cluster-beta", id: 17, identityEpoch: 1, spki: [32]byte{1}, profile: [32]byte{2}, notAfter: time.Now().Add(time.Hour), heartbeat: time.Now()}
	inventory, err := NewInventory("cluster-beta", 17, clusterInfo, &fakePeerEvidenceProvider{evidence: peer}, sink)
	if err != nil {
		t.Fatal(err)
	}
	return inventory, sink
}

func validPair(ip, podUID, namespaceUID, sa string) *identity.IPIdentityPair {
	clusterInfo := cmtypes.ClusterInfo{ID: 1, Name: "cluster-alpha", MaxConnectedClusters: 255}
	id := identity.NumericIdentity(clusterInfo.MinimalAllocationIdentityFor(17) + 1)
	return &identity.IPIdentityPair{
		IP:                          net.ParseIP(ip),
		ID:                          id,
		K8sNamespace:                "orders",
		K8sNamespaceUID:             namespaceUID,
		K8sNodeName:                 "node-a",
		K8sPodName:                  "api",
		K8sPodUID:                   podUID,
		K8sServiceAccount:           sa,
		ZtunnelMembershipVersion:    1,
		ZtunnelMembershipEpoch:      "agent-epoch-a",
		ZtunnelMembershipGeneration: 1,
		ZtunnelMembershipState:      "captured",
	}
}

func last(t *testing.T, sink *recordingSink) Snapshot {
	t.Helper()
	if len(sink.snapshots) == 0 {
		t.Fatal("no snapshot published")
	}
	return sink.snapshots[len(sink.snapshots)-1]
}

func TestInitialListPublishesOneCompleteSortedSnapshot(t *testing.T) {
	inventory, sink := newTestInventory(t)
	inventory.Begin(context.Background())
	if got := last(t, sink); got.Valid {
		t.Fatal("Begin must invalidate the previous session")
	}

	inventory.OnUpdate(validPair("10.17.0.12", "pod-a", "ns-a", "api"))
	inventory.OnUpdate(validPair("fd00:17::12", "pod-a", "ns-a", "api"))
	if got := last(t, sink); got.Valid {
		t.Fatal("initial list must remain staged before ListDone")
	}

	beforeListDone := len(sink.snapshots)
	inventory.ListDone(context.Background())
	got := last(t, sink)
	if len(sink.snapshots) != beforeListDone+1 {
		t.Fatalf("ListDone published %d events, want exactly one", len(sink.snapshots)-beforeListDone)
	}
	if !got.Valid || len(got.Workloads) != 1 {
		t.Fatalf("unexpected complete snapshot: %+v", got)
	}
	workload := got.Workloads[0]
	if workload.Key != (WorkloadKey{ClusterID: 17, NamespaceUID: "ns-a", PodUID: "pod-a"}) {
		t.Fatalf("unexpected workload key: %+v", workload.Key)
	}
	if workload.NodeName != "node-a" || workload.Identity != validPair("10.17.0.12", "pod-a", "ns-a", "api").ID {
		t.Fatalf("source node or Cilium numeric identity was not preserved: %+v", workload)
	}
	if workload.MembershipEpoch != "agent-epoch-a" || workload.MembershipGeneration != 1 || workload.MembershipState != "captured" {
		t.Fatalf("capture membership provenance was not preserved: %+v", workload)
	}
	if len(workload.Addresses) != 2 || !workload.Addresses[0].Less(workload.Addresses[1]) {
		t.Fatalf("addresses are not complete and sorted: %v", workload.Addresses)
	}
	if got.Generation <= 1 {
		t.Fatalf("generation did not advance: %d", got.Generation)
	}
}

func TestRequiredMembershipWithdrawsUntilFreshCaptureAndAck(t *testing.T) {
	inventory, sink := newTestInventory(t)
	pair := validPair("10.17.0.12", "pod-a", "ns-a", "api")
	inventory.Begin(context.Background())
	inventory.OnUpdate(pair)
	inventory.ListDone(context.Background())
	requireValidWorkloads(t, sink, 1)

	pending := *pair
	pending.ZtunnelMembershipGeneration = 2
	pending.ZtunnelMembershipState = "required"
	inventory.OnUpdate(&pending)
	requireValidWorkloads(t, sink, 0)

	captured := pending
	captured.ZtunnelMembershipState = "captured"
	inventory.OnUpdate(&captured)
	requireValidWorkloads(t, sink, 1)
}

func TestMembershipGenerationAndStateMustAgreeAcrossPodAddresses(t *testing.T) {
	inventory, sink := newTestInventory(t)
	inventory.Begin(context.Background())
	v4 := validPair("10.17.0.12", "pod-a", "ns-a", "api")
	v6 := validPair("fd00:17::12", "pod-a", "ns-a", "api")
	inventory.OnUpdate(v4)
	inventory.OnUpdate(v6)
	inventory.ListDone(context.Background())
	requireValidWorkloads(t, sink, 1)

	changed := *v6
	changed.ZtunnelMembershipGeneration++
	inventory.OnUpdate(&changed)
	if last(t, sink).Valid {
		t.Fatal("mixed membership generations across addresses remained publishable")
	}
}

func TestMissingMembershipVersionFailsClosed(t *testing.T) {
	inventory, sink := newTestInventory(t)
	pair := validPair("10.17.0.12", "pod-a", "ns-a", "api")
	pair.ZtunnelMembershipVersion = 0
	inventory.Begin(context.Background())
	inventory.OnUpdate(pair)
	inventory.ListDone(context.Background())
	if last(t, sink).Valid {
		t.Fatal("legacy workload record without membership version was accepted")
	}
}

// nativePair is a record as the ClusterMesh API server writes it from a
// CiliumEndpoint under CRD identity allocation (ciliumEndpointMapper): no
// namespace UID, node or ztunnel membership.
func nativePair(ip, podUID, sa string) *identity.IPIdentityPair {
	pair := validPair(ip, podUID, "", sa)
	pair.HostIP = net.ParseIP("172.18.0.5")
	pair.K8sNodeName = ""
	pair.ZtunnelMembershipVersion = 0
	pair.ZtunnelMembershipEpoch = ""
	pair.ZtunnelMembershipGeneration = 0
	pair.ZtunnelMembershipState = ""
	return pair
}

// A native record must not end the session: before this, the first CiliumEndpoint
// of the peer refused the whole list, so no remote workload was ever joined.
func TestNativeRecordWithoutMembershipIsOnlyAnIPWitness(t *testing.T) {
	inventory, sink := newTestInventory(t)
	inventory.Begin(context.Background())
	inventory.OnUpdate(nativePair("10.17.0.12", "pod-a", "api"))
	inventory.OnUpdate(nativePair("fd00:17::12", "pod-a", "api"))
	inventory.ListDone(context.Background())
	requireValidWorkloads(t, sink, 1)
	workload := last(t, sink).Workloads[0]
	if workload.Key != (WorkloadKey{ClusterID: 17, PodUID: "pod-a"}) || workload.NodeName != "" ||
		workload.MembershipState != unannotatedMembership || workload.MembershipEpoch != "" || workload.MembershipGeneration != 0 {
		t.Fatalf("native record gained membership it does not carry: %+v", workload)
	}
	if len(workload.Addresses) != 2 {
		t.Fatalf("native record addresses = %v", workload.Addresses)
	}
}

func TestPartialOrMixedMembershipStillFailsClosed(t *testing.T) {
	for name, change := range map[string]func(*identity.IPIdentityPair){
		"version without state":  func(p *identity.IPIdentityPair) { p.ZtunnelMembershipVersion = 1 },
		"epoch without version":  func(p *identity.IPIdentityPair) { p.ZtunnelMembershipEpoch = "agent-epoch-a" },
		"state without version":  func(p *identity.IPIdentityPair) { p.ZtunnelMembershipState = "captured" },
		"noncanonical namespace": func(p *identity.IPIdentityPair) { p.K8sNamespaceUID = " ns-a" },
		"noncanonical node name": func(p *identity.IPIdentityPair) { p.K8sNodeName = "node-a " },
		"unknown future version": func(p *identity.IPIdentityPair) { p.ZtunnelMembershipVersion = 2 },
	} {
		t.Run(name, func(t *testing.T) {
			inventory, sink := newTestInventory(t)
			pair := nativePair("10.17.0.12", "pod-a", "api")
			change(pair)
			inventory.Begin(context.Background())
			inventory.OnUpdate(pair)
			inventory.ListDone(context.Background())
			if last(t, sink).Valid {
				t.Fatalf("record was accepted: %+v", pair)
			}
		})
	}
	// One Pod cannot have one annotated and one native address.
	inventory, sink := newTestInventory(t)
	inventory.Begin(context.Background())
	inventory.OnUpdate(validPair("10.17.0.12", "pod-a", "ns-a", "api"))
	inventory.OnUpdate(nativePair("fd00:17::12", "pod-a", "api"))
	inventory.ListDone(context.Background())
	if last(t, sink).Valid {
		t.Fatal("a Pod with an annotated and a native address was accepted")
	}
}

func TestUnenrolledMembershipIsNotAnExportedWorkload(t *testing.T) {
	inventory, sink := newTestInventory(t)
	pair := validPair("10.17.0.12", "pod-a", "ns-a", "api")
	pair.ZtunnelMembershipEpoch = ""
	pair.ZtunnelMembershipGeneration = 0
	pair.ZtunnelMembershipState = "unenrolled"
	inventory.Begin(context.Background())
	inventory.OnUpdate(pair)
	inventory.ListDone(context.Background())
	requireValidWorkloads(t, sink, 0)
}

func requireValidWorkloads(t *testing.T, sink *recordingSink, want int) {
	t.Helper()
	got := last(t, sink)
	if !got.Valid || len(got.Workloads) != want {
		t.Fatalf("membership snapshot = valid:%t workloads:%d, want valid:%t workloads:%d (%s)", got.Valid, len(got.Workloads), true, want, got.Reason)
	}
}

func TestSemanticFailureWithdrawsSnapshotUntilFreshSession(t *testing.T) {
	inventory, sink := newTestInventory(t)
	inventory.Begin(context.Background())
	inventory.OnUpdate(validPair("10.17.0.12", "pod-a", "ns-a", "api"))
	inventory.ListDone(context.Background())
	if !last(t, sink).Valid {
		t.Fatal("valid initial list did not publish")
	}

	bad := validPair("10.17.0.13", "pod-b", "", "api")
	inventory.OnUpdate(bad)
	if got := last(t, sink); got.Valid || got.Reason == "" {
		t.Fatalf("semantic failure did not invalidate inventory: %+v", got)
	}
	count := len(sink.snapshots)
	inventory.ListDone(context.Background())
	if len(sink.snapshots) != count {
		t.Fatal("ListDone recovered an invalid session")
	}

	inventory.Begin(context.Background())
	inventory.OnUpdate(validPair("10.17.0.14", "pod-c", "ns-c", "api"))
	inventory.ListDone(context.Background())
	got := last(t, sink)
	if !got.Valid || len(got.Workloads) != 1 || got.Workloads[0].Key.PodUID != "pod-c" {
		t.Fatalf("fresh complete session did not recover with only current data: %+v", got)
	}
}

func TestAddressDeleteAndPodUIDReplacementPublishCompleteReplacement(t *testing.T) {
	inventory, sink := newTestInventory(t)
	old := validPair("10.17.0.12", "pod-old", "ns-old", "api")
	inventory.Begin(context.Background())
	inventory.OnUpdate(old)
	inventory.ListDone(context.Background())

	inventory.OnDelete(old)
	deleted := last(t, sink)
	if !deleted.Valid || len(deleted.Workloads) != 0 {
		t.Fatalf("delete did not replace the whole view: %+v", deleted)
	}

	newPod := validPair("10.17.0.12", "pod-new", "ns-new", "api")
	inventory.OnUpdate(newPod)
	replaced := last(t, sink)
	if !replaced.Valid || len(replaced.Workloads) != 1 {
		t.Fatalf("same-address replacement did not publish a full view: %+v", replaced)
	}
	if replaced.Workloads[0].Key.PodUID != "pod-new" || replaced.Workloads[0].Key.NamespaceUID != "ns-new" {
		t.Fatalf("old workload incarnation survived address reuse: %+v", replaced.Workloads)
	}
	if replaced.Generation <= deleted.Generation {
		t.Fatal("replacement generation is not monotonic")
	}
}

func TestInconsistentPodMetadataInvalidatesFullSnapshot(t *testing.T) {
	inventory, sink := newTestInventory(t)
	inventory.Begin(context.Background())
	inventory.OnUpdate(validPair("10.17.0.12", "pod-a", "ns-a", "api"))
	inventory.ListDone(context.Background())

	inventory.OnUpdate(validPair("fd00:17::12", "pod-a", "ns-a", "other-sa"))
	got := last(t, sink)
	if got.Valid || got.Reason == "" {
		t.Fatalf("contradictory ServiceAccount was not rejected: %+v", got)
	}
}

func TestPodUIDCannotBeReusedAcrossNamespaceIncarnations(t *testing.T) {
	inventory, sink := newTestInventory(t)
	inventory.Begin(context.Background())
	inventory.OnUpdate(validPair("10.17.0.12", "pod-same", "ns-a", "api"))
	inventory.OnUpdate(validPair("fd00:17::12", "pod-same", "ns-b", "api"))
	inventory.ListDone(context.Background())
	got := last(t, sink)
	if got.Valid || got.Reason == "" {
		t.Fatalf("reused Pod UID across namespace incarnations was accepted: %+v", got)
	}
}

func TestPeerCertificateIdentityChangeWithdrawsUntilNewList(t *testing.T) {
	sink := &recordingSink{}
	provider := &fakePeerEvidenceProvider{evidence: fakePeerEvidence{
		name: "cluster-beta", id: 17, identityEpoch: 1, spki: [32]byte{1}, profile: [32]byte{2},
		notAfter: time.Now().Add(time.Hour), heartbeat: time.Now(),
	}}
	clusterInfo := cmtypes.ClusterInfo{ID: 1, Name: "cluster-alpha", MaxConnectedClusters: 255}
	inventory, err := NewInventory("cluster-beta", 17, clusterInfo, provider, sink)
	if err != nil {
		t.Fatal(err)
	}
	inventory.Begin(context.Background())
	inventory.OnUpdate(validPair("10.17.0.12", "pod-a", "ns-a", "api"))
	inventory.ListDone(context.Background())
	if !last(t, sink).Valid {
		t.Fatal("valid pinned peer did not publish its initial snapshot")
	}

	provider.evidence = fakePeerEvidence{
		name: "cluster-beta", id: 17, identityEpoch: 2, spki: [32]byte{3}, profile: [32]byte{2},
		notAfter: time.Now().Add(time.Hour), heartbeat: time.Now(),
	}
	inventory.OnUpdate(validPair("10.17.0.13", "pod-b", "ns-b", "api"))
	if got := last(t, sink); got.Valid {
		t.Fatalf("peer certificate transition retained the old snapshot: %+v", got)
	}

	inventory.Begin(context.Background())
	inventory.OnUpdate(validPair("10.17.0.13", "pod-b", "ns-b", "api"))
	inventory.ListDone(context.Background())
	if got := last(t, sink); !got.Valid || len(got.Workloads) != 1 || got.Workloads[0].Key.PodUID != "pod-b" {
		t.Fatalf("fresh full list did not recover after peer identity transition: %+v", got)
	}
}

func TestNonWorkloadIdentityDoesNotEnterWorkloadSnapshot(t *testing.T) {
	inventory, sink := newTestInventory(t)
	inventory.Begin(context.Background())
	inventory.OnUpdate(&identity.IPIdentityPair{IP: net.ParseIP("10.17.0.1"), ID: identity.ReservedIdentityRemoteNode})
	inventory.ListDone(context.Background())
	got := last(t, sink)
	if !got.Valid || len(got.Workloads) != 0 {
		t.Fatalf("non-workload entry was not ignored: %+v", got)
	}
}

func TestPartialWorkloadMetadataNeverPublishes(t *testing.T) {
	tests := []struct {
		name string
		pair *identity.IPIdentityPair
	}{
		{
			name: "namespace UID without Pod metadata",
			pair: &identity.IPIdentityPair{
				IP:              net.ParseIP("10.17.0.12"),
				K8sNamespaceUID: "ns-a",
			},
		},
		{
			name: "legacy workload record without namespace UID",
			pair: validPair("10.17.0.12", "pod-a", "", "api"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inventory, sink := newTestInventory(t)
			inventory.Begin(context.Background())
			inventory.OnUpdate(tt.pair)
			inventory.ListDone(context.Background())
			if got := last(t, sink); got.Valid {
				t.Fatalf("partial workload metadata was published: %+v", got)
			}
		})
	}
}

func TestRejectsNonUnicastWorkloadAddresses(t *testing.T) {
	for _, address := range []string{"0.0.0.0", "127.0.0.1", "169.254.1.2", "224.0.0.1", "::", "::1", "fe80::1", "ff02::1"} {
		t.Run(address, func(t *testing.T) {
			inventory, sink := newTestInventory(t)
			inventory.Begin(context.Background())
			inventory.OnUpdate(validPair(address, "pod-a", "ns-a", "api"))
			inventory.ListDone(context.Background())
			if got := last(t, sink); got.Valid {
				t.Fatalf("non-unicast address %q was published: %+v", address, got)
			}
		})
	}
}

func TestWorkloadAddressCanBecomeNonWorkloadWithoutStaleSnapshot(t *testing.T) {
	inventory, sink := newTestInventory(t)
	workload := validPair("10.17.0.12", "pod-a", "ns-a", "api")
	inventory.Begin(context.Background())
	inventory.OnUpdate(workload)
	inventory.ListDone(context.Background())
	if !last(t, sink).Valid || len(last(t, sink).Workloads) != 1 {
		t.Fatal("initial workload record was not published")
	}

	// A later host/service identity at the same IP no longer describes a pod.
	inventory.OnUpdate(&identity.IPIdentityPair{
		IP: net.ParseIP("10.17.0.12"),
		ID: identity.ReservedIdentityRemoteNode,
	})
	got := last(t, sink)
	if !got.Valid || len(got.Workloads) != 0 {
		t.Fatalf("non-workload replacement retained stale workload: %+v", got)
	}
}

func TestDeleteWithInvalidKeyFailsClosed(t *testing.T) {
	tests := []struct {
		name string
		ip   net.IP
	}{
		{name: "empty IP", ip: net.IP{}},
		{name: "malformed IP length", ip: net.IP{10, 17, 0}},
		{name: "oversized IP", ip: net.IP{10, 17, 0, 12, 1}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inventory, sink := newTestInventory(t)
			inventory.Begin(context.Background())
			inventory.OnUpdate(validPair("10.17.0.12", "pod-a", "ns-a", "api"))
			inventory.ListDone(context.Background())
			if got := last(t, sink); !got.Valid || len(got.Workloads) != 1 {
				t.Fatalf("test precondition: valid workload was not published: %+v", got)
			}

			deleteKey := validPair("10.17.0.12", "pod-a", "ns-a", "api")
			deleteKey.IP = tt.ip
			inventory.OnDelete(store.NamedKey(deleteKey))
			got := last(t, sink)
			if got.Valid || got.Reason == "" || inventory.Ready() || inventory.NumEntries() != 0 {
				t.Fatalf("invalid delete did not withdraw and invalidate inventory: snapshot=%+v ready=%t entries=%d",
					got, inventory.Ready(), inventory.NumEntries())
			}

			// Ordinary events cannot repair a session whose delete key could not
			// be mapped to the inventory's canonical address. Recovery requires
			// a fresh complete watch list.
			snapshotCount := len(sink.snapshots)
			inventory.OnUpdate(validPair("10.17.0.13", "pod-b", "ns-b", "api"))
			inventory.ListDone(context.Background())
			if len(sink.snapshots) != snapshotCount || inventory.Ready() {
				t.Fatal("invalid session recovered without a fresh watch session")
			}

			inventory.Begin(context.Background())
			inventory.OnUpdate(validPair("10.17.0.14", "pod-c", "ns-c", "api"))
			inventory.ListDone(context.Background())
			got = last(t, sink)
			if !got.Valid || len(got.Workloads) != 1 || got.Workloads[0].Key.PodUID != "pod-c" {
				t.Fatalf("fresh complete watch list did not recover inventory: %+v", got)
			}
		})
	}
}

func TestConstructorRejectsMissingAuthenticatedClusterProfile(t *testing.T) {
	sink := &recordingSink{}
	clusterInfo := cmtypes.ClusterInfo{ID: 1, Name: "cluster-alpha", MaxConnectedClusters: 255}
	peer := fakePeerEvidence{name: "cluster-beta", id: 17, identityEpoch: 1, spki: [32]byte{1}, profile: [32]byte{2}, notAfter: time.Now().Add(time.Hour), heartbeat: time.Now()}
	provider := &fakePeerEvidenceProvider{evidence: peer}
	if _, err := NewInventory("cluster-beta", 0, clusterInfo, provider, sink); err == nil {
		t.Fatal("zero/unset cluster ID accepted")
	}
	if _, err := NewInventory("cluster-beta", 17, clusterInfo, provider, nil); err == nil {
		t.Fatal("nil snapshot sink accepted")
	}
}

func TestWrongClusterIdentityRangeInvalidates(t *testing.T) {
	inventory, sink := newTestInventory(t)
	wrong := validPair("10.17.0.12", "pod-a", "ns-a", "api")
	wrong.ID = identity.NumericIdentity(123)
	inventory.Begin(context.Background())
	inventory.OnUpdate(wrong)
	inventory.ListDone(context.Background())
	if got := last(t, sink); got.Valid {
		t.Fatal("identity from another cluster range was accepted")
	}
}

func TestDeleteUsesCanonicalUnmappedAddress(t *testing.T) {
	inventory, sink := newTestInventory(t)
	pair := validPair("10.17.0.12", "pod-a", "ns-a", "api")
	inventory.Begin(context.Background())
	inventory.OnUpdate(pair)
	inventory.ListDone(context.Background())
	pair.IP = net.ParseIP("::ffff:10.17.0.12")
	inventory.OnDelete(pair)
	got := last(t, sink)
	if !got.Valid || len(got.Workloads) != 0 {
		t.Fatalf("mapped IPv4 deletion left stale address: %+v", got)
	}
}

func TestPodIdentityAndNodeMustAgreeAcrossAddresses(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*identity.IPIdentityPair)
	}{
		{
			name: "different Cilium identity",
			mutate: func(pair *identity.IPIdentityPair) {
				pair.ID++
			},
		},
		{
			name: "different source node",
			mutate: func(pair *identity.IPIdentityPair) {
				pair.K8sNodeName = "node-b"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inventory, sink := newTestInventory(t)
			inventory.Begin(context.Background())
			inventory.OnUpdate(validPair("10.17.0.12", "pod-a", "ns-a", "api"))
			other := validPair("fd00:17::12", "pod-a", "ns-a", "api")
			tt.mutate(other)
			inventory.OnUpdate(other)
			inventory.ListDone(context.Background())
			if got := last(t, sink); got.Valid || got.Reason == "" {
				t.Fatalf("conflicting address identity was not rejected: %+v", got)
			}
		})
	}
}

func TestWorkloadRecordRequiresSourceNode(t *testing.T) {
	inventory, sink := newTestInventory(t)
	pair := validPair("10.17.0.12", "pod-a", "ns-a", "api")
	pair.K8sNodeName = ""
	inventory.Begin(context.Background())
	inventory.OnUpdate(pair)
	inventory.ListDone(context.Background())
	if got := last(t, sink); got.Valid || got.Reason == "" {
		t.Fatalf("workload without a source node was not rejected: %+v", got)
	}
}

func TestValidUnicastAddressHelper(t *testing.T) {
	if !netip.MustParseAddr("10.17.0.12").IsGlobalUnicast() {
		t.Fatal("private IPv4 should be accepted as a unicast Pod address")
	}
}
