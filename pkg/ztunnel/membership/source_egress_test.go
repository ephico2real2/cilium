// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package membership

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/policy"
)

// emptyNativePolicy returns a decoded native snapshot with no entries, built
// from the v1 wire layout, so the test needs no endpoint policy machinery.
func emptyNativePolicy(t *testing.T, owner cmtypes.ClusterInfo) *policy.ZtunnelL4Snapshot {
	t.Helper()
	wire := []byte("CL4SNAP1")
	wire = binary.BigEndian.AppendUint32(wire, owner.ID)
	wire = binary.BigEndian.AppendUint32(wire, owner.MaxConnectedClusters)
	wire = append(wire, byte(len(owner.Name)))
	wire = append(wire, owner.Name...)
	wire = binary.BigEndian.AppendUint64(wire, 7)
	wire = binary.BigEndian.AppendUint64(wire, 3)
	wire = binary.BigEndian.AppendUint32(wire, 0)
	digest := sha256.Sum256(wire)
	wire = append(wire, digest[:]...)
	snapshot, err := policy.DecodeNativeZtunnelL4(hivetest.Logger(t), policy.NativeZtunnelL4Expectation{
		Owner: owner, PolicyRevision: 7, SelectorRevision: 3, Digest: hex.EncodeToString(digest[:])}, wire)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func testReleaseCandidate(t *testing.T, snapshot sourceEndpointSnapshot) endpoint.ZtunnelReleaseCandidate {
	t.Helper()
	addresses := make([]netip.Addr, 0, len(snapshot.Addresses))
	for i := len(snapshot.Addresses) - 1; i >= 0; i-- {
		addresses = append(addresses, netip.MustParseAddr(snapshot.Addresses[i]))
	}
	return endpoint.ZtunnelReleaseCandidate{HasMembership: true, Membership: snapshot.Membership,
		Subject: policy.ZtunnelPolicySubject{EndpointID: snapshot.EndpointID, Namespace: snapshot.Namespace,
			NamespaceUID: snapshot.NamespaceUID, PodUID: snapshot.PodUID, ServiceAccount: snapshot.ServiceAccount,
			NumericIdentity: snapshot.Identity, Addresses: addresses,
			Policy: emptyNativePolicy(t, cmtypes.ClusterInfo{ID: 1, Name: "cluster-alpha", MaxConnectedClusters: 255})}}
}

func TestSourceEgressPolicyIsBoundToThePublishedIncarnation(t *testing.T) {
	_, _, endpoints, _ := newSourcePublisherTest(t)
	snapshot := endpoints.snapshot
	exported, err := sourceEgressPolicy(testReleaseCandidate(t, snapshot), snapshot)
	if err != nil {
		t.Fatalf("matching release candidate refused: %v", err)
	}
	if exported.Version != SourceEgressPolicyVersion || exported.PolicyRevision != 7 || exported.SelectorRevision != 3 {
		t.Fatalf("envelope does not carry the realized revisions: %+v", exported)
	}
	owner := cmtypes.ClusterInfo{ID: 1, Name: "cluster-alpha", MaxConnectedClusters: 255}
	if _, err := policy.DecodeNativeZtunnelL4(hivetest.Logger(t), policy.NativeZtunnelL4Expectation{Owner: owner,
		PolicyRevision: exported.PolicyRevision, SelectorRevision: exported.SelectorRevision, Digest: exported.Digest}, exported.Wire); err != nil {
		t.Fatalf("published egress policy does not decode for its owner: %v", err)
	}

	for name, mutate := range map[string]func(*endpoint.ZtunnelReleaseCandidate){
		"no membership":   func(r *endpoint.ZtunnelReleaseCandidate) { r.HasMembership = false },
		"zds generation":  func(r *endpoint.ZtunnelReleaseCandidate) { r.Membership.Generation++ },
		"endpoint":        func(r *endpoint.ZtunnelReleaseCandidate) { r.Subject.EndpointID++ },
		"namespace uid":   func(r *endpoint.ZtunnelReleaseCandidate) { r.Subject.NamespaceUID = "recreated" },
		"pod uid":         func(r *endpoint.ZtunnelReleaseCandidate) { r.Subject.PodUID = "replacement" },
		"service account": func(r *endpoint.ZtunnelReleaseCandidate) { r.Subject.ServiceAccount = "other" },
		"identity":        func(r *endpoint.ZtunnelReleaseCandidate) { r.Subject.NumericIdentity++ },
		"address": func(r *endpoint.ZtunnelReleaseCandidate) {
			r.Subject.Addresses = r.Subject.Addresses[:1]
		},
	} {
		release := testReleaseCandidate(t, snapshot)
		mutate(&release)
		if exported, err := sourceEgressPolicy(release, snapshot); err == nil || exported != nil {
			t.Fatalf("%s: egress policy of another incarnation was exported", name)
		}
	}
}

func validTestEgressPolicy(size int) *SourceEgressPolicy {
	body := make([]byte, size-sha256.Size)
	sum := sha256.Sum256(body)
	return &SourceEgressPolicy{Version: SourceEgressPolicyVersion, PolicyRevision: 7, SelectorRevision: 3,
		Digest: hex.EncodeToString(sum[:]), Wire: append(body, sum[:]...)}
}

func TestSourceEgressPolicyValidateRefusesMalformedEnvelopes(t *testing.T) {
	if err := validTestEgressPolicy(70).Validate(); err != nil {
		t.Fatalf("valid envelope refused: %v", err)
	}
	if err := validTestEgressPolicy(policy.MaxNativeZtunnelL4WireBytes).Validate(); err != nil {
		t.Fatalf("envelope at the wire bound refused: %v", err)
	}
	for name, mutate := range map[string]func(*SourceEgressPolicy){
		"version":           func(p *SourceEgressPolicy) { p.Version = 2 },
		"policy revision":   func(p *SourceEgressPolicy) { p.PolicyRevision = 0 },
		"selector revision": func(p *SourceEgressPolicy) { p.SelectorRevision = 0 },
		"no wire":           func(p *SourceEgressPolicy) { p.Wire = nil },
		"digest only":       func(p *SourceEgressPolicy) { p.Wire = p.Wire[len(p.Wire)-sha256.Size:] },
		"oversized":         func(p *SourceEgressPolicy) { *p = *validTestEgressPolicy(policy.MaxNativeZtunnelL4WireBytes + 1) },
		"digest":            func(p *SourceEgressPolicy) { p.Digest = strings.Repeat("0", 64) },
		"digest case":       func(p *SourceEgressPolicy) { p.Digest = strings.ToUpper(p.Digest) },
		"wire":              func(p *SourceEgressPolicy) { p.Wire[len(p.Wire)-1] ^= 1 },
	} {
		envelope := validTestEgressPolicy(70)
		mutate(envelope)
		if err := envelope.Validate(); err == nil {
			t.Fatalf("%s: malformed envelope accepted", name)
		}
	}
	if err := (*SourceEgressPolicy)(nil).Validate(); err == nil {
		t.Fatal("nil envelope accepted")
	}
}

func TestSourcePublisherPublishesRealizedEgressPolicy(t *testing.T) {
	publisher, backend, endpoints, _ := newSourcePublisherTest(t)
	endpoints.egress = validTestEgressPolicy(70)
	if err := publisher.refresh(context.Background(), lockSourceTestBackend(t, backend)); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	record := readSourceRecord(t, backend, publisher.key)
	if !record.Valid || len(record.Workloads) != 1 || record.Workloads[0].EgressPolicy == nil {
		t.Fatalf("realized egress policy was not published: %+v", record)
	}
	if err := record.Workloads[0].EgressPolicy.Validate(); err != nil || record.Workloads[0].EgressPolicy.Digest != endpoints.egress.Digest {
		t.Fatalf("published egress policy did not survive the record encoding: %v", err)
	}
}

// A regeneration that outlasts the wait leaves the workload a destination
// only; it does not delay the record by more than the wait or withdraw it.
func TestSourcePublisherBoundsTheWaitForAPendingRegeneration(t *testing.T) {
	publisher, backend, endpoints, ref := newSourcePublisherTest(t)
	endpoints.egressPending = true
	locker := lockSourceTestBackend(t, backend)
	started := time.Now()
	if err := publisher.refresh(context.Background(), locker); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if elapsed := time.Since(started); elapsed < sourcePolicyRealizationWait || elapsed > sourcePolicyRealizationWait+time.Second {
		t.Fatalf("refresh took %s, want about %s", elapsed, sourcePolicyRealizationWait)
	}
	record := readSourceRecord(t, backend, publisher.key)
	if !record.Valid || len(record.Workloads) != 1 || record.Workloads[0].EgressPolicy != nil {
		t.Fatalf("workload with a pending regeneration was not published as a destination only: %+v", record)
	}
	if publisher.egressAbsent[ref] == "" {
		t.Fatal("the reason the egress policy is absent was not recorded")
	}

	endpoints.egressPending, endpoints.egress = false, validTestEgressPolicy(70)
	if err := publisher.refresh(context.Background(), locker); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if record := readSourceRecord(t, backend, publisher.key); record.Workloads[0].EgressPolicy == nil {
		t.Fatal("egress policy realized later was not published")
	}
	if len(publisher.egressAbsent) != 0 {
		t.Fatalf("recovered workload still recorded as absent: %v", publisher.egressAbsent)
	}
}

func TestSourcePublisherWithdrawsARecordOverTheReaderBound(t *testing.T) {
	publisher, backend, endpoints, _ := newSourcePublisherTest(t)
	endpoints.egress = validTestEgressPolicy(MaxSourceMembershipRecordBytes)
	if err := publisher.refresh(context.Background(), lockSourceTestBackend(t, backend)); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	record := readSourceRecord(t, backend, publisher.key)
	if record.Valid || len(record.Workloads) != 0 || record.Reason != "record_too_large" {
		t.Fatalf("record over the reader bound was not withdrawn: %+v", record)
	}
}

// Every field at the largest value the reader accepts or Kubernetes issues,
// and eight full egress policies, still fit the reader bound.
func TestSourceMembershipRecordWorstCaseFitsReaderBound(t *testing.T) {
	label := strings.Repeat("a", 63)
	subdomain := strings.Join([]string{label, label, label, strings.Repeat("a", 61)}, ".")
	uid := "ffffffff-ffff-4fff-bfff-ffffffffffff"
	epoch := strings.Repeat("e", 128)
	record := SourceMembershipRecord{Version: 1, ClusterName: strings.Repeat("c", 32), ClusterID: 511,
		NodeName: subdomain, AgentEpoch: epoch, Generation: ^uint64(0), RegistryRevision: ^uint64(0),
		LeaseTTLSeconds: 60, IssuedAt: time.Date(2026, 12, 31, 23, 59, 59, 999999999, time.UTC), Valid: true}
	for range DefaultSourceMaxWorkloads {
		record.Workloads = append(record.Workloads, SourceMembershipEntry{
			EndpointID: ^uint16(0), EndpointIncarnation: ^uint64(0), Namespace: label, NamespaceUID: uid,
			PodName: subdomain, PodUID: uid, NodeName: subdomain, ServiceAccount: subdomain, Identity: ^uint32(0),
			Addresses:          []string{"255.255.255.255", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
			MembershipRevision: ^uint64(0), MembershipEpoch: epoch, ZDSGeneration: ^uint64(0),
			EgressPolicy: &SourceEgressPolicy{Version: SourceEgressPolicyVersion, PolicyRevision: ^uint64(0),
				SelectorRevision: ^uint64(0), Digest: strings.Repeat("f", 64), Wire: make([]byte, policy.MaxNativeZtunnelL4WireBytes)},
		})
	}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("worst-case record: %d bytes, bound %d, margin %d", len(data), MaxSourceMembershipRecordBytes, MaxSourceMembershipRecordBytes-len(data))
	if len(data) > MaxSourceMembershipRecordBytes {
		t.Fatalf("worst-case record is %d bytes, over the %d byte reader bound", len(data), MaxSourceMembershipRecordBytes)
	}
}
