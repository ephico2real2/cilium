// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package remote_workload

import (
	"errors"
	"net/netip"
	"testing"
)

type allowSnapshotAdmission struct{ err error }

func (a allowSnapshotAdmission) AuthorizeRemoteWorkloadSnapshot(Snapshot) error { return a.err }

type mutatingAdmission struct{}

func (mutatingAdmission) AuthorizeRemoteWorkloadSnapshot(snapshot Snapshot) error {
	snapshot.Workloads[0].Addresses[0] = netip.MustParseAddr("10.0.0.99")
	return nil
}

func TestGatedSnapshotSinkFailsClosedWithoutEnrollmentAndPolicy(t *testing.T) {
	mailbox := NewSnapshotMailbox()
	sink := GatedSnapshotSink{Mailbox: mailbox}
	sink.PublishRemoteWorkloadSnapshot(Snapshot{
		ClusterName: "cluster-beta", ClusterID: 17, Generation: 4,
		Valid: true, Workloads: []Workload{{Key: WorkloadKey{ClusterID: 17, NamespaceUID: "ns-uid", PodUID: "pod-uid"}}},
	})
	got, ok := mailbox.Latest()
	if !ok || got.Valid || got.Reason != "remote enrollment and policy generations are unavailable" || len(got.Workloads) != 0 {
		t.Fatalf("snapshot without enrollment/policy generations was not denied: %+v, exists=%v", got, ok)
	}
}

func TestGatedSnapshotSinkRequiresAdmissionAndWithdrawsOnDenial(t *testing.T) {
	mailbox := NewSnapshotMailbox()
	valid := Snapshot{
		ClusterName: "cluster-beta", ClusterID: 17, Generation: 7,
		EnrollmentGeneration: 3, PolicyGeneration: 2,
		Valid: true, Workloads: []Workload{{Key: WorkloadKey{ClusterID: 17, NamespaceUID: "ns-uid", PodUID: "pod-uid"}}},
	}

	GatedSnapshotSink{Mailbox: mailbox}.PublishRemoteWorkloadSnapshot(valid)
	got, _ := mailbox.Latest()
	if got.Valid || got.Reason == "" {
		t.Fatalf("missing admission provider must deny: %+v", got)
	}

	GatedSnapshotSink{Mailbox: mailbox, Admission: allowSnapshotAdmission{err: errors.New("namespace UID is not enrolled")}}.PublishRemoteWorkloadSnapshot(valid)
	got, _ = mailbox.Latest()
	if got.Valid || got.Reason != "remote workload admission denied: namespace UID is not enrolled" {
		t.Fatalf("admission rejection did not withdraw snapshot: %+v", got)
	}

	GatedSnapshotSink{Mailbox: mailbox, Admission: allowSnapshotAdmission{}}.PublishRemoteWorkloadSnapshot(valid)
	got, _ = mailbox.Latest()
	if !got.Valid || got.Generation != valid.Generation || len(got.Workloads) != 1 {
		t.Fatalf("explicit admission did not publish replacement snapshot: %+v", got)
	}
}

func TestSnapshotMailboxCoalescesCompleteReplacementsWithoutAliasing(t *testing.T) {
	mailbox := NewSnapshotMailbox()
	first := Snapshot{Generation: 1, Valid: true, Workloads: []Workload{{Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.1")}}}}
	mailbox.PublishRemoteWorkloadSnapshot(first)
	first.Workloads[0].Addresses[0] = netip.MustParseAddr("10.0.0.99")
	second := Snapshot{Generation: 2, Valid: false, Reason: "watch invalid"}
	mailbox.PublishRemoteWorkloadSnapshot(second)

	got, ok := mailbox.Latest()
	if !ok || got.Generation != 2 || got.Valid || got.Reason != "watch invalid" {
		t.Fatalf("mailbox did not retain latest full replacement: %+v", got)
	}

	waited, err := mailbox.Wait(t.Context())
	if err != nil || waited.Generation != 2 || waited.Valid {
		t.Fatalf("mailbox wait did not return coalesced latest snapshot: %+v, err=%v", waited, err)
	}
}

func TestAdmissionCannotMutatePublishedSnapshot(t *testing.T) {
	mailbox := NewSnapshotMailbox()
	snapshot := Snapshot{
		Generation: 1, EnrollmentGeneration: 2, PolicyGeneration: 3, Valid: true,
		Workloads: []Workload{{Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.1")}}},
	}
	GatedSnapshotSink{Mailbox: mailbox, Admission: mutatingAdmission{}}.PublishRemoteWorkloadSnapshot(snapshot)
	got, ok := mailbox.Latest()
	if !ok || !got.Valid || got.Workloads[0].Addresses[0] != netip.MustParseAddr("10.0.0.1") {
		t.Fatalf("admission provider mutated published state: %+v, exists=%v", got, ok)
	}
}
