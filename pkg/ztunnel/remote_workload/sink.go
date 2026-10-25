// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package remote_workload

import (
	"context"
	"net/netip"
	"sync/atomic"
)

// SnapshotAdmission must be an in-memory, bounded check. It must verify
// authoritative enrollment and policy state bound to each NamespaceUID and
// PodUID. It must never perform network I/O from a WatchStore callback.
type SnapshotAdmission interface {
	AuthorizeRemoteWorkloadSnapshot(Snapshot) error
}

// SnapshotMailbox retains only the latest immutable full-replacement snapshot.
// It is bounded to one item and PublishRemoteWorkloadSnapshot never blocks the
// ClusterMesh watcher. No current component consumes this mailbox into xDS.
type SnapshotMailbox struct {
	latest atomic.Pointer[Snapshot]
	notify chan struct{}
}

func NewSnapshotMailbox() *SnapshotMailbox {
	return &SnapshotMailbox{notify: make(chan struct{}, 1)}
}

func (m *SnapshotMailbox) PublishRemoteWorkloadSnapshot(snapshot Snapshot) {
	copy := cloneSnapshot(snapshot)
	m.latest.Store(&copy)
	select {
	case m.notify <- struct{}{}:
	default:
	}
}

// Latest returns a defensive copy of the most recently published snapshot.
func (m *SnapshotMailbox) Latest() (Snapshot, bool) {
	p := m.latest.Load()
	if p == nil {
		return Snapshot{}, false
	}
	return cloneSnapshot(*p), true
}

// Wait returns the current latest snapshot after a publication notification.
// Notifications may coalesce; each returned snapshot is a full replacement.
func (m *SnapshotMailbox) Wait(ctx context.Context) (Snapshot, error) {
	select {
	case <-ctx.Done():
		return Snapshot{}, ctx.Err()
	case <-m.notify:
	}
	p := m.latest.Load()
	if p == nil {
		return Snapshot{}, nil
	}
	return cloneSnapshot(*p), nil
}

func cloneSnapshot(snapshot Snapshot) Snapshot {
	copy := snapshot
	copy.Workloads = make([]Workload, len(snapshot.Workloads))
	for i := range snapshot.Workloads {
		copy.Workloads[i] = snapshot.Workloads[i]
		copy.Workloads[i].Addresses = append([]netip.Addr(nil), snapshot.Workloads[i].Addresses...)
	}
	return copy
}

// GatedSnapshotSink rejects valid discovery snapshots until both an
// authoritative enrollment/policy provider and a publisher exist. It always
// forwards invalidations so a future consumer can withdraw stale state.
type GatedSnapshotSink struct {
	Admission SnapshotAdmission
	Mailbox   *SnapshotMailbox
}

func (s GatedSnapshotSink) PublishRemoteWorkloadSnapshot(snapshot Snapshot) {
	if s.Mailbox == nil {
		return
	}
	if !snapshot.Valid {
		s.Mailbox.PublishRemoteWorkloadSnapshot(snapshot)
		return
	}
	if snapshot.EnrollmentGeneration == 0 || snapshot.PolicyGeneration == 0 {
		snapshot.Valid = false
		snapshot.Workloads = nil
		snapshot.Reason = "remote enrollment and policy generations are unavailable"
		s.Mailbox.PublishRemoteWorkloadSnapshot(snapshot)
		return
	}
	if s.Admission == nil {
		snapshot.Valid = false
		snapshot.Workloads = nil
		snapshot.Reason = "authoritative remote enrollment and policy admission is not configured"
		s.Mailbox.PublishRemoteWorkloadSnapshot(snapshot)
		return
	}
	if err := s.Admission.AuthorizeRemoteWorkloadSnapshot(cloneSnapshot(snapshot)); err != nil {
		snapshot.Valid = false
		snapshot.Workloads = nil
		snapshot.Reason = "remote workload admission denied: " + err.Error()
	}
	s.Mailbox.PublishRemoteWorkloadSnapshot(snapshot)
}
