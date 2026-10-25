// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package remote_workload

import (
	"reflect"

	"github.com/cilium/cilium/pkg/lock"
)

const (
	// MaxRemotePeers bounds the number of ClusterMesh peers retained.
	MaxRemotePeers = 16
	// MaxRemoteWorkloadsPerPeer bounds one peer's complete snapshot.
	MaxRemoteWorkloadsPerPeer = 4096
)

// PeerSnapshotStore keeps the latest raw discovery snapshot of every
// ClusterMesh peer separately, and broadcasts every change to all readers.
// A snapshot here is discovery state only, not an admission or policy grant:
// consumers apply their own authority before projecting workloads.
type PeerSnapshotStore struct {
	mu      lock.Mutex
	peers   map[string]PeerSnapshotView
	changed chan struct{}
}

// PeerSnapshotView is one peer's latest snapshot with its fence state.
type PeerSnapshotView struct {
	Snapshot Snapshot
	// Fence increases on every invalidation, also when a later valid snapshot
	// coalesces it. A reader that saw a lower fence missed or observed an
	// invalidation and must not carry its earlier view across it.
	Fence uint64
	// WriterEpoch is the receiver-owned observer incarnation. It is assigned
	// by NewWriter, never taken from the peer.
	WriterEpoch uint64
}

func NewPeerSnapshotStore() *PeerSnapshotStore {
	return &PeerSnapshotStore{peers: make(map[string]PeerSnapshotView), changed: make(chan struct{})}
}

type peerSnapshotWriter struct {
	store *PeerSnapshotStore
	name  string
	epoch uint64
}

func (w peerSnapshotWriter) PublishRemoteWorkloadSnapshot(snapshot Snapshot) {
	w.store.publish(w.name, w.epoch, snapshot)
}

// NewWriter returns the sink of a new observer for one peer. It is called
// once per observer incarnation. The previous observer's writer is retired:
// its later callbacks are ignored, and the peer is invalidated until the new
// observer publishes, so a fresh observer may restart its generations at one.
func (s *PeerSnapshotStore) NewWriter(name string) SnapshotSink {
	s.mu.Lock()
	defer s.mu.Unlock()
	view, exists := s.peers[name]
	if name == "" || (!exists && len(s.peers) >= MaxRemotePeers) {
		// Capacity or naming refusal invalidates every served peer instead of
		// silently dropping one peer's state.
		s.invalidateAllLocked("remote observer capacity exceeded or empty peer name")
		return peerSnapshotWriter{store: s, name: name}
	}
	view.WriterEpoch++
	view.Fence++
	view.Snapshot = Snapshot{ClusterName: name, Reason: "new remote workload observer"}
	s.peers[name] = view
	s.notifyLocked()
	return peerSnapshotWriter{store: s, name: name, epoch: view.WriterEpoch}
}

func (s *PeerSnapshotStore) publish(name string, epoch uint64, snapshot Snapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	view, ok := s.peers[name]
	if !ok || epoch == 0 || epoch != view.WriterEpoch {
		return // retired or refused observer
	}
	snapshot = cloneSnapshot(snapshot)
	if reflect.DeepEqual(view.Snapshot, snapshot) {
		return // an identical republish is neither a change nor a replay
	}
	switch {
	case snapshot.ClusterName != name || snapshot.ClusterID == 0:
		snapshot = invalidated(view.Snapshot, "remote snapshot does not name its observer's peer")
	case view.Snapshot.ClusterID != 0 && snapshot.ClusterID != view.Snapshot.ClusterID:
		snapshot = invalidated(view.Snapshot, "remote cluster ID changed within one observer")
	case view.Snapshot.ClusterID != 0 && snapshot.Generation <= view.Snapshot.Generation:
		snapshot = invalidated(view.Snapshot, "remote snapshot generation did not increase")
	case len(snapshot.Workloads) > MaxRemoteWorkloadsPerPeer:
		snapshot = invalidated(snapshot, "remote snapshot exceeds the workload bound")
	}
	if reflect.DeepEqual(view.Snapshot, snapshot) {
		return
	}
	if !snapshot.Valid {
		snapshot.Workloads = nil
		view.Fence++
	}
	view.Snapshot = snapshot
	s.peers[name] = view
	s.notifyLocked()
}

func invalidated(base Snapshot, reason string) Snapshot {
	out := cloneSnapshot(base)
	out.Valid = false
	out.Workloads = nil
	out.Reason = reason
	return out
}

func (s *PeerSnapshotStore) invalidateAllLocked(reason string) {
	for name, view := range s.peers {
		view.Fence++
		view.Snapshot = invalidated(view.Snapshot, reason)
		s.peers[name] = view
	}
	s.notifyLocked()
}

func (s *PeerSnapshotStore) notifyLocked() {
	close(s.changed)
	s.changed = make(chan struct{})
}

// View returns a copy of every peer's view and the channel that is closed on
// the next change, read atomically.
func (s *PeerSnapshotStore) View() (map[string]PeerSnapshotView, <-chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]PeerSnapshotView, len(s.peers))
	for name, view := range s.peers {
		view.Snapshot = cloneSnapshot(view.Snapshot)
		out[name] = view
	}
	return out, s.changed
}
