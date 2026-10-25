// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package remote_workload

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func storeSnapshot(name string, id uint32, generation uint64, valid bool) Snapshot {
	s := Snapshot{ClusterName: name, ClusterID: id, Generation: generation, SessionEpoch: 1, Valid: valid}
	if valid {
		s.Workloads = []Workload{{Key: WorkloadKey{ClusterID: id, NamespaceUID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
			PodUID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"}, Addresses: []netip.Addr{netip.MustParseAddr("10.2.0.10")}}}
	}
	return s
}

func closed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func TestPeerSnapshotStoreBroadcastsToEveryReaderAndSeparatesPeers(t *testing.T) {
	s := NewPeerSnapshotStore()
	a, b := s.NewWriter("cmtc-a"), s.NewWriter("cmtc-b")
	a.PublishRemoteWorkloadSnapshot(storeSnapshot("cmtc-a", 1, 1, true))
	b.PublishRemoteWorkloadSnapshot(storeSnapshot("cmtc-b", 2, 1, true))
	view, first := s.View()
	_, second := s.View()
	require.Len(t, view, 2)
	require.True(t, view["cmtc-a"].Snapshot.Valid)
	require.True(t, view["cmtc-b"].Snapshot.Valid)

	a.PublishRemoteWorkloadSnapshot(storeSnapshot("cmtc-a", 1, 2, true))
	require.True(t, closed(first), "first reader is notified")
	require.True(t, closed(second), "second reader is notified independently")

	// Views are copies: mutating one cannot change the store.
	view, _ = s.View()
	view["cmtc-a"].Snapshot.Workloads[0].Addresses[0] = netip.MustParseAddr("192.0.2.1")
	again, _ := s.View()
	require.Equal(t, netip.MustParseAddr("10.2.0.10"), again["cmtc-a"].Snapshot.Workloads[0].Addresses[0])
	require.Equal(t, uint64(1), again["cmtc-b"].Fence, "peers are fenced separately")
}

func TestPeerSnapshotStoreCoalescedInvalidationKeepsTheFence(t *testing.T) {
	s := NewPeerSnapshotStore()
	w := s.NewWriter("cmtc-b")
	w.PublishRemoteWorkloadSnapshot(storeSnapshot("cmtc-b", 2, 1, true))
	view, watch := s.View()
	baseline := view["cmtc-b"].Fence

	// Invalid then valid before any reader wakes up.
	w.PublishRemoteWorkloadSnapshot(storeSnapshot("cmtc-b", 2, 2, false))
	w.PublishRemoteWorkloadSnapshot(storeSnapshot("cmtc-b", 2, 3, true))
	require.True(t, closed(watch))
	view, _ = s.View()
	require.True(t, view["cmtc-b"].Snapshot.Valid)
	require.Greater(t, view["cmtc-b"].Fence, baseline, "the coalesced invalidation remains visible to a stream that saw the baseline")
}

func TestPeerSnapshotStoreRejectsReplayAndClusterChange(t *testing.T) {
	s := NewPeerSnapshotStore()
	w := s.NewWriter("cmtc-b")
	w.PublishRemoteWorkloadSnapshot(storeSnapshot("cmtc-b", 2, 5, true))
	w.PublishRemoteWorkloadSnapshot(storeSnapshot("cmtc-b", 2, 5, true))
	view, _ := s.View()
	require.True(t, view["cmtc-b"].Snapshot.Valid, "an identical republish is not a replay")

	w.PublishRemoteWorkloadSnapshot(storeSnapshot("cmtc-b", 2, 4, true))
	view, _ = s.View()
	require.False(t, view["cmtc-b"].Snapshot.Valid, "an older generation cannot restore or replace state")
	require.Empty(t, view["cmtc-b"].Snapshot.Workloads)

	w.PublishRemoteWorkloadSnapshot(storeSnapshot("cmtc-b", 2, 6, true))
	view, _ = s.View()
	require.True(t, view["cmtc-b"].Snapshot.Valid, "a later generation recovers")

	w.PublishRemoteWorkloadSnapshot(storeSnapshot("cmtc-b", 3, 7, true))
	view, _ = s.View()
	require.False(t, view["cmtc-b"].Snapshot.Valid, "a cluster ID change within one observer is refused")

	w.PublishRemoteWorkloadSnapshot(storeSnapshot("cmtc-c", 2, 8, true))
	view, _ = s.View()
	require.False(t, view["cmtc-b"].Snapshot.Valid, "a snapshot naming another peer is refused")
	require.NotContains(t, view, "cmtc-c")
}

func TestPeerSnapshotStoreRetiresReplacedObservers(t *testing.T) {
	s := NewPeerSnapshotStore()
	old := s.NewWriter("cmtc-b")
	old.PublishRemoteWorkloadSnapshot(storeSnapshot("cmtc-b", 2, 9, true))
	view, _ := s.View()
	fence := view["cmtc-b"].Fence

	fresh := s.NewWriter("cmtc-b")
	view, _ = s.View()
	require.False(t, view["cmtc-b"].Snapshot.Valid, "a new observer starts invalid")
	require.Greater(t, view["cmtc-b"].Fence, fence)
	require.Equal(t, uint64(2), view["cmtc-b"].WriterEpoch)

	fresh.PublishRemoteWorkloadSnapshot(storeSnapshot("cmtc-b", 2, 1, true))
	view, _ = s.View()
	require.True(t, view["cmtc-b"].Snapshot.Valid, "a fresh observer may restart its generations at one")

	old.PublishRemoteWorkloadSnapshot(storeSnapshot("cmtc-b", 2, 99, false))
	old.PublishRemoteWorkloadSnapshot(storeSnapshot("cmtc-b", 2, 100, true))
	view, _ = s.View()
	require.True(t, view["cmtc-b"].Snapshot.Valid)
	require.Equal(t, uint64(1), view["cmtc-b"].Snapshot.Generation, "a retired observer can neither invalidate nor replace the fresh one")
}

func TestPeerSnapshotStoreCapacityRefusalInvalidatesEveryPeer(t *testing.T) {
	s := NewPeerSnapshotStore()
	for i := range MaxRemotePeers {
		name := fmt.Sprintf("peer-%d", i)
		s.NewWriter(name).PublishRemoteWorkloadSnapshot(storeSnapshot(name, uint32(i+1), 1, true))
	}
	view, _ := s.View()
	for _, v := range view {
		require.True(t, v.Snapshot.Valid)
	}
	refused := s.NewWriter("one-too-many")
	refused.PublishRemoteWorkloadSnapshot(storeSnapshot("one-too-many", 99, 1, true))
	view, _ = s.View()
	require.Len(t, view, MaxRemotePeers)
	for name, v := range view {
		require.False(t, v.Snapshot.Valid, "%s must be invalidated rather than one peer being dropped silently", name)
	}

	empty := s.NewWriter("")
	empty.PublishRemoteWorkloadSnapshot(storeSnapshot("", 1, 1, true))
	view, _ = s.View()
	require.NotContains(t, view, "")
}

func TestPeerSnapshotStoreBoundsWorkloads(t *testing.T) {
	s := NewPeerSnapshotStore()
	w := s.NewWriter("cmtc-b")
	big := storeSnapshot("cmtc-b", 2, 1, true)
	big.Workloads = make([]Workload, MaxRemoteWorkloadsPerPeer+1)
	w.PublishRemoteWorkloadSnapshot(big)
	view, _ := s.View()
	require.False(t, view["cmtc-b"].Snapshot.Valid)
	require.Empty(t, view["cmtc-b"].Snapshot.Workloads)
}
