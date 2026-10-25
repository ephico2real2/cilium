// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package remote_workload

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/ztunnel/membership"
)

func newLocalJoinerTest(t *testing.T) (*SourceMembershipJoiner, *recordingSink, *time.Time) {
	t.Helper()
	sink := &recordingSink{}
	now := time.Now()
	joiner, err := NewLocalSourceMembershipJoiner("cluster-beta", 17, "node-a", newTestLogger(t), sink)
	if err != nil {
		t.Fatal(err)
	}
	joiner.now = func() time.Time { return now }
	return joiner, sink, &now
}

// nodeSourceRecord is a valid record of node with one workload.
func nodeSourceRecord(node, podUID, address string, generation uint64) membership.SourceMembershipRecord {
	record := validSourceMembershipRecord(generation)
	record.NodeName, record.AgentEpoch = node, "agent-epoch-"+node
	w := &record.Workloads[0]
	w.NodeName, w.MembershipEpoch, w.PodUID, w.Addresses = node, record.AgentEpoch, podUID, []string{address}
	return record
}

func TestLocalJoinerPublishesOtherNodesWorkloadsOnly(t *testing.T) {
	j, sink, now := newLocalJoinerTest(t)
	other := nodeSourceRecord("node-b", "pod-b", "10.17.1.12", 1)
	other.Workloads[0].EgressPolicy = testEgressPolicy()
	j.Begin(context.Background())
	j.OnUpdate(sourceKey(nodeSourceRecord("node-a", "pod-a", "10.17.0.12", 1)))
	j.OnUpdate(sourceKey(other))
	if latestJoined(t, sink).Valid || j.Ready() {
		t.Fatal("local view became usable before its list completed")
	}
	j.ListDone(context.Background())
	got := latestJoined(t, sink)
	if !got.Valid || !j.Ready() || len(got.Workloads) != 1 {
		t.Fatalf("other node's workload was not published alone: %+v", got)
	}
	w := got.Workloads[0]
	if w.Key != (WorkloadKey{ClusterID: 17, NamespaceUID: "ns-a", PodUID: "pod-b"}) || w.NodeName != "node-b" ||
		w.MembershipState != "captured" || w.MembershipEpoch != "agent-epoch-node-b" || w.MembershipGeneration != 2 ||
		w.EndpointID != 42 || len(w.Addresses) != 1 || w.Addresses[0] != netip.MustParseAddr("10.17.1.12") {
		t.Fatalf("workload does not carry its lease: %+v", w)
	}
	if w.EgressPolicy == nil || w.EgressPolicy.Digest != other.Workloads[0].EgressPolicy.Digest {
		t.Fatal("egress policy was not carried")
	}
	if want := now.Add(30 * time.Second); !got.SourceMembershipLeaseValidUntil.Equal(want) {
		t.Fatalf("lease deadline %s, want the other node's %s", got.SourceMembershipLeaseValidUntil, want)
	}
}

func TestLocalJoinerExpiresAWriterThatStopsRefreshing(t *testing.T) {
	j, sink, now := newLocalJoinerTest(t)
	j.Begin(context.Background())
	j.OnUpdate(sourceKey(nodeSourceRecord("node-b", "pod-b", "10.17.1.12", 1)))
	j.ListDone(context.Background())
	*now = now.Add(31 * time.Second)
	j.Expire(*now)
	if got := latestJoined(t, sink); !got.Valid || len(got.Workloads) != 0 {
		t.Fatalf("expired lease still publishes its workload: %+v", got)
	}
}

func TestLocalJoinerKeepsTheRemoteFloors(t *testing.T) {
	j, sink, _ := newLocalJoinerTest(t)
	j.Begin(context.Background())
	j.OnUpdate(sourceKey(nodeSourceRecord("node-b", "pod-b", "10.17.1.12", 2)))
	j.ListDone(context.Background())
	j.OnUpdate(sourceKey(nodeSourceRecord("node-b", "pod-b", "10.17.1.12", 1)))
	if got := latestJoined(t, sink); got.Valid {
		t.Fatalf("generation rollback was accepted: %+v", got)
	}
}

func TestLocalJoinerRefusesOnePodOnTwoNodes(t *testing.T) {
	j, sink, _ := newLocalJoinerTest(t)
	j.Begin(context.Background())
	j.OnUpdate(sourceKey(nodeSourceRecord("node-b", "pod-b", "10.17.1.12", 1)))
	j.OnUpdate(sourceKey(nodeSourceRecord("node-c", "pod-b", "10.17.2.12", 1)))
	j.ListDone(context.Background())
	if got := latestJoined(t, sink); got.Valid {
		t.Fatalf("one Pod UID leased by two nodes was accepted: %+v", got)
	}
}

func TestLocalJoinerHasNoIPIdentityInput(t *testing.T) {
	j, sink, _ := newLocalJoinerTest(t)
	j.Begin(context.Background())
	j.ListDone(context.Background())
	if got := latestJoined(t, sink); !got.Valid || len(got.Workloads) != 0 {
		t.Fatalf("an empty complete list is not a valid empty view: %+v", got)
	}
	j.PublishRemoteWorkloadSnapshot(validIPSnapshotAt(j.now()))
	if got := latestJoined(t, sink); got.Valid {
		t.Fatal("an IP identity snapshot was accepted by a local joiner")
	}
	if _, err := NewLocalSourceMembershipJoiner("cluster-beta", 17, "", newTestLogger(t), &recordingSink{}); err == nil {
		t.Fatal("local joiner without a node name was accepted")
	}
}

type endingWatchStore struct{ ended chan struct{} }

func (s *endingWatchStore) Watch(ctx context.Context, _ store.WatchStoreBackend, _ string) {
	select {
	case <-ctx.Done():
	case <-s.ended:
	}
}
func (*endingWatchStore) NumEntries() uint64 { return 0 }
func (*endingWatchStore) Synced() bool       { return false }
func (*endingWatchStore) Drain()             {}

type noBackend struct{}

func (noBackend) ListAndWatch(context.Context, string, ...kvstore.ListAndWatchOption) kvstore.EventChan {
	return nil
}

func TestLocalSourceWatchReturnsWhenItsWatchEnds(t *testing.T) {
	j, _, _ := newLocalJoinerTest(t)
	ended := make(chan struct{})
	close(ended)
	if err := runLocalSourceMembershipWatch(context.Background(), noBackend{}, &endingWatchStore{ended: ended}, j); err == nil {
		t.Fatal("a watch that ended on its own was reported as cancellation")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runLocalSourceMembershipWatch(ctx, noBackend{}, &endingWatchStore{ended: make(chan struct{})}, j); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled watch returned %v", err)
	}
	remote, _, _ := newSourceJoinerTest(t)
	if err := runLocalSourceMembershipWatch(context.Background(), noBackend{}, &endingWatchStore{ended: ended}, remote); err == nil {
		t.Fatal("a remote joiner was accepted by the local watch")
	}
}
