// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package remote_workload

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
)

type eventWatchBackend struct {
	events []kvstore.KeyValueEvent
}

func (b eventWatchBackend) ListAndWatch(ctx context.Context, _ string, _ ...kvstore.ListAndWatchOption) kvstore.EventChan {
	ch := make(chan kvstore.KeyValueEvent)
	go func() {
		defer close(ch)
		for _, event := range b.events {
			select {
			case ch <- event:
			case <-ctx.Done():
				return
			}
		}
	}()
	return ch
}

func workloadCreate(t *testing.T, prefix string, pair *identity.IPIdentityPair) kvstore.KeyValueEvent {
	t.Helper()
	value, err := json.Marshal(pair)
	if err != nil {
		t.Fatal(err)
	}
	return kvstore.KeyValueEvent{
		Typ:   kvstore.EventTypeCreate,
		Key:   kvstore.JoinKey(prefix, pair.IP.String()),
		Value: value,
	}
}

func TestInventoryThroughRestartableWatchStoreSessions(t *testing.T) {
	clusterInfo := cmtypes.ClusterInfo{ID: 1, Name: "cluster-alpha", MaxConnectedClusters: 255}
	sink := &recordingSink{}
	peer := fakePeerEvidence{name: "cluster-beta", id: 17, identityEpoch: 1, spki: [32]byte{1}, profile: [32]byte{2}, notAfter: time.Now().Add(time.Hour), heartbeat: time.Now()}
	inventory, err := NewInventory("cluster-beta", 17, clusterInfo, &fakePeerEvidenceProvider{evidence: peer}, sink)
	if err != nil {
		t.Fatal(err)
	}
	factory := store.NewFactory(slog.New(slog.NewTextHandler(testOutput{t}, nil)), store.MetricsProvider())
	watch := factory.NewWatchStore("cluster-beta", func() store.Key { return &identity.IPIdentityPair{} }, inventory, store.RWSWithSessionObserver(inventory))
	prefix := kvstore.JoinKey(ipcache.IPIdentitiesPath, ipcache.AddressSpace)

	initial := eventWatchBackend{events: []kvstore.KeyValueEvent{
		workloadCreate(t, prefix, validPair("10.17.0.12", "pod-a", "ns-a", "api")),
		workloadCreate(t, prefix, validPair("fd00:17::12", "pod-a", "ns-a", "api")),
		{Typ: kvstore.EventTypeListDone},
	}}
	watch.Watch(context.Background(), initial, prefix)
	if len(sink.snapshots) < 3 {
		t.Fatalf("watch session did not publish begin, complete-list, and end transitions: %+v", sink.snapshots)
	}
	var complete *Snapshot
	for i := range sink.snapshots {
		if sink.snapshots[i].Valid {
			complete = &sink.snapshots[i]
		}
	}
	if complete == nil || len(complete.Workloads) != 1 || len(complete.Workloads[0].Addresses) != 2 {
		t.Fatalf("watcher did not publish the complete dual-stack view: %+v", sink.snapshots)
	}
	if last(t, sink).Valid || inventory.Ready() {
		t.Fatal("watch end did not revoke the published snapshot")
	}

	countBeforeReconnect := len(sink.snapshots)
	reconnect := eventWatchBackend{events: []kvstore.KeyValueEvent{
		workloadCreate(t, prefix, validPair("10.17.0.13", "pod-b", "ns-b", "api")),
		{Typ: kvstore.EventTypeListDone},
	}}
	watch.Watch(context.Background(), reconnect, prefix)
	var recovered *Snapshot
	for i := countBeforeReconnect; i < len(sink.snapshots); i++ {
		if sink.snapshots[i].Valid {
			recovered = &sink.snapshots[i]
		}
	}
	if recovered == nil || len(recovered.Workloads) != 1 || recovered.Workloads[0].Key.PodUID != "pod-b" {
		t.Fatalf("fresh full list did not recover only current peer state: %+v", sink.snapshots[countBeforeReconnect:])
	}
	if last(t, sink).Valid || inventory.Ready() {
		t.Fatal("second watch end did not invalidate the snapshot")
	}
}

func TestWatchStoreDeletePublishesFullReplacementBeforeEnd(t *testing.T) {
	clusterInfo := cmtypes.ClusterInfo{ID: 1, Name: "cluster-alpha", MaxConnectedClusters: 255}
	sink := &recordingSink{}
	peer := fakePeerEvidence{name: "cluster-beta", id: 17, identityEpoch: 1, spki: [32]byte{1}, profile: [32]byte{2}, notAfter: time.Now().Add(time.Hour), heartbeat: time.Now()}
	inventory, err := NewInventory("cluster-beta", 17, clusterInfo, &fakePeerEvidenceProvider{evidence: peer}, sink)
	if err != nil {
		t.Fatal(err)
	}
	factory := store.NewFactory(slog.New(slog.NewTextHandler(testOutput{t}, nil)), store.MetricsProvider())
	watch := factory.NewWatchStore("cluster-beta", func() store.Key { return &identity.IPIdentityPair{} }, inventory, store.RWSWithSessionObserver(inventory))
	prefix := kvstore.JoinKey(ipcache.IPIdentitiesPath, ipcache.AddressSpace)
	pairA := validPair("10.17.0.12", "pod-a", "ns-a", "api")
	pairB := validPair("10.17.0.13", "pod-b", "ns-b", "api")

	deleteA := kvstore.KeyValueEvent{Typ: kvstore.EventTypeDelete, Key: kvstore.JoinKey(prefix, pairA.IP.String())}
	backend := eventWatchBackend{events: []kvstore.KeyValueEvent{
		workloadCreate(t, prefix, pairA),
		workloadCreate(t, prefix, pairB),
		{Typ: kvstore.EventTypeListDone},
		deleteA,
	}}
	watch.Watch(context.Background(), backend, prefix)

	var deleted *Snapshot
	for i := range sink.snapshots {
		if sink.snapshots[i].Valid && sink.snapshots[i].Generation > 1 && len(sink.snapshots[i].Workloads) == 1 {
			deleted = &sink.snapshots[i]
		}
	}
	if deleted == nil || deleted.Workloads[0].Key.PodUID != "pod-b" {
		t.Fatalf("delete did not publish the complete replacement before session end: %+v", sink.snapshots)
	}
	if last(t, sink).Valid {
		t.Fatal("watch end should withdraw the snapshot after the delete event")
	}
}

type testOutput struct{ t *testing.T }

func (w testOutput) Write(p []byte) (int, error) {
	w.t.Logf("watchstore: %s", string(p))
	return len(p), nil
}
