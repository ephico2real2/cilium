// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package remote_workload

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/ztunnel/membership"
)

func newSourceJoinerTest(t *testing.T) (*SourceMembershipJoiner, *recordingSink, *time.Time) {
	t.Helper()
	sink := &recordingSink{}
	now := time.Now()
	joiner, err := NewSourceMembershipJoiner("cluster-beta", 17, newTestLogger(t), sink)
	if err != nil {
		t.Fatal(err)
	}
	joiner.now = func() time.Time { return now }
	return joiner, sink, &now
}

func newTestLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.New(slog.NewTextHandler(testLogWriter{t}, nil))
}

type testLogWriter struct{ t *testing.T }

func (w testLogWriter) Write(p []byte) (int, error) {
	w.t.Log(string(p))
	return len(p), nil
}

func validSourceMembershipRecord(generation uint64) membership.SourceMembershipRecord {
	return membership.SourceMembershipRecord{
		Version: 1, ClusterName: "cluster-beta", ClusterID: 17, NodeName: "node-a",
		AgentEpoch: "agent-epoch-a", Generation: generation, RegistryRevision: 12,
		LeaseTTLSeconds: 30, IssuedAt: time.Time{}, Valid: true,
		Workloads: []membership.SourceMembershipEntry{{
			EndpointID: 42, EndpointIncarnation: 7,
			Namespace: "orders", NamespaceUID: "ns-a", PodName: "api", PodUID: "pod-a",
			NodeName: "node-a", ServiceAccount: "api", Identity: uint32(validPair("10.17.0.12", "pod-a", "ns-a", "api").ID),
			Addresses: []string{"10.17.0.12"}, MembershipRevision: 4,
			MembershipEpoch: "agent-epoch-a", ZDSGeneration: 2,
		}},
	}
}

func validIPSnapshotAt(now time.Time) Snapshot {
	return Snapshot{
		ClusterName: "cluster-beta", ClusterID: 17, Generation: 1, SessionEpoch: 1,
		PeerIdentityEpoch: 2, PeerCertificateNotAfter: now.Add(time.Hour), PeerHeartbeatAt: now,
		Valid: true, Workloads: []Workload{{
			Key:       WorkloadKey{ClusterID: 17, NamespaceUID: "ns-a", PodUID: "pod-a"},
			Namespace: "orders", NodeName: "node-a", PodName: "api", ServiceAccount: "api",
			Identity:        validPair("10.17.0.12", "pod-a", "ns-a", "api").ID,
			MembershipEpoch: "agent-epoch-a", MembershipGeneration: 2, MembershipState: "captured",
			Addresses: []netip.Addr{netip.MustParseAddr("10.17.0.12")},
		}},
	}
}

func sourceKey(record membership.SourceMembershipRecord) *SourceMembershipKey {
	return &SourceMembershipKey{NodeName: record.NodeName, Record: record}
}

func completeJoinerSession(j *SourceMembershipJoiner, record membership.SourceMembershipRecord) {
	j.Begin(context.Background())
	j.OnUpdate(sourceKey(record))
	j.ListDone(context.Background())
	j.PublishRemoteWorkloadSnapshot(validIPSnapshotAt(j.now()))
}

func latestJoined(t *testing.T, sink *recordingSink) Snapshot {
	t.Helper()
	return last(t, sink)
}

func TestSourceMembershipJoinWaitsForBothListsAndExactIdentity(t *testing.T) {
	j, sink, _ := newSourceJoinerTest(t)
	record := validSourceMembershipRecord(1)
	j.Begin(context.Background())
	j.OnUpdate(sourceKey(record))
	j.PublishRemoteWorkloadSnapshot(validIPSnapshotAt(j.now()))
	if latestJoined(t, sink).Valid {
		t.Fatal("IP snapshot became usable before source membership ListDone")
	}
	j.ListDone(context.Background())
	got := latestJoined(t, sink)
	if !got.Valid || len(got.Workloads) != 1 || got.SourceMembershipSessionEpoch == 0 || got.SourceMembershipLeaseValidUntil.IsZero() {
		t.Fatalf("exact joined source snapshot was not published: %+v", got)
	}
	if got.Workloads[0].Key != (WorkloadKey{ClusterID: 17, NamespaceUID: "ns-a", PodUID: "pod-a"}) {
		t.Fatalf("joined workload identity mismatch: %+v", got.Workloads[0])
	}

	changed := validIPSnapshotAt(j.now())
	changed.Workloads[0].ServiceAccount = "other"
	j.PublishRemoteWorkloadSnapshot(changed)
	got = latestJoined(t, sink)
	if !got.Valid || len(got.Workloads) != 0 {
		t.Fatalf("mismatched ServiceAccount was not excluded: %+v", got)
	}
}

func TestSourceMembershipDeleteAndReceiverDeadlineRemoveCachedIPWorkload(t *testing.T) {
	j, sink, now := newSourceJoinerTest(t)
	completeJoinerSession(j, validSourceMembershipRecord(1))
	if got := latestJoined(t, sink); !got.Valid || len(got.Workloads) != 1 {
		t.Fatalf("setup did not produce one joined workload: %+v", got)
	}
	j.OnDelete(&SourceMembershipKey{NodeName: "node-a"})
	got := latestJoined(t, sink)
	if got.Valid || len(got.Workloads) != 0 || !got.SourceMembershipLeaseValidUntil.IsZero() {
		t.Fatalf("source lease deletion left a cached workload usable: %+v", got)
	}

	completeJoinerSession(j, validSourceMembershipRecord(2))
	*now = now.Add(defaultReaderLeaseTTL + time.Second)
	j.Expire(*now)
	got = latestJoined(t, sink)
	if got.Valid || len(got.Workloads) != 0 {
		t.Fatalf("receiver-side lease expiry left a cached IPIdentity workload usable: %+v", got)
	}
}

func TestDeletedSourceGenerationCannotBeReplayedBesideAnotherLiveNode(t *testing.T) {
	j, sink, _ := newSourceJoinerTest(t)
	nodeA := validSourceMembershipRecord(1)
	nodeB := membership.SourceMembershipRecord{
		Version: 1, ClusterName: "cluster-beta", ClusterID: 17, NodeName: "node-b",
		AgentEpoch: "agent-epoch-b", Generation: 1, RegistryRevision: 13,
		LeaseTTLSeconds: 30, Valid: true, Workloads: []membership.SourceMembershipEntry{},
	}
	j.Begin(context.Background())
	j.OnUpdate(sourceKey(nodeA))
	j.OnUpdate(sourceKey(nodeB))
	j.PublishRemoteWorkloadSnapshot(validIPSnapshotAt(j.now()))
	j.ListDone(context.Background())
	if got := latestJoined(t, sink); !got.Valid || len(got.Workloads) != 1 {
		t.Fatalf("two-node setup failed: %+v", got)
	}
	j.OnDelete(&SourceMembershipKey{NodeName: "node-a"})
	if got := latestJoined(t, sink); !got.Valid || len(got.Workloads) != 0 {
		t.Fatalf("deleted node membership did not withdraw its workloads: %+v", got)
	}
	j.OnUpdate(sourceKey(nodeA))
	if latestJoined(t, sink).Valid {
		t.Fatal("deleted source generation was replayed into an otherwise live watch epoch")
	}
}

func TestSourceRegistryRevisionRollbackFailsClosed(t *testing.T) {
	j, sink, _ := newSourceJoinerTest(t)
	completeJoinerSession(j, validSourceMembershipRecord(2))
	rolledBack := validSourceMembershipRecord(3)
	rolledBack.RegistryRevision--
	j.OnUpdate(sourceKey(rolledBack))
	if latestJoined(t, sink).Valid {
		t.Fatal("new source generation with an older registry revision was accepted")
	}
}

func TestEmptySourceWatchCannotPublishUsableSnapshot(t *testing.T) {
	j, sink, _ := newSourceJoinerTest(t)
	j.Begin(context.Background())
	j.PublishRemoteWorkloadSnapshot(validIPSnapshotAt(j.now()))
	j.ListDone(context.Background())
	if latestJoined(t, sink).Valid || j.Ready() {
		t.Fatal("empty source membership list was treated as a live membership lease")
	}
}

func TestSourceReadyCallbackRunsOutsideJoinerLock(t *testing.T) {
	j, _, _ := newSourceJoinerTest(t)
	callbackDone := make(chan struct{})
	j.SetOnReady(func() {
		_ = j.Ready()
		close(callbackDone)
	})
	completeJoinerSession(j, validSourceMembershipRecord(1))
	select {
	case <-callbackDone:
	case <-time.After(time.Second):
		t.Fatal("source-ready callback deadlocked while reentering the joiner")
	}
}

type pairedWatchFactory struct {
	store.Factory
	started chan string
}

func (f *pairedWatchFactory) NewWatchStore(_ string, _ store.KeyCreator, observer store.Observer, _ ...store.RWSOpt) store.WatchStore {
	session, _ := observer.(store.WatchSessionObserver)
	return &pairedWatchStore{observer: session, started: f.started}
}

type pairedWatchStore struct {
	observer store.WatchSessionObserver
	started  chan string
}

func (s *pairedWatchStore) Watch(ctx context.Context, _ store.WatchStoreBackend, prefix string) {
	if s.observer != nil {
		s.observer.Begin(ctx)
	}
	s.started <- prefix
	<-ctx.Done()
	if s.observer != nil {
		s.observer.End(ctx)
	}
}

func (*pairedWatchStore) NumEntries() uint64 { return 0 }
func (*pairedWatchStore) Synced() bool       { return false }
func (*pairedWatchStore) Drain()             {}

func TestOriginWatchSessionUsesPairedDirectPrefixesAndRetainsJoinFloors(t *testing.T) {
	peer := fakePeerEvidence{name: "cluster-beta", id: 17, identityEpoch: 3, spki: [32]byte{1}, profile: [32]byte{2}, notAfter: time.Now().Add(time.Hour), heartbeat: time.Now()}
	provider := &fakePeerEvidenceProvider{evidence: peer}
	factory := &pairedWatchFactory{started: make(chan string, 4)}
	session := &IPIdentityOriginWatchSession{
		Factory: factory, ClusterInfo: cmtypes.ClusterInfo{ID: 1, Name: "cluster-alpha", MaxConnectedClusters: 255},
		Logger: slog.New(slog.DiscardHandler),
		Joiner: func() *SourceMembershipJoiner {
			j, _ := NewSourceMembershipJoiner("cluster-beta", 17, slog.New(slog.DiscardHandler), &recordingSink{})
			return j
		}(),
	}
	profile := validOriginProfile(1)
	connection := &OriginPeerConnection{Backend: &testOriginBackend{}, Evidence: provider, RemoteConfig: requiredRemoteClusterConfig(17), ProfileID: peer.ProfileID(), IdentityEpoch: peer.IdentityEpoch()}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- session.Run(ctx, profile, connection) }()

	want := map[string]bool{
		kvstore.JoinKey(ipcache.IPIdentitiesPath, ipcache.AddressSpace): true,
		kvstore.JoinKey(membership.SourceMembershipPrefix):              true,
	}
	for range 2 {
		select {
		case prefix := <-factory.started:
			if !want[prefix] {
				t.Fatalf("origin session watched unexpected prefix %q", prefix)
			}
			delete(want, prefix)
		case <-time.After(time.Second):
			t.Fatal("origin session did not start both direct-origin watches")
		}
	}
	if len(want) != 0 {
		t.Fatalf("origin session omitted direct watch prefixes: %v", want)
	}
	joiner := session.Joiner
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("origin session cancellation returned %v", err)
	}

	ctx, cancel = context.WithCancel(context.Background())
	go func() { result <- session.Run(ctx, profile, connection) }()
	for range 2 {
		select {
		case <-factory.started:
		case <-time.After(time.Second):
			cancel()
			t.Fatal("reconnected origin session did not start both watches")
		}
	}
	if session.Joiner != joiner {
		cancel()
		t.Fatal("origin session replaced its joiner and lost monotonic source floors on reconnect")
	}
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("reconnected origin session cancellation returned %v", err)
	}
}

func TestSourceLeaseReplayAcrossReconnectCannotExtendDeadline(t *testing.T) {
	j, sink, now := newSourceJoinerTest(t)
	record := validSourceMembershipRecord(1)
	completeJoinerSession(j, record)
	firstDeadline := latestJoined(t, sink).SourceMembershipLeaseValidUntil
	*now = now.Add(25 * time.Second)

	// The watch reconnects and relists the same bytes. The receiver reuses the
	// original monotonic deadline instead of treating the list as a new lease.
	j.Begin(context.Background())
	j.OnUpdate(sourceKey(record))
	j.ListDone(context.Background())
	j.PublishRemoteWorkloadSnapshot(validIPSnapshotAt(j.now()))
	got := latestJoined(t, sink)
	if !got.Valid || len(got.Workloads) != 1 || !got.SourceMembershipLeaseValidUntil.Equal(firstDeadline) {
		t.Fatalf("same-generation relist extended source lease: %+v, original deadline %s", got, firstDeadline)
	}

	*now = now.Add(6 * time.Second)
	j.Expire(*now)
	if got = latestJoined(t, sink); got.Valid || len(got.Workloads) != 0 {
		t.Fatalf("replayed source record survived its original receiver deadline: %+v", got)
	}
	// A second list of the same expired generation still cannot resurrect it.
	j.Begin(context.Background())
	j.OnUpdate(sourceKey(record))
	j.ListDone(context.Background())
	j.PublishRemoteWorkloadSnapshot(validIPSnapshotAt(j.now()))
	if got = latestJoined(t, sink); got.Valid || len(got.Workloads) != 0 {
		t.Fatalf("expired source record was resurrected by another reconnect: %+v", got)
	}
}

func TestNewSourceGenerationRenewsButTLSOrHeartbeatDeadlineClamps(t *testing.T) {
	j, sink, now := newSourceJoinerTest(t)
	record := validSourceMembershipRecord(1)
	completeJoinerSession(j, record)
	*now = now.Add(20 * time.Second)
	newRecord := validSourceMembershipRecord(2)
	j.OnUpdate(sourceKey(newRecord))
	got := latestJoined(t, sink)
	if len(got.Workloads) != 1 || !got.SourceMembershipLeaseValidUntil.Equal(now.Add(defaultReaderLeaseTTL)) {
		t.Fatalf("fresh source generation did not establish a fresh bounded deadline: %+v", got)
	}

	shortCert := validIPSnapshotAt(j.now())
	shortCert.PeerCertificateNotAfter = now.Add(4 * time.Second)
	j.PublishRemoteWorkloadSnapshot(shortCert)
	got = latestJoined(t, sink)
	want := now.Add(4 * time.Second)
	if !got.SourceMembershipLeaseValidUntil.Equal(want) {
		t.Fatalf("source deadline was not clamped to peer heartbeat evidence: got %s want %s", got.SourceMembershipLeaseValidUntil, want)
	}
	*now = want
	j.Expire(*now)
	if got = latestJoined(t, sink); got.Valid {
		t.Fatal("snapshot remained valid after the peer certificate deadline")
	}

	j, sink, now = newSourceJoinerTest(t)
	record = validSourceMembershipRecord(1)
	record.LeaseTTLSeconds = int64(maxReaderLeaseTTL / time.Second)
	completeJoinerSession(j, record)
	heartbeatSnapshot := validIPSnapshotAt(*now)
	heartbeatSnapshot.PeerHeartbeatAt = now.Add(-110 * time.Second)
	heartbeatSnapshot.PeerCertificateNotAfter = now.Add(time.Hour)
	j.PublishRemoteWorkloadSnapshot(heartbeatSnapshot)
	got = latestJoined(t, sink)
	want = now.Add(10 * time.Second)
	if !got.SourceMembershipLeaseValidUntil.Equal(want) {
		t.Fatalf("source deadline was not clamped to heartbeat freshness: got %s want %s", got.SourceMembershipLeaseValidUntil, want)
	}
}

func TestSourceGenerationRollbackAndAgentEpochReplayFailClosed(t *testing.T) {
	j, sink, _ := newSourceJoinerTest(t)
	completeJoinerSession(j, validSourceMembershipRecord(3))
	j.OnUpdate(sourceKey(validSourceMembershipRecord(2)))
	if latestJoined(t, sink).Valid {
		t.Fatal("source generation rollback was accepted")
	}

	j, sink, _ = newSourceJoinerTest(t)
	record := validSourceMembershipRecord(3)
	completeJoinerSession(j, record)
	restarted := validSourceMembershipRecord(1)
	restarted.AgentEpoch = "agent-epoch-b"
	restarted.Workloads = []membership.SourceMembershipEntry{}
	j.OnUpdate(sourceKey(restarted))
	if got := latestJoined(t, sink); !got.Valid || len(got.Workloads) != 0 {
		t.Fatalf("empty generation-one process restart did not withdraw prior workloads: %+v", got)
	}
	oldEpoch := validSourceMembershipRecord(1)
	oldEpoch.Workloads = []membership.SourceMembershipEntry{}
	j.OnUpdate(sourceKey(oldEpoch))
	if latestJoined(t, sink).Valid {
		t.Fatal("previously retired source epoch was replayed")
	}
}

func TestSourceMembershipKeyRejectsUnknownTrailingAndMismatchedFields(t *testing.T) {
	valid, err := json.Marshal(validSourceMembershipRecord(1))
	if err != nil {
		t.Fatal(err)
	}
	var key SourceMembershipKey
	if err := key.Unmarshal("node-a", valid); err != nil {
		t.Fatalf("valid source membership record rejected: %v", err)
	}
	if err := key.Unmarshal("node-b", valid); err == nil {
		t.Fatal("source key/node mismatch was accepted")
	}
	if err := key.Unmarshal("node-a", append(append([]byte(nil), valid...), []byte(` {}`)...)); err == nil {
		t.Fatal("trailing JSON was accepted")
	}
	duplicate := strings.Replace(string(valid), `"version":1`, `"version":1,"version":1`, 1)
	if err := key.Unmarshal("node-a", []byte(duplicate)); err == nil {
		t.Fatal("duplicate JSON fields were accepted")
	}
	unknown := append(append([]byte(nil), valid[:len(valid)-1]...), []byte(`,"futureField":true}`)...)
	if err := key.Unmarshal("node-a", unknown); err == nil {
		t.Fatal("unknown source record field was accepted")
	}
	if err := key.Unmarshal("bad/key", valid); err == nil {
		t.Fatal("non-node key path was accepted")
	}
}

func TestSourceMembershipMaximumTTLIsClampedToReaderPolicy(t *testing.T) {
	j, sink, now := newSourceJoinerTest(t)
	record := validSourceMembershipRecord(1)
	record.LeaseTTLSeconds = int64(maxReaderLeaseTTL / time.Second)
	record.IssuedAt = now.Add(48 * time.Hour)
	completeJoinerSession(j, record)
	got := latestJoined(t, sink)
	if !got.SourceMembershipLeaseValidUntil.Equal(now.Add(defaultReaderLeaseTTL)) {
		t.Fatalf("peer-controlled TTL exceeded local receiver policy: got %s", got.SourceMembershipLeaseValidUntil)
	}
}

func TestSourceMembershipDeadlineIsClampedToHeartbeatFreshness(t *testing.T) {
	j, sink, now := newSourceJoinerTest(t)
	record := validSourceMembershipRecord(1)
	record.LeaseTTLSeconds = int64(maxReaderLeaseTTL / time.Second)
	completeJoinerSession(j, record)
	peer := validIPSnapshotAt(*now)
	peer.PeerHeartbeatAt = now.Add(-110 * time.Second)
	peer.PeerCertificateNotAfter = now.Add(time.Hour)
	j.PublishRemoteWorkloadSnapshot(peer)
	got := latestJoined(t, sink)
	want := now.Add(10 * time.Second)
	if !got.SourceMembershipLeaseValidUntil.Equal(want) {
		t.Fatalf("lease deadline did not honor heartbeat freshness: got %s want %s", got.SourceMembershipLeaseValidUntil, want)
	}
	*now = want
	j.Expire(*now)
	if got = latestJoined(t, sink); got.Valid {
		t.Fatal("joined snapshot remained valid after peer heartbeat freshness expired")
	}
}

func TestSourceRecordClusterMismatchInvalidatesSession(t *testing.T) {
	j, sink, _ := newSourceJoinerTest(t)
	completeJoinerSession(j, validSourceMembershipRecord(1))
	wrong := validSourceMembershipRecord(2)
	wrong.ClusterName = "cluster-alpha"
	j.OnUpdate(sourceKey(wrong))
	if latestJoined(t, sink).Valid {
		t.Fatal("source record from a different cluster was accepted")
	}
}

func TestSourceEpochRecoveryAfterMissedTransientReset(t *testing.T) {
	j, sink, _ := newSourceJoinerTest(t)
	completeJoinerSession(j, validSourceMembershipRecord(3))
	j.End(context.Background())
	j.PublishRemoteWorkloadSnapshot(Snapshot{ClusterName: "cluster-beta", ClusterID: 17, Valid: false})
	j.Begin(context.Background())
	restarted := validSourceMembershipRecord(7)
	restarted.AgentEpoch = "agent-epoch-b"
	restarted.Workloads[0].MembershipEpoch = restarted.AgentEpoch
	j.OnUpdate(sourceKey(restarted))
	if latestJoined(t, sink).Valid {
		t.Fatal("new epoch bypassed initial source list completion")
	}
	j.ListDone(context.Background())
	if latestJoined(t, sink).Valid {
		t.Fatal("new epoch bypassed paired IP list completion")
	}
	ips := validIPSnapshotAt(j.now())
	ips.Workloads[0].MembershipEpoch = restarted.AgentEpoch
	j.PublishRemoteWorkloadSnapshot(ips)
	if got := latestJoined(t, sink); !got.Valid || len(got.Workloads) != 1 {
		t.Fatalf("missed transient reset prevented complete-list recovery: %+v", got)
	}

	// The recovery barrier must not discard previous process-epoch floors.
	j.End(context.Background())
	j.Begin(context.Background())
	old := validSourceMembershipRecord(1)
	old.Workloads = nil
	j.OnUpdate(sourceKey(old))
	j.ListDone(context.Background())
	j.PublishRemoteWorkloadSnapshot(validIPSnapshotAt(j.now()))
	if latestJoined(t, sink).Valid {
		t.Fatal("complete relist resurrected a retired source process epoch")
	}
}

func TestSourceLiveEpochChangeRequiresNewCompleteList(t *testing.T) {
	j, sink, _ := newSourceJoinerTest(t)
	completeJoinerSession(j, validSourceMembershipRecord(3))
	cancelled := false
	j.SetSessionCancel(func() { cancelled = true })
	restarted := validSourceMembershipRecord(7)
	restarted.AgentEpoch = "agent-epoch-b"
	restarted.Workloads[0].MembershipEpoch = restarted.AgentEpoch
	j.OnUpdate(sourceKey(restarted))
	if latestJoined(t, sink).Valid || !cancelled {
		t.Fatal("live unseen epoch bypassed reset and complete-list barriers")
	}
	j.End(context.Background())
	j.PublishRemoteWorkloadSnapshot(Snapshot{ClusterName: "cluster-beta", ClusterID: 17, Valid: false})
	j.Begin(context.Background())
	j.OnUpdate(sourceKey(restarted))
	j.ListDone(context.Background())
	ips := validIPSnapshotAt(j.now())
	ips.Workloads[0].MembershipEpoch = restarted.AgentEpoch
	j.PublishRemoteWorkloadSnapshot(ips)
	if got := latestJoined(t, sink); !got.Valid || len(got.Workloads) != 1 {
		t.Fatalf("valid new full-list epoch did not recover: %+v", got)
	}
}

// nativeIPSnapshotAt is validIPSnapshotAt as the inventory reports a native
// record: no namespace UID, node or capture membership.
func nativeIPSnapshotAt(now time.Time) Snapshot {
	snapshot := validIPSnapshotAt(now)
	w := &snapshot.Workloads[0]
	w.Key.NamespaceUID, w.NodeName = "", ""
	w.MembershipEpoch, w.MembershipGeneration, w.MembershipState = "", 0, unannotatedMembership
	return snapshot
}

func TestNativeIPRecordJoinsItsSourceLease(t *testing.T) {
	j, sink, _ := newSourceJoinerTest(t)
	j.Begin(context.Background())
	j.OnUpdate(sourceKey(validSourceMembershipRecord(1)))
	j.ListDone(context.Background())
	j.PublishRemoteWorkloadSnapshot(nativeIPSnapshotAt(j.now()))
	got := latestJoined(t, sink)
	if !got.Valid || len(got.Workloads) != 1 {
		t.Fatalf("native record did not join its source lease: %+v", got)
	}
	want := validIPSnapshotAt(j.now()).Workloads[0]
	if w := got.Workloads[0]; w.Key != want.Key || w.NodeName != "node-a" || w.MembershipEpoch != "agent-epoch-a" ||
		w.MembershipGeneration != 2 || w.MembershipState != "captured" {
		t.Fatalf("joined workload does not carry the source lease's membership: %+v", w)
	}
}

func TestNativeIPRecordMustMatchItsSourceLeaseExactly(t *testing.T) {
	for name, change := range map[string]func(*Workload){
		"service account":     func(w *Workload) { w.ServiceAccount = "other" },
		"identity":            func(w *Workload) { w.Identity++ },
		"namespace":           func(w *Workload) { w.Namespace = "billing" },
		"pod name":            func(w *Workload) { w.PodName = "api-2" },
		"address":             func(w *Workload) { w.Addresses = []netip.Addr{netip.MustParseAddr("10.17.0.13")} },
		"extra address":       func(w *Workload) { w.Addresses = append(w.Addresses, netip.MustParseAddr("fd00:17::12")) },
		"pod UID":             func(w *Workload) { w.Key.PodUID = "pod-b" },
		"other namespace UID": func(w *Workload) { w.Key.NamespaceUID = "ns-b" },
		"other node":          func(w *Workload) { w.NodeName = "node-b" },
		"carries an epoch":    func(w *Workload) { w.MembershipEpoch = "agent-epoch-a" },
	} {
		t.Run(name, func(t *testing.T) {
			j, sink, _ := newSourceJoinerTest(t)
			j.Begin(context.Background())
			j.OnUpdate(sourceKey(validSourceMembershipRecord(1)))
			j.ListDone(context.Background())
			snapshot := nativeIPSnapshotAt(j.now())
			change(&snapshot.Workloads[0])
			j.PublishRemoteWorkloadSnapshot(snapshot)
			if got := latestJoined(t, sink); !got.Valid || len(got.Workloads) != 0 {
				t.Fatalf("mismatched native record was joined: %+v", got)
			}
		})
	}
	// A native record that carries the namespace UID and node still joins.
	j, sink, _ := newSourceJoinerTest(t)
	j.Begin(context.Background())
	j.OnUpdate(sourceKey(validSourceMembershipRecord(1)))
	j.ListDone(context.Background())
	snapshot := nativeIPSnapshotAt(j.now())
	snapshot.Workloads[0].Key.NamespaceUID, snapshot.Workloads[0].NodeName = "ns-a", "node-a"
	j.PublishRemoteWorkloadSnapshot(snapshot)
	if got := latestJoined(t, sink); !got.Valid || len(got.Workloads) != 1 {
		t.Fatalf("native record with matching namespace UID and node was not joined: %+v", got)
	}
}

// The native join keys on the Pod UID, so two leases may not claim one Pod
// UID under different namespace UIDs.
func TestSourceLeasesCannotClaimOnePodUIDTwice(t *testing.T) {
	j, sink, _ := newSourceJoinerTest(t)
	first := validSourceMembershipRecord(1)
	second := validSourceMembershipRecord(1)
	second.NodeName, second.AgentEpoch = "node-b", "agent-epoch-b"
	second.Workloads[0].NodeName, second.Workloads[0].MembershipEpoch = "node-b", "agent-epoch-b"
	second.Workloads[0].NamespaceUID, second.Workloads[0].Addresses = "ns-b", []string{"10.17.0.13"}
	j.Begin(context.Background())
	j.OnUpdate(sourceKey(first))
	j.OnUpdate(sourceKey(second))
	j.ListDone(context.Background())
	j.PublishRemoteWorkloadSnapshot(nativeIPSnapshotAt(j.now()))
	if got := latestJoined(t, sink); got.Valid {
		t.Fatalf("two source leases claimed one Pod UID: %+v", got)
	}
}

// The inventory's reason for an invalid list is logged, not only published.
func TestInvalidIPSnapshotReasonIsLogged(t *testing.T) {
	var logged strings.Builder
	j, err := NewSourceMembershipJoiner("cluster-beta", 17, slog.New(slog.NewTextHandler(&logged, nil)), &recordingSink{})
	if err != nil {
		t.Fatal(err)
	}
	j.PublishRemoteWorkloadSnapshot(Snapshot{ClusterName: "cluster-beta", ClusterID: 17, Reason: "workload record lacks ztunnel membership wire version 1"})
	if !strings.Contains(logged.String(), "Remote IP identity snapshot is invalid") || !strings.Contains(logged.String(), "lacks ztunnel membership wire version 1") {
		t.Fatalf("invalid IP snapshot reason was not logged: %q", logged.String())
	}
}
