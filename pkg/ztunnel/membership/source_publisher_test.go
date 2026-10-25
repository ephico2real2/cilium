// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package membership

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"
	"time"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/lock"
)

type sourceTestLocker struct {
	mu    lock.Mutex
	valid bool
}

func (l *sourceTestLocker) Unlock(context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.valid = false
	return nil
}

func (l *sourceTestLocker) Comparator() any { return l }

func (l *sourceTestLocker) isValid() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.valid
}

type sourceTestBackend struct {
	mu        lock.Mutex
	active    *sourceTestLocker
	records   map[string][]byte
	ttls      map[string]time.Duration
	writeErr  error
	writeHook func()
	writes    chan []byte
	deleteErr error
	lockErr   error
}

func newSourceTestBackend() *sourceTestBackend {
	return &sourceTestBackend{records: make(map[string][]byte), ttls: make(map[string]time.Duration), writes: make(chan []byte, 8)}
}

func (b *sourceTestBackend) LockPath(ctx context.Context, _ string) (kvstore.KVLocker, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.lockErr != nil {
		return nil, b.lockErr
	}
	if b.active != nil && b.active.isValid() {
		return nil, errors.New("test writer lock already held")
	}
	b.active = &sourceTestLocker{valid: true}
	return b.active, nil
}

func (b *sourceTestBackend) DeleteIfLocked(ctx context.Context, key string, lock kvstore.KVLocker) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if lock != b.active || !b.active.isValid() {
		return kvstore.ErrLockLeaseExpired
	}
	if b.deleteErr != nil {
		return b.deleteErr
	}
	delete(b.records, key)
	delete(b.ttls, key)
	return nil
}

func (b *sourceTestBackend) UpdateWithLeaseTTLIfLocked(ctx context.Context, key string, value []byte, ttl time.Duration, lock kvstore.KVLocker) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if b.writeHook != nil {
		b.writeHook()
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if lock != b.active || !b.active.isValid() {
		return kvstore.ErrLockLeaseExpired
	}
	if b.writeErr != nil {
		return b.writeErr
	}
	copyValue := append([]byte(nil), value...)
	b.records[key] = copyValue
	b.ttls[key] = ttl
	select {
	case b.writes <- append([]byte(nil), copyValue...):
	default:
	}
	return nil
}

type sourceTestEndpoints struct {
	mu             lock.Mutex
	registry       *Registry
	ref            Reference
	snapshot       sourceEndpointSnapshot
	revalidateErr  error
	revalidateHook func()
	readHook       func()
	revalidations  int
	reads          int
	egress         *SourceEgressPolicy
	egressErr      error
	// egressPending blocks EgressPolicy until its context ends, as a pending
	// regeneration does.
	egressPending bool
}

func (p *sourceTestEndpoints) Revalidate(ctx context.Context, id uint16) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if id != p.snapshot.EndpointID {
		return errors.New("unexpected endpoint ID")
	}
	p.revalidations++
	if p.revalidateHook != nil {
		p.revalidateHook()
	}
	return p.revalidateErr
}

func (p *sourceTestEndpoints) Read(id uint16) (sourceEndpointSnapshot, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.reads++
	if id != p.snapshot.EndpointID {
		return sourceEndpointSnapshot{}, errors.New("unexpected endpoint ID")
	}
	if p.readHook != nil {
		p.readHook()
	}
	return p.snapshot, nil
}

func (p *sourceTestEndpoints) EgressPolicy(ctx context.Context, snapshot sourceEndpointSnapshot) (*SourceEgressPolicy, error) {
	p.mu.Lock()
	pending, egress, err := p.egressPending, p.egress, p.egressErr
	p.mu.Unlock()
	if snapshot.EndpointID != p.snapshot.EndpointID {
		return nil, errors.New("unexpected endpoint ID")
	}
	if pending {
		<-ctx.Done()
		return nil, errors.New("endpoint native policy is not current and realized")
	}
	if egress == nil && err == nil {
		err = errors.New("test endpoint has no realized policy")
	}
	return egress, err
}

func newSourcePublisherTest(t *testing.T) (*SourcePublisher, *sourceTestBackend, *sourceTestEndpoints, Reference) {
	t.Helper()
	registry := NewRegistry(1)
	ref, err := registry.Require("namespace-uid-a", "pod-uid-a", 42, "/var/run/netns/cilium/pod-42")
	if err != nil {
		t.Fatal(err)
	}
	generation, ok := registry.BeginZDS(ref)
	if !ok || !registry.MarkCaptured(ref, generation) || !registry.AcknowledgeZDS(ref, generation) {
		t.Fatal("could not establish test capture and ZDS evidence")
	}
	publication, ok := registry.Publication(ref)
	if !ok {
		t.Fatal("registry lost current publication")
	}
	provider := &sourceTestEndpoints{
		registry: registry,
		ref:      ref,
		snapshot: sourceEndpointSnapshot{
			EndpointID: 42, Namespace: "orders", NamespaceUID: ref.Key.NamespaceUID,
			PodName: "orders-api", PodUID: ref.Key.PodUID, NodeName: "node-a",
			ServiceAccount: "api", Identity: identity.NumericIdentity(1025),
			Addresses: []string{"10.0.0.42", "fd00::42"},
			Membership: endpoint.ZtunnelMembership{
				Version: publication.Version, Revision: publication.Revision, Epoch: publication.Epoch,
				Generation: publication.Generation, State: publication.State,
				NamespaceUID: ref.Key.NamespaceUID, NodeName: "node-a", ServiceAccount: "api",
			},
		},
	}
	backend := newSourceTestBackend()
	cfg := SourcePublisherConfig{
		ClusterInfo: cmtypes.ClusterInfo{ID: 1, Name: "cluster-alpha", MaxConnectedClusters: 255},
		NodeName:    "node-a", RefreshInterval: time.Second, LeaseTTL: 10 * time.Second,
		MaxWorkloads: 2, WriteTimeout: time.Second, RevalidationTimeout: time.Second,
		Now: func() time.Time { return time.Unix(1_800_000_000, 0).UTC() },
	}
	publisher, err := newSourcePublisher(registry, provider, backend, slog.New(slog.NewTextHandler(testWriter{t}, nil)), cfg, registry.SourceSnapshot().Epoch)
	if err != nil {
		t.Fatal(err)
	}
	return publisher, backend, provider, ref
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) { w.t.Log(string(p)); return len(p), nil }

func lockSourceTestBackend(t *testing.T, backend *sourceTestBackend) kvstore.KVLocker {
	t.Helper()
	locker, err := backend.LockPath(context.Background(), "test")
	if err != nil {
		t.Fatal(err)
	}
	return locker
}

func readSourceRecord(t *testing.T, backend *sourceTestBackend, key string) SourceMembershipRecord {
	t.Helper()
	backend.mu.Lock()
	data := append([]byte(nil), backend.records[key]...)
	backend.mu.Unlock()
	if len(data) == 0 {
		t.Fatal("source membership record was not written")
	}
	var record SourceMembershipRecord
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatalf("decode source membership record: %v", err)
	}
	return record
}

func TestSourcePublisherPublishesRevalidatedCompleteSnapshotWithShortLease(t *testing.T) {
	publisher, backend, endpoints, _ := newSourcePublisherTest(t)
	locker := lockSourceTestBackend(t, backend)
	if err := publisher.refresh(context.Background(), locker); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	record := readSourceRecord(t, backend, publisher.key)
	if !record.Valid || record.Generation == 0 || record.AgentEpoch != publisher.epoch || record.ClusterID != 1 || record.ClusterName != "cluster-alpha" {
		t.Fatalf("unexpected source record header: %+v", record)
	}
	if len(record.Workloads) != 1 {
		t.Fatalf("published %d workloads, want one", len(record.Workloads))
	}
	workload := record.Workloads[0]
	if workload.NamespaceUID != "namespace-uid-a" || workload.PodUID != "pod-uid-a" || workload.ServiceAccount != "api" || workload.Identity != 1025 {
		t.Fatalf("immutable Kubernetes identity was not preserved: %+v", workload)
	}
	if workload.ZDSGeneration == 0 || workload.MembershipEpoch != publisher.epoch || workload.MembershipRevision == 0 {
		t.Fatalf("fresh source capture evidence was not included: %+v", workload)
	}
	if len(workload.Addresses) != 2 || workload.Addresses[0] != "10.0.0.42" || workload.Addresses[1] != "fd00::42" {
		t.Fatalf("addresses are incomplete or unsorted: %v", workload.Addresses)
	}
	backend.mu.Lock()
	ttl := backend.ttls[publisher.key]
	backend.mu.Unlock()
	if ttl != 10*time.Second || record.LeaseTTLSeconds != 10 {
		t.Fatalf("lease ttl backend=%s record=%d, want 10 seconds", ttl, record.LeaseTTLSeconds)
	}
	if endpoints.revalidations != 1 {
		t.Fatalf("endpoint revalidation count=%d, want 1", endpoints.revalidations)
	}
}

func TestSourcePublisherWithdrawsOldSnapshotOnRevalidationFailure(t *testing.T) {
	publisher, backend, endpoints, _ := newSourcePublisherTest(t)
	backend.records[publisher.key] = []byte(`{"valid":true,"workloads":[{"podUID":"old"}]}`)
	endpoints.revalidateErr = errors.New("ZDS ACK timed out")
	locker := lockSourceTestBackend(t, backend)
	if err := publisher.refresh(context.Background(), locker); err != nil {
		t.Fatalf("fail-closed refresh should publish an empty invalid record: %v", err)
	}
	record := readSourceRecord(t, backend, publisher.key)
	if record.Valid || len(record.Workloads) != 0 || record.Reason != "endpoint_revalidation_failed" {
		t.Fatalf("stale workload survived failed live revalidation: %+v", record)
	}
}

func TestSourcePublisherWithdrawsIdentityMismatch(t *testing.T) {
	publisher, backend, endpoints, _ := newSourcePublisherTest(t)
	endpoints.snapshot.NamespaceUID = "recreated-namespace-uid"
	locker := lockSourceTestBackend(t, backend)
	if err := publisher.refresh(context.Background(), locker); err != nil {
		t.Fatalf("identity mismatch should publish empty invalid record: %v", err)
	}
	record := readSourceRecord(t, backend, publisher.key)
	if record.Valid || len(record.Workloads) != 0 || record.Reason != "endpoint_identity_mismatch" {
		t.Fatalf("identity mismatch was not withdrawn: %+v", record)
	}
}

func TestSourcePublisherDoesNotReuseCaptureRevalidationAcrossGenerationChange(t *testing.T) {
	publisher, backend, endpoints, ref := newSourcePublisherTest(t)
	changed := false
	endpoints.readHook = func() {
		if changed {
			return
		}
		changed = true
		generation, ok := publisher.registry.BeginZDS(ref)
		if !ok || !publisher.registry.MarkCaptured(ref, generation) || !publisher.registry.AcknowledgeZDS(ref, generation) {
			t.Fatal("could not simulate a newer capture generation")
		}
		endpoints.snapshot.Membership = endpoint.ZtunnelMembership{
			Version: 1, Revision: publisher.registry.SourceSnapshot().Entries[0].Publication.Revision,
			Epoch: ref.Epoch, Generation: generation, State: PublicationCaptured,
			NamespaceUID: ref.Key.NamespaceUID, NodeName: "node-a", ServiceAccount: "api",
		}
	}
	locker := lockSourceTestBackend(t, backend)
	if err := publisher.refresh(context.Background(), locker); err != nil {
		t.Fatalf("generation race should publish an invalid record: %v", err)
	}
	record := readSourceRecord(t, backend, publisher.key)
	if record.Valid || len(record.Workloads) != 0 {
		t.Fatalf("newer generation was advertised without its own revalidation: %+v", record)
	}
}

func TestSourcePublisherPreservesPreviousLeaseWhenWriteFails(t *testing.T) {
	publisher, backend, _, _ := newSourcePublisherTest(t)
	old := []byte(`{"valid":true,"agentEpoch":"previous"}`)
	backend.records[publisher.key] = append([]byte(nil), old...)
	backend.writeErr = errors.New("etcd unavailable")
	locker := lockSourceTestBackend(t, backend)
	err := publisher.refresh(context.Background(), locker)
	if err == nil {
		t.Fatal("refresh succeeded despite failed etcd write")
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if string(backend.records[publisher.key]) != string(old) {
		t.Fatal("failed write changed existing value; lease expiry remains the fail-closed bound")
	}
}

func TestSourcePublisherRejectsUnsafeBudgetAndWorkloadLimit(t *testing.T) {
	publisher, _, _, _ := newSourcePublisherTest(t)
	cfg := publisher.config
	cfg.LeaseTTL = 3 * time.Second
	if _, err := newSourcePublisher(publisher.registry, publisher.endpoints, publisher.backend, publisher.logger, cfg, publisher.epoch); err == nil {
		t.Fatal("configuration whose full endpoint revalidation budget exceeds its lease was accepted")
	}
}

func TestSourcePublisherPublishesOnlyEmptyRecordForRequiredMembership(t *testing.T) {
	publisher, backend, endpoints, ref := newSourcePublisherTest(t)
	if _, ok := publisher.registry.BeginZDS(ref); !ok {
		t.Fatal("BeginZDS rejected current membership")
	}
	locker := lockSourceTestBackend(t, backend)
	if err := publisher.refresh(context.Background(), locker); err != nil {
		t.Fatalf("refresh of Required source membership: %v", err)
	}
	record := readSourceRecord(t, backend, publisher.key)
	if !record.Valid || len(record.Workloads) != 0 || endpoints.revalidations != 0 {
		t.Fatalf("uncaptured membership was eligible for publication: record=%+v revalidations=%d", record, endpoints.revalidations)
	}
}

func TestSourcePublisherWithdrawsAllWorkloadsWhenBoundExceeded(t *testing.T) {
	publisher, backend, _, _ := newSourcePublisherTest(t)
	second, err := publisher.registry.Require("namespace-uid-b", "pod-uid-b", 43, "/var/run/netns/cilium/pod-43")
	if err != nil {
		t.Fatal(err)
	}
	generation, ok := publisher.registry.BeginZDS(second)
	if !ok || !publisher.registry.MarkCaptured(second, generation) || !publisher.registry.AcknowledgeZDS(second, generation) {
		t.Fatal("second workload was not captured")
	}
	cfg := publisher.config
	cfg.MaxWorkloads = 1
	limited, err := newSourcePublisher(publisher.registry, publisher.endpoints, publisher.backend, publisher.logger, cfg, publisher.epoch)
	if err != nil {
		t.Fatal(err)
	}
	locker := lockSourceTestBackend(t, backend)
	if err := limited.refresh(context.Background(), locker); err != nil {
		t.Fatalf("bound-exceeded refresh: %v", err)
	}
	record := readSourceRecord(t, backend, limited.key)
	if record.Valid || record.Reason != "workload_limit_exceeded" || len(record.Workloads) != 0 {
		t.Fatalf("bound-exceeded refresh did not withdraw the whole snapshot: %+v", record)
	}
}

// The bound limits the workloads a record publishes and revalidates. Required
// or Draining entries are neither, so they cannot withdraw a node's record.
func TestSourcePublisherBoundCountsOnlyCapturedWorkloads(t *testing.T) {
	publisher, backend, _, _ := newSourcePublisherTest(t)
	if _, err := publisher.registry.Require("namespace-uid-b", "pod-uid-b", 43, "/var/run/netns/cilium/pod-43"); err != nil {
		t.Fatal(err)
	}
	cfg := publisher.config
	cfg.MaxWorkloads = 1
	limited, err := newSourcePublisher(publisher.registry, publisher.endpoints, publisher.backend, publisher.logger, cfg, publisher.epoch)
	if err != nil {
		t.Fatal(err)
	}
	locker := lockSourceTestBackend(t, backend)
	if err := limited.refresh(context.Background(), locker); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	record := readSourceRecord(t, backend, limited.key)
	if !record.Valid || len(record.Workloads) != 1 {
		t.Fatalf("a Required-only entry withdrew the captured workload: %+v", record)
	}
}

func TestSourcePublisherAlwaysAllowsFailClosedWithdrawalAcrossRegistryMutation(t *testing.T) {
	publisher, backend, endpoints, ref := newSourcePublisherTest(t)
	endpoints.revalidateErr = errors.New("capture recheck failed")
	backend.writeHook = func() {
		if _, ok := publisher.registry.BeginDrain(ref); !ok {
			t.Fatal("could not simulate a concurrent source registry mutation")
		}
	}
	locker := lockSourceTestBackend(t, backend)
	if err := publisher.refresh(context.Background(), locker); err != nil {
		t.Fatalf("empty fail-closed record must not be blocked by a concurrent registry revision: %v", err)
	}
	record := readSourceRecord(t, backend, publisher.key)
	if record.Valid || len(record.Workloads) != 0 {
		t.Fatalf("source registry mutation did not result in withdrawal: %+v", record)
	}
}

func TestSourcePublisherShutdownPublishesRestrictiveLeaseWhileStillHoldingLock(t *testing.T) {
	registry := NewRegistry(1)
	backend := newSourceTestBackend()
	provider := &sourceTestEndpoints{registry: registry}
	cfg := SourcePublisherConfig{ClusterInfo: cmtypes.ClusterInfo{ID: 1, Name: "cluster-alpha", MaxConnectedClusters: 255}, NodeName: "node-a",
		RefreshInterval: time.Second, LeaseTTL: 10 * time.Second, MaxWorkloads: 2, WriteTimeout: time.Second, RevalidationTimeout: time.Second}
	publisher, err := newSourcePublisher(registry, provider, backend, slog.New(slog.NewTextHandler(testWriter{t}, nil)), cfg, registry.SourceSnapshot().Epoch)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- publisher.Run(ctx) }()
	// The startup empty snapshot and its first live refresh are separate writes.
	for range 2 {
		select {
		case <-backend.writes:
		case <-time.After(2 * time.Second):
			cancel()
			t.Fatal("publisher did not establish its startup epoch and initial snapshot")
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("publisher shutdown: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("publisher did not stop after context cancellation")
	}
	record := readSourceRecord(t, backend, publisher.key)
	if record.Valid || len(record.Workloads) != 0 || record.Reason != "source_publishing_session_ended" {
		t.Fatalf("shutdown left usable source metadata: %+v", record)
	}
	if backend.active.isValid() {
		t.Fatal("shutdown did not release the writer lock after withdrawal")
	}
}

func TestSourcePublisherPositiveWriteDoesNotHoldRegistryLockAndWithdrawsRace(t *testing.T) {
	publisher, backend, _, ref := newSourcePublisherTest(t)
	writes := 0
	backend.writeHook = func() {
		writes++
		if writes == 1 {
			// Executing this in the callback used to deadlock on Registry.mu.
			if _, ok := publisher.registry.BeginDrain(ref); !ok {
				t.Fatal("could not drain during source metadata write")
			}
		}
	}
	locker := lockSourceTestBackend(t, backend)
	if err := publisher.refresh(context.Background(), locker); err != nil {
		t.Fatalf("concurrent revision was not replaced by a restrictive record: %v", err)
	}
	record := readSourceRecord(t, backend, publisher.key)
	if writes != 2 || record.Valid || len(record.Workloads) != 0 || record.Generation != 2 {
		t.Fatalf("raced write did not publish a newer restrictive generation: writes=%d record=%+v", writes, record)
	}
}

func TestSourcePublisherWithdrawsAfterWriteErrorBeforeUnlock(t *testing.T) {
	publisher, backend, _, _ := newSourcePublisherTest(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	attempts := 0
	backend.writeHook = func() {
		attempts++
		switch attempts {
		case 2:
			backend.writeErr = errors.New("ambiguous session write")
		case 3:
			backend.writeErr = nil
			cancel()
		}
	}
	if err := publisher.Run(ctx); err != nil {
		t.Fatalf("publisher did not end after restrictive recovery: %v", err)
	}
	record := readSourceRecord(t, backend, publisher.key)
	if attempts != 3 || record.Valid || len(record.Workloads) != 0 || record.Generation != 3 {
		t.Fatalf("session error was not followed by restrictive publication: attempts=%d record=%+v", attempts, record)
	}
	if backend.active.isValid() {
		t.Fatal("publisher retained distributed lock after restrictive withdrawal")
	}
}
