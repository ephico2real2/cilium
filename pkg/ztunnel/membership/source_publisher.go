// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package membership

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"reflect"
	"sort"

	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

const (
	SourceMembershipRoot         = "cilium/state/ztunnel/membership/v1"
	SourceMembershipPrefix       = SourceMembershipRoot + "/agents"
	SourceMembershipLockPrefix   = SourceMembershipRoot + "/locks"
	DefaultSourceRefreshInterval = 5 * time.Second
	DefaultSourceLeaseTTL        = 30 * time.Second
	DefaultSourceMaxWorkloads    = 8
	logSourceStage               = "stage"
	logSourceWorkloads           = "workloads"
	logSourceRegistryRevision    = "registryRevision"
)

var ErrSourcePublicationStale = errors.New("source membership changed during snapshot publication")

// SourceMembershipRecord is a complete per-node replacement view. Its
// LeaseTTLSeconds and IssuedAt fields are diagnostic only: a consumer must
// trust etcd key deletion/lease expiry, not a timestamp carried by the writer.
// This record proves only the trusted Cilium control plane's live endpoint,
// capture reassertion, and ZDS ACK view. It does not prove xDS, policy, or
// workload-mTLS activation.
type SourceMembershipRecord struct {
	Version          uint8                   `json:"version"`
	ClusterName      string                  `json:"clusterName"`
	ClusterID        uint32                  `json:"clusterID"`
	NodeName         string                  `json:"nodeName"`
	AgentEpoch       string                  `json:"agentEpoch"`
	Generation       uint64                  `json:"generation"`
	RegistryRevision uint64                  `json:"registryRevision"`
	LeaseTTLSeconds  int64                   `json:"leaseTTLSeconds"`
	IssuedAt         time.Time               `json:"issuedAt"`
	Valid            bool                    `json:"valid"`
	Reason           string                  `json:"reason,omitempty"`
	Workloads        []SourceMembershipEntry `json:"workloads"`
}

// SourceMembershipEntry binds remote workload metadata to a current source
// endpoint and the exact process-local capture/ZDS publication.
type SourceMembershipEntry struct {
	EndpointID          uint16   `json:"endpointID"`
	EndpointIncarnation uint64   `json:"endpointIncarnation"`
	Namespace           string   `json:"namespace"`
	NamespaceUID        string   `json:"namespaceUID"`
	PodName             string   `json:"podName"`
	PodUID              string   `json:"podUID"`
	NodeName            string   `json:"nodeName"`
	ServiceAccount      string   `json:"serviceAccount"`
	Identity            uint32   `json:"identity"`
	Addresses           []string `json:"addresses"`
	MembershipRevision  uint64   `json:"membershipRevision"`
	MembershipEpoch     string   `json:"membershipEpoch"`
	ZDSGeneration       uint64   `json:"zdsGeneration"`
}

type sourceEndpointSnapshot struct {
	EndpointID     uint16
	Namespace      string
	NamespaceUID   string
	PodName        string
	PodUID         string
	NodeName       string
	ServiceAccount string
	Identity       identity.NumericIdentity
	Addresses      []string
	Membership     endpoint.ZtunnelMembership
}

// SourceEndpointProvider is deliberately narrow so snapshot assembly and
// ordering can be tested without pretending that a fake endpoint is live.
// Revalidate must perform live Namespace/Pod UID checks, reassert capture, and
// complete a fresh ZDS ACK before it returns nil.
type SourceEndpointProvider interface {
	Revalidate(context.Context, uint16) error
	Read(uint16) (sourceEndpointSnapshot, error)
}

type ciliumSourceEndpointProvider struct {
	endpoints    endpointmanager.EndpointsLookup
	revalidators []EndpointRevalidator
}

func (p ciliumSourceEndpointProvider) Revalidate(ctx context.Context, id uint16) error {
	ep := p.endpoints.LookupCiliumID(id)
	if ep == nil || !ep.IsAlive() {
		return fmt.Errorf("required Cilium endpoint %d is unavailable", id)
	}
	if len(p.revalidators) == 0 {
		return fmt.Errorf("strict endpoint revalidator is unavailable")
	}
	for _, revalidator := range p.revalidators {
		if revalidator == nil {
			return fmt.Errorf("strict endpoint revalidator is nil")
		}
		if err := revalidator.RevalidateEndpoint(ctx, ep); err != nil {
			return err
		}
	}
	return nil
}

func (p ciliumSourceEndpointProvider) Read(id uint16) (sourceEndpointSnapshot, error) {
	ep := p.endpoints.LookupCiliumID(id)
	if ep == nil || !ep.IsAlive() {
		return sourceEndpointSnapshot{}, fmt.Errorf("required Cilium endpoint %d is unavailable", id)
	}
	pod := ep.GetPod()
	if pod == nil {
		return sourceEndpointSnapshot{}, fmt.Errorf("endpoint %d has no current Kubernetes Pod metadata", id)
	}
	podUID := ep.GetK8sPodUID()
	if podUID == "" || string(pod.UID) != podUID || pod.Namespace != ep.GetK8sNamespace() || pod.Name != ep.GetK8sPodName() {
		return sourceEndpointSnapshot{}, fmt.Errorf("endpoint %d Pod metadata does not match its immutable CNI identity", id)
	}
	securityIdentity, err := ep.GetSecurityIdentity()
	if err != nil || securityIdentity == nil || securityIdentity.ID == 0 {
		return sourceEndpointSnapshot{}, fmt.Errorf("endpoint %d has no current security identity", id)
	}

	membership, ok := ep.GetZtunnelMembership()
	if !ok {
		return sourceEndpointSnapshot{}, fmt.Errorf("endpoint %d has no source membership publication", id)
	}
	addresses := make([]string, 0, 2)
	for _, value := range []string{ep.GetIPv4Address(), ep.GetIPv6Address()} {
		if value == "" {
			continue
		}
		addr, err := netip.ParseAddr(value)
		if err != nil || !addr.IsValid() || addr.IsUnspecified() || addr.IsMulticast() {
			return sourceEndpointSnapshot{}, fmt.Errorf("endpoint %d has an invalid workload address", id)
		}
		addresses = append(addresses, addr.Unmap().String())
	}
	sort.Strings(addresses)
	if len(addresses) == 0 {
		return sourceEndpointSnapshot{}, fmt.Errorf("endpoint %d has no workload address", id)
	}
	return sourceEndpointSnapshot{
		EndpointID: id, Namespace: ep.GetK8sNamespace(), NamespaceUID: ep.GetK8sNamespaceUID(),
		PodName: ep.GetK8sPodName(), PodUID: ep.GetK8sPodUID(), NodeName: pod.Spec.NodeName,
		ServiceAccount: pod.Spec.ServiceAccountName, Identity: securityIdentity.ID,
		Addresses: addresses, Membership: membership,
	}, nil
}

type sourceMembershipBackend interface {
	LockPath(context.Context, string) (kvstore.KVLocker, error)
	DeleteIfLocked(context.Context, string, kvstore.KVLocker) error
	UpdateWithLeaseTTLIfLocked(context.Context, string, []byte, time.Duration, kvstore.KVLocker) error
}

type sourceMembershipBackendAdapter struct {
	kvstore.Client
}

func (b sourceMembershipBackendAdapter) UpdateWithLeaseTTLIfLocked(ctx context.Context, key string, value []byte, ttl time.Duration, lock kvstore.KVLocker) error {
	writer, ok := kvstore.LeaseTTLWriterFor(b.Client)
	if !ok {
		return fmt.Errorf("KVStore backend does not provide lock-fenced short leases")
	}
	return writer.UpdateWithLeaseTTLIfLocked(ctx, key, value, ttl, lock)
}

type SourcePublisherConfig struct {
	ClusterInfo         types.ClusterInfo
	NodeName            string
	RefreshInterval     time.Duration
	LeaseTTL            time.Duration
	MaxWorkloads        int
	WriteTimeout        time.Duration
	RevalidationTimeout time.Duration
	Now                 func() time.Time
}

// SourcePublisher writes a current complete per-node membership snapshot under
// a short etcd lease. It serializes writers with a distributed lock and does
// not extend the lease unless current source state was revalidated and written.
type SourcePublisher struct {
	registry  *Registry
	endpoints SourceEndpointProvider
	backend   sourceMembershipBackend
	client    kvstore.Client
	logger    *slog.Logger
	config    SourcePublisherConfig
	key       string
	lockKey   string
	epoch     string

	mu         lock.Mutex
	generation uint64
}

func NewSourcePublisher(registry *Registry, endpoints endpointmanager.EndpointsLookup, revalidators []EndpointRevalidator, backend kvstore.Client, logger *slog.Logger, cfg SourcePublisherConfig) (*SourcePublisher, error) {
	if registry == nil || endpoints == nil || backend == nil || logger == nil {
		return nil, fmt.Errorf("source membership publisher requires registry, endpoint manager, KVStore, and logger")
	}
	if !backend.IsEnabled() {
		return nil, fmt.Errorf("source membership publisher requires an enabled KVStore")
	}
	if _, ok := kvstore.LeaseTTLWriterFor(backend); !ok {
		return nil, fmt.Errorf("source membership publisher requires lock-fenced short key leases")
	}
	if len(revalidators) == 0 {
		return nil, fmt.Errorf("source membership publisher requires a live endpoint revalidator")
	}
	snapshot := registry.SourceSnapshot()
	if snapshot.Epoch == "" {
		return nil, fmt.Errorf("membership registry has no process epoch")
	}
	publisher, err := newSourcePublisher(registry, ciliumSourceEndpointProvider{endpoints: endpoints, revalidators: revalidators}, sourceMembershipBackendAdapter{Client: backend}, logger, cfg, snapshot.Epoch)
	if err != nil {
		return nil, err
	}
	publisher.client = backend
	return publisher, nil
}

func newSourcePublisher(registry *Registry, endpoints SourceEndpointProvider, backend sourceMembershipBackend, logger *slog.Logger, cfg SourcePublisherConfig, epoch string) (*SourcePublisher, error) {
	if registry == nil || endpoints == nil || backend == nil || logger == nil {
		return nil, fmt.Errorf("source membership publisher requires registry, endpoints, backend, and logger")
	}
	if epoch == "" || registry.SourceSnapshot().Epoch != epoch {
		return nil, fmt.Errorf("source publisher epoch must match the current membership registry")
	}
	if err := cfg.ClusterInfo.ValidateStrict(); err != nil {
		return nil, fmt.Errorf("invalid source cluster identity: %w", err)
	}
	if problems := validation.IsDNS1123Subdomain(cfg.NodeName); len(problems) != 0 {
		return nil, fmt.Errorf("invalid source node name")
	}
	if cfg.RefreshInterval == 0 {
		cfg.RefreshInterval = DefaultSourceRefreshInterval
	}
	if cfg.LeaseTTL == 0 {
		cfg.LeaseTTL = DefaultSourceLeaseTTL
	}
	if cfg.MaxWorkloads == 0 {
		cfg.MaxWorkloads = DefaultSourceMaxWorkloads
	}
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = time.Second
	}
	if cfg.RevalidationTimeout == 0 {
		cfg.RevalidationTimeout = 3 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	// Serial revalidation intentionally limits concurrent CNI/ZDS work. Ensure
	// the maximum configured endpoint set can be checked and written inside one
	// lease interval; scale tuning follows measured lab results.
	if cfg.RefreshInterval <= 0 || cfg.LeaseTTL/3 < cfg.RefreshInterval || cfg.LeaseTTL > DefaultSourceLeaseTTL || cfg.LeaseTTL%time.Second != 0 || cfg.MaxWorkloads < 1 || cfg.MaxWorkloads > DefaultSourceMaxWorkloads || cfg.WriteTimeout <= 0 || cfg.WriteTimeout >= cfg.LeaseTTL || cfg.RevalidationTimeout <= 0 {
		return nil, fmt.Errorf("source membership refresh, lease, workload limit, or operation budget is unsafe")
	}
	revalidationBudget := cfg.LeaseTTL - cfg.WriteTimeout
	if revalidationBudget <= time.Nanosecond || uint64(cfg.MaxWorkloads) > uint64((revalidationBudget-time.Nanosecond)/cfg.RevalidationTimeout) {
		return nil, fmt.Errorf("source membership refresh, lease, workload limit, or operation budget is unsafe")
	}
	return &SourcePublisher{
		registry:  registry,
		endpoints: endpoints,
		backend:   backend,
		logger:    logger.With(logfields.LogSubsys, "ztunnel-membership-source"), config: cfg,
		key:     kvstore.JoinKey(SourceMembershipPrefix, cfg.NodeName),
		lockKey: kvstore.JoinKey(SourceMembershipLockPrefix, cfg.NodeName, "writer"), epoch: epoch,
	}, nil
}

// Run publishes an empty current-epoch record before serving memberships, then
// refreshes one complete record at a bounded interval. Loss of the process
// stops lease extension; etcd expiry withdraws the record for direct-origin
// readers. A failed write is followed by a restrictive publication while the
// writer lock is still held. If that also fails, the prior lease is the bound.
func (p *SourcePublisher) Run(ctx context.Context) error {
	if p.client != nil {
		if _, ok := kvstore.LeaseTTLWriterFor(p.client); !ok {
			return fmt.Errorf("KVStore backend does not provide lock-fenced short leases")
		}
	}
	var attempt uint64
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		attempt++
		started := time.Now()
		lockCtx, lockCancel := context.WithTimeout(ctx, p.config.WriteTimeout)
		locker, err := p.backend.LockPath(lockCtx, p.lockKey)
		lockCancel()
		if err != nil {
			p.logger.Warn("Unable to acquire source membership writer lock",
				logSourceStage, "lock",
				logfields.ClusterName, p.config.ClusterInfo.Name,
				logfields.Attempt, attempt,
				logfields.ElapsedDuration, time.Since(started),
				logfields.RetryDelay, p.config.RefreshInterval,
				logfields.Timeout, p.config.WriteTimeout,
				logfields.Error, err)
			if !sleepContext(ctx, p.config.RefreshInterval) {
				return nil
			}
			continue
		}
		err = p.runLocked(ctx, locker)
		// Do not delete the source key as an error-recovery fence: publish a
		// restrictive generation under the same persistent server write head.
		// An ambiguous earlier transaction cannot overwrite that generation.
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), p.config.WriteTimeout)
		if withdrawErr := p.publishInvalid(cleanupCtx, locker, p.registry.SourceSnapshot(), "source_publishing_session_ended"); withdrawErr != nil {
			p.logger.Warn("Unable to withdraw source membership before releasing writer lock",
				logSourceStage, "withdraw",
				logfields.Error, withdrawErr)
		}
		cleanupCancel()
		unlockCtx, cancel := context.WithTimeout(context.Background(), p.config.WriteTimeout)
		if unlockErr := locker.Unlock(unlockCtx); unlockErr != nil {
			p.logger.Warn("Unable to release source membership writer lock",
				logSourceStage, "unlock",
				logfields.Error, unlockErr)
		}
		cancel()
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			p.logger.Warn("Source membership publishing session ended",
				logSourceStage, "session",
				logfields.ClusterName, p.config.ClusterInfo.Name,
				logfields.Attempt, attempt,
				logfields.ElapsedDuration, time.Since(started),
				logfields.RetryDelay, p.config.RefreshInterval,
				logfields.Timeout, p.config.WriteTimeout,
				logfields.Error, err)
			if !sleepContext(ctx, p.config.RefreshInterval) {
				return nil
			}
		}
	}
}

func (p *SourcePublisher) runLocked(ctx context.Context, locker kvstore.KVLocker) error {
	// Replacing any prior process epoch with an empty record is the first write
	// of a restarted agent. It withdraws old workload metadata before this
	// process starts advertising newly revalidated endpoints.
	if err := p.publishRecord(ctx, locker, SourceMembershipRecord{Valid: true, Workloads: []SourceMembershipEntry{}}, p.registry.SourceSnapshot()); err != nil {
		return err
	}
	if err := p.refresh(ctx, locker); err != nil {
		return err
	}
	ticker := time.NewTicker(p.config.RefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := p.refresh(ctx, locker); err != nil {
				return err
			}
		}
	}
}

func (p *SourcePublisher) refresh(ctx context.Context, locker kvstore.KVLocker) error {
	// Bound the entire live revalidation phase, not just each endpoint call.
	// Under churn the second source snapshot may contain new captures; if the
	// aggregate operation budget is exhausted, publish an empty restrictive
	// record with the remaining write budget instead of extending old data.
	revalidationCtx, cancelRevalidation := context.WithTimeout(ctx, p.config.LeaseTTL-p.config.WriteTimeout)
	defer cancelRevalidation()
	initial := p.registry.SourceSnapshot()
	if initial.Epoch != p.epoch {
		return fmt.Errorf("membership registry epoch changed; source publisher must restart")
	}
	if len(initial.Entries) > p.config.MaxWorkloads {
		return p.publishInvalid(ctx, locker, initial, "workload_limit_exceeded")
	}

	revalidated := make(map[Reference]Publication, len(initial.Entries))
	for _, entry := range initial.Entries {
		if entry.Publication.State != PublicationCaptured {
			continue
		}
		publication, err := p.revalidate(revalidationCtx, entry)
		if err != nil {
			return p.publishInvalid(ctx, locker, p.registry.SourceSnapshot(), "endpoint_revalidation_failed")
		}
		revalidated[entry.Reference] = publication
	}

	// Revalidation starts fresh ZDS generations, so read a new atomic registry
	// snapshot. If admission added a new captured endpoint concurrently, re-run
	// its live checks once before considering it for publication.
	current := p.registry.SourceSnapshot()
	if current.Epoch != p.epoch || len(current.Entries) > p.config.MaxWorkloads {
		return p.publishInvalid(ctx, locker, current, "source_registry_changed")
	}
	for _, entry := range current.Entries {
		if entry.Publication.State != PublicationCaptured {
			continue
		}
		if publication, ok := revalidated[entry.Reference]; ok && publication == entry.Publication {
			continue
		}
		publication, err := p.revalidate(revalidationCtx, entry)
		if err != nil {
			return p.publishInvalid(ctx, locker, p.registry.SourceSnapshot(), "endpoint_revalidation_failed")
		}
		revalidated[entry.Reference] = publication
	}
	current = p.registry.SourceSnapshot()
	if err := revalidationCtx.Err(); err != nil {
		return p.publishInvalid(ctx, locker, current, "source_revalidation_budget_exhausted")
	}

	record := SourceMembershipRecord{Valid: true, Workloads: make([]SourceMembershipEntry, 0, len(current.Entries))}
	endpointSnapshots := make(map[Reference]sourceEndpointSnapshot, len(current.Entries))
	for _, entry := range current.Entries {
		if entry.Publication.State != PublicationCaptured {
			continue
		}
		if publication, ok := revalidated[entry.Reference]; !ok || publication != entry.Publication {
			return p.publishInvalid(ctx, locker, current, "endpoint_not_revalidated")
		}
		snapshot, err := p.endpoints.Read(entry.EndpointID)
		if err != nil || !sourceSnapshotMatches(entry, snapshot, p.config.ClusterInfo.ID, p.config.NodeName) {
			return p.publishInvalid(ctx, locker, current, "endpoint_identity_mismatch")
		}
		entryWire, err := makeSourceEntry(entry, snapshot)
		if err != nil {
			return p.publishInvalid(ctx, locker, current, "endpoint_record_invalid")
		}
		endpointSnapshots[entry.Reference] = snapshot
		record.Workloads = append(record.Workloads, entryWire)
	}
	sort.Slice(record.Workloads, func(i, j int) bool {
		x, y := record.Workloads[i], record.Workloads[j]
		if x.NamespaceUID != y.NamespaceUID {
			return x.NamespaceUID < y.NamespaceUID
		}
		return x.PodUID < y.PodUID
	})

	// Check endpoint fields again immediately before the lock-fenced etcd write.
	// Registry revisions are checked under its read lock by publishRecord.
	for ref, before := range endpointSnapshots {
		entry, ok := findSourceEntry(current, ref)
		if !ok {
			return p.publishInvalid(ctx, locker, current, "source_registry_changed")
		}
		after, err := p.endpoints.Read(entry.EndpointID)
		if err != nil || !reflect.DeepEqual(before, after) {
			return p.publishInvalid(ctx, locker, current, "endpoint_changed_during_publish")
		}
		publication, ok := p.registry.Publication(ref)
		if !ok || publication != entry.Publication {
			return p.publishInvalid(ctx, locker, p.registry.SourceSnapshot(), "source_publication_changed")
		}
	}
	err := p.publishRecord(ctx, locker, record, current)
	if errors.Is(err, ErrSourcePublicationStale) {
		return p.publishInvalid(ctx, locker, p.registry.SourceSnapshot(), "source_snapshot_changed_before_write")
	}
	return err
}

func (p *SourcePublisher) publishInvalid(ctx context.Context, locker kvstore.KVLocker, snapshot SourceSnapshot, reason string) error {
	p.logger.Warn("Withdrawing source membership after failed revalidation",
		logSourceStage, "source-revalidation",
		logfields.Reason, reason,
		logSourceWorkloads, len(snapshot.Entries),
		logSourceRegistryRevision, snapshot.Revision)
	return p.publishRecord(ctx, locker, SourceMembershipRecord{Valid: false, Reason: reason, Workloads: []SourceMembershipEntry{}}, snapshot)
}

func (p *SourcePublisher) publishRecord(ctx context.Context, locker kvstore.KVLocker, record SourceMembershipRecord, snapshot SourceSnapshot) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if snapshot.Epoch != p.epoch {
		return fmt.Errorf("source registry epoch changed before write")
	}
	if p.generation == ^uint64(0) {
		return fmt.Errorf("source membership generation exhausted")
	}
	p.generation++
	record.Version = 1
	record.ClusterName = p.config.ClusterInfo.Name
	record.ClusterID = p.config.ClusterInfo.ID
	record.NodeName = p.config.NodeName
	record.AgentEpoch = p.epoch
	record.Generation = p.generation
	record.RegistryRevision = snapshot.Revision
	record.LeaseTTLSeconds = int64(p.config.LeaseTTL / time.Second)
	record.IssuedAt = p.config.Now().UTC()
	if record.Workloads == nil {
		record.Workloads = []SourceMembershipEntry{}
	}
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshal source membership record: %w", err)
	}
	writeCtx, cancel := context.WithTimeout(ctx, p.config.WriteTimeout)
	defer cancel()
	write := func() error {
		return p.backend.UpdateWithLeaseTTLIfLocked(writeCtx, p.key, data, p.config.LeaseTTL, locker)
	}
	// Empty or invalid records only remove remote candidates, so they remain
	// safe even if local state changes while the bounded etcd write is in flight.
	if !record.Valid || len(record.Workloads) == 0 {
		return write()
	}
	return p.registry.PublishIfSourceSnapshotCurrent(snapshot, write)
}

func (p *SourcePublisher) revalidate(ctx context.Context, entry SourceEntry) (Publication, error) {
	attemptCtx, cancel := context.WithTimeout(ctx, p.config.RevalidationTimeout)
	err := p.endpoints.Revalidate(attemptCtx, entry.EndpointID)
	if err == nil {
		err = attemptCtx.Err()
	}
	cancel()
	if err != nil {
		return Publication{}, err
	}
	publication, ok := p.registry.Publication(entry.Reference)
	if !ok || publication.State != PublicationCaptured {
		return Publication{}, fmt.Errorf("endpoint %d did not complete fresh capture and ZDS acknowledgment", entry.EndpointID)
	}
	return publication, nil
}

func sourceSnapshotMatches(entry SourceEntry, snapshot sourceEndpointSnapshot, clusterID uint32, nodeName string) bool {
	m := snapshot.Membership
	return snapshot.EndpointID == entry.EndpointID && snapshot.NamespaceUID == entry.Reference.Key.NamespaceUID &&
		snapshot.PodUID == entry.Reference.Key.PodUID && snapshot.NodeName == nodeName &&
		snapshot.Namespace != "" && snapshot.PodName != "" && snapshot.ServiceAccount != "" &&
		snapshot.Identity != 0 && len(snapshot.Addresses) > 0 &&
		entry.Reference.Key.ClusterID == clusterID && entry.Publication.State == PublicationCaptured &&
		m.Version == entry.Publication.Version && m.Revision == entry.Publication.Revision &&
		m.Epoch == entry.Publication.Epoch && m.Generation == entry.Publication.Generation &&
		m.State == endpoint.ZtunnelMembershipCaptured && m.NamespaceUID == entry.Reference.Key.NamespaceUID &&
		m.NodeName == nodeName && m.ServiceAccount == snapshot.ServiceAccount
}

func makeSourceEntry(entry SourceEntry, snapshot sourceEndpointSnapshot) (SourceMembershipEntry, error) {
	if !sourceSnapshotMatches(entry, snapshot, entry.Reference.Key.ClusterID, snapshot.NodeName) {
		return SourceMembershipEntry{}, fmt.Errorf("source endpoint is not bound to captured membership")
	}
	for _, address := range snapshot.Addresses {
		if _, err := netip.ParseAddr(address); err != nil {
			return SourceMembershipEntry{}, fmt.Errorf("invalid workload address")
		}
	}
	return SourceMembershipEntry{
		EndpointID: snapshot.EndpointID, EndpointIncarnation: entry.Reference.Incarnation,
		Namespace: snapshot.Namespace, NamespaceUID: snapshot.NamespaceUID,
		PodName: snapshot.PodName, PodUID: snapshot.PodUID, NodeName: snapshot.NodeName,
		ServiceAccount: snapshot.ServiceAccount, Identity: uint32(snapshot.Identity), Addresses: append([]string(nil), snapshot.Addresses...),
		MembershipRevision: snapshot.Membership.Revision, MembershipEpoch: snapshot.Membership.Epoch,
		ZDSGeneration: snapshot.Membership.Generation,
	}, nil
}

func findSourceEntry(snapshot SourceSnapshot, ref Reference) (SourceEntry, bool) {
	for _, entry := range snapshot.Entries {
		if entry.Reference == ref {
			return entry, true
		}
	}
	return SourceEntry{}, false
}

func sleepContext(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
