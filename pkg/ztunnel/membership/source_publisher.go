// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package membership

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"reflect"
	"slices"
	"sort"

	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/time"
)

const (
	SourceMembershipRoot         = kvstore.ZtunnelMembershipPrefix
	SourceMembershipPrefix       = SourceMembershipRoot + "/agents"
	SourceMembershipLockPrefix   = SourceMembershipRoot + "/locks"
	DefaultSourceRefreshInterval = 5 * time.Second
	DefaultSourceLeaseTTL        = 30 * time.Second
	DefaultSourceMaxWorkloads    = 8
	// MaxSourceMembershipRecordBytes is the largest record a reader accepts and
	// a writer publishes. Eight workloads with a full egress policy each fit
	// (TestSourceMembershipRecordWorstCaseFitsReaderBound).
	MaxSourceMembershipRecordBytes = 1 << 20
	SourceEgressPolicyVersion      = 1
	// sourcePolicyRealizationWait bounds, per refresh, how long publication
	// waits for regenerating endpoints to realize their policy. On the lab
	// agents, 692 of 725 measured regenerations finished within 0.25 s.
	sourcePolicyRealizationWait = time.Second
	sourcePolicyRealizationPoll = 50 * time.Millisecond
	logSourceStage              = "stage"
	logSourceWorkloads          = "workloads"
	logSourceRegistryRevision   = "registryRevision"
)

var (
	ErrSourcePublicationStale = errors.New("source membership changed during snapshot publication")
	ErrSourceRecordTooLarge   = errors.New("source membership record exceeds the reader bound")
)

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
	// EgressPolicy is absent while the workload's policy is not realized. The
	// workload is then still a destination, but no destination admits it as
	// a source.
	EgressPolicy *SourceEgressPolicy `json:"egressPolicy,omitempty"`
}

// SourceEgressPolicy is the realized native egress map of one published
// workload, in the policy package's native wire format. Its digest binds the
// wire content only; the receiver supplies the owner cluster when decoding,
// and the record's lease and membership remain the authority for the source.
type SourceEgressPolicy struct {
	Version          uint8  `json:"version"`
	PolicyRevision   uint64 `json:"policyRevision"`
	SelectorRevision uint64 `json:"selectorRevision"`
	Digest           string `json:"digest"`
	Wire             []byte `json:"wire"`
}

// Clone returns a copy that shares no memory with p.
func (p *SourceEgressPolicy) Clone() *SourceEgressPolicy {
	if p == nil {
		return nil
	}
	clone := *p
	clone.Wire = append([]byte(nil), p.Wire...)
	return &clone
}

// Validate checks the envelope's shape and that its digest is the wire's own.
// policy.DecodeNativeZtunnelL4 verifies the content when the policy is used.
func (p *SourceEgressPolicy) Validate() error {
	if p == nil || p.Version != SourceEgressPolicyVersion || p.PolicyRevision == 0 || p.SelectorRevision == 0 ||
		len(p.Wire) <= sha256.Size || len(p.Wire) > policy.MaxNativeZtunnelL4WireBytes {
		return fmt.Errorf("source egress policy has an invalid version, revision or size")
	}
	if p.Digest != hex.EncodeToString(p.Wire[len(p.Wire)-sha256.Size:]) {
		return fmt.Errorf("source egress policy digest does not match its wire")
	}
	return nil
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
// Revalidate returns nil only when live Namespace/Pod identity, sandbox, and a
// ZDS ADD acknowledged by the live ztunnel execution are current for the
// captured membership, re-admitting the endpoint first when they are not.
// EgressPolicy returns the realized egress policy of the workload a snapshot
// describes, waiting until the context ends while a regeneration is pending.
type SourceEndpointProvider interface {
	Revalidate(context.Context, uint16) error
	Read(uint16) (sourceEndpointSnapshot, error)
	EgressPolicy(context.Context, sourceEndpointSnapshot) (*SourceEgressPolicy, error)
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
	return ensureAdmitted(ctx, ep, p.revalidators)
}

// ensureAdmitted keeps a lease refresh from changing a current capture.
// Re-admission quarantines the endpoint and starts a new capture generation,
// so it runs only when the current evidence no longer verifies (for example
// after a ztunnel or agent restart).
func ensureAdmitted(ctx context.Context, ep *endpoint.Endpoint, revalidators []EndpointRevalidator) error {
	if len(revalidators) == 0 {
		return fmt.Errorf("strict endpoint revalidator is unavailable")
	}
	for _, revalidator := range revalidators {
		if revalidator == nil {
			return fmt.Errorf("strict endpoint revalidator is nil")
		}
		if err := revalidator.EnsureEndpoint(ctx, ep, StageSourceVerification); err != nil {
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

func (p ciliumSourceEndpointProvider) EgressPolicy(ctx context.Context, snapshot sourceEndpointSnapshot) (*SourceEgressPolicy, error) {
	for {
		ep := p.endpoints.LookupCiliumID(snapshot.EndpointID)
		if ep == nil || !ep.IsAlive() {
			return nil, fmt.Errorf("required Cilium endpoint %d is unavailable", snapshot.EndpointID)
		}
		release, err := ep.SnapshotZtunnelReleaseCandidate()
		if err == nil {
			return sourceEgressPolicy(release, snapshot)
		}
		if !sleepContext(ctx, sourcePolicyRealizationPoll) {
			return nil, err
		}
	}
}

// sourceEgressPolicy exports a release candidate's egress map only when the
// candidate, read under one endpoint lock, is the workload incarnation the
// published entry describes: the same capture publication, Pod, identity and
// addresses.
func sourceEgressPolicy(release endpoint.ZtunnelReleaseCandidate, snapshot sourceEndpointSnapshot) (*SourceEgressPolicy, error) {
	subject := release.Subject
	addresses := make([]string, 0, len(subject.Addresses))
	for _, addr := range subject.Addresses {
		addresses = append(addresses, addr.Unmap().String())
	}
	sort.Strings(addresses)
	if !release.HasMembership || release.Membership != snapshot.Membership || subject.EndpointID != snapshot.EndpointID ||
		subject.NamespaceUID != snapshot.NamespaceUID || subject.PodUID != snapshot.PodUID ||
		subject.ServiceAccount != snapshot.ServiceAccount || subject.NumericIdentity != snapshot.Identity ||
		!slices.Equal(addresses, snapshot.Addresses) {
		return nil, fmt.Errorf("realized policy belongs to another workload incarnation")
	}
	egress, err := subject.Policy.Egress()
	if err != nil {
		return nil, err
	}
	wire, digest, err := egress.MarshalNative()
	if err != nil {
		return nil, err
	}
	exported := &SourceEgressPolicy{Version: SourceEgressPolicyVersion, PolicyRevision: egress.Revision(),
		SelectorRevision: egress.SelectorRevision(), Digest: digest, Wire: wire}
	if err := exported.Validate(); err != nil {
		return nil, err
	}
	return exported, nil
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

	// egressAbsent is the reason each workload was last published without
	// its egress policy. Only the publishing goroutine uses it.
	egressAbsent map[Reference]string
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
	provider := ciliumSourceEndpointProvider{endpoints: endpoints, revalidators: revalidators}
	publisher, err := newSourcePublisher(registry, provider, sourceMembershipBackendAdapter{Client: backend}, logger, cfg, snapshot.Epoch)
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
		egressAbsent: make(map[Reference]string),
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
	waitStarted := time.Now() // A writer that ended without unlocking holds the lock until its lease expires.
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
		p.logger.Info("Acquired source membership writer lock",
			logSourceStage, "lock",
			logfields.ClusterName, p.config.ClusterInfo.Name,
			logfields.Attempt, attempt,
			logfields.ElapsedDuration, time.Since(waitStarted))
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
		waitStarted = time.Now()
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
	if capturedEntries(initial) > p.config.MaxWorkloads {
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
	if current.Epoch != p.epoch || capturedEntries(current) > p.config.MaxWorkloads {
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
	// One wait budget for the whole record: a regenerating endpoint delays
	// this refresh by at most sourcePolicyRealizationWait.
	egressCtx, cancelEgress := context.WithTimeout(revalidationCtx, sourcePolicyRealizationWait)
	defer cancelEgress()
	absent := make(map[Reference]string)
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
		egress, err := p.endpoints.EgressPolicy(egressCtx, snapshot)
		if err != nil {
			absent[entry.Reference] = err.Error()
		}
		entryWire.EgressPolicy = egress
		endpointSnapshots[entry.Reference] = snapshot
		record.Workloads = append(record.Workloads, entryWire)
	}
	p.logEgressAbsence(absent)
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
	switch {
	case errors.Is(err, ErrSourcePublicationStale):
		return p.publishInvalid(ctx, locker, p.registry.SourceSnapshot(), "source_snapshot_changed_before_write")
	case errors.Is(err, ErrSourceRecordTooLarge):
		return p.publishInvalid(ctx, locker, current, "record_too_large")
	}
	return err
}

// logEgressAbsence logs when a workload starts or stops being published
// without its egress policy, not on every refresh.
func (p *SourcePublisher) logEgressAbsence(absent map[Reference]string) {
	for ref, reason := range absent {
		if p.egressAbsent[ref] != reason {
			p.logger.Info("Publishing source workload without its egress policy; no destination admits it as a source",
				logSourceStage, "source-egress",
				logfields.PodUID, ref.Key.PodUID,
				logfields.Reason, reason)
		}
	}
	for ref := range p.egressAbsent {
		if _, ok := absent[ref]; !ok {
			p.logger.Info("Publishing source workload egress policy again",
				logSourceStage, "source-egress",
				logfields.PodUID, ref.Key.PodUID)
		}
	}
	p.egressAbsent = absent
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
	if len(data) > MaxSourceMembershipRecordBytes {
		return fmt.Errorf("%w: %d bytes", ErrSourceRecordTooLarge, len(data))
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

// capturedEntries counts the workloads a record would publish. Required and
// Draining entries are never published, so they do not count toward the bound.
func capturedEntries(snapshot SourceSnapshot) int {
	n := 0
	for _, entry := range snapshot.Entries {
		if entry.Publication.State == PublicationCaptured {
			n++
		}
	}
	return n
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
