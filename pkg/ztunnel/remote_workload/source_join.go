// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package remote_workload

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"sync"

	"k8s.io/apimachinery/pkg/util/validation"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/ztunnel/membership"
)

const (
	maxSourceMembershipWorkloads = 8
	maxSourceMembershipAddresses = 2
	maxSourceMembershipNodes     = 1024
	maxSourceAgentEpochsPerNode  = 32
	logSourceJoinStage           = "stage"
	defaultReaderLeaseTTL        = 30 * time.Second
	maxReaderLeaseTTL            = time.Minute
)

// SourceMembershipKey decodes one complete per-node source record. Its key is
// the node name relative to SourceMembershipPrefix. Unknown JSON fields and
// trailing data fail the entire source watch session closed.
type SourceMembershipKey struct {
	NodeName string
	Record   membership.SourceMembershipRecord
}

var _ store.Key = (*SourceMembershipKey)(nil)

func (k *SourceMembershipKey) GetKeyName() string { return k.NodeName }

func (k *SourceMembershipKey) Marshal() ([]byte, error) { return json.Marshal(k.Record) }

func (k *SourceMembershipKey) Unmarshal(key string, data []byte) error {
	if problems := validation.IsDNS1123Subdomain(key); len(problems) != 0 {
		return fmt.Errorf("invalid source membership node key")
	}
	if len(data) == 0 || len(data) > membership.MaxSourceMembershipRecordBytes {
		return fmt.Errorf("source membership record size is invalid")
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var record membership.SourceMembershipRecord
	if err := decoder.Decode(&record); err != nil {
		return fmt.Errorf("decode source membership record: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("source membership record has trailing JSON")
		}
		return fmt.Errorf("decode trailing source membership data: %w", err)
	}
	if err := validateSourceMembershipRecord(key, record); err != nil {
		return err
	}
	k.NodeName = key
	k.Record = record
	return nil
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var readValue func() error
	readValue = func() error {
		token, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("decode source membership JSON token: %w", err)
		}
		delimiter, isDelimiter := token.(json.Delim)
		if !isDelimiter {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return fmt.Errorf("decode source membership JSON object key: %w", err)
				}
				key, ok := keyToken.(string)
				if !ok {
					return fmt.Errorf("source membership JSON object contains a non-string key")
				}
				if _, exists := seen[key]; exists {
					return fmt.Errorf("source membership JSON contains duplicate field %q", key)
				}
				seen[key] = struct{}{}
				if err := readValue(); err != nil {
					return err
				}
			}
			if _, err := decoder.Token(); err != nil {
				return fmt.Errorf("finish source membership JSON object: %w", err)
			}
		case '[':
			for decoder.More() {
				if err := readValue(); err != nil {
					return err
				}
			}
			if _, err := decoder.Token(); err != nil {
				return fmt.Errorf("finish source membership JSON array: %w", err)
			}
		default:
			return fmt.Errorf("source membership JSON has an unexpected delimiter")
		}
		return nil
	}
	if err := readValue(); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("source membership record has trailing JSON")
		}
		return fmt.Errorf("decode trailing source membership data: %w", err)
	}
	return nil
}

func validateSourceMembershipRecord(key string, record membership.SourceMembershipRecord) error {
	if record.Version != 1 || record.NodeName != key || strings.TrimSpace(record.AgentEpoch) != record.AgentEpoch || record.AgentEpoch == "" || len(record.AgentEpoch) > 128 {
		return fmt.Errorf("source membership record has invalid version, node, or agent epoch")
	}
	if record.ClusterName == "" || cmtypes.ValidateClusterName(record.ClusterName) != nil || cmtypes.ValidateClusterID(record.ClusterID) != nil {
		return fmt.Errorf("source membership record has invalid cluster identity")
	}
	if record.Generation == 0 || record.LeaseTTLSeconds < 1 || record.LeaseTTLSeconds > int64(maxReaderLeaseTTL/time.Second) {
		return fmt.Errorf("source membership record has invalid generation or lease TTL")
	}
	if len(record.Workloads) > maxSourceMembershipWorkloads {
		return fmt.Errorf("source membership record exceeds workload limit")
	}
	if len(record.Workloads) > 0 && record.RegistryRevision == 0 {
		return fmt.Errorf("source membership record has workloads without a registry revision")
	}
	if !record.Valid && len(record.Workloads) != 0 {
		return fmt.Errorf("invalid source membership record contains workloads")
	}
	seenPods := make(map[string]struct{}, len(record.Workloads))
	seenAddresses := make(map[string]struct{}, len(record.Workloads)*maxSourceMembershipAddresses)
	for _, workload := range record.Workloads {
		if workload.EndpointID == 0 || workload.EndpointIncarnation == 0 || workload.MembershipRevision == 0 || workload.ZDSGeneration == 0 ||
			workload.MembershipEpoch != record.AgentEpoch || workload.NodeName != key || workload.Namespace == "" || workload.NamespaceUID == "" ||
			workload.PodName == "" || workload.PodUID == "" || workload.ServiceAccount == "" || workload.Identity == 0 ||
			strings.TrimSpace(workload.NamespaceUID) != workload.NamespaceUID || strings.TrimSpace(workload.PodUID) != workload.PodUID {
			return fmt.Errorf("source membership record contains an incomplete workload identity")
		}
		if len(validation.IsDNS1123Label(workload.Namespace)) != 0 || len(validation.IsDNS1123Subdomain(workload.PodName)) != 0 ||
			len(validation.IsDNS1123Subdomain(workload.ServiceAccount)) != 0 {
			return fmt.Errorf("source membership record contains invalid Kubernetes names")
		}
		podKey := workload.NamespaceUID + "/" + workload.PodUID
		if _, exists := seenPods[podKey]; exists {
			return fmt.Errorf("source membership record contains a duplicate Pod incarnation")
		}
		seenPods[podKey] = struct{}{}
		if len(workload.Addresses) == 0 || len(workload.Addresses) > maxSourceMembershipAddresses {
			return fmt.Errorf("source membership record contains invalid address count")
		}
		for _, address := range workload.Addresses {
			parsed, err := netip.ParseAddr(address)
			if err != nil || !parsed.IsValid() || parsed.Zone() != "" || !parsed.IsGlobalUnicast() || parsed.IsUnspecified() || parsed.IsLoopback() || parsed.IsMulticast() || parsed.IsLinkLocalUnicast() || parsed.Unmap().String() != address {
				return fmt.Errorf("source membership record contains a noncanonical workload address")
			}
			if _, exists := seenAddresses[address]; exists {
				return fmt.Errorf("source membership record contains a duplicate address")
			}
			seenAddresses[address] = struct{}{}
		}
		if workload.EgressPolicy != nil {
			if err := workload.EgressPolicy.Validate(); err != nil {
				return fmt.Errorf("source membership record contains an invalid egress policy: %w", err)
			}
		}
	}
	return nil
}

type receivedSourceMembership struct {
	key       SourceMembershipKey
	expiresAt time.Time
}

type sourceMembershipFloor struct {
	generation       uint64
	registryRevision uint64
	digest           [sha256.Size]byte
	expiresAt        time.Time
	deleted          bool
}

// SourceMembershipJoiner joins the existing IPIdentity watch with a separate
// direct-origin watch of short-lived source membership records. It never reads
// KVStoreMesh cache records. The current trust boundary is the configured
// authenticated Cilium peer and its cluster-wide Cilium writer credentials;
// this does not claim per-node cryptographic signatures or workload-mTLS.
//
// A valid output snapshot requires both initial lists to finish. Every output
// workload must match its source lease by cluster, node, namespace UID, Pod UID,
// names, ServiceAccount, numeric identity, address set, membership epoch and
// fresh ZDS generation. The sink must be bounded and nonblocking.
type SourceMembershipJoiner struct {
	mu lock.Mutex

	clusterName string
	clusterID   uint32
	maxLeaseTTL time.Duration
	now         func() time.Time
	logger      *slog.Logger
	sink        SnapshotSink

	ipSnapshot       Snapshot
	haveIP           bool
	sourceListed     bool
	sourceInvalid    bool
	sourceSession    uint64
	outputGeneration uint64
	leases           map[string]receivedSourceMembership
	// Floors survive Watch Begin/End in this process. A full-list replay of an
	// unchanged key cannot restart its local TTL or roll back an agent epoch.
	floors        map[string]map[string]sourceMembershipFloor
	currentEpoch  map[string]string
	cancelSession func()
	onReady       func()
	readyOnce     sync.Once
}

var _ SnapshotSink = (*SourceMembershipJoiner)(nil)
var _ store.Observer = (*SourceMembershipJoiner)(nil)
var _ store.WatchSessionObserver = (*SourceMembershipJoiner)(nil)

func NewSourceMembershipJoiner(clusterName string, clusterID uint32, logger *slog.Logger, sink SnapshotSink) (*SourceMembershipJoiner, error) {
	if logger == nil || sink == nil || clusterName == "" || cmtypes.ValidateClusterName(clusterName) != nil || cmtypes.ValidateClusterID(clusterID) != nil {
		return nil, fmt.Errorf("source membership joiner requires valid peer identity, logger, and sink")
	}
	return &SourceMembershipJoiner{
		clusterName:  clusterName,
		clusterID:    clusterID,
		maxLeaseTTL:  defaultReaderLeaseTTL,
		now:          time.Now,
		logger:       logger.With(logfields.LogSubsys, "ztunnel-source-membership-join"),
		sink:         sink,
		leases:       make(map[string]receivedSourceMembership),
		floors:       make(map[string]map[string]sourceMembershipFloor),
		currentEpoch: make(map[string]string),
	}, nil
}

// Begin starts a new source-record list epoch and immediately withdraws the
// prior joined view. Previously cached KVStore IPIdentity entries remain
// unusable until both lists have completed and their identities join exactly.
func (j *SourceMembershipJoiner) Begin(_ context.Context) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.sourceSession++
	j.sourceListed = false
	j.sourceInvalid = false
	j.leases = make(map[string]receivedSourceMembership)
	j.publishLocked(false, "source membership list started", nil, time.Time{})
}

func (j *SourceMembershipJoiner) ListDone(context.Context) {
	j.mu.Lock()
	if j.sourceInvalid {
		j.mu.Unlock()
		return
	}
	j.sourceListed = true
	notifyReady := j.publishJoinedLocked()
	j.mu.Unlock()
	if notifyReady != nil {
		notifyReady()
	}
}

func (j *SourceMembershipJoiner) Invalid(key string, err error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.invalidateLocked(fmt.Sprintf("invalid source membership record %q: %v", key, err))
}

func (j *SourceMembershipJoiner) End(context.Context) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.sourceListed = false
	j.leases = make(map[string]receivedSourceMembership)
	j.invalidateLocked("source membership watch ended")
}

// Invalidate synchronously withdraws every joined workload for a peer. The
// observer calls it before a direct-origin backend is canceled or closed.
func (j *SourceMembershipJoiner) Invalidate(reason string) {
	j.mu.Lock()
	j.invalidateLocked(reason)
	j.mu.Unlock()
}

func (j *SourceMembershipJoiner) OnUpdate(key store.Key) {
	entry, ok := key.(*SourceMembershipKey)
	if !ok || entry == nil {
		j.Invalid("<unknown>", fmt.Errorf("unexpected source membership key type %T", key))
		return
	}
	if err := validateSourceMembershipRecord(entry.NodeName, entry.Record); err != nil {
		j.Invalid(entry.NodeName, err)
		return
	}
	if entry.Record.ClusterName != j.clusterName || entry.Record.ClusterID != j.clusterID {
		j.Invalid(entry.NodeName, fmt.Errorf("source record cluster does not match authenticated direct peer"))
		return
	}
	digest, err := digestSourceMembershipRecord(entry.Record)
	if err != nil {
		j.Invalid(entry.NodeName, err)
		return
	}

	j.mu.Lock()
	var notifyReady func()
	defer func() {
		j.mu.Unlock()
		if notifyReady != nil {
			notifyReady()
		}
	}()
	if j.sourceInvalid {
		return
	}
	currentEpoch := j.currentEpoch[entry.NodeName]
	if _, knownNode := j.floors[entry.NodeName]; !knownNode && len(j.floors) >= maxSourceMembershipNodes {
		j.invalidateLocked("source membership node limit exceeded")
		return
	}
	if currentEpoch != "" && entry.Record.AgentEpoch != currentEpoch {
		// A live stream must first withdraw the old epoch. On a fresh full
		// list the current trusted origin may already have overwritten its
		// transient generation-one reset. Accept an unseen epoch only behind
		// that complete-list barrier; never accept a previously retired one.
		if j.sourceListed && (entry.Record.Generation != 1 || len(entry.Record.Workloads) != 0) {
			j.invalidateLocked("source agent epoch changed without an empty reset or fresh complete list")
			return
		}
		if _, seen := j.floors[entry.NodeName][entry.Record.AgentEpoch]; seen {
			j.invalidateLocked("source agent epoch was replayed after rotation")
			return
		}
		if len(j.floors[entry.NodeName]) >= maxSourceAgentEpochsPerNode {
			j.invalidateLocked("source agent epoch history limit exceeded")
			return
		}
	} else if currentEpoch == "" {
		j.currentEpoch[entry.NodeName] = entry.Record.AgentEpoch
	}
	if byEpoch := j.floors[entry.NodeName]; byEpoch != nil {
		if floor, seen := byEpoch[entry.Record.AgentEpoch]; seen {
			if entry.Record.Generation < floor.generation {
				j.invalidateLocked("source membership generation rolled back")
				return
			}
			if entry.Record.Generation > floor.generation && entry.Record.RegistryRevision < floor.registryRevision {
				j.invalidateLocked("source registry revision rolled back")
				return
			}
			if entry.Record.Generation == floor.generation {
				if floor.deleted {
					j.invalidateLocked("deleted source membership generation was replayed")
					return
				}
				if digest != floor.digest {
					j.invalidateLocked("conflicting source membership reused a generation")
					return
				}
				if !j.now().Before(floor.expiresAt) {
					// Replayed bytes after their original receive deadline do not
					// renew the lease. Wait for a newer source generation.
					delete(j.leases, entry.NodeName)
					if j.sourceListed {
						notifyReady = j.publishJoinedLocked()
					}
					return
				}
				j.leases[entry.NodeName] = receivedSourceMembership{
					key:       SourceMembershipKey{NodeName: entry.NodeName, Record: cloneSourceRecord(entry.Record)},
					expiresAt: floor.expiresAt,
				}
				if j.sourceListed {
					notifyReady = j.publishJoinedLocked()
				}
				return
			}
		}
	}
	received := j.now()
	ttl := time.Duration(entry.Record.LeaseTTLSeconds) * time.Second
	ttl = min(ttl, j.maxLeaseTTL)
	if j.floors[entry.NodeName] == nil {
		j.floors[entry.NodeName] = make(map[string]sourceMembershipFloor)
	}
	floor := sourceMembershipFloor{
		generation:       entry.Record.Generation,
		registryRevision: entry.Record.RegistryRevision,
		digest:           digest,
		expiresAt:        received.Add(ttl),
	}
	j.floors[entry.NodeName][entry.Record.AgentEpoch] = floor
	j.currentEpoch[entry.NodeName] = entry.Record.AgentEpoch
	j.leases[entry.NodeName] = receivedSourceMembership{
		key:       SourceMembershipKey{NodeName: entry.NodeName, Record: cloneSourceRecord(entry.Record)},
		expiresAt: floor.expiresAt,
	}
	if j.sourceListed {
		notifyReady = j.publishJoinedLocked()
	}
}

func (j *SourceMembershipJoiner) OnDelete(key store.NamedKey) {
	entry, ok := key.(*SourceMembershipKey)
	if !ok || entry == nil || entry.NodeName == "" {
		j.Invalid("<delete>", fmt.Errorf("unexpected source membership delete key type %T", key))
		return
	}
	j.mu.Lock()
	var notifyReady func()
	defer func() {
		j.mu.Unlock()
		if notifyReady != nil {
			notifyReady()
		}
	}()
	if epoch := j.currentEpoch[entry.NodeName]; epoch != "" {
		if byEpoch := j.floors[entry.NodeName]; byEpoch != nil {
			floor, exists := byEpoch[epoch]
			if exists {
				floor.deleted = true
				byEpoch[epoch] = floor
			}
		}
	}
	delete(j.leases, entry.NodeName)
	if j.sourceListed && !j.sourceInvalid {
		notifyReady = j.publishJoinedLocked()
	}
}

// SetSessionCancel joins malformed lease data or peer/session invalidation to
// the shared two-watch context. It must be set before the watches start.
func (j *SourceMembershipJoiner) SetSessionCancel(cancel func()) {
	j.mu.Lock()
	j.cancelSession = cancel
	j.mu.Unlock()
}

// SetOnReady installs a bounded notification for the first joined snapshot.
// It runs once after both the IPIdentity and source membership lists are valid.
func (j *SourceMembershipJoiner) SetOnReady(callback func()) {
	j.mu.Lock()
	j.onReady = callback
	j.mu.Unlock()
}

// Expire withdraws records whose receiver-local monotonic lease deadline has
// passed. It is called by the bounded watch-session reaper even if etcd's
// delete notification is delayed. IssuedAt and writer-provided wall-clock
// timestamps are never used to extend the lease.
func (j *SourceMembershipJoiner) Expire(now time.Time) {
	j.mu.Lock()
	var notifyReady func()
	defer func() {
		j.mu.Unlock()
		if notifyReady != nil {
			notifyReady()
		}
	}()
	changed := j.expireLeasesLocked(now)
	peerDeadline := peerEvidenceDeadline(j.ipSnapshot)
	if !peerDeadline.IsZero() && !now.Before(peerDeadline) {
		j.invalidateLocked("remote TLS certificate or etcd heartbeat evidence expired")
		return
	}
	if changed && j.sourceListed && !j.sourceInvalid {
		notifyReady = j.publishJoinedLocked()
	}
}

func (j *SourceMembershipJoiner) Ready() bool {
	j.mu.Lock()
	var notifyReady func()
	if j.expireLeasesLocked(j.now()) {
		notifyReady = j.publishJoinedLocked()
	}
	deadline := peerEvidenceDeadline(j.ipSnapshot)
	if !deadline.IsZero() && !j.now().Before(deadline) {
		j.invalidateLocked("remote TLS certificate or etcd heartbeat evidence expired")
		j.mu.Unlock()
		if notifyReady != nil {
			notifyReady()
		}
		return false
	}
	ready := j.sourceListed && !j.sourceInvalid && j.haveIP && j.ipSnapshot.Valid
	j.mu.Unlock()
	if notifyReady != nil {
		notifyReady()
	}
	return ready
}

// PublishRemoteWorkloadSnapshot receives the raw, independently validated
// IPIdentity snapshot. It is not forwarded until source leases have completed
// their list and exact workload matches are available.
func (j *SourceMembershipJoiner) PublishRemoteWorkloadSnapshot(snapshot Snapshot) {
	j.mu.Lock()
	var notifyReady func()
	j.ipSnapshot = cloneSnapshot(snapshot)
	j.haveIP = true
	if snapshot.Valid && j.sourceListed && !j.sourceInvalid {
		notifyReady = j.publishJoinedLocked()
	} else {
		j.publishLocked(false, snapshot.Reason, nil, time.Time{})
	}
	if !snapshot.Valid && snapshot.Reason != "" {
		// The inventory has no logger; without this its reason (a refused
		// record ends the whole watch session) appears nowhere.
		j.logger.Warn("Remote IP identity snapshot is invalid",
			logSourceJoinStage, "ip-identity",
			logfields.Reason, snapshot.Reason,
			logfields.ClusterName, j.clusterName)
	}
	j.mu.Unlock()
	if notifyReady != nil {
		notifyReady()
	}
}

func (j *SourceMembershipJoiner) invalidateLocked(reason string) {
	wasInvalid := j.sourceInvalid
	j.sourceInvalid = true
	j.sourceListed = false
	j.leases = make(map[string]receivedSourceMembership)
	j.publishLocked(false, reason, nil, time.Time{})
	if !wasInvalid && j.cancelSession != nil {
		j.cancelSession()
	}
	j.logger.Warn("Remote workload source membership was withdrawn",
		logSourceJoinStage, "source-lease",
		logfields.Reason, reason,
		logfields.ClusterName, j.clusterName)
}

func (j *SourceMembershipJoiner) publishJoinedLocked() func() {
	if !j.haveIP || !j.ipSnapshot.Valid || !j.sourceListed || j.sourceInvalid {
		j.publishLocked(false, "source membership and IP identity lists are not both current", nil, time.Time{})
		return nil
	}
	now := j.now()
	j.expireLeasesLocked(now)
	peerDeadline := peerEvidenceDeadline(j.ipSnapshot)
	if !peerDeadline.IsZero() && !now.Before(peerDeadline) {
		j.invalidateLocked("remote TLS certificate or etcd heartbeat evidence expired")
		return nil
	}

	byPod := make(map[string]membership.SourceMembershipEntry)
	byPodUID := make(map[string]membership.SourceMembershipEntry)
	leaseDeadline := time.Time{}
	for _, source := range j.leases {
		record := source.key.Record
		if record.ClusterName != j.clusterName || record.ClusterID != j.clusterID || !record.Valid {
			continue
		}
		if leaseDeadline.IsZero() || source.expiresAt.Before(leaseDeadline) {
			leaseDeadline = source.expiresAt
		}
		for _, workload := range record.Workloads {
			// A Pod UID names one incarnation in the whole cluster; a native
			// IP record is matched by it alone.
			podKey := workload.NamespaceUID + "/" + workload.PodUID
			_, duplicate := byPod[podKey]
			_, duplicateUID := byPodUID[workload.PodUID]
			if duplicate || duplicateUID {
				j.invalidateLocked("source leases contain a duplicate Pod incarnation")
				return nil
			}
			byPod[podKey] = workload
			byPodUID[workload.PodUID] = workload
		}
	}
	if leaseDeadline.IsZero() {
		j.invalidateLocked("no live source membership lease is available")
		return nil
	}
	if peerDeadline := peerEvidenceDeadline(j.ipSnapshot); !peerDeadline.IsZero() && peerDeadline.Before(leaseDeadline) {
		leaseDeadline = peerDeadline
	}

	workloads := make([]Workload, 0, len(j.ipSnapshot.Workloads))
	for _, ipWorkload := range j.ipSnapshot.Workloads {
		if ipWorkload.MembershipState == unannotatedMembership {
			source, exists := byPodUID[ipWorkload.Key.PodUID]
			if exists && sourceMatchesNativeIPWorkload(j.clusterID, source, ipWorkload) {
				workloads = append(workloads, joinNativeIPWorkload(source, ipWorkload))
			}
			continue
		}
		source, exists := byPod[ipWorkload.Key.NamespaceUID+"/"+ipWorkload.Key.PodUID]
		if !exists || !sourceMatchesIPWorkload(j.clusterID, source, ipWorkload) {
			continue
		}
		workloads = append(workloads, cloneWorkload(ipWorkload))
	}
	sort.Slice(workloads, func(i, k int) bool {
		if workloads[i].Key.NamespaceUID != workloads[k].Key.NamespaceUID {
			return workloads[i].Key.NamespaceUID < workloads[k].Key.NamespaceUID
		}
		return workloads[i].Key.PodUID < workloads[k].Key.PodUID
	})
	j.publishLocked(true, "", workloads, leaseDeadline)
	if j.onReady != nil {
		var callback func()
		j.readyOnce.Do(func() { callback = j.onReady })
		return callback
	}
	return nil
}

func (j *SourceMembershipJoiner) publishLocked(valid bool, reason string, workloads []Workload, leaseDeadline time.Time) {
	j.outputGeneration++
	out := cloneSnapshot(j.ipSnapshot)
	out.Generation = j.outputGeneration
	out.ClusterName = j.clusterName
	out.ClusterID = j.clusterID
	out.Valid = valid
	out.Reason = reason
	if valid {
		out.Workloads = workloads
		out.SourceMembershipSessionEpoch = j.sourceSession
		out.SourceMembershipLeaseValidUntil = leaseDeadline
	} else {
		out.Workloads = []Workload{}
		out.SourceMembershipLeaseValidUntil = time.Time{}
	}
	j.sink.PublishRemoteWorkloadSnapshot(out)
}

func (j *SourceMembershipJoiner) expireLeasesLocked(now time.Time) bool {
	changed := false
	for node, record := range j.leases {
		if !now.Before(record.expiresAt) {
			delete(j.leases, node)
			changed = true
		}
	}
	return changed
}

func peerEvidenceDeadline(snapshot Snapshot) time.Time {
	deadline := snapshot.PeerCertificateNotAfter
	if !snapshot.PeerHeartbeatAt.IsZero() {
		heartbeatDeadline := snapshot.PeerHeartbeatAt.Add(2 * kvstore.HeartbeatWriteInterval)
		if deadline.IsZero() || heartbeatDeadline.Before(deadline) {
			deadline = heartbeatDeadline
		}
	}
	return deadline
}

// runSourceMembershipWatchPair owns both direct-origin watches as one source
// epoch. Either watcher ending revokes the joined snapshot and stops the other
// before a reconnect can begin. The peer-evidence guard refreshes the bounded
// certificate/heartbeat deadline in the joined snapshot; it does not refresh a
// source lease or turn the result into authorization.
func runSourceMembershipWatchPair(
	ctx context.Context,
	backend kvstore.BackendOperations,
	workloadWatch store.WatchStore,
	workloadPrefix string,
	sourceWatch store.WatchStore,
	sourcePrefix string,
	inventory *Inventory,
	joiner *SourceMembershipJoiner,
	provider kvstore.RemotePeerEvidenceProvider,
	clusterName string,
	clusterID uint32,
) error {
	if backend == nil || workloadWatch == nil || sourceWatch == nil || inventory == nil || joiner == nil || provider == nil {
		return fmt.Errorf("direct-origin paired watch dependencies are incomplete")
	}
	evidence, err := provider.CurrentRemotePeerEvidence()
	if err != nil {
		return fmt.Errorf("read direct-origin peer evidence before watch: %w", err)
	}
	if evidence == nil || evidence.ClusterName() != clusterName || evidence.ClusterID() != clusterID {
		return fmt.Errorf("direct-origin peer identity does not match paired watch")
	}
	if err := evidence.Validate(time.Now()); err != nil {
		return fmt.Errorf("direct-origin peer evidence is not current: %w", err)
	}
	identityEpoch, profileID := evidence.IdentityEpoch(), evidence.ProfileID()

	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	inventory.SetSessionCancel(cancel)
	joiner.SetSessionCancel(cancel)
	defer inventory.SetSessionCancel(nil)
	defer joiner.SetSessionCancel(nil)

	watchGroup := sync.WaitGroup{}
	watchGroup.Add(2)
	watchDone := make(chan struct{})
	go func() {
		defer watchGroup.Done()
		workloadWatch.Watch(sessionCtx, backend, workloadPrefix)
	}()
	go func() {
		defer watchGroup.Done()
		sourceWatch.Watch(sessionCtx, backend, sourcePrefix)
	}()
	go func() {
		watchGroup.Wait()
		close(watchDone)
	}()

	guardErr := make(chan error, 1)
	guardDone := make(chan struct{})
	go func() {
		defer close(guardDone)
		ticker := time.NewTicker(peerEvidenceRecheckInterval)
		defer ticker.Stop()
		for {
			select {
			case <-sessionCtx.Done():
				return
			case <-ticker.C:
				current, err := provider.CurrentRemotePeerEvidence()
				if err == nil && current == nil {
					err = fmt.Errorf("direct-origin evidence provider returned no evidence")
				}
				if err == nil && (current.IdentityEpoch() != identityEpoch || current.ProfileID() != profileID) {
					err = fmt.Errorf("direct-origin TLS identity changed; a fresh complete watch list is required")
				}
				if err == nil {
					err = current.Validate(time.Now())
				}
				if err == nil {
					err = inventory.CheckPeerEvidence()
				}
				if err != nil {
					select {
					case guardErr <- err:
					default:
					}
					inventory.Invalidate("direct-origin peer evidence changed: " + err.Error())
					cancel()
					return
				}
			}
		}
	}()

	reaperDone := make(chan struct{})
	go func() {
		defer close(reaperDone)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-sessionCtx.Done():
				return
			case now := <-ticker.C:
				joiner.Expire(now)
			}
		}
	}()

	select {
	case <-ctx.Done():
	case <-sessionCtx.Done():
	case <-watchDone:
	}
	cancel()
	<-watchDone
	<-guardDone
	<-reaperDone
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case err := <-guardErr:
		return fmt.Errorf("direct-origin peer evidence guard failed: %w", err)
	default:
	}
	return fmt.Errorf("direct-origin source or IPIdentity watch ended before cancellation")
}

func sourceMatchesIPWorkload(clusterID uint32, source membership.SourceMembershipEntry, ip Workload) bool {
	if ip.Key.ClusterID != clusterID || ip.MembershipState != "captured" || ip.MembershipEpoch != source.MembershipEpoch ||
		ip.MembershipGeneration != source.ZDSGeneration || source.MembershipRevision == 0 || source.ZDSGeneration == 0 ||
		source.MembershipEpoch == "" || source.MembershipEpoch != strings.TrimSpace(source.MembershipEpoch) ||
		source.NodeName != ip.NodeName || source.Namespace != ip.Namespace || source.NamespaceUID != ip.Key.NamespaceUID ||
		source.PodName != ip.PodName || source.PodUID != ip.Key.PodUID || source.ServiceAccount != ip.ServiceAccount || uint32(ip.Identity) != source.Identity {
		return false
	}
	ipAddresses := make([]string, len(ip.Addresses))
	for i, address := range ip.Addresses {
		ipAddresses[i] = address.Unmap().String()
	}
	sourceAddresses := append([]string(nil), source.Addresses...)
	sort.Strings(ipAddresses)
	sort.Strings(sourceAddresses)
	return reflect.DeepEqual(ipAddresses, sourceAddresses)
}

// sourceMatchesNativeIPWorkload matches a record without membership (see
// unannotatedMembership) to its source entry on every field both carry: the
// Pod, its ServiceAccount, its Cilium identity and its exact address set.
// The namespace UID and node are compared when the record has them.
func sourceMatchesNativeIPWorkload(clusterID uint32, source membership.SourceMembershipEntry, ip Workload) bool {
	if ip.MembershipEpoch != "" || ip.MembershipGeneration != 0 ||
		(ip.Key.NamespaceUID != "" && ip.Key.NamespaceUID != source.NamespaceUID) ||
		(ip.NodeName != "" && ip.NodeName != source.NodeName) {
		return false
	}
	joined := joinNativeIPWorkload(source, ip)
	return sourceMatchesIPWorkload(clusterID, source, joined)
}

// joinNativeIPWorkload completes a native record from its source entry: the
// source lease is the only witness of the namespace UID, node and capture.
func joinNativeIPWorkload(source membership.SourceMembershipEntry, ip Workload) Workload {
	joined := cloneWorkload(ip)
	joined.Key.NamespaceUID = source.NamespaceUID
	joined.NodeName = source.NodeName
	joined.MembershipEpoch = source.MembershipEpoch
	joined.MembershipGeneration = source.ZDSGeneration
	joined.MembershipState = "captured"
	return joined
}

func cloneSourceRecord(record membership.SourceMembershipRecord) membership.SourceMembershipRecord {
	clone := record
	clone.Workloads = make([]membership.SourceMembershipEntry, len(record.Workloads))
	for i := range record.Workloads {
		clone.Workloads[i] = record.Workloads[i]
		clone.Workloads[i].Addresses = append([]string(nil), record.Workloads[i].Addresses...)
		if egress := record.Workloads[i].EgressPolicy; egress != nil {
			copied := *egress
			copied.Wire = append([]byte(nil), egress.Wire...)
			clone.Workloads[i].EgressPolicy = &copied
		}
	}
	return clone
}

func digestSourceMembershipRecord(record membership.SourceMembershipRecord) ([sha256.Size]byte, error) {
	data, err := json.Marshal(record)
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("canonicalize source membership record: %w", err)
	}
	return sha256.Sum256(data), nil
}

func cloneWorkload(workload Workload) Workload {
	clone := workload
	clone.Addresses = append([]netip.Addr(nil), workload.Addresses...)
	return clone
}
