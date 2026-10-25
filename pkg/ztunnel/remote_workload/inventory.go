// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package remote_workload converts one authenticated ClusterMesh IPIdentityPair
// watch session into ordered, complete workload snapshots. It does not grant
// authorization or protection; its consumer must separately qualify capture,
// policy, TLS and ACK state.
package remote_workload

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/time"
)

// WorkloadKey fences namespace and Pod name reuse. ClusterID is supplied from
// the authenticated local peer profile, never from the IPIdentityPair.
type WorkloadKey struct {
	ClusterID    uint32
	NamespaceUID string
	PodUID       string
}

// unannotatedMembership is the MembershipState of a workload whose records
// carry no ztunnel membership: the ClusterMesh API server writes them from
// CiliumEndpoints when identities are allocated as CRDs. Such a record is
// evidence of the native IP-to-identity mapping only; the source membership
// join supplies the namespace UID, node and capture from the source lease.
const unannotatedMembership = "unannotated"

// Workload is one remote Kubernetes Pod represented by its current addresses.
type Workload struct {
	Key                  WorkloadKey
	Namespace            string
	NodeName             string
	PodName              string
	ServiceAccount       string
	Identity             identity.NumericIdentity
	MembershipEpoch      string
	MembershipGeneration uint64
	MembershipState      string
	Addresses            []netip.Addr
}

// Snapshot is a complete replacement view. Invalid=true withdraws the prior
// snapshot. Generation is strictly increasing for this observer instance.
type Snapshot struct {
	ClusterName                     string
	ClusterID                       uint32
	Generation                      uint64
	SessionEpoch                    uint64
	SourceMembershipSessionEpoch    uint64
	SourceMembershipLeaseValidUntil time.Time
	PeerIdentityEpoch               uint64
	PeerCertificateNotAfter         time.Time
	PeerHeartbeatAt                 time.Time
	EnrollmentGeneration            uint64
	PolicyGeneration                uint64
	Valid                           bool
	Workloads                       []Workload
	Reason                          string
}

// SnapshotSink must be bounded and nonblocking. WatchStore invokes this from
// its watch goroutine. A recommended implementation is a single-slot,
// latest-snapshot mailbox because every item is a complete replacement.
type SnapshotSink interface {
	PublishRemoteWorkloadSnapshot(Snapshot)
}

// Inventory consumes one authenticated remote IP-identity prefix.
// The caller must construct it only after verifying the TLS peer profile and
// checking that the advertised CiliumClusterConfig.ID equals clusterID.
type Inventory struct {
	mu lock.Mutex

	clusterName string
	clusterID   uint32
	clusterInfo cmtypes.ClusterInfo
	peer        kvstore.RemotePeerEvidenceProvider
	sink        SnapshotSink

	generation    uint64
	sessionEpoch  uint64
	peerEvidence  kvstore.RemotePeerEvidence
	listed        bool
	invalid       bool
	entries       map[string]identity.IPIdentityPair // canonical IP -> latest workload record
	onListDone    func()
	cancelSession context.CancelFunc
}

var _ store.Observer = (*Inventory)(nil)
var _ store.WatchSessionObserver = (*Inventory)(nil)

func NewInventory(clusterName string, clusterID uint32, clusterInfo cmtypes.ClusterInfo, peer kvstore.RemotePeerEvidenceProvider, sink SnapshotSink) (*Inventory, error) {
	if strings.TrimSpace(clusterName) == "" || clusterID == cmtypes.ClusterIDUnset || peer == nil || sink == nil {
		return nil, fmt.Errorf("remote workload inventory requires an authenticated peer, cluster name, nonzero cluster ID, and snapshot sink")
	}
	if err := clusterInfo.ValidateStrict(); err != nil {
		return nil, fmt.Errorf("local Cilium cluster identity is invalid: %w", err)
	}
	if clusterInfo.MaxConnectedClusters != 255 && clusterInfo.MaxConnectedClusters != cmtypes.ClusterIDExt511 {
		return nil, fmt.Errorf("unsupported local MaxConnectedClusters %d", clusterInfo.MaxConnectedClusters)
	}
	if err := cmtypes.ValidateClusterName(clusterName); err != nil {
		return nil, fmt.Errorf("invalid authenticated cluster name: %w", err)
	}
	if err := cmtypes.ValidateClusterID(clusterID); err != nil {
		return nil, err
	}
	if clusterID > clusterInfo.MaxConnectedClusters {
		return nil, fmt.Errorf("authenticated remote ClusterID %d exceeds local MaxConnectedClusters %d", clusterID, clusterInfo.MaxConnectedClusters)
	}
	return &Inventory{
		clusterName: clusterName,
		clusterID:   clusterID,
		clusterInfo: clusterInfo,
		peer:        peer,
		sink:        sink,
		entries:     make(map[string]identity.IPIdentityPair),
	}, nil
}

// Begin invalidates old state immediately; nothing from the previous watch
// session remains usable while the new initial list is incomplete.
func (i *Inventory) Begin(context.Context) {
	evidence, evidenceErr := i.peer.CurrentRemotePeerEvidence()
	if evidenceErr == nil && evidence == nil {
		evidenceErr = fmt.Errorf("remote peer evidence provider returned no evidence")
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	i.sessionEpoch++
	i.entries = make(map[string]identity.IPIdentityPair)
	i.listed = false
	i.invalid = evidenceErr != nil || evidence == nil || evidence.ClusterName() != i.clusterName || evidence.ClusterID() != i.clusterID
	if evidenceErr == nil && !i.invalid {
		i.peerEvidence = evidence
		i.publishLocked(false, "watch session started", nil)
		return
	}
	i.peerEvidence = nil
	if evidenceErr != nil {
		i.publishLocked(false, "peer evidence unavailable at watch start: "+evidenceErr.Error(), nil)
	} else {
		i.publishLocked(false, "peer identity changed at watch start", nil)
	}
}

// ListDone publishes only a complete valid initial list. Any decode or semantic
// error in this session prevents publication until a fresh session begins.
func (i *Inventory) ListDone(context.Context) {
	i.mu.Lock()
	if i.invalid {
		i.mu.Unlock()
		return
	}
	if err := i.requireCurrentPeerLocked(); err != nil {
		i.invalidateLocked(err.Error())
		i.mu.Unlock()
		return
	}
	snapshot, err := i.snapshotLockedChecked()
	if err != nil {
		i.invalidateLocked(err.Error())
		i.mu.Unlock()
		return
	}
	i.listed = true
	i.publishLocked(true, "", snapshot)
	onListDone := i.onListDone
	i.mu.Unlock()
	if onListDone != nil {
		onListDone()
	}
}

// Invalid is called by WatchStore when a key cannot be decoded. Semantic
// failures from OnUpdate call invalidateLocked directly.
func (i *Inventory) Invalid(key string, err error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.invalidateLocked(fmt.Sprintf("invalid remote identity record %q: %v", key, err))
}

// End revokes the snapshot even when the watch context was canceled.
func (i *Inventory) End(context.Context) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.entries = make(map[string]identity.IPIdentityPair)
	i.listed = false
	i.invalidateLocked("watch session ended")
}

func (i *Inventory) OnUpdate(key store.Key) {
	pair, ok := key.(*identity.IPIdentityPair)
	if !ok || pair == nil {
		i.Invalid("<unknown>", fmt.Errorf("unexpected key type %T", key))
		return
	}

	i.mu.Lock()
	defer i.mu.Unlock()
	if !i.invalid && i.listed {
		if err := i.requireCurrentPeerLocked(); err != nil {
			i.invalidateLocked(err.Error())
			return
		}
	}

	ip, workload, err := i.validate(*pair)
	if err != nil {
		i.invalidateLocked(err.Error())
		return
	}
	if !workload {
		// An address can change from workload metadata to a non-workload entry.
		// Remove the former workload record rather than retaining stale identity.
		if ip.IsValid() {
			delete(i.entries, ip.String())
			if i.listed && !i.invalid {
				snapshot, err := i.snapshotLockedChecked()
				if err != nil {
					i.invalidateLocked(err.Error())
					return
				}
				i.publishLocked(true, "", snapshot)
			}
		}
		return
	}
	if i.invalid {
		return
	}
	i.entries[ip.String()] = *pair
	if i.listed {
		snapshot, err := i.snapshotLockedChecked()
		if err != nil {
			i.invalidateLocked(err.Error())
			return
		}
		i.publishLocked(true, "", snapshot)
	}
}

func (i *Inventory) OnDelete(key store.NamedKey) {
	pair, ok := key.(*identity.IPIdentityPair)
	if !ok || pair == nil {
		i.Invalid("<unknown>", fmt.Errorf("unexpected delete key type %T", key))
		return
	}
	ip, valid := netip.AddrFromSlice(pair.IP)
	if !valid || !ip.IsValid() {
		i.Invalid("<delete>", fmt.Errorf("delete key has invalid IP address"))
		return
	}
	ip = ip.Unmap()

	i.mu.Lock()
	defer i.mu.Unlock()
	if !i.invalid && i.listed {
		if err := i.requireCurrentPeerLocked(); err != nil {
			i.invalidateLocked(err.Error())
			return
		}
	}
	if ip.IsValid() {
		delete(i.entries, ip.String())
	}
	if i.listed && !i.invalid {
		snapshot, err := i.snapshotLockedChecked()
		if err != nil {
			i.invalidateLocked(err.Error())
			return
		}
		i.publishLocked(true, "", snapshot)
	}
}

// Drain withdraws all current workload records. The caller must invoke it only
// after Watch has stopped, as required by WatchStore.Drain.
func (i *Inventory) Drain() {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.entries = make(map[string]identity.IPIdentityPair)
	i.listed = false
	i.invalidateLocked("remote workload inventory drained")
}

// SetOnListDone installs a short callback which is called after a complete,
// valid watch list has been published. It must not perform network I/O.
func (i *Inventory) SetOnListDone(callback func()) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.onListDone = callback
}

// SetSessionCancel allows malformed/contradictory source data to terminate
// the current WatchStore invocation. Recovery then requires a fresh complete
// list and a fresh peer-evidence check.
func (i *Inventory) SetSessionCancel(cancel context.CancelFunc) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.cancelSession = cancel
}

// CheckPeerEvidence invalidates an active snapshot when the pinned TLS
// connection changes, its certificate expires, or actual etcd heartbeat
// progress becomes stale.
func (i *Inventory) CheckPeerEvidence() error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.invalid || !i.listed {
		return fmt.Errorf("remote workload watch session is not currently valid")
	}
	if err := i.requireCurrentPeerLocked(); err != nil {
		i.invalidateLocked(err.Error())
		return err
	}
	snapshot, err := i.snapshotLockedChecked()
	if err != nil {
		i.invalidateLocked(err.Error())
		return err
	}
	// Refresh the downstream bounded peer-evidence deadline even when the
	// workload key set is unchanged. The source lease itself is not extended by
	// this event; it still requires a fresh source publisher generation.
	i.publishLocked(true, "", snapshot)
	return nil
}

// Invalidate withdraws the current replacement snapshot and cancels its watch
// session. It is used by the bounded peer-evidence guard.
func (i *Inventory) Invalidate(reason string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.invalidateLocked(reason)
}

// Ready reports whether the latest watch session produced a complete valid
// snapshot and has not since been invalidated.
func (i *Inventory) Ready() bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.listed && !i.invalid
}

// NumEntries returns the number of current per-address workload records.
func (i *Inventory) NumEntries() uint64 {
	i.mu.Lock()
	defer i.mu.Unlock()
	return uint64(len(i.entries))
}

func (i *Inventory) validate(pair identity.IPIdentityPair) (netip.Addr, bool, error) {
	ip, validIP := netip.AddrFromSlice(pair.IP)
	if validIP {
		ip = ip.Unmap()
	}

	hasK8s := pair.K8sNamespace != "" || pair.K8sNamespaceUID != "" ||
		pair.K8sNodeName != "" || pair.K8sPodName != "" || pair.K8sPodUID != "" || pair.K8sServiceAccount != "" ||
		pair.K8sWorkloadName != "" || pair.K8sWorkloadKind != ""
	if !hasK8s {
		return ip, false, nil
	}
	// A record with no membership field at all is a native record (see
	// unannotatedMembership); a partial one is refused, as is any other version.
	unannotated := pair.ZtunnelMembershipVersion == 0 && pair.ZtunnelMembershipEpoch == "" &&
		pair.ZtunnelMembershipGeneration == 0 && pair.ZtunnelMembershipState == ""
	if !unannotated && pair.ZtunnelMembershipVersion != 1 {
		return netip.Addr{}, false, fmt.Errorf("workload record lacks ztunnel membership wire version 1")
	}
	switch pair.ZtunnelMembershipState {
	case "":
		if !unannotated {
			return netip.Addr{}, false, fmt.Errorf("workload record has membership version 1 without a state")
		}
	case "unenrolled":
		if pair.ZtunnelMembershipEpoch != "" || pair.ZtunnelMembershipGeneration != 0 {
			return netip.Addr{}, false, fmt.Errorf("unenrolled workload carries membership epoch or generation")
		}
	case "required", "captured", "draining":
		if !nonEmptyCanonical(pair.ZtunnelMembershipEpoch) || pair.ZtunnelMembershipGeneration == 0 {
			return netip.Addr{}, false, fmt.Errorf("required workload lacks current membership epoch or generation")
		}
	default:
		return netip.Addr{}, false, fmt.Errorf("workload has unknown ztunnel membership state %q", pair.ZtunnelMembershipState)
	}
	if !validIP || !ip.IsValid() || ip.Zone() != "" || !ip.IsGlobalUnicast() ||
		ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
		return netip.Addr{}, false, fmt.Errorf("workload record has invalid unicast Pod IP")
	}
	if !nonEmptyCanonical(pair.K8sNamespace) || !nonEmptyCanonical(pair.K8sPodName) || !nonEmptyCanonical(pair.K8sPodUID) ||
		!nonEmptyCanonical(pair.K8sServiceAccount) {
		return netip.Addr{}, false, fmt.Errorf("workload record lacks Pod UID, namespace, Pod name, or ServiceAccount")
	}
	// A native record may lack the namespace UID and node; the join then
	// takes them from the source lease. When present they must be exact.
	for _, field := range []string{pair.K8sNamespaceUID, pair.K8sNodeName} {
		if !nonEmptyCanonical(field) && !(unannotated && field == "") {
			return netip.Addr{}, false, fmt.Errorf("workload record lacks a canonical namespace UID or node name")
		}
	}

	min := identity.NumericIdentity(i.clusterInfo.MinimalAllocationIdentityFor(i.clusterID))
	max := identity.NumericIdentity(i.clusterInfo.MaximumAllocationIdentityFor(i.clusterID))
	if pair.ID < min || pair.ID > max {
		return netip.Addr{}, false, fmt.Errorf("workload identity %d is outside authenticated cluster %d range [%d,%d]", pair.ID, i.clusterID, min, max)
	}
	return ip, true, nil
}

func nonEmptyCanonical(s string) bool {
	return s != "" && strings.TrimSpace(s) == s
}

func (i *Inventory) snapshotLockedChecked() ([]Workload, error) {
	workloads := make(map[WorkloadKey]*Workload)
	byPodUID := make(map[string]WorkloadKey)
	for _, pair := range i.entries {
		ip, valid := netip.AddrFromSlice(pair.IP)
		if !valid {
			return nil, fmt.Errorf("stored workload record has invalid IP")
		}
		ip = ip.Unmap()
		key := WorkloadKey{ClusterID: i.clusterID, NamespaceUID: pair.K8sNamespaceUID, PodUID: pair.K8sPodUID}
		if previous, exists := byPodUID[pair.K8sPodUID]; exists && previous != key {
			return nil, fmt.Errorf("Pod UID %q is associated with multiple Namespace UIDs", pair.K8sPodUID)
		}
		byPodUID[pair.K8sPodUID] = key
		workload, exists := workloads[key]
		if !exists {
			workload = &Workload{
				Key:                  key,
				Namespace:            pair.K8sNamespace,
				NodeName:             pair.K8sNodeName,
				PodName:              pair.K8sPodName,
				ServiceAccount:       pair.K8sServiceAccount,
				Identity:             pair.ID,
				MembershipEpoch:      pair.ZtunnelMembershipEpoch,
				MembershipGeneration: pair.ZtunnelMembershipGeneration,
				MembershipState:      pair.ZtunnelMembershipState,
				Addresses:            []netip.Addr{},
			}
			workloads[key] = workload
		} else if workload.Namespace != pair.K8sNamespace || workload.NodeName != pair.K8sNodeName ||
			workload.PodName != pair.K8sPodName || workload.ServiceAccount != pair.K8sServiceAccount ||
			workload.Identity != pair.ID || workload.MembershipEpoch != pair.ZtunnelMembershipEpoch ||
			workload.MembershipGeneration != pair.ZtunnelMembershipGeneration ||
			workload.MembershipState != pair.ZtunnelMembershipState {
			return nil, fmt.Errorf("conflicting namespace, node, Pod name, ServiceAccount, Cilium identity, or membership across addresses for Pod UID %q", pair.K8sPodUID)
		}
		workload.Addresses = append(workload.Addresses, ip)
	}

	out := make([]Workload, 0, len(workloads))
	for _, workload := range workloads {
		if workload.MembershipState == "" {
			workload.MembershipState = unannotatedMembership
		}
		if workload.MembershipState != "captured" && workload.MembershipState != unannotatedMembership {
			continue
		}
		sort.Slice(workload.Addresses, func(a, b int) bool { return workload.Addresses[a].Less(workload.Addresses[b]) })
		workload.Addresses = slices.Compact(workload.Addresses)
		out = append(out, *workload)
	}
	sort.Slice(out, func(a, b int) bool {
		left, right := out[a].Key, out[b].Key
		if left.ClusterID != right.ClusterID {
			return left.ClusterID < right.ClusterID
		}
		if left.NamespaceUID != right.NamespaceUID {
			return left.NamespaceUID < right.NamespaceUID
		}
		return left.PodUID < right.PodUID
	})
	return out, nil
}

func (i *Inventory) invalidateLocked(reason string) {
	if i.invalid && reason == "" {
		return
	}
	i.invalid = true
	i.entries = make(map[string]identity.IPIdentityPair)
	i.publishLocked(false, reason, nil)
	if i.cancelSession != nil {
		i.cancelSession()
	}
}

func (i *Inventory) publishLocked(valid bool, reason string, workloads []Workload) {
	i.generation++
	snapshot := Snapshot{
		ClusterName:  i.clusterName,
		ClusterID:    i.clusterID,
		Generation:   i.generation,
		SessionEpoch: i.sessionEpoch,
		Valid:        valid,
		Workloads:    workloads,
		Reason:       reason,
	}
	if i.peerEvidence != nil && i.peerEvidence.IdentityEpoch() != 0 {
		snapshot.PeerIdentityEpoch = i.peerEvidence.IdentityEpoch()
		snapshot.PeerCertificateNotAfter = i.peerEvidence.CertificateNotAfter()
		snapshot.PeerHeartbeatAt = i.peerEvidence.LastHeartbeat()
	}
	i.sink.PublishRemoteWorkloadSnapshot(snapshot)
}

func (i *Inventory) requireCurrentPeerLocked() error {
	evidence, err := i.peer.CurrentRemotePeerEvidence()
	if err != nil {
		return fmt.Errorf("remote peer evidence expired or stale: %w", err)
	}
	if evidence == nil {
		return fmt.Errorf("remote peer evidence provider returned no evidence")
	}
	if evidence.ClusterName() != i.clusterName || evidence.ClusterID() != i.clusterID {
		return fmt.Errorf("remote peer evidence identity does not match configured cluster")
	}
	if evidence.IdentityEpoch() != i.peerEvidence.IdentityEpoch() || evidence.ProfileID() != i.peerEvidence.ProfileID() {
		return fmt.Errorf("remote TLS peer identity changed; a fresh complete watch epoch is required")
	}
	i.peerEvidence = evidence
	return nil
}
