// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"context"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/ztunnel/membership"
	remote "github.com/cilium/cilium/pkg/ztunnel/remote_workload"
)

// Source origins, also the values of the effective_policy_sources origin label.
const (
	sourceOriginNode    = "node"    // captured workloads of this node
	sourceOriginCluster = "cluster" // this cluster's other nodes
	sourceOriginPeer    = "peer"    // other ClusterMesh clusters
)

// sourceAddressView is the destination agent's own record of which workload
// owns an address: the ipcache its datapath enforces with.
type sourceAddressView interface {
	workloadAt(netip.Addr) (identity.NumericIdentity, string, bool)
}

type ipcacheAddressView struct{ ipc *ipcache.IPCache }

func (v ipcacheAddressView) workloadAt(ip netip.Addr) (identity.NumericIdentity, string, bool) {
	id, meta, ok := v.ipc.LookupWorkloadByIP(ip)
	if !ok || meta == nil {
		return 0, "", false
	}
	return id.ID, meta.PodUID, true
}

// externalSources are the inputs from which the owner admits callers that are
// not captured workloads of this node. A missing input admits no caller of
// its origin; it never widens what the others admit.
type externalSources struct {
	// cluster holds this cluster's leased workloads of other nodes.
	cluster *remote.LocalSourceMailbox
	// peers, trust and nodes are the remote projection's own inputs, so a peer's
	// workloads are callers only while they are also projected destinations.
	peers *remote.PeerSnapshotStore
	trust *remoteTrustAuthority
	nodes nodeNameResolver
	// addresses must be set for any external caller to be admitted.
	addresses sourceAddressView
}

func (s externalSources) enabled() bool {
	return s.addresses != nil && (s.cluster != nil || s.peers != nil)
}

// watch kicks the owner whenever an input changes, so a narrowed or
// withdrawn source does not wait for the next periodic reconcile.
func (s externalSources) watch(ctx context.Context, kick func()) {
	if !s.enabled() {
		return
	}
	if s.cluster != nil {
		go func() {
			for {
				if _, err := s.cluster.Wait(ctx); err != nil {
					return
				}
				kick()
			}
		}()
	}
	if s.peers != nil {
		waitAndKick(ctx, func() <-chan struct{} { _, changed := s.peers.View(); return changed }, kick)
	}
	if s.trust != nil {
		waitAndKick(ctx, func() <-chan struct{} { _, changed := s.trust.View(); return changed }, kick)
	}
}

// waitAndKick reads the first change channel before it returns, so a change
// made after watch returns is never missed.
func waitAndKick(ctx context.Context, next func() <-chan struct{}, kick func()) {
	changed := next()
	if changed == nil {
		return
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-changed:
				kick()
				changed = next()
			}
		}
	}()
}

// decodeKey identifies one decoded egress policy: the receiver-fixed owner
// and the envelope's exact expectation.
type decodeKey struct {
	owner     cmtypes.ClusterInfo
	revision  uint64
	selectors uint64
	digest    string
}

type decodeResult struct {
	snapshot *policy.ZtunnelL4Snapshot
	err      error
}

// sourceAdmission is one reconcile's evaluation of external callers.
type sourceAdmission struct {
	admitted []policy.ZtunnelPolicySubject
	// refused maps a source to its reason; whole-input refusals use the
	// origin as the key.
	refused map[string]string
	counts  map[string]int // admitted per origin
}

func (a *sourceAdmission) refuse(key, format string, args ...any) {
	a.refused[key] = fmt.Sprintf(format, args...)
}

// externalSubjects admits callers from this cluster's other nodes and from
// ClusterMesh peers. Each is admitted only with a valid lease, an approved
// trust domain, a policy that decodes under the owner this agent fixes, and
// an ipcache that maps every one of its addresses to its identity and Pod UID.
// A source that fails any check is left out, never approximated.
func (o *effectivePolicyOwner) externalSubjects(local []candidate, now time.Time) sourceAdmission {
	out := sourceAdmission{refused: make(map[string]string), counts: make(map[string]int)}
	if !o.sources.enabled() {
		return out
	}
	used := make(map[decodeKey]decodeResult, len(o.decoded))
	var subjects []sourcedSubject
	if o.sources.cluster != nil {
		subjects = append(subjects, o.clusterSources(&out, used, now)...)
	}
	if o.sources.peers != nil {
		subjects = append(subjects, o.peerSources(&out, used, now)...)
	}
	o.decoded = used
	for _, s := range withoutConflicts(&out, o.cluster, o.trustDomain, local, subjects) {
		out.admitted = append(out.admitted, s.subject)
		out.counts[s.origin]++
	}
	slices.SortFunc(out.admitted, func(a, b policy.ZtunnelPolicySubject) int {
		return strings.Compare(sourceKey(a), sourceKey(b))
	})
	return out
}

type sourcedSubject struct {
	origin  string
	subject policy.ZtunnelPolicySubject
}

func sourceKey(s policy.ZtunnelPolicySubject) string {
	return fmt.Sprintf("%d/%s/%s", s.ClusterID, s.NamespaceUID, s.PodUID)
}

func (o *effectivePolicyOwner) clusterSources(out *sourceAdmission, used map[decodeKey]decodeResult, now time.Time) []sourcedSubject {
	snapshot, ok := o.sources.cluster.Latest()
	switch {
	case !ok:
		out.refuse(sourceOriginCluster, "this cluster's source leases have not been read")
		return nil
	case !snapshot.Valid:
		out.refuse(sourceOriginCluster, "this cluster's source leases are unavailable: %s", snapshot.Reason)
		return nil
	case snapshot.ClusterID != o.cluster.ID || snapshot.ClusterName != o.cluster.Name:
		out.refuse(sourceOriginCluster, "source leases name cluster %q (%d), not this cluster", snapshot.ClusterName, snapshot.ClusterID)
		return nil
	case !now.Before(snapshot.SourceMembershipLeaseValidUntil):
		out.refuse(sourceOriginCluster, "this cluster's source leases expired at %s", snapshot.SourceMembershipLeaseValidUntil)
		return nil
	}
	var subjects []sourcedSubject
	for _, w := range snapshot.Workloads {
		if w.Key.ClusterID != o.cluster.ID {
			out.refuse(fmt.Sprintf("%s/%d/%s", sourceOriginCluster, w.Key.ClusterID, w.Key.PodUID), "workload is keyed to another cluster")
			continue
		}
		if s, ok := o.admitWorkload(out, used, sourceOriginCluster, o.cluster.Name, o.trustDomain, w); ok {
			subjects = append(subjects, sourcedSubject{origin: sourceOriginCluster, subject: s})
		}
	}
	return subjects
}

func (o *effectivePolicyOwner) peerSources(out *sourceAdmission, used map[decodeKey]decodeResult, now time.Time) []sourcedSubject {
	if o.sources.nodes == nil {
		out.refuse(sourceOriginPeer, "Kubernetes node discovery is not configured")
		return nil
	}
	nodes, _, err := o.sources.nodes.localNames()
	if err != nil {
		out.refuse(sourceOriginPeer, "local node names are unavailable: %s", err)
		return nil
	}
	views, _ := o.sources.peers.View()
	trust, _ := o.sources.trust.View()
	// No local address map: every source address is checked against the
	// ipcache below, and a collision with a local caller is refused later.
	projections := projectRemotePeers(views, trust, nodes, nil, now)
	var subjects []sourcedSubject
	for _, name := range slices.Sorted(maps.Keys(views)) {
		key := sourceOriginPeer + "/" + name
		if err := projections[name].err; err != nil {
			out.refuse(key, "peer is not projected: %s", err)
			continue
		}
		snapshot := views[name].Snapshot
		if snapshot.ClusterID == o.cluster.ID || snapshot.ClusterName == o.cluster.Name {
			out.refuse(key, "peer claims this cluster's name or ID")
			continue
		}
		domain, err := trust.domain(name, now)
		if err != nil {
			out.refuse(key, "peer trust domain: %s", err)
			continue
		}
		for _, w := range snapshot.Workloads {
			if s, ok := o.admitWorkload(out, used, sourceOriginPeer, snapshot.ClusterName, domain, w); ok {
				subjects = append(subjects, sourcedSubject{origin: sourceOriginPeer, subject: s})
			}
		}
	}
	return subjects
}

// admitWorkload builds one source subject and checks it alone.
func (o *effectivePolicyOwner) admitWorkload(out *sourceAdmission, used map[decodeKey]decodeResult, origin, clusterName, trustDomain string,
	w remote.Workload) (policy.ZtunnelPolicySubject, bool) {
	key := fmt.Sprintf("%s/%d/%s", origin, w.Key.ClusterID, w.Key.PodUID)
	if w.MembershipState != "captured" {
		out.refuse(key, "workload is not captured by its source (state %q)", w.MembershipState)
		return policy.ZtunnelPolicySubject{}, false
	}
	if w.EgressPolicy == nil {
		out.refuse(key, "source published no realized egress policy")
		return policy.ZtunnelPolicySubject{}, false
	}
	owner := cmtypes.ClusterInfo{ID: w.Key.ClusterID, Name: clusterName, MaxConnectedClusters: o.cluster.MaxConnectedClusters}
	decoded, err := o.decodeEgress(used, owner, w.EgressPolicy)
	if err != nil {
		out.refuse(key, "egress policy does not decode: %s", err)
		return policy.ZtunnelPolicySubject{}, false
	}
	subject := policy.ZtunnelPolicySubject{ClusterID: w.Key.ClusterID, EndpointID: w.EndpointID, ClusterName: clusterName,
		TrustDomain: trustDomain, Namespace: w.Namespace, NamespaceUID: w.Key.NamespaceUID, PodUID: w.Key.PodUID,
		ServiceAccount: w.ServiceAccount, NumericIdentity: w.Identity, Addresses: slices.Clone(w.Addresses), Policy: decoded}
	if err := policy.ValidateZtunnelSubject(o.cluster, subject); err != nil {
		out.refuse(key, "source subject is invalid: %s", err)
		return policy.ZtunnelPolicySubject{}, false
	}
	for _, ip := range subject.Addresses {
		id, podUID, ok := o.sources.addresses.workloadAt(ip)
		switch {
		case !ok:
			out.refuse(key, "ipcache has no workload at %s", ip)
			return policy.ZtunnelPolicySubject{}, false
		case id != subject.NumericIdentity:
			out.refuse(key, "ipcache maps %s to identity %d, not %d", ip, id, subject.NumericIdentity)
			return policy.ZtunnelPolicySubject{}, false
		case podUID != subject.PodUID:
			out.refuse(key, "ipcache maps %s to Pod UID %q, not %q", ip, podUID, subject.PodUID)
			return policy.ZtunnelPolicySubject{}, false
		}
	}
	return subject, true
}

// decodeEgress decodes an envelope once per content: the key includes the
// owner and the digest, so a cached result is the result of decoding again.
func (o *effectivePolicyOwner) decodeEgress(used map[decodeKey]decodeResult, owner cmtypes.ClusterInfo,
	envelope *membership.SourceEgressPolicy) (*policy.ZtunnelL4Snapshot, error) {
	if err := envelope.Validate(); err != nil {
		return nil, err
	}
	key := decodeKey{owner: owner, revision: envelope.PolicyRevision, selectors: envelope.SelectorRevision, digest: envelope.Digest}
	result, ok := used[key]
	if !ok {
		if result, ok = o.decoded[key]; !ok {
			snapshot, err := policy.DecodeNativeZtunnelL4(o.log, policy.NativeZtunnelL4Expectation{Owner: owner,
				PolicyRevision: envelope.PolicyRevision, SelectorRevision: envelope.SelectorRevision, Digest: envelope.Digest}, envelope.Wire)
			result = decodeResult{snapshot: snapshot, err: err}
		}
		used[key] = result
	}
	return result.snapshot, result.err
}

// withoutConflicts removes every external source that CompileZtunnelTCP would
// refuse together with the whole plan: a second claim on an incarnation, an
// address or a cluster ID. A local caller keeps its claim; external claimants
// that conflict with it or with each other are all left out.
func withoutConflicts(out *sourceAdmission, cluster cmtypes.ClusterInfo, trustDomain string, local []candidate, subjects []sourcedSubject) []sourcedSubject {
	localKeys := make(map[string]bool, len(local))
	localAddrs := make(map[netip.Addr]bool)
	for _, c := range local {
		localKeys[sourceKey(c.subject)] = true
		for _, ip := range c.subject.Addresses {
			localAddrs[ip] = true
		}
	}
	keys := make(map[string]int)
	addrs := make(map[netip.Addr]int)
	// The compiler binds each cluster ID to one name and trust domain,
	// starting with the destination's own.
	bindings := map[uint32]map[string]bool{cluster.ID: {cluster.Name + "/" + trustDomain: true}}
	for _, s := range subjects {
		keys[sourceKey(s.subject)]++
		for _, ip := range s.subject.Addresses {
			addrs[ip]++
		}
		if bindings[s.subject.ClusterID] == nil {
			bindings[s.subject.ClusterID] = make(map[string]bool)
		}
		bindings[s.subject.ClusterID][s.subject.ClusterName+"/"+s.subject.TrustDomain] = true
	}
	var kept []sourcedSubject
	for _, s := range subjects {
		key := fmt.Sprintf("%s/%d/%s", s.origin, s.subject.ClusterID, s.subject.PodUID)
		incarnation := sourceKey(s.subject)
		switch {
		case localKeys[incarnation] || keys[incarnation] > 1:
			out.refuse(key, "another source claims incarnation %s", incarnation)
			continue
		case len(bindings[s.subject.ClusterID]) > 1:
			out.refuse(key, "cluster ID %d is claimed with more than one name or trust domain", s.subject.ClusterID)
			continue
		}
		collides := false
		for _, ip := range s.subject.Addresses {
			if localAddrs[ip] || addrs[ip] > 1 {
				out.refuse(key, "another source claims address %s", ip)
				collides = true
				break
			}
		}
		if !collides {
			kept = append(kept, s)
		}
	}
	return kept
}

// logSources logs each refused source once, when its reason changes, and the
// admitted count per origin when it changes.
func (o *effectivePolicyOwner) logSources(a sourceAdmission, local int) {
	for key, reason := range a.refused {
		if o.refusedSources[key] != reason {
			o.log.Info("Caller is not admitted as an effective ztunnel policy source",
				logStage, "effective-policy", logfields.Key, key, logfields.Reason, reason)
		}
	}
	o.refusedSources = a.refused
	counts := map[string]int{sourceOriginNode: local, sourceOriginCluster: a.counts[sourceOriginCluster], sourceOriginPeer: a.counts[sourceOriginPeer]}
	for origin, n := range counts {
		if o.metrics != nil {
			o.metrics.EffectivePolicySources.WithLabelValues(origin).Set(float64(n))
		}
	}
	if !maps.Equal(o.sourceCounts, counts) {
		o.log.Info("Effective ztunnel policy sources changed", logStage, "effective-policy",
			"node", counts[sourceOriginNode], "cluster", counts[sourceOriginCluster], "peer", counts[sourceOriginPeer])
		o.sourceCounts = counts
	}
}
