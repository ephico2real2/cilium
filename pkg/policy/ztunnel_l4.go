// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"cmp"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	validation "k8s.io/apimachinery/pkg/util/validation"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/identity"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/u8proto"
	"github.com/cilium/cilium/pkg/ztunnel/pb/security"
)

const (
	maxZtunnelPolicyEntries = 4096
	maxZtunnelSources       = 64
	maxZtunnelBoundaries    = 512
	maxZtunnelRules         = 512
	maxZtunnelExpandedPorts = 4096
)

// ZtunnelL4Snapshot is an immutable copy of an actual distilled endpoint map.
// No rule selector is reinterpreted here. Caller MUST hold the endpoint lock
// while obtaining it; the clone retains no mutable policy/selector resources.
type ZtunnelL4Snapshot struct {
	state            mapState
	revision         uint64
	selectorRevision policyTypes.SelectorRevision
	digest           string
	// contentDigest covers the enforced entries only, not the revisions they
	// were computed at: identical content keeps the same contentDigest across
	// policy revisions and regenerations.
	contentDigest string
	boundaries    []uint32
}

func (p *EndpointPolicy) SnapshotZtunnelL4(realizedRevision uint64) (*ZtunnelL4Snapshot, error) {
	// A policy computed at SelectorPolicy.Revision stays current up to the
	// realized revision (the computation advances CurrentAtRevision for
	// identities an update did not select); it is unavailable only if it was
	// computed at a revision newer than the one realized.
	if p == nil || !p.IsValid() || p.SelectorPolicy == nil || realizedRevision == 0 ||
		p.SelectorPolicy.Revision > realizedRevision || p.selectors.Revision == 0 {
		return nil, fmt.Errorf("native realized policy/revision is unavailable")
	}
	if p.SelectorPolicy.L4Policy.HasRedirect() {
		return nil, fmt.Errorf("ztunnel L4 compiler does not implement Envoy/L7 redirects")
	}
	// Hold the actual incremental-change lock through the copy. An enqueued
	// selector change is unavailable policy, never a reason to use old allows.
	p.policyMapChanges.mutex.Lock()
	defer p.policyMapChanges.mutex.Unlock()
	if len(p.policyMapChanges.changes) != 0 || len(p.policyMapChanges.synced) != 0 {
		return nil, fmt.Errorf("native selector updates are pending")
	}
	return cloneZtunnelL4Snapshot(p.policyMapState, realizedRevision, p.selectors.Revision)
}

// ZtunnelContentDigest is the revision-free digest of the ztunnel L4 input this
// policy enforces now: its distilled map state, including incremental changes
// already consumed. Changes queued after the last consume are not included;
// consuming them is a new mutation. Caller MUST hold the endpoint lock.
func (p *EndpointPolicy) ZtunnelContentDigest() (string, error) {
	if p == nil || !p.IsValid() || p.SelectorPolicy == nil {
		return "", fmt.Errorf("native policy is unavailable")
	}
	if p.SelectorPolicy.L4Policy.HasRedirect() {
		return "", fmt.Errorf("ztunnel L4 compiler does not implement Envoy/L7 redirects")
	}
	p.policyMapChanges.mutex.Lock()
	defer p.policyMapChanges.mutex.Unlock()
	snapshot, err := cloneZtunnelL4Snapshot(p.policyMapState, p.SelectorPolicy.Revision, p.selectors.Revision)
	if err != nil {
		return "", err
	}
	return snapshot.contentDigest, nil
}

// One constructor is shared by native capture and the bounded wire decoder.
// It preserves the native LPM map and priority semantics; no selectors are
// translated into SPIFFE wildcards.
func cloneZtunnelL4Snapshot(source mapState, realizedRevision uint64, selectorRevision policyTypes.SelectorRevision) (*ZtunnelL4Snapshot, error) {
	if len(source.entries) > maxZtunnelPolicyEntries {
		return nil, fmt.Errorf("native policy exceeds bounded compiler size")
	}
	cloned := newMapState(source.logger, source.Sizes(), allFeatures, source.clusterInfo)
	keys := make([]Key, 0, len(source.entries))
	cuts := []uint32{1, 65536}
	for key, entry := range source.entries {
		if err := validateNativeZtunnelL4Entry(key, entry.MapStateEntry); err != nil {
			return nil, err
		}
		if !entry.IsValid() || entry.ProxyPort != 0 || entry.Precedence.IsPass() {
			return nil, fmt.Errorf("unsupported or unrealized native policy entry")
		}
		cloned.upsert(key, NewMapStateEntry(entry.MapStateEntry))
		keys = append(keys, key)
		if key.Nexthdr == 0 || key.Nexthdr == u8proto.TCP {
			start := max(uint32(1), uint32(key.DestPort))
			end := uint32(key.EndPort()) + 1
			if start < end {
				cuts = append(cuts, start, end)
			}
		}
	}
	slices.Sort(cuts)
	cuts = slices.Compact(cuts)
	if len(cuts) > maxZtunnelBoundaries {
		return nil, fmt.Errorf("too many native port boundaries")
	}
	slices.SortFunc(keys, func(a, b Key) int {
		for _, order := range []int{cmp.Compare(a.TrafficDirection(), b.TrafficDirection()), cmp.Compare(a.Nexthdr, b.Nexthdr), cmp.Compare(a.DestPort, b.DestPort), cmp.Compare(a.PortPrefixLen(), b.PortPrefixLen()), cmp.Compare(a.Identity, b.Identity)} {
			if order != 0 {
				return order
			}
		}
		return 0
	})
	h, content := sha256.New(), sha256.New()
	var encoded [8]byte
	appendTo := func(w io.Writer, v uint64) { binary.BigEndian.PutUint64(encoded[:], v); _, _ = w.Write(encoded[:]) }
	appendTo(h, realizedRevision)
	appendTo(h, uint64(selectorRevision))
	for _, k := range keys {
		v := source.entries[k]
		for _, value := range []uint64{uint64(k.TrafficDirection()), uint64(k.Nexthdr), uint64(k.DestPort),
			uint64(k.PortPrefixLen()), uint64(k.Identity), uint64(v.Precedence), uint64(v.ProxyPort), uint64(v.Cookie)} {
			appendTo(h, value)
			appendTo(content, value)
		}
	}
	return &ZtunnelL4Snapshot{state: cloned, revision: realizedRevision,
		selectorRevision: selectorRevision, digest: hex.EncodeToString(h.Sum(nil)),
		contentDigest: hex.EncodeToString(content.Sum(nil)), boundaries: cuts}, nil
}

func (s *ZtunnelL4Snapshot) Revision() uint64 {
	if s == nil {
		return 0
	}
	return s.revision
}
func (s *ZtunnelL4Snapshot) SelectorRevision() uint64 {
	if s == nil {
		return 0
	}
	return uint64(s.selectorRevision)
}
func (s *ZtunnelL4Snapshot) Digest() string {
	if s == nil {
		return ""
	}
	return s.digest
}

// ContentDigest is the revision-free digest of the snapshot's entries.
func (s *ZtunnelL4Snapshot) ContentDigest() string {
	if s == nil {
		return ""
	}
	return s.contentDigest
}

func (s *ZtunnelL4Snapshot) permits(id identity.NumericIdentity, port uint16, ingress bool) bool {
	if s == nil || port == 0 || id == 0 {
		return false
	}
	key := EgressKey()
	if ingress {
		key = IngressKey()
	}
	entry, found := s.state.lookup(key.WithIdentity(id).WithTCPPort(port))
	return found && entry.IsValid() && entry.IsAllow() && entry.ProxyPort == 0
}

// ZtunnelPolicySubject is a native Kubernetes endpoint incarnation. Domain and
// cluster binding require independently authenticated issuer/membership input.
// This DTO is not proof that an inbound TCP source owns these fields.
type ZtunnelPolicySubject struct {
	ClusterID       uint32
	EndpointID      uint16
	ClusterName     string
	TrustDomain     string
	Namespace       string
	NamespaceUID    string
	PodUID          string
	ServiceAccount  string
	NumericIdentity identity.NumericIdentity
	Addresses       []netip.Addr
	Policy          *ZtunnelL4Snapshot
}

// ValidateZtunnelSubject applies the checks CompileZtunnelTCP applies to every
// subject. A caller that admits sources from outside its own node uses it to
// leave out one invalid source, since any invalid source fails the whole plan.
func ValidateZtunnelSubject(info cmtypes.ClusterInfo, s ZtunnelPolicySubject) error {
	return validateZtunnelSubject(info, s)
}

func validateZtunnelSubject(info cmtypes.ClusterInfo, s ZtunnelPolicySubject) error {
	if s.ClusterID == 0 || s.EndpointID == 0 || s.ClusterName == "" || s.NamespaceUID == "" || s.PodUID == "" ||
		s.Namespace == "" || s.ServiceAccount == "" || s.TrustDomain == "" || s.Policy == nil ||
		s.Policy.Revision() == 0 || s.NumericIdentity == 0 || s.NumericIdentity.IsReservedIdentity() || s.NumericIdentity.HasLocalScope() {
		return fmt.Errorf("native workload/namespace/identity/policy binding is incomplete")
	}
	// Native aggregate lookup depends on the policy owner's cluster, not
	// merely the queried identity bits. Never apply cluster A's distilled map
	// as the source egress policy of a subject claiming to belong to cluster B.
	native := s.Policy.state.clusterInfo
	if native.ID != s.ClusterID || native.Name != s.ClusterName || native.MaxConnectedClusters != info.MaxConnectedClusters {
		return fmt.Errorf("native policy snapshot cluster binding does not match workload subject")
	}
	if err := cmtypes.ValidateClusterName(s.ClusterName); err != nil {
		return err
	}
	if td, err := spiffeid.TrustDomainFromString(s.TrustDomain); err != nil || td.String() != s.TrustDomain {
		return fmt.Errorf("noncanonical bound trust domain")
	}
	if len(validation.IsDNS1123Label(s.Namespace)) != 0 || len(validation.IsDNS1123Subdomain(s.ServiceAccount)) != 0 {
		return fmt.Errorf("noncanonical namespace/service account")
	}
	for _, raw := range []string{s.NamespaceUID, s.PodUID} {
		value, err := uuid.Parse(raw)
		if err != nil || value == uuid.Nil || value.String() != raw {
			return fmt.Errorf("canonical Kubernetes incarnation UID required")
		}
	}
	if s.NumericIdentity.ClusterID(info) != s.ClusterID {
		return fmt.Errorf("numeric identity belongs to a different cluster")
	}
	for _, v := range []string{s.ClusterName, s.Namespace, s.ServiceAccount, s.TrustDomain} {
		if strings.ContainsAny(v, "/\x00\r\n\t ") {
			return fmt.Errorf("noncanonical workload identity")
		}
	}
	if len(s.Addresses) == 0 || len(s.Addresses) > 2 {
		return fmt.Errorf("one address per family is required")
	}
	families := make(map[bool]bool)
	for _, ip := range s.Addresses {
		if !ip.IsValid() || ip.Is4In6() || ip.Zone() != "" || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || families[ip.Is4()] {
			return fmt.Errorf("invalid/ambiguous workload addresses")
		}
		families[ip.Is4()] = true
	}
	return nil
}

func exactZtunnelIPs(ips []netip.Addr) []*security.Address {
	sorted := slices.Clone(ips)
	slices.SortFunc(sorted, func(a, b netip.Addr) int { return a.Compare(b) })
	out := make([]*security.Address, 0, len(sorted))
	for _, ip := range sorted {
		out = append(out, &security.Address{Address: slices.Clone(ip.AsSlice()), Length: uint32(ip.BitLen())})
	}
	return out
}

// ZtunnelL4Plan describes desired L4 semantics, NOT accepted source provenance.
// Review rules must not be sent as live allows before native connection-bound
// membership and remote source-egress delivery are implemented and qualified.
type ZtunnelL4Plan struct {
	Destination         ZtunnelPolicySubject
	Sources             []ZtunnelPolicySubject
	ReviewAuthorization *security.Authorization
	Digest              string
}

// CompileZtunnelTCP evaluates actual native destination ingress AND source
// egress policy. It emits no principal-only selector approximation. Unknown
// source policy, unsupported L7, ambiguity or expansion limits fail closed.
func CompileZtunnelTCP(info cmtypes.ClusterInfo, destination ZtunnelPolicySubject, sources []ZtunnelPolicySubject) (*ZtunnelL4Plan, error) {
	if err := info.ValidateStrict(); err != nil {
		return nil, err
	}
	if info.MaxConnectedClusters != 255 && info.MaxConnectedClusters != cmtypes.ClusterIDExt511 {
		return nil, fmt.Errorf("unsupported cluster identity allocation")
	}
	if err := validateZtunnelSubject(info, destination); err != nil {
		return nil, err
	}
	if len(sources) > maxZtunnelSources {
		return nil, fmt.Errorf("too many native source workloads")
	}
	sorted := slices.Clone(sources)
	slices.SortFunc(sorted, func(a, b ZtunnelPolicySubject) int {
		return strings.Compare(fmt.Sprintf("%d/%s/%s", a.ClusterID, a.NamespaceUID, a.PodUID), fmt.Sprintf("%d/%s/%s", b.ClusterID, b.NamespaceUID, b.PodUID))
	})
	owners := make(map[netip.Addr]string)
	for _, ip := range destination.Addresses {
		owners[ip] = fmt.Sprintf("%d/%s/%s", destination.ClusterID, destination.NamespaceUID, destination.PodUID)
	}
	clusterBindings := map[uint32]string{destination.ClusterID: destination.ClusterName + "/" + destination.TrustDomain}
	seen := make(map[string]bool)
	for _, source := range sorted {
		if err := validateZtunnelSubject(info, source); err != nil {
			return nil, fmt.Errorf("source native policy unavailable: %w", err)
		}
		binding := source.ClusterName + "/" + source.TrustDomain
		if old, ok := clusterBindings[source.ClusterID]; ok && old != binding {
			return nil, fmt.Errorf("ambiguous source cluster authority")
		}
		clusterBindings[source.ClusterID] = binding
		key := fmt.Sprintf("%d/%s/%s", source.ClusterID, source.NamespaceUID, source.PodUID)
		if seen[key] {
			return nil, fmt.Errorf("duplicate source workload incarnation")
		}
		seen[key] = true
		for _, ip := range source.Addresses {
			if old, ok := owners[ip]; ok && old != key {
				return nil, fmt.Errorf("source address has multiple workload owners")
			}
			owners[ip] = key
		}
	}
	auth := &security.Authorization{Name: "cilium_l4_review_only", Namespace: destination.Namespace,
		Scope: security.Scope_WORKLOAD_SELECTOR, Action: security.Action_ALLOW}
	for _, source := range sorted {
		cuts := append(slices.Clone(destination.Policy.boundaries), source.Policy.boundaries...)
		slices.Sort(cuts)
		cuts = slices.Compact(cuts)
		if len(cuts) > maxZtunnelBoundaries {
			return nil, fmt.Errorf("combined native policy exceeds bounded interval count")
		}
		type interval struct{ start, end uint32 }
		var allowed []interval
		for i := 0; i+1 < len(cuts); i++ {
			start, end := cuts[i], cuts[i+1]
			if start == 0 || start >= end || start > 65535 {
				continue
			}
			if !destination.Policy.permits(source.NumericIdentity, uint16(start), true) || !source.Policy.permits(destination.NumericIdentity, uint16(start), false) {
				continue
			}
			if len(allowed) > 0 && allowed[len(allowed)-1].end == start {
				allowed[len(allowed)-1].end = end
			} else {
				allowed = append(allowed, interval{start, end})
			}
		}
		if len(allowed) == 0 {
			continue
		}
		all := len(allowed) == 1 && allowed[0].start == 1 && allowed[0].end == 65536
		var ports []uint32
		if !all {
			for _, span := range allowed {
				if span.end-span.start > maxZtunnelExpandedPorts || len(ports)+int(span.end-span.start) > maxZtunnelExpandedPorts {
					return nil, fmt.Errorf("allowed native ports exceed protobuf expansion limit")
				}
				for port := span.start; port < span.end; port++ {
					ports = append(ports, port)
				}
			}
		}
		// Types inside one Match are AND. Source alternatives stay separate
		// rules, so two selected Pods cannot cross-combine principal/IP fields.
		match := &security.Match{Principals: []*security.StringMatch{{MatchType: &security.StringMatch_Exact{
			Exact: source.TrustDomain + "/ns/" + source.Namespace + "/sa/" + source.ServiceAccount}}},
			SourceIps: exactZtunnelIPs(source.Addresses), DestinationIps: exactZtunnelIPs(destination.Addresses), DestinationPorts: ports}
		auth.Rules = append(auth.Rules, &security.Rule{Clauses: []*security.Clause{{Matches: []*security.Match{match}}}})
		if len(auth.Rules) > maxZtunnelRules {
			return nil, fmt.Errorf("native compiled policy exceeds rule bound")
		}
	}
	// A digest binds both original endpoint policy maps and every workload
	// incarnation. The review resource is deliberately not a live policy name.
	h := sha256.New()
	write := func(s ZtunnelPolicySubject) {
		_, _ = fmt.Fprintf(h, "%d\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%d\x00%s\x00", s.ClusterID, s.ClusterName, s.TrustDomain, s.Namespace, s.NamespaceUID, s.PodUID, s.ServiceAccount, s.NumericIdentity, s.Policy.ContentDigest())
		_, _ = fmt.Fprintf(h, "%d\x00", s.EndpointID)
		for _, ip := range exactZtunnelIPs(s.Addresses) {
			_, _ = fmt.Fprintf(h, "%d:", len(ip.Address))
			_, _ = h.Write(ip.Address)
		}
	}
	write(destination)
	for _, source := range sorted {
		write(source)
	}
	return &ZtunnelL4Plan{Destination: destination, Sources: sorted, ReviewAuthorization: auth, Digest: hex.EncodeToString(h.Sum(nil))}, nil
}
