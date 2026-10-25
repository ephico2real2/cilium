// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/ztunnel/membership"
	"github.com/cilium/cilium/pkg/ztunnel/pb/security"
)

// policyWorkload is the part of a local endpoint the owner uses.
type policyWorkload interface {
	GetK8sPodUID() string
	SnapshotZtunnelReleaseCandidate() (endpoint.ZtunnelReleaseCandidate, error)
	IsZtunnelQuarantined() bool
	ReleaseZtunnelQuarantine(endpoint.ZtunnelAdmissionReceipt) error
	RegenerateIfAlive(*regeneration.ExternalRegenerationMetadata) <-chan bool
}

// endpointLookup finds the local endpoint of a membership reference.
type endpointLookup interface {
	lookup(id uint16) policyWorkload
}

// managerLookup adapts the endpoint manager; it never returns a typed nil.
type managerLookup struct {
	manager interface {
		LookupCiliumID(id uint16) *endpoint.Endpoint
	}
}

func (m managerLookup) lookup(id uint16) policyWorkload {
	if m.manager == nil {
		return nil
	}
	if ep := m.manager.LookupCiliumID(id); ep != nil {
		return ep
	}
	return nil
}

// effectivePolicyOwner publishes the effective inbound policy of every
// Required, captured local workload and releases its datapath quarantine
// once the local ztunnel acknowledged, on the current ADS stream, both the
// workload Address and that exact policy.
//
// The ALLOW rules come from policy.CompileZtunnelTCP over the destination's
// realized native ingress map and each source's realized egress map, with
// exact principal, source IP, destination IP and port. A source is included
// only when this agent has its realized policy: captured workloads of this
// node. Callers on other nodes or clusters match no rule and are denied by
// ztunnel until authenticated source-policy delivery exists.
type effectivePolicyOwner struct {
	log         *slog.Logger
	registry    *membership.Registry
	endpoints   endpointLookup
	policies    *AuthorizationPolicies
	cluster     cmtypes.ClusterInfo
	trustDomain string
	metrics     *Metrics
	interval    time.Duration
	trigger     chan struct{}

	mu         lock.Mutex
	generation uint64 // current ADS stream generation
	acked      uint64 // Authorization cache version that stream's ztunnel ACKed
	published  map[membership.Reference]publishedPolicy

	// ineligible holds the last logged reason each Required workload is not an
	// effective-policy destination. Only the reconcile goroutine uses it.
	ineligible map[membership.Reference]string
}

type publishedPolicy struct {
	generation     uint64
	addressVersion uint64
	digest         string
	policyVersion  uint64
	cacheVersion   uint64
	acknowledged   bool
	// sources holds the subject digest of every local workload this plan was
	// compiled with as a caller, by membership reference.
	sources map[membership.Reference]string
}

func newEffectivePolicyOwner(log *slog.Logger, registry *membership.Registry, endpoints endpointLookup, policies *AuthorizationPolicies,
	cluster cmtypes.ClusterInfo, trustDomain string, metrics *Metrics) *effectivePolicyOwner {
	return &effectivePolicyOwner{log: log, registry: registry, endpoints: endpoints, policies: policies, cluster: cluster,
		trustDomain: trustDomain, metrics: metrics, interval: time.Second, trigger: make(chan struct{}, 1),
		published: make(map[membership.Reference]publishedPolicy), ineligible: make(map[membership.Reference]string)}
}

// beginStream starts a new ADS generation for a new ztunnel stream. Every
// earlier Address and policy acknowledgment becomes stale.
func (o *effectivePolicyOwner) beginStream() uint64 {
	generation := o.registry.BeginADSGeneration()
	o.mu.Lock()
	o.generation, o.acked = generation, 0
	clear(o.published)
	o.mu.Unlock()
	o.kick()
	return generation
}

// observeAuthorizationAck records that the ztunnel on stream generation
// applied the Authorization resources of cache version.
func (o *effectivePolicyOwner) observeAuthorizationAck(generation, version uint64) {
	o.mu.Lock()
	if generation != 0 && generation == o.generation && version > o.acked {
		o.acked = version
	}
	o.mu.Unlock()
	o.kick()
}

func (o *effectivePolicyOwner) kick() {
	select {
	case o.trigger <- struct{}{}:
	default:
	}
}

func (o *effectivePolicyOwner) run(ctx context.Context) {
	ticker := time.NewTicker(o.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-o.trigger:
		}
		o.reconcile()
	}
}

func (o *effectivePolicyOwner) event(event string) {
	if o.metrics != nil {
		o.metrics.EffectivePolicyEvents.WithLabelValues(event).Inc()
	}
}

// candidate is one captured local workload with its realized policy.
type candidate struct {
	ref      membership.Reference
	state    membership.State
	endpoint policyWorkload
	release  endpoint.ZtunnelReleaseCandidate
	subject  policy.ZtunnelPolicySubject
}

func (o *effectivePolicyOwner) candidates(reasons map[membership.Reference]string) []candidate {
	var out []candidate
	for ref, state := range o.registry.Snapshot() {
		if !state.ReadyForAddress() {
			reasons[ref] = "capture or ZDS acknowledgment is not current"
			continue
		}
		ep := o.endpoints.lookup(state.EndpointID)
		if ep == nil || ep.GetK8sPodUID() != ref.Key.PodUID {
			reasons[ref] = "endpoint is not the registered incarnation"
			continue
		}
		release, err := ep.SnapshotZtunnelReleaseCandidate()
		if err != nil {
			// Policy not realized: neither a destination nor a source now.
			reasons[ref] = "native policy is not realized: " + err.Error()
			continue
		}
		m := release.Membership
		if !release.HasMembership || m.Epoch != ref.Epoch || m.Generation != state.ZDSGeneration ||
			m.State != membership.PublicationCaptured || m.NamespaceUID != ref.Key.NamespaceUID {
			reasons[ref] = "endpoint has not published this exact captured incarnation"
			continue
		}
		subject := release.Subject
		subject.ClusterID, subject.ClusterName, subject.TrustDomain = o.cluster.ID, o.cluster.Name, o.trustDomain
		out = append(out, candidate{ref: ref, state: state, endpoint: ep, release: release, subject: subject})
	}
	slices.SortFunc(out, func(a, b candidate) int { return strings.Compare(a.ref.Key.PodUID, b.ref.Key.PodUID) })
	return out
}

func (o *effectivePolicyOwner) reconcile() {
	o.mu.Lock()
	generation, acked := o.generation, o.acked
	o.mu.Unlock()
	if generation == 0 {
		return
	}
	reasons := make(map[membership.Reference]string)
	defer o.logIneligible(reasons)
	o.pruneRetired()
	all := o.candidates(reasons)
	// Publish every plan first, then release: a workload that is a caller in
	// other plans is released only once those plans reflect it (see
	// callerPlansCurrent).
	var acknowledged []candidate
	for i, dst := range all {
		if dst.state.ADSGeneration != generation || !dst.state.AddressAcked {
			reasons[dst.ref] = "workload Address is not acknowledged on the current ADS stream"
			continue
		}
		sources := make([]policy.ZtunnelPolicySubject, 0, len(all)-1)
		sourceDigests := make(map[membership.Reference]string, len(all)-1)
		for j, src := range all {
			if j != i {
				sources = append(sources, src.subject)
				sourceDigests[src.ref] = subjectDigest(src.subject)
			}
		}
		key, err := effectivePolicyKey(dst.subject.Namespace, dst.ref.Key.NamespaceUID, dst.ref.Key.PodUID)
		if err != nil {
			continue
		}
		plan, compileErr := policy.CompileZtunnelTCP(o.cluster, dst.subject, sources)
		if compileErr != nil {
			// Unknown or unsupported policy: deny every caller.
			deny, _ := quarantineAuthorization(dst.subject.Namespace, dst.ref.Key.NamespaceUID, dst.ref.Key.PodUID)
			_, setErr := o.policies.setEffective(key, deny)
			reason := "effective policy compilation failed: " + compileErr.Error()
			if setErr == nil && o.ineligible[dst.ref] != reason {
				o.event("compile_failed")
				o.log.Warn("Effective ztunnel policy compilation failed; workload denies every caller",
					logStage, "effective-policy", logfields.PodUID, dst.ref.Key.PodUID, logfields.Error, compileErr)
			}
			reasons[dst.ref] = reason
			o.forget(dst.ref)
			continue
		}
		allow := &security.Authorization{Name: strings.TrimPrefix(key, dst.subject.Namespace+"/"), Namespace: dst.subject.Namespace,
			Scope: security.Scope_WORKLOAD_SELECTOR, Action: security.Action_ALLOW, Rules: plan.ReviewAuthorization.Rules}
		if published, ok := o.publish(generation, acked, dst, key, allow, plan.Digest, sourceDigests); ok && published.acknowledged {
			acknowledged = append(acknowledged, dst)
		}
	}
	for _, dst := range acknowledged {
		if !o.callerPlansCurrent(dst) {
			reasons[dst.ref] = "a released workload's plan does not yet reflect this workload as a caller"
			continue
		}
		o.mu.Lock()
		cacheVersion := o.published[dst.ref].cacheVersion
		o.mu.Unlock()
		o.release(dst, cacheVersion)
	}
}

// callerPlansCurrent reports whether every plan that admits dst as a caller
// was compiled with dst's current subject and acknowledged by ztunnel. A plan
// of a quarantined destination admits nothing, so it never blocks. Without
// this, a workload whose egress narrowed (or whose identity changed) could be
// released while another destination still enforces the earlier ALLOW for it.
func (o *effectivePolicyOwner) callerPlansCurrent(dst candidate) bool {
	digest := subjectDigest(dst.subject)
	o.mu.Lock()
	defer o.mu.Unlock()
	for ref, plan := range o.published {
		listed, ok := plan.sources[dst.ref]
		if ref == dst.ref || !ok || (listed == digest && plan.acknowledged) {
			continue
		}
		state, ok := o.registry.Get(ref)
		if !ok {
			continue
		}
		if destination := o.endpoints.lookup(state.EndpointID); destination != nil && !destination.IsZtunnelQuarantined() {
			return false
		}
	}
	return true
}

// pruneRetired forgets plans of incarnations that no longer exist.
func (o *effectivePolicyOwner) pruneRetired() {
	o.mu.Lock()
	defer o.mu.Unlock()
	for ref := range o.published {
		if _, ok := o.registry.Get(ref); !ok {
			delete(o.published, ref)
		}
	}
}

// subjectDigest binds the caller fields a plan was compiled from.
func subjectDigest(s policy.ZtunnelPolicySubject) string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%d\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%d\x00%d\x00%s\x00", s.ClusterID, s.ClusterName, s.TrustDomain,
		s.Namespace, s.NamespaceUID, s.PodUID, s.ServiceAccount, s.NumericIdentity, s.EndpointID, s.Policy.ContentDigest())
	for _, addr := range s.Addresses {
		_, _ = fmt.Fprintf(h, "%s\x00", addr)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// logIneligible logs each workload's reason for not being an effective-policy
// destination once, when the reason changes, and when it becomes eligible.
func (o *effectivePolicyOwner) logIneligible(reasons map[membership.Reference]string) {
	for ref, reason := range reasons {
		if o.ineligible[ref] != reason {
			o.log.Info("Required workload is not an effective ztunnel policy destination",
				logStage, "effective-policy",
				logfields.PodUID, ref.Key.PodUID,
				logfields.Reason, reason)
			o.ineligible[ref] = reason
		}
	}
	for ref := range o.ineligible {
		if _, still := reasons[ref]; !still {
			delete(o.ineligible, ref)
			if _, ok := o.registry.Get(ref); ok {
				o.log.Info("Required workload is now an effective ztunnel policy destination",
					logStage, "effective-policy",
					logfields.PodUID, ref.Key.PodUID)
			}
		}
	}
}

func (o *effectivePolicyOwner) forget(ref membership.Reference) {
	o.mu.Lock()
	delete(o.published, ref)
	o.mu.Unlock()
}

func (o *effectivePolicyOwner) publish(generation, acked uint64, dst candidate, key string, allow *security.Authorization, digest string,
	sources map[membership.Reference]string) (publishedPolicy, bool) {
	o.mu.Lock()
	prev, had := o.published[dst.ref]
	o.mu.Unlock()
	// The registry's PolicyVersion is cleared when the endpoint's native policy
	// changes; that revocation must force a new publication and acknowledgment
	// even when the compiled digest is unchanged.
	current := had && prev.generation == generation && prev.addressVersion == dst.state.AddressVersion && prev.digest == digest &&
		dst.state.PolicyVersion == prev.policyVersion
	if !current {
		cacheVersion, err := o.policies.setEffective(key, allow)
		if err != nil {
			return publishedPolicy{}, false // the stream has not bound the workload yet
		}
		policyVersion, ok := o.registry.PublishPolicy(dst.ref, generation, membership.PolicyEvidence{
			WorkloadUID: dst.ref.Key.PodUID, AddressVersion: dst.state.AddressVersion, Revision: digest,
			BoundToWorkload: true, RequiresAuthenticatedPeer: true, DenyByDefault: true})
		if !ok {
			return publishedPolicy{}, false
		}
		prev = publishedPolicy{generation: generation, addressVersion: dst.state.AddressVersion, digest: digest,
			policyVersion: policyVersion, cacheVersion: cacheVersion, sources: sources}
		o.event("published")
		o.log.Info("Published effective ztunnel policy",
			logStage, "effective-policy", logfields.PodUID, dst.ref.Key.PodUID,
			"rules", len(allow.Rules), "authorizationVersion", cacheVersion, "planDigest", digest)
	}
	if !prev.acknowledged && acked >= prev.cacheVersion {
		if o.registry.AcknowledgePolicy(dst.ref, generation, prev.policyVersion) {
			prev.acknowledged = true
			o.event("acknowledged")
		}
	}
	o.mu.Lock()
	o.published[dst.ref] = prev
	o.mu.Unlock()
	return prev, true
}

// release frees the datapath quarantine of a workload whose membership,
// Address and effective policy are all current and acknowledged. The endpoint
// verifies the receipt again against its own state.
func (o *effectivePolicyOwner) release(dst candidate, authorizationVersion uint64) {
	state, ok := o.registry.Get(dst.ref)
	if !ok || !state.Active() || !dst.endpoint.IsZtunnelQuarantined() {
		return
	}
	receipt := endpoint.ZtunnelAdmissionReceipt{Binding: dst.release.Binding, Membership: dst.release.Membership,
		PolicyRevision: dst.release.PolicyRevision, PolicyDigest: dst.release.PolicyDigest,
		Identity: dst.release.Subject.NumericIdentity, AuthorizationVersion: authorizationVersion}
	if err := dst.endpoint.ReleaseZtunnelQuarantine(receipt); err != nil {
		o.event("release_refused")
		return
	}
	o.event("released")
	dst.endpoint.RegenerateIfAlive(endpoint.ZtunnelReleaseRegeneration())
}

// effectivePolicyKey is the namespace/name of a workload's effective policy.
func effectivePolicyKey(namespace, namespaceUID, podUID string) (string, error) {
	policy, err := quarantineAuthorization(namespace, namespaceUID, podUID)
	if err != nil {
		return "", err
	}
	return policy.Namespace + "/" + policy.Name, nil
}
