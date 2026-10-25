// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xds

import (
	"context"
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
}

type publishedPolicy struct {
	generation     uint64
	addressVersion uint64
	digest         string
	policyVersion  uint64
	cacheVersion   uint64
	acknowledged   bool
}

func newEffectivePolicyOwner(log *slog.Logger, registry *membership.Registry, endpoints endpointLookup, policies *AuthorizationPolicies,
	cluster cmtypes.ClusterInfo, trustDomain string, metrics *Metrics) *effectivePolicyOwner {
	return &effectivePolicyOwner{log: log, registry: registry, endpoints: endpoints, policies: policies, cluster: cluster,
		trustDomain: trustDomain, metrics: metrics, interval: time.Second, trigger: make(chan struct{}, 1),
		published: make(map[membership.Reference]publishedPolicy)}
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

func (o *effectivePolicyOwner) candidates() []candidate {
	var out []candidate
	for ref, state := range o.registry.Snapshot() {
		if !state.ReadyForAddress() {
			continue
		}
		ep := o.endpoints.lookup(state.EndpointID)
		if ep == nil || ep.GetK8sPodUID() != ref.Key.PodUID {
			continue
		}
		release, err := ep.SnapshotZtunnelReleaseCandidate()
		if err != nil {
			continue // policy not realized: neither a destination nor a source now
		}
		m := release.Membership
		if !release.HasMembership || m.Epoch != ref.Epoch || m.Generation != state.ZDSGeneration ||
			m.State != membership.PublicationCaptured || m.NamespaceUID != ref.Key.NamespaceUID {
			continue // the endpoint has not published this exact captured incarnation
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
	all := o.candidates()
	for i, dst := range all {
		if dst.state.ADSGeneration != generation || !dst.state.AddressAcked {
			continue // the workload Address must be acknowledged on this stream first
		}
		sources := make([]policy.ZtunnelPolicySubject, 0, len(all)-1)
		for j, src := range all {
			if j != i {
				sources = append(sources, src.subject)
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
			if _, err := o.policies.setEffective(key, deny); err == nil {
				o.event("compile_failed")
				o.log.Warn("Effective ztunnel policy compilation failed; workload denies every caller",
					logStage, "effective-policy", logfields.PodUID, dst.ref.Key.PodUID, logfields.Error, compileErr)
			}
			o.forget(dst.ref)
			continue
		}
		allow := &security.Authorization{Name: strings.TrimPrefix(key, dst.subject.Namespace+"/"), Namespace: dst.subject.Namespace,
			Scope: security.Scope_WORKLOAD_SELECTOR, Action: security.Action_ALLOW, Rules: plan.ReviewAuthorization.Rules}
		o.publish(generation, acked, dst, key, allow, plan.Digest)
	}
}

func (o *effectivePolicyOwner) forget(ref membership.Reference) {
	o.mu.Lock()
	delete(o.published, ref)
	o.mu.Unlock()
}

func (o *effectivePolicyOwner) publish(generation, acked uint64, dst candidate, key string, allow *security.Authorization, digest string) {
	o.mu.Lock()
	prev, had := o.published[dst.ref]
	o.mu.Unlock()
	current := had && prev.generation == generation && prev.addressVersion == dst.state.AddressVersion && prev.digest == digest
	if !current {
		cacheVersion, err := o.policies.setEffective(key, allow)
		if err != nil {
			return // the stream has not bound the workload yet
		}
		policyVersion, ok := o.registry.PublishPolicy(dst.ref, generation, membership.PolicyEvidence{
			WorkloadUID: dst.ref.Key.PodUID, AddressVersion: dst.state.AddressVersion, Revision: digest,
			BoundToWorkload: true, RequiresAuthenticatedPeer: true, DenyByDefault: true})
		if !ok {
			return
		}
		prev = publishedPolicy{generation: generation, addressVersion: dst.state.AddressVersion, digest: digest,
			policyVersion: policyVersion, cacheVersion: cacheVersion}
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
	if prev.acknowledged {
		o.release(dst, prev.cacheVersion)
	}
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
		AuthorizationVersion: authorizationVersion}
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
