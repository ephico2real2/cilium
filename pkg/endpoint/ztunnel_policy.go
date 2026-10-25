// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"fmt"
	"net/netip"

	"github.com/cilium/cilium/pkg/policy"
)

// SnapshotZtunnelPolicy copies only a current, realized native endpoint policy.
// Its metadata is not a substitute for capture or connection-bound membership.
// Cluster/domain authority is deliberately supplied later by the native caller.
func (e *Endpoint) SnapshotZtunnelPolicy() (policy.ZtunnelPolicySubject, error) {
	if err := e.rlockAlive(); err != nil {
		return policy.ZtunnelPolicySubject{}, err
	}
	defer e.runlock()
	return e.snapshotZtunnelPolicyRLocked()
}

// ZtunnelReleaseCandidate is everything a release owner binds to one
// workload incarnation, read under one endpoint lock: the exact incarnation,
// its published membership, and its realized native policy.
type ZtunnelReleaseCandidate struct {
	Binding        ZtunnelPolicyBinding
	Membership     ZtunnelMembership
	HasMembership  bool
	Subject        policy.ZtunnelPolicySubject
	PolicyRevision uint64
	PolicyDigest   string
}

// SnapshotZtunnelReleaseCandidate returns the native evidence for a release
// receipt. It is evidence, not a release: ReleaseZtunnelQuarantine verifies it
// again against the endpoint's state at release time.
func (e *Endpoint) SnapshotZtunnelReleaseCandidate() (ZtunnelReleaseCandidate, error) {
	if err := e.rlockAlive(); err != nil {
		return ZtunnelReleaseCandidate{}, err
	}
	defer e.runlock()
	subject, err := e.snapshotZtunnelPolicyRLocked()
	if err != nil {
		return ZtunnelReleaseCandidate{}, err
	}
	membership, ok := e.GetZtunnelMembership()
	return ZtunnelReleaseCandidate{Binding: e.ztunnelPolicyBindingLocked(), Membership: membership, HasMembership: ok,
		Subject: subject, PolicyRevision: e.policyRevision, PolicyDigest: subject.Policy.Digest()}, nil
}

func (e *Endpoint) snapshotZtunnelPolicyRLocked() (policy.ZtunnelPolicySubject, error) {
	if e.state != StateReady || e.realizedPolicy == nil || e.realizedPolicy != e.desiredPolicy ||
		e.policyRevision == 0 || e.desiredPolicyRevision != e.policyRevision || e.SecurityIdentity == nil {
		return policy.ZtunnelPolicySubject{}, fmt.Errorf("endpoint native policy is not current and realized")
	}
	nsUID := e.GetK8sNamespaceUID()
	pod := e.GetPod()
	if pod == nil || nsUID == "" || e.GetK8sPodUID() == "" || string(pod.UID) != e.GetK8sPodUID() ||
		pod.Namespace != e.K8sNamespace || pod.Spec.ServiceAccountName == "" {
		return policy.ZtunnelPolicySubject{}, fmt.Errorf("current Kubernetes endpoint incarnation is unavailable")
	}
	resolved, err := e.realizedPolicy.SnapshotZtunnelL4(e.policyRevision)
	if err != nil {
		return policy.ZtunnelPolicySubject{}, err
	}
	var addresses []netip.Addr
	if e.IPv4.IsValid() {
		addresses = append(addresses, e.IPv4)
	}
	if e.IPv6.IsValid() {
		addresses = append(addresses, e.IPv6)
	}
	if nsUID != e.GetK8sNamespaceUID() || e.GetPod() != pod {
		return policy.ZtunnelPolicySubject{}, fmt.Errorf("Kubernetes endpoint incarnation changed during policy capture")
	}
	return policy.ZtunnelPolicySubject{EndpointID: e.ID, Namespace: e.K8sNamespace, NamespaceUID: nsUID, PodUID: e.GetK8sPodUID(),
		ServiceAccount: pod.Spec.ServiceAccountName, NumericIdentity: e.SecurityIdentity.ID, Addresses: addresses, Policy: resolved}, nil
}
