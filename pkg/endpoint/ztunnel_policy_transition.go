// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

// ZtunnelPolicyBinding is captured under the endpoint lock. It is correlation
// for a native registry/ZDS join, never authority supplied by a workload.
type ZtunnelPolicyBinding struct {
	// RequiredObserved is a sticky local restriction, not proof of capture,
	// authorization or an ADD. It must never make an unsafe state eligible.
	RequiredObserved                             bool
	EndpointID                                   uint16
	NamespaceUID, PodUID, NetNSPath, ContainerID string
	NetNSCookie                                  uint64
}

func (e *Endpoint) ztunnelPolicyBindingLocked() ZtunnelPolicyBinding {
	return ZtunnelPolicyBinding{RequiredObserved: e.ztunnelRequiresSourceIPLocked(), EndpointID: e.ID, NamespaceUID: e.GetK8sNamespaceUID(),
		PodUID: e.K8sUID, NetNSPath: e.containerNetnsPath, ContainerID: e.GetContainerID(), NetNSCookie: e.NetNsCookie}
}

// fenceZtunnelPolicyChangeLocked withdraws the datapath admission of a released
// Required endpoint when the ztunnel input it was released for no longer
// holds: the enforced L4 policy content or the security identity changed.
//
// It runs once per policy-map mutation, after incremental changes are
// consumed into the desired policy and before any of them reach the BPF policy
// map or a compiled program, so nothing flows under superseded authority. A
// regeneration that keeps the same content and identity (periodic, release,
// unrelated revision bumps) leaves admission untouched. It never waits and
// never fails: without a receipt the endpoint is already quarantined, and the
// next release re-verifies everything. The endpoint mutex must be held.
func (e *Endpoint) fenceZtunnelPolicyChangeLocked() {
	if !e.ztunnelRequiresSourceIPLocked() {
		return
	}
	r := e.ztunnelAdmission.Load()
	if r == nil {
		return
	}
	if e.SecurityIdentity == nil || e.SecurityIdentity.ID != r.Identity {
		e.WithdrawZtunnelAdmission("security identity changed")
		return
	}
	digest, err := e.desiredPolicy.ZtunnelContentDigest()
	if err != nil || digest != r.PolicyDigest {
		e.WithdrawZtunnelAdmission("enforced ztunnel policy content changed")
	}
}

// ObserveZtunnelRequired records the sticky SourceIPVerification obligation and
// independently closes the datapath quarantine. It provides no capture/ACK/TLS
// evidence. Release requires ReleaseZtunnelQuarantine with a verified receipt;
// every later observation (including a new membership generation) withdraws
// it. Atomics plus one endpoint-map write: safe for callers that already hold
// another subsystem's mutex.
func (e *Endpoint) ObserveZtunnelRequired() {
	e.ztunnelSourceIPRequired.Store(true)
	e.WithdrawZtunnelAdmission("Required intent or a new membership generation observed")
}
