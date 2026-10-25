// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package zds

import "fmt"

// The ownership observation below inspects retained ADD bookkeeping (pending,
// history, attempts, drain bindings and the replay cache). Production code no
// longer consults it: policy changes are fenced by enforced content in the
// endpoint. Tests use it to assert what the bookkeeping retains.

type PolicyOwnership uint8

const (
	PolicyOwnershipAbsent PolicyOwnership = iota + 1
	PolicyOwnershipRetained
)

// PolicyOwnershipInspector is native process-local correlation, not an ACK,
// authentication, authorization, or a remotely supplied proof API.
type PolicyOwnershipInspector interface {
	ObservePolicyOwnership(uint16, string, string) (PolicyOwnership, error)
}

// ObservePolicyOwnership is called with the endpoint mutex held. The cache
// contains callbacks that may need that mutex, so NEVER block taking its lock.
// The observation only reads, so it takes the shared lock: concurrent
// observers do not exclude each other, and only an in-progress writer makes it
// unavailable. An unavailable observation fails this update closed and can be
// retried. No endpoint method, filesystem/network operation or FD retention
// occurs here.
func (s *Server) ObservePolicyOwnership(id uint16, uid, path string) (PolicyOwnership, error) {
	if s == nil {
		return 0, fmt.Errorf("native ZDS owner is unavailable")
	}
	if !s.endpointCacheMutex.TryRLock() {
		return 0, fmt.Errorf("native ZDS ownership is busy")
	}
	defer s.endpointCacheMutex.RUnlock()
	matches := func(candidateID uint16, candidateUID, candidatePath string) bool {
		return (id != 0 && id == candidateID) || (uid != "" && uid == candidateUID) || (path != "" && path == candidatePath)
	}
	for pending := range s.policyADDPending {
		if matches(pending.key.id, pending.key.uid, pending.key.netnsPath) {
			return PolicyOwnershipRetained, nil
		}
	}
	for key, history := range s.policyADDHistory {
		if matches(key.id, key.uid, key.netnsPath) {
			return PolicyOwnershipRetained, nil
		}
		for _, binding := range history {
			if binding != nil && matches(uint16(binding.EndpointId), binding.PodUid, "") {
				return PolicyOwnershipRetained, nil
			}
		}
	}
	for key, binding := range s.policyADDAttempts {
		if matches(key.id, key.uid, key.netnsPath) || (binding != nil && matches(uint16(binding.EndpointId), binding.PodUid, "")) {
			return PolicyOwnershipRetained, nil
		}
	}
	for key, binding := range s.drainBindings {
		if matches(key.id, key.uid, key.netnsPath) {
			return PolicyOwnershipRetained, nil
		}
		// Corrupt/mismatched retained payload is restrictive, not proof of absence.
		if binding != nil && matches(uint16(binding.EndpointId), binding.PodUid, "") {
			return PolicyOwnershipRetained, nil
		}
	}
	for candidateID, cached := range s.endpointCache {
		if id != 0 && id == candidateID {
			return PolicyOwnershipRetained, nil
		}
		// Pod UID is immutable in the native cache. Do not call getters that could
		// acquire an endpoint lock while holding this subsystem lock.
		if cached != nil && uid != "" && cached.K8sUID == uid {
			return PolicyOwnershipRetained, nil
		}
	}
	return PolicyOwnershipAbsent, nil
}
