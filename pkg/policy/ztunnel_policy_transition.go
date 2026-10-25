// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package policy

// HasPendingZtunnelMapChanges is only an off-lock preparation hint. The guarded
// consumer rechecks under this same queue lock before mutating map state.
func (p *EndpointPolicy) HasPendingZtunnelMapChanges() bool {
	if p == nil {
		return false
	}
	p.policyMapChanges.mutex.Lock()
	defer p.policyMapChanges.mutex.Unlock()
	return len(p.policyMapChanges.changes) != 0 || len(p.policyMapChanges.synced) != 0
}
