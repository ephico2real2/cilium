// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import "github.com/cilium/cilium/pkg/option"

// ztunnelRequiresSourceIPLocked reports states for which source-IP
// verification must remain enabled. Endpoint mutex is held by option writers.
func (e *Endpoint) ztunnelRequiresSourceIPLocked() bool {
	if e.ztunnelSourceIPRequired.Load() {
		return true
	}
	membership, ok := e.GetZtunnelMembership()
	return ok && membership.State != ZtunnelMembershipUnenrolled
}

func (e *Endpoint) sourceIPDisableDeniedLocked(setting option.OptionSetting) bool {
	return setting == option.OptionDisabled && e.ztunnelRequiresSourceIPLocked()
}
