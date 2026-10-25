// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import "github.com/cilium/cilium/pkg/option"

// ZtunnelMembership is process-local evidence exported with the endpoint's
// native IPIdentityPair. It is deliberately omitted from endpoint restore
// state. A restored endpoint must pass admission and receive a new ZDS ACK.
type ZtunnelMembership struct {
	Version        uint8
	Revision       uint64
	Epoch          string
	Generation     uint64
	State          string
	NamespaceUID   string
	NodeName       string
	ServiceAccount string
}

const (
	ZtunnelMembershipUnenrolled = "unenrolled"
	ZtunnelMembershipRequired   = "required"
	ZtunnelMembershipCaptured   = "captured"
	ZtunnelMembershipDraining   = "draining"
)

// SetZtunnelMembership replaces the in-memory source evidence and schedules an
// immediate native IPIdentityPair refresh. The membership registry, not this
// copied wire value, remains the authority for ACK transitions.
func (e *Endpoint) SetZtunnelMembership(m ZtunnelMembership) bool {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	if m.Version != 1 {
		return false
	}
	switch m.State {
	case ZtunnelMembershipUnenrolled, ZtunnelMembershipRequired, ZtunnelMembershipCaptured, ZtunnelMembershipDraining:
	default:
		return false
	}
	if m.State == ZtunnelMembershipCaptured && (m.Revision == 0 || m.Epoch == "" || m.Generation == 0) {
		return false
	}
	if m.State != ZtunnelMembershipUnenrolled && (e.Options == nil || !e.Options.IsEnabled(option.SourceIPVerification)) {
		e.Logger(subsystem).Warn("Refusing ztunnel membership without source IP verification")
		return false
	}
	if previous := e.ztunnelMembership.Load(); previous != nil {
		if previous.Epoch != "" && previous.Epoch != m.Epoch {
			return false
		}
		if previous.Revision > 0 && m.Revision <= previous.Revision {
			return *previous == m
		}
	}
	if m.State != ZtunnelMembershipUnenrolled {
		e.ztunnelSourceIPRequired.Store(true)
	}
	copy := m
	e.ztunnelMembership.Store(&copy)
	if e.kvstoreSyncher == nil || !e.kvstoreSyncher.IsEnabled() {
		return true
	}
	if option.Config.EnableIPv4 {
		e.runIPIdentitySync(e.IPv4)
	}
	if option.Config.EnableIPv6 {
		e.runIPIdentitySync(e.IPv6)
	}
	return true
}

// GetZtunnelMembership returns a copy of the process-local source evidence.
func (e *Endpoint) GetZtunnelMembership() (ZtunnelMembership, bool) {
	p := e.ztunnelMembership.Load()
	if p == nil {
		return ZtunnelMembership{}, false
	}
	return *p, true
}
