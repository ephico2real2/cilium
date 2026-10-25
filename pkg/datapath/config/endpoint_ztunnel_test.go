// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	endpointtypes "github.com/cilium/cilium/pkg/endpoint/types"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/option"
)

type testZtunnelConfigEndpoint struct {
	endpointtypes.Config
	options     *option.IntOptions
	required    bool
	quarantined bool
}

func (e testZtunnelConfigEndpoint) GetID() uint64                         { return 42 }
func (e testZtunnelConfigEndpoint) GetIdentity() identity.NumericIdentity { return 100 }
func (e testZtunnelConfigEndpoint) IPv4Address() netip.Addr               { return netip.Addr{} }
func (e testZtunnelConfigEndpoint) IPv6Address() netip.Addr               { return netip.Addr{} }
func (e testZtunnelConfigEndpoint) GetNodeMAC() mac.MAC                   { return mac.MAC{} }
func (e testZtunnelConfigEndpoint) GetIfIndex() int                       { return 1 }
func (e testZtunnelConfigEndpoint) GetEndpointNetNsCookie() uint64        { return 1 }
func (e testZtunnelConfigEndpoint) GetPolicyVerdictLogFilter() uint32     { return 0 }
func (e testZtunnelConfigEndpoint) GetRTInfo() (uint32, endpointtypes.RTInfoEncoding) {
	return 0, endpointtypes.RTInfoNone
}
func (e testZtunnelConfigEndpoint) GetOptions() *option.IntOptions { return e.options }
func (e testZtunnelConfigEndpoint) RequireBPFRouting() bool        { return false }
func (e testZtunnelConfigEndpoint) SourceIPDatapathIdentity() endpointtypes.SourceIPDatapathIdentity {
	return endpointtypes.SourceIPDatapathIdentity{ZtunnelRequired: e.required}
}
func (e testZtunnelConfigEndpoint) IsZtunnelQuarantined() bool { return e.quarantined }

func TestEndpointConfigSeparatesRequiredFromQuarantine(t *testing.T) {
	lib := option.GetEndpointMutableOptionLibrary()
	for _, tc := range []struct {
		name        string
		required    bool
		quarantined bool
	}{
		{name: "ordinary", required: false, quarantined: false},
		{name: "required with quarantine withheld", required: true, quarantined: false},
		{name: "required and quarantined", required: true, quarantined: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ep := testZtunnelConfigEndpoint{
				options: option.NewIntOptions(&lib), required: tc.required, quarantined: tc.quarantined,
			}
			cfg := Endpoint(ep, &Config{}).(*BPFLXC)
			require.Equal(t, tc.required, ep.SourceIPDatapathIdentity().ZtunnelRequired, "SourceIP identity keeps the sticky Required meaning")
			require.Equal(t, tc.quarantined, cfg.ZtunnelQuarantined, "BPF drop config reads quarantine only")
		})
	}
}
