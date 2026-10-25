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
	ipv4, ipv6  netip.Addr
}

func (e testZtunnelConfigEndpoint) GetID() uint64                         { return 42 }
func (e testZtunnelConfigEndpoint) GetIdentity() identity.NumericIdentity { return 100 }
func (e testZtunnelConfigEndpoint) IPv4Address() netip.Addr               { return e.ipv4 }
func (e testZtunnelConfigEndpoint) IPv6Address() netip.Addr               { return e.ipv6 }
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
func (e testZtunnelConfigEndpoint) IsZtunnelMeshOnly() bool    { return e.required }

func TestEndpointConfigSeparatesRequiredFromQuarantine(t *testing.T) {
	lib := option.GetEndpointMutableOptionLibrary()
	v4, v6 := netip.MustParseAddr("10.0.0.7"), netip.MustParseAddr("fd00::7")
	for _, tc := range []struct {
		name            string
		required        bool
		quarantined     bool
		ipv4, ipv6      netip.Addr
		wantQuarantined bool
	}{
		{name: "ordinary", ipv4: v4},
		{name: "ordinary without address", wantQuarantined: false},
		{name: "required with quarantine withheld", required: true, ipv4: v4},
		{name: "required single-stack IPv6 with quarantine withheld", required: true, ipv6: v6},
		{name: "required and quarantined", required: true, quarantined: true, ipv4: v4, ipv6: v6, wantQuarantined: true},
		{name: "required without any address is compiled quarantined", required: true, wantQuarantined: true},
		{name: "required with only unspecified addresses is compiled quarantined", required: true,
			ipv4: netip.IPv4Unspecified(), ipv6: netip.IPv6Unspecified(), wantQuarantined: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ep := testZtunnelConfigEndpoint{
				options: option.NewIntOptions(&lib), required: tc.required, quarantined: tc.quarantined,
				ipv4: tc.ipv4, ipv6: tc.ipv6,
			}
			cfg := Endpoint(ep, &Config{}).(*BPFLXC)
			require.Equal(t, tc.required, ep.SourceIPDatapathIdentity().ZtunnelRequired, "SourceIP identity keeps the sticky Required meaning")
			require.Equal(t, tc.wantQuarantined, cfg.ZtunnelQuarantined, "BPF drop config")
			require.Equal(t, tc.required, cfg.ZtunnelRequired, "sticky Required forbids ordinary forwarding at load time")
			if tc.ipv4.IsValid() && !tc.ipv4.IsUnspecified() {
				require.Equal(t, tc.ipv4.As4(), cfg.EndpointIPv4.Addr)
			} else {
				require.Equal(t, [4]byte{}, cfg.EndpointIPv4.Addr, "an unspecified address is not compiled")
			}
			if tc.ipv6.IsValid() && !tc.ipv6.IsUnspecified() {
				require.Equal(t, tc.ipv6.As16(), cfg.EndpointIPv6.Addr)
			} else {
				require.Equal(t, [16]byte{}, cfg.EndpointIPv6.Addr, "an unspecified address is not compiled")
			}
		})
	}
}
