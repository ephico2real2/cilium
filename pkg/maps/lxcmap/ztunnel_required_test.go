// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lxcmap

import (
	"net/netip"
	"testing"

	eptypes "github.com/cilium/cilium/pkg/endpoint/types"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/mac"
)

type testEndpointFrontend struct {
	required    bool // the sticky obligation is exposed only as the mesh-only bit
	quarantined bool
}

func (e testEndpointFrontend) LXCMac() mac.MAC       { return mac.MAC{} }
func (e testEndpointFrontend) GetNodeMAC() mac.MAC   { return mac.MAC{} }
func (e testEndpointFrontend) GetIfIndex() int       { return 1 }
func (e testEndpointFrontend) GetParentIfIndex() int { return 0 }
func (e testEndpointFrontend) GetID() uint64         { return 42 }
func (e testEndpointFrontend) GetRTInfo() (uint32, eptypes.RTInfoEncoding) {
	return 0, eptypes.RTInfoNone
}
func (e testEndpointFrontend) IPv4Address() netip.Addr               { return netip.MustParseAddr("10.0.0.2") }
func (e testEndpointFrontend) IPv6Address() netip.Addr               { return netip.Addr{} }
func (e testEndpointFrontend) GetIdentity() identity.NumericIdentity { return 100 }
func (e testEndpointFrontend) IsAtHostNS() bool                      { return false }
func (e testEndpointFrontend) SkipMasqueradeV4() bool                { return false }
func (e testEndpointFrontend) SkipMasqueradeV6() bool                { return false }
func (e testEndpointFrontend) IsZtunnelQuarantined() bool            { return e.quarantined }
func (e testEndpointFrontend) IsZtunnelMeshOnly() bool               { return e.required }

func TestGetBPFValueSeparatesQuarantineAndMeshOnly(t *testing.T) {
	const both = EndpointFlagZtunnelQuarantined | EndpointFlagZtunnelMeshOnly
	for _, tc := range []struct {
		name        string
		required    bool
		quarantined bool
		want        uint32
	}{
		{name: "ordinary endpoint", want: 0},
		{name: "released Required endpoint is mesh-only", required: true, want: EndpointFlagZtunnelMeshOnly},
		{name: "quarantined Required endpoint carries both bits", required: true, quarantined: true, want: both},
		{name: "quarantine without Required still drops", quarantined: true, want: EndpointFlagZtunnelQuarantined},
	} {
		t.Run(tc.name, func(t *testing.T) {
			info, err := (&lxcMap{}).getBPFValue(testEndpointFrontend{required: tc.required, quarantined: tc.quarantined})
			if err != nil {
				t.Fatalf("getBPFValue() error = %v", err)
			}
			if got := info.Flags & both; got != tc.want {
				t.Fatalf("ztunnel admission flags = %#x, want %#x", got, tc.want)
			}
		})
	}
}
