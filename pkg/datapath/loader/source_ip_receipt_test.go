// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"context"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/datapath/config"
	"github.com/cilium/cilium/pkg/endpoint/types"
)

func validSourceIPIdentity() types.SourceIPDatapathIdentity {
	return types.SourceIPDatapathIdentity{
		EndpointID:      42,
		NamespaceUID:    "namespace-uid-a",
		PodUID:          "pod-uid-a",
		NetNSPath:       "/var/run/netns/pod-a",
		NetNSCookie:     111,
		Interface:       "lxc1234",
		IfIndex:         17,
		ConfigHash:      "bpf-config-a",
		IPv4:            netip.MustParseAddr("10.0.0.42"),
		SourceIPEnabled: true,
	}
}

func validSourceIPObservation() types.SourceIPDatapathObservation {
	return types.SourceIPDatapathObservation{
		Identity:          validSourceIPIdentity(),
		ProgramID:         99,
		ProgramTag:        "abcd1234",
		LinkID:            88,
		AttachSetRevision: 5,
		ProgramMapIDsHash: "maps-hash",
		ConfigMapID:       77,
		ConfigMapName:     ".rodata.config",
		ConfigMapHash:     "config-hash",
		SIPConfigSize:     1,
		SIPConfigEnabled:  true,
		ConfigMapReadOnly: true,
		ConfigMapFrozen:   true,
	}
}

func TestSourceIPReceiptMatchesExactEndpointAndKernelState(t *testing.T) {
	receipt := validSourceIPObservation()
	require.True(t, sourceIPAttachmentMatches(receipt, receipt.Identity, receipt))

	identityCases := map[string]func(*types.SourceIPDatapathIdentity){
		"endpoint id":           func(i *types.SourceIPDatapathIdentity) { i.EndpointID++ },
		"namespace uid":         func(i *types.SourceIPDatapathIdentity) { i.NamespaceUID = "namespace-uid-b" },
		"pod uid":               func(i *types.SourceIPDatapathIdentity) { i.PodUID = "pod-uid-b" },
		"netns path":            func(i *types.SourceIPDatapathIdentity) { i.NetNSPath += ".new" },
		"netns cookie":          func(i *types.SourceIPDatapathIdentity) { i.NetNSCookie++ },
		"interface name":        func(i *types.SourceIPDatapathIdentity) { i.Interface = "lxc5678" },
		"interface index":       func(i *types.SourceIPDatapathIdentity) { i.IfIndex++ },
		"config hash":           func(i *types.SourceIPDatapathIdentity) { i.ConfigHash = "bpf-config-b" },
		"endpoint address":      func(i *types.SourceIPDatapathIdentity) { i.IPv4 = netip.MustParseAddr("10.0.0.43") },
		"source guard disabled": func(i *types.SourceIPDatapathIdentity) { i.SourceIPEnabled = false },
	}
	for name, mutate := range identityCases {
		t.Run(name, func(t *testing.T) {
			expected := receipt.Identity
			mutate(&expected)
			require.False(t, sourceIPAttachmentMatches(receipt, expected, receipt))
		})
	}

	kernelCases := map[string]func(*types.SourceIPDatapathObservation){
		"program replaced":         func(o *types.SourceIPDatapathObservation) { o.ProgramID++ },
		"program bytecode changed": func(o *types.SourceIPDatapathObservation) { o.ProgramTag = "different" },
		"link replaced":            func(o *types.SourceIPDatapathObservation) { o.LinkID++ },
		"attachment set changed":   func(o *types.SourceIPDatapathObservation) { o.AttachSetRevision++ },
	}
	for name, mutate := range kernelCases {
		t.Run(name, func(t *testing.T) {
			current := receipt
			mutate(&current)
			require.False(t, sourceIPAttachmentMatches(receipt, receipt.Identity, current))
		})
	}

	for name, mutate := range map[string]func(*types.SourceIPDatapathObservation){
		"missing rodata map id": func(o *types.SourceIPDatapathObservation) { o.ConfigMapID = 0 },
		"missing rodata digest": func(o *types.SourceIPDatapathObservation) { o.ConfigMapHash = "" },
		"wrong rodata section":  func(o *types.SourceIPDatapathObservation) { o.ConfigMapName = ".rodata" },
		"source check off":      func(o *types.SourceIPDatapathObservation) { o.SIPConfigEnabled = false },
		"writable map":          func(o *types.SourceIPDatapathObservation) { o.ConfigMapReadOnly = false },
		"unfrozen map":          func(o *types.SourceIPDatapathObservation) { o.ConfigMapFrozen = false },
	} {
		t.Run(name, func(t *testing.T) {
			incomplete := receipt
			mutate(&incomplete)
			require.False(t, sourceIPAttachmentMatches(incomplete, receipt.Identity, receipt))
		})
	}
}

func TestValidateSourceIPIdentityRejectsIncompleteIncarnations(t *testing.T) {
	valid := validSourceIPIdentity()
	require.NoError(t, validateSourceIPIdentity(valid))
	cases := map[string]func(*types.SourceIPDatapathIdentity){
		"endpoint id":           func(i *types.SourceIPDatapathIdentity) { i.EndpointID = 0 },
		"namespace uid":         func(i *types.SourceIPDatapathIdentity) { i.NamespaceUID = "" },
		"pod uid":               func(i *types.SourceIPDatapathIdentity) { i.PodUID = "" },
		"netns path":            func(i *types.SourceIPDatapathIdentity) { i.NetNSPath = "" },
		"netns cookie":          func(i *types.SourceIPDatapathIdentity) { i.NetNSCookie = 0 },
		"interface":             func(i *types.SourceIPDatapathIdentity) { i.Interface = "" },
		"interface index":       func(i *types.SourceIPDatapathIdentity) { i.IfIndex = 0 },
		"config hash":           func(i *types.SourceIPDatapathIdentity) { i.ConfigHash = "" },
		"endpoint address":      func(i *types.SourceIPDatapathIdentity) { i.IPv4 = netip.Addr{} },
		"invalid IPv4 family":   func(i *types.SourceIPDatapathIdentity) { i.IPv4 = netip.MustParseAddr("::ffff:10.0.0.42") },
		"source guard disabled": func(i *types.SourceIPDatapathIdentity) { i.SourceIPEnabled = false },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			identity := valid
			mutate(&identity)
			require.Error(t, validateSourceIPIdentity(identity))
		})
	}
}

func TestExpectedSourceIPConfigMatchesEndpointIncarnation(t *testing.T) {
	identity := validSourceIPIdentity()
	cfg := &config.BPFLXC{
		EnableSIPVerification: true,
		EndpointID:            identity.EndpointID,
		EndpointNetNSCookie:   identity.NetNSCookie,
		InterfaceIfIndex:      uint32(identity.IfIndex),
	}
	copy(cfg.EndpointIPv4.Addr[:], identity.IPv4.AsSlice())

	expected, err := expectedSourceIPConfigValues(identity, cfg)
	require.NoError(t, err)
	require.Equal(t, []byte{1}, expected["__config_enable_sip_verification"])
	require.Equal(t, identity.IPv4.AsSlice(), expected["__config_endpoint_ipv4"])

	cases := map[string]func(*config.BPFLXC){
		"disabled source verification": func(c *config.BPFLXC) { c.EnableSIPVerification = false },
		"different endpoint id":        func(c *config.BPFLXC) { c.EndpointID++ },
		"different namespace cookie":   func(c *config.BPFLXC) { c.EndpointNetNSCookie++ },
		"different interface":          func(c *config.BPFLXC) { c.InterfaceIfIndex++ },
		"different endpoint address":   func(c *config.BPFLXC) { c.EndpointIPv4.Addr[3]++ },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			changed := *cfg
			mutate(&changed)
			_, err := expectedSourceIPConfigValues(identity, &changed)
			require.Error(t, err)
		})
	}

	noIPv4Identity := identity
	noIPv4Identity.IPv4 = netip.Addr{}
	_, err = expectedSourceIPConfigValues(noIPv4Identity, cfg)
	require.ErrorContains(t, err, "unowned IPv4 address")
}

func TestVerifySourceIPConfigVariablesChecksKernelOffsetsAndValues(t *testing.T) {
	const section = ".rodata.config"
	expected := map[string][]byte{
		"__config_enable_sip_verification": {1},
		"__config_endpoint_id":             {42, 0},
	}
	variables := map[string]*ebpf.VariableSpec{
		"__config_enable_sip_verification": {Name: "__config_enable_sip_verification", SectionName: section, Offset: 1, Value: []byte{0}},
		"__config_endpoint_id":             {Name: "__config_endpoint_id", SectionName: section, Offset: 4, Value: []byte{0, 0}},
	}
	value := make([]byte, 8)
	copy(value[1:], expected["__config_enable_sip_verification"])
	copy(value[4:], expected["__config_endpoint_id"])
	require.NoError(t, verifySourceIPConfigVariables(variables, section, value, expected))

	wrongValue := append([]byte(nil), value...)
	wrongValue[1] = 0
	require.ErrorContains(t, verifySourceIPConfigVariables(variables, section, wrongValue, expected), "does not match")

	wrongSection := map[string]*ebpf.VariableSpec{
		"__config_enable_sip_verification": {Name: "__config_enable_sip_verification", SectionName: ".rodata", Offset: 1, Value: []byte{0}},
		"__config_endpoint_id":             variables["__config_endpoint_id"],
	}
	require.ErrorContains(t, verifySourceIPConfigVariables(wrongSection, section, value, expected), "unexpected layout")

	outOfBounds := map[string]*ebpf.VariableSpec{
		"__config_enable_sip_verification": {Name: "__config_enable_sip_verification", SectionName: section, Offset: 8, Value: []byte{0}},
		"__config_endpoint_id":             variables["__config_endpoint_id"],
	}
	require.ErrorContains(t, verifySourceIPConfigVariables(outOfBounds, section, value, expected), "exceeds")
}

func TestSourceIPVerificationFailsClosedWithoutRetainedReceipt(t *testing.T) {
	l := &loader{}
	_, err := l.VerifySourceIPDatapath(context.Background(), validSourceIPIdentity())
	require.ErrorContains(t, err, "no current source IP datapath receipt")
}

func TestInvalidateSourceIPReceiptRemovesExactEndpointEntry(t *testing.T) {
	l := &loader{sourceIPReceiptGenerations: map[uint16]uint64{42: 1, 43: 1}, sourceIPReceipts: map[uint16]sourceIPReceipt{
		42: {generation: 1, observation: validSourceIPObservation()},
		43: {generation: 1, observation: func() types.SourceIPDatapathObservation {
			o := validSourceIPObservation()
			o.Identity.EndpointID = 43
			return o
		}()},
	}}
	l.invalidateSourceIPReceipt(42)
	require.NotContains(t, l.sourceIPReceipts, uint16(42))
	require.Contains(t, l.sourceIPReceipts, uint16(43))
}

func TestLateSourceIPReceiptCannotCrossReloadOrUnloadGeneration(t *testing.T) {
	l := &loader{}
	old := l.beginSourceIPReceiptGeneration(42)
	newGeneration := l.beginSourceIPReceiptGeneration(42)
	require.NotEqual(t, old, newGeneration)
	require.False(t, l.storeSourceIPReceiptIfCurrent(42, old, validSourceIPObservation()))
	require.True(t, l.storeSourceIPReceiptIfCurrent(42, newGeneration, validSourceIPObservation()))
	l.invalidateSourceIPReceipt(42)
	require.False(t, l.storeSourceIPReceiptIfCurrent(42, newGeneration, validSourceIPObservation()))
	require.NotContains(t, l.sourceIPReceipts, uint16(42))
}

func TestSourceIPReceiptGenerationExhaustionFailsClosed(t *testing.T) {
	l := &loader{sourceIPReceiptGenerations: map[uint16]uint64{42: ^uint64(0)}}
	require.Zero(t, l.beginSourceIPReceiptGeneration(42))
	require.False(t, l.storeSourceIPReceiptIfCurrent(42, ^uint64(0), validSourceIPObservation()))
	require.NotContains(t, l.sourceIPReceipts, uint16(42))
}

func TestKernelObjectNameUsesLinuxVisibleNameLimit(t *testing.T) {
	const ciliumIngressSymbol = "cil_from_container"
	require.Equal(t, "cil_from_contai", kernelObjectName(ciliumIngressSymbol))
	require.Len(t, kernelObjectName(ciliumIngressSymbol), 15)
	require.Equal(t, "short", kernelObjectName("short"))
}

func TestSourceIPConfigMapValueSizeIsBoundedAndMatchesSpec(t *testing.T) {
	tests := []struct {
		name     string
		expected uint32
		actual   uint32
		wantErr  bool
	}{
		{name: "normal exact layout", expected: 4096, actual: 4096},
		{name: "zero layout", expected: 0, actual: 0, wantErr: true},
		{name: "oversized spec", expected: maxSourceIPConfigMapValueSize + 1, actual: maxSourceIPConfigMapValueSize + 1, wantErr: true},
		{name: "kernel map mismatch", expected: 4096, actual: 8192, wantErr: true},
		{name: "kernel map oversized", expected: 4096, actual: maxSourceIPConfigMapValueSize + 1, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSourceIPConfigMapValueSize(tt.expected, tt.actual)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestSourceIPProgramNameAcceptsExactBTFOrLegacyNameOnly(t *testing.T) {
	require.True(t, sourceIPProgramName(symbolFromEndpoint))
	require.True(t, sourceIPProgramName(kernelObjectName(symbolFromEndpoint)))
	for _, name := range []string{"", "cil_from", symbolFromEndpoint + "_foreign", "cil_from_contax", "cil_to_container"} {
		require.False(t, sourceIPProgramName(name), name)
	}
}
