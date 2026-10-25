// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package loader

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	linuxConfig "github.com/cilium/cilium/pkg/datapath/linux/config"
	dpdef "github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/datapath/loader/metrics"
	"github.com/cilium/cilium/pkg/defaults"
	endpointtypes "github.com/cilium/cilium/pkg/endpoint/types"
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/cilium/cilium/pkg/maps/egressmap"
	fakeNodeMap "github.com/cilium/cilium/pkg/maps/nodemap/fake"
	"github.com/cilium/cilium/pkg/maps/policymap"
	fakenode "github.com/cilium/cilium/pkg/node/fake"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestZtunnelPolicyReachabilityIndexesMatchBPFHeader(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	require.True(t, ok)
	headerPath := filepath.Join(filepath.Dir(sourceFile), "../../../bpf/lib/tailcall.h")
	header, err := os.ReadFile(headerPath)
	require.NoError(t, err)

	cases := map[string]uint32{
		"CILIUM_CALL_IPV4_FROM_LXC":               callIPv4FromLXC,
		"CILIUM_CALL_IPV6_FROM_LXC":               callIPv6FromLXC,
		"CILIUM_CALL_IPV4_TO_LXC_POLICY_ONLY":     callIPv4ToLXCPolicyOnly,
		"CILIUM_CALL_IPV6_TO_LXC_POLICY_ONLY":     callIPv6ToLXCPolicyOnly,
		"CILIUM_CALL_IPV4_TO_ENDPOINT":            callIPv4ToEndpoint,
		"CILIUM_CALL_IPV6_TO_ENDPOINT":            callIPv6ToEndpoint,
		"CILIUM_CALL_IPV4_FROM_LXC_CONT":          callIPv4FromLXCCont,
		"CILIUM_CALL_IPV6_FROM_LXC_CONT":          callIPv6FromLXCCont,
		"CILIUM_CALL_IPV4_CT_INGRESS":             callIPv4CTIngress,
		"CILIUM_CALL_IPV4_CT_INGRESS_POLICY_ONLY": callIPv4CTIngressPolicyOnly,
		"CILIUM_CALL_IPV4_CT_EGRESS":              callIPv4CTEgress,
		"CILIUM_CALL_IPV6_CT_INGRESS":             callIPv6CTIngress,
		"CILIUM_CALL_IPV6_CT_INGRESS_POLICY_ONLY": callIPv6CTIngressPolicyOnly,
		"CILIUM_CALL_IPV6_CT_EGRESS":              callIPv6CTEgress,
	}
	for macro, want := range cases {
		t.Run(macro, func(t *testing.T) {
			pattern := regexp.MustCompile(`(?m)^#define\s+` + regexp.QuoteMeta(macro) + `\s+([0-9]+)\s*$`)
			match := pattern.FindSubmatch(header)
			require.Len(t, match, 2, "macro must remain a numeric BPF tail-call index")
			got, err := strconv.ParseUint(string(match[1]), 10, 32)
			require.NoError(t, err)
			require.Equal(t, want, uint32(got))
		})
	}
}

// The verifier requires an empty policy-only CT slot in single-stack objects.
// This source check fails if bpf_lxc.c stops gating that tail call on both families.
func TestZtunnelPolicyReachabilityPolicyOnlyCTSlotIsDualStackOnly(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	require.True(t, ok)
	source, err := os.ReadFile(filepath.Join(filepath.Dir(sourceFile), "../../../bpf/bpf_lxc.c"))
	require.NoError(t, err)

	for family, macro := range map[string]string{
		"IPv4": "CILIUM_CALL_IPV4_CT_INGRESS_POLICY_ONLY",
		"IPv6": "CILIUM_CALL_IPV6_CT_INGRESS_POLICY_ONLY",
	} {
		t.Run(family, func(t *testing.T) {
			pattern := regexp.MustCompile(`if \(is_defined\(ENABLE_IPV4\) && is_defined\(ENABLE_IPV6\)\)\s+ret = tail_call_internal\(ctx, ` + macro + `,`)
			require.Regexp(t, pattern, string(source))
		})
	}
}

func TestZtunnelPolicyReachabilityIdentityRequiresKernelMapAndIncarnation(t *testing.T) {
	valid := endpointtypes.ZtunnelPolicyMapReachabilityIdentity{
		EndpointID: 42, NamespaceUID: "00000000-0000-4000-8000-000000000001", PodUID: "00000000-0000-4000-8000-000000000002",
		NetNSPath: "/var/run/netns/pod", NetNSCookie: 12, Interface: "lxc123", IfIndex: 7,
		PolicyMapID: 91, PolicyDigest: "policy-digest", DatapathConfigHash: "bpf-config", IPv4: true, RequireToContainer: true,
	}
	require.NoError(t, valid.Validate())
	for name, mutate := range map[string]func(*endpointtypes.ZtunnelPolicyMapReachabilityIdentity){
		"missing policy map ID":             func(i *endpointtypes.ZtunnelPolicyMapReachabilityIdentity) { i.PolicyMapID = 0 },
		"missing Pod UID":                   func(i *endpointtypes.ZtunnelPolicyMapReachabilityIdentity) { i.PodUID = "" },
		"missing Namespace UID":             func(i *endpointtypes.ZtunnelPolicyMapReachabilityIdentity) { i.NamespaceUID = "" },
		"missing netns cookie":              func(i *endpointtypes.ZtunnelPolicyMapReachabilityIdentity) { i.NetNSCookie = 0 },
		"missing policy observation":        func(i *endpointtypes.ZtunnelPolicyMapReachabilityIdentity) { i.PolicyDigest = "" },
		"missing loaded config hash":        func(i *endpointtypes.ZtunnelPolicyMapReachabilityIdentity) { i.DatapathConfigHash = "" },
		"missing address family":            func(i *endpointtypes.ZtunnelPolicyMapReachabilityIdentity) { i.IPv4 = false },
		"missing destination endpoint hook": func(i *endpointtypes.ZtunnelPolicyMapReachabilityIdentity) { i.RequireToContainer = false },
	} {
		t.Run(name, func(t *testing.T) {
			identity := valid
			mutate(&identity)
			require.Error(t, identity.Validate())
		})
	}
}

// The shared fixture embeds TestEndpoint, whose default RequireEgressProg is
// false. This wrapper opts into the actual destination-side TCX hook without
// changing the shared fixture's behavior in other tests.
type policyReachabilityTestEndpoint struct {
	*sourceIPReceiptTestEndpoint
}

func (*policyReachabilityTestEndpoint) RequireEgressProg() bool { return true }

// reachabilityNodeDefinesForTest returns the node defines that production map
// cells contribute through the header-node-defines group. The loader test Hive
// omits those cells because their start hooks create and pin maps.
func reachabilityNodeDefinesForTest(t *testing.T) dpdef.Map {
	t.Helper()

	possibleCPUs, err := ebpf.PossibleCPU()
	require.NoError(t, err)
	statsEntries := policymap.DefaultPolicyConfig.BpfPolicyStatsMapMax
	statsEntries -= statsEntries % possibleCPUs

	nodeDefines := dpdef.Map{
		"POLICY_MAP_SIZE":        strconv.Itoa(policymap.DefaultPolicyConfig.BpfPolicyMapMax),
		"POLICY_STATS_MAP_SIZE":  strconv.Itoa(statsEntries),
		"EGRESS_POLICY_MAP_SIZE": strconv.Itoa(egressmap.DefaultPolicyConfig.EgressGatewayPolicyMapMax),
	}
	// srv6map does not export its map sizes; bpf/node_config.h carries the same values.
	checkedIn, err := os.ReadFile(filepath.Join(bpfDir, "node_config.h"))
	require.NoError(t, err)
	for _, name := range []string{"SRV6_VRF_MAP_SIZE", "SRV6_POLICY_MAP_SIZE", "SRV6_SID_MAP_SIZE"} {
		value, ok := numericDefine(checkedIn, name)
		require.Truef(t, ok, "bpf/node_config.h must define %s as a decimal literal", name)
		nodeDefines[name] = strconv.FormatUint(value, 10)
	}
	return nodeDefines
}

func numericDefine(header []byte, name string) (uint64, bool) {
	match := regexp.MustCompile(`(?m)^#define\s+` + regexp.QuoteMeta(name) + `\s+([0-9]+)\s*$`).FindSubmatch(header)
	if len(match) != 2 {
		return 0, false
	}
	value, err := strconv.ParseUint(string(match[1]), 10, 32)
	return value, err == nil
}

func reachabilityConfigWriterForTest(t *testing.T) linuxConfig.Writer {
	t.Helper()

	writer, err := linuxConfig.NewHeaderfileWriter(linuxConfig.WriterParams{
		NodeMap:          fakeNodeMap.NewFakeNodeMapV2(),
		NodeAddressing:   fakenode.NewAddressing(),
		NodeExtraDefines: []dpdef.Map{reachabilityNodeDefinesForTest(t)},
	})
	require.NoError(t, err)
	return writer
}

// reachabilityNodeSizeDefines are node_config.h map sizes that bpf_lxc.c can
// read. A zero value compiles, but map creation then fails at load time.
var reachabilityNodeSizeDefines = []string{
	"CILIUM_IPV4_FRAG_MAP_MAX_ENTRIES",
	"CILIUM_IPV6_FRAG_MAP_MAX_ENTRIES",
	"CILIUM_LB_AFFINITY_MAP_MAX_ENTRIES",
	"CILIUM_LB_BACKENDS_MAP_MAX_ENTRIES",
	"CILIUM_LB_MAGLEV_MAP_MAX_ENTRIES",
	"CILIUM_LB_REV_NAT_MAP_MAX_ENTRIES",
	"CILIUM_LB_SERVICE_MAP_MAX_ENTRIES",
	"CT_MAP_SIZE_ANY",
	"CT_MAP_SIZE_TCP",
	"EGRESS_POLICY_MAP_SIZE",
	"LB4_REVERSE_NAT_SK_MAP_SIZE",
	"LB4_SRC_RANGE_MAP_SIZE",
	"LB6_REVERSE_NAT_SK_MAP_SIZE",
	"LB6_SRC_RANGE_MAP_SIZE",
	"LB_MAGLEV_LUT_SIZE",
	"NODEPORT_NEIGH4_SIZE",
	"NODEPORT_NEIGH6_SIZE",
	"POLICY_MAP_SIZE",
	"POLICY_STATS_MAP_SIZE",
	"SNAT_MAPPING_IPV4_SIZE",
	"SNAT_MAPPING_IPV6_SIZE",
	"SRV6_POLICY_MAP_SIZE",
	"SRV6_SID_MAP_SIZE",
	"SRV6_VRF_MAP_SIZE",
}

type reachabilityGlobalConfig struct {
	enableTCX             bool
	enableIPv4            bool
	enableIPv6            bool
	enableL7Proxy         bool
	enableEnvoyConfig     bool
	enableDatapathPlugins bool
	enableIPv4Masquerade  bool
	enableIPv6Masquerade  bool
	enableBPFMasquerade   bool
	fragmentsMapEntries   int
	natMapEntriesGlobal   int
	neighMapEntriesGlobal int
}

func snapshotReachabilityGlobalConfig() reachabilityGlobalConfig {
	return reachabilityGlobalConfig{
		enableTCX:             option.Config.EnableTCX,
		enableIPv4:            option.Config.EnableIPv4,
		enableIPv6:            option.Config.EnableIPv6,
		enableL7Proxy:         option.Config.EnableL7Proxy,
		enableEnvoyConfig:     option.Config.EnableEnvoyConfig,
		enableDatapathPlugins: option.Config.EnableDatapathPlugins,
		enableIPv4Masquerade:  option.Config.EnableIPv4Masquerade,
		enableIPv6Masquerade:  option.Config.EnableIPv6Masquerade,
		enableBPFMasquerade:   option.Config.EnableBPFMasquerade,
		fragmentsMapEntries:   option.Config.FragmentsMapEntries,
		natMapEntriesGlobal:   option.Config.NATMapEntriesGlobal,
		neighMapEntriesGlobal: option.Config.NeighMapEntriesGlobal,
	}
}

func (c reachabilityGlobalConfig) restore() {
	option.Config.EnableTCX = c.enableTCX
	option.Config.EnableIPv4 = c.enableIPv4
	option.Config.EnableIPv6 = c.enableIPv6
	option.Config.EnableL7Proxy = c.enableL7Proxy
	option.Config.EnableEnvoyConfig = c.enableEnvoyConfig
	option.Config.EnableDatapathPlugins = c.enableDatapathPlugins
	option.Config.EnableIPv4Masquerade = c.enableIPv4Masquerade
	option.Config.EnableIPv6Masquerade = c.enableIPv6Masquerade
	option.Config.EnableBPFMasquerade = c.enableBPFMasquerade
	option.Config.FragmentsMapEntries = c.fragmentsMapEntries
	option.Config.NATMapEntriesGlobal = c.natMapEntriesGlobal
	option.Config.NeighMapEntriesGlobal = c.neighMapEntriesGlobal
}

func programIndexes(references []endpointtypes.ZtunnelPolicyProgramReference) []uint32 {
	indexes := make([]uint32, 0, len(references))
	for _, reference := range references {
		indexes = append(indexes, reference.Index)
	}
	return indexes
}

// logPolicyPathInventory records which endpoint maps each attached and
// tail-called program references in the kernel. It asserts no reachability; it
// makes a wrong verifier map table diagnosable from one privileged run.
func logPolicyPathInventory(t *testing.T, l *loader, endpointID uint16, ifIndex int) {
	t.Helper()

	calls, callsID, err := loadKernelMap(l.CallsMapPath(endpointID), ebpf.ProgramArray, 4, 4)
	require.NoError(t, err)
	defer calls.Close()
	policy, policyMapID, err := loadKernelMap(
		bpf.LocalMapPath(l.logger, policymap.MapName, endpointID),
		ebpf.LPMTrie,
		uint32(unsafe.Sizeof(policymap.PolicyKey{})),
		uint32(unsafe.Sizeof(policymap.PolicyEntry{})),
	)
	require.NoError(t, err)
	defer policy.Close()
	policyCalls, policyCallID, err := loadKernelMap(bpf.MapPath(l.logger, policymap.PolicyCallMapName), ebpf.ProgramArray, 4, 4)
	require.NoError(t, err)
	defer policyCalls.Close()

	describe := func(label string, program *ebpf.Program) {
		defer program.Close()
		info, err := program.Info()
		require.NoError(t, err)
		ids, ok := info.MapIDs()
		require.True(t, ok, "kernel must expose program map IDs")
		t.Logf("policy-path inventory %s: name=%s calls=%t policy=%t policy_call=%t",
			label, info.Name,
			slices.Contains(ids, ebpf.MapID(callsID)),
			slices.Contains(ids, ebpf.MapID(policyMapID)),
			slices.Contains(ids, ebpf.MapID(policyCallID)))
	}

	for index := range calls.MaxEntries() {
		var program *ebpf.Program
		err := calls.Lookup(&index, &program)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			continue
		}
		require.NoError(t, err)
		if program != nil {
			describe(fmt.Sprintf("cilium_calls[%d]", index), program)
		}
	}
	endpointKey := uint32(endpointID)
	var policyProgram *ebpf.Program
	require.NoError(t, policyCalls.Lookup(&endpointKey, &policyProgram))
	require.NotNil(t, policyProgram)
	describe("cilium_call_policy[endpoint]", policyProgram)
	for _, attach := range []ebpf.AttachType{ebpf.AttachTCXIngress, ebpf.AttachTCXEgress} {
		result, err := link.QueryPrograms(link.QueryOptions{Target: ifIndex, Attach: attach})
		require.NoError(t, err)
		for _, attached := range result.Programs {
			program, err := ebpf.NewProgramFromID(attached.ID)
			require.NoError(t, err)
			describe("tcx "+attach.String(), program)
		}
	}
}

func TestPrivilegedZtunnelPolicyMapReachabilityReadsAndRejectsKernelPathChanges(t *testing.T) {
	testutils.PrivilegedTest(t)
	lock.SetLogger(slog.Default())
	require.NoError(t, rlimit.RemoveMemlock())
	skipTCXUnsupported(t)

	globalsBefore := snapshotReachabilityGlobalConfig()
	includesBefore := slices.Clone(testIncludes)
	_, err := os.Stat(bpf.TCGlobalsPath())
	globalsPathExisted := err == nil

	t.Run("kernel path", verifyPolicyMapReachabilityKernelPath)

	require.Equal(t, globalsBefore, snapshotReachabilityGlobalConfig(), "the test must restore every option.Config field it changes")
	require.Equal(t, includesBefore, testIncludes, "the test must restore the shared compile include list")
	if !globalsPathExisted {
		_, err = os.Stat(bpf.TCGlobalsPath())
		require.ErrorIs(t, err, os.ErrNotExist, "the private bpffs fixture must remove its pinned maps")
	}
}

func verifyPolicyMapReachabilityKernelPath(t *testing.T) {
	initBpffs(t)

	globals := snapshotReachabilityGlobalConfig()
	t.Cleanup(globals.restore)
	option.Config.EnableTCX = true
	// First compile with no IP-family datapath enabled. bpf_lxc.c then has no
	// reachable policy lookup, so the ELF correctly omits cilium_policy. The
	// verifier must reject that endpoint instead of treating intended policy as
	// evidence that a kernel map exists.
	option.Config.EnableIPv4 = false
	option.Config.EnableIPv6 = false
	option.Config.EnableL7Proxy = false
	option.Config.EnableEnvoyConfig = false
	option.Config.EnableDatapathPlugins = false
	option.Config.EnableIPv4Masquerade = false
	option.Config.EnableIPv6Masquerade = false
	option.Config.EnableBPFMasquerade = false
	// The agent never writes these sizes as zero: DaemonConfig.Validate rejects
	// small NAT and fragment maps, and dynamic sizing copies NAT to neighbour.
	option.Config.FragmentsMapEntries = defaults.FragmentsMapEntries
	option.Config.NATMapEntriesGlobal = option.NATMapEntriesGlobalDefault
	option.Config.NeighMapEntriesGlobal = option.NATMapEntriesGlobalDefault

	l := newTestLoaderWithConfigWriter(t, reachabilityConfigWriterForTest(t))
	l.logger = hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
	// The shared fixture lists static bpf/ before the generated globals
	// directory, so bpf/node_config.h would shadow the profiles below. compile()
	// appends to testIncludes, so the override must not leave spare capacity.
	sharedIncludes := testIncludes
	testIncludes = slices.Clip(append([]string{"-I" + option.Config.GetGlobalsDir()}, sharedIncludes...))
	t.Cleanup(func() { testIncludes = sharedIncludes })

	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()

	lbConfig, err := loadbalancer.NewConfig(l.logger, loadbalancer.DefaultUserConfig, option.Config, kpr.KPRConfig{})
	require.NoError(t, err)
	lnc := localNodeConfig
	lnc.LBConfig = lbConfig
	lnc.EnableIPv4 = false
	lnc.EnableIPv6 = false
	lnc.DeviceMTU = 1500
	lnc.MaglevConfig = maglev.DefaultConfig
	ep := &policyReachabilityTestEndpoint{sourceIPReceiptTestEndpoint: newSourceIPReceiptTestEndpoint(t, 42, "p", "00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002", true)}
	t.Cleanup(func() { l.Unload(ep) })
	policyPath := bpf.LocalMapPath(l.logger, policymap.MapName, 42)

	// Production Reinitialize writes the node header before endpoint loads.
	require.NoError(t, os.MkdirAll(option.Config.GetGlobalsDir(), 0o755))
	writeNodeConfig := func() string {
		t.Helper()
		require.NoError(t, l.writeNodeConfigHeader(&lnc))
		header, err := os.ReadFile(option.Config.GetNodeConfigPath())
		require.NoError(t, err)
		for _, name := range reachabilityNodeSizeDefines {
			value, ok := numericDefine(header, name)
			require.Truef(t, ok, "generated node_config.h must define %s", name)
			require.NotZerof(t, value, "generated node_config.h must not size %s to zero", name)
		}
		require.NoError(t, l.templateCache.UpdateDatapathHash(&lnc))
		return string(header)
	}

	nodeConfig := writeNodeConfig()
	require.NotContains(t, nodeConfig, "ENABLE_IPV4")
	require.NotContains(t, nodeConfig, "ENABLE_IPV6")
	_, err = l.ReloadDatapath(ctx, ep, &lnc, &metrics.SpanStat{})
	require.NoError(t, err, "test must load the actual Cilium endpoint object")
	_, err = os.Stat(policyPath)
	require.ErrorIs(t, err, os.ErrNotExist, "an object without IP-family policy hooks must not pin an endpoint policy map")

	compiledOutIdentity := endpointtypes.ZtunnelPolicyMapReachabilityIdentity{
		EndpointID: 42, NamespaceUID: "00000000-0000-4000-8000-000000000001", PodUID: "00000000-0000-4000-8000-000000000002",
		NetNSPath: ep.netNSPath, NetNSCookie: ep.NetNsCookie,
		Interface: ep.InterfaceName(), IfIndex: ep.GetIfIndex(), PolicyMapID: 1,
		PolicyDigest: "compile-out-policy", DatapathConfigHash: "compile-out-config",
		IPv4: true, RequireToContainer: ep.RequireEgressProg(),
	}
	_, err = l.VerifyZtunnelPolicyMapReachability(ctx, compiledOutIdentity)
	require.ErrorContains(t, err, "open endpoint policy map", "a profile without compiled IPv4/IPv6 policy hooks must not produce a reachability observation")

	// Reconfigure the actual node header and invalidate the template cache, then
	// reload the same endpoint with IPv4 enabled. This exercises recovery through
	// the normal Cilium template and loader path rather than manufacturing BPF maps.
	l.Unload(ep)
	option.Config.EnableIPv4 = true
	lnc.EnableIPv4 = true
	nodeConfig = writeNodeConfig()
	require.Contains(t, nodeConfig, "#define ENABLE_IPV4 1")
	require.NotContains(t, nodeConfig, "ENABLE_IPV6")
	_, err = l.ReloadDatapath(ctx, ep, &lnc, &metrics.SpanStat{})
	require.NoError(t, err, "the real IPv4 Cilium endpoint should load after the node feature is enabled")

	policyMap, policyMapID, err := loadKernelMap(
		policyPath,
		ebpf.LPMTrie,
		uint32(unsafe.Sizeof(policymap.PolicyKey{})),
		uint32(unsafe.Sizeof(policymap.PolicyEntry{})),
	)
	require.NoError(t, err)
	require.NoError(t, policyMap.Close())
	logPolicyPathInventory(t, l, 42, ep.GetIfIndex())

	identity := endpointtypes.ZtunnelPolicyMapReachabilityIdentity{
		EndpointID: 42, NamespaceUID: "00000000-0000-4000-8000-000000000001", PodUID: "00000000-0000-4000-8000-000000000002",
		NetNSPath: ep.netNSPath, NetNSCookie: ep.NetNsCookie,
		Interface: ep.InterfaceName(), IfIndex: ep.GetIfIndex(), PolicyMapID: policyMapID,
		PolicyDigest: "kernel-fixture-policy", DatapathConfigHash: "kernel-fixture-config",
		IPv4: ep.IPv4Address().IsValid(), IPv6: ep.IPv6Address().IsValid(), RequireToContainer: ep.RequireEgressProg(),
	}
	verify := func() error {
		_, err := l.VerifyZtunnelPolicyMapReachability(ctx, identity)
		return err
	}

	observation, err := l.VerifyZtunnelPolicyMapReachability(ctx, identity)
	require.NoError(t, err)
	require.Equal(t, identity, observation.Identity)
	require.Equal(t, policyMapID, observation.PolicyMapID)
	require.NotZero(t, observation.CallsMapID)
	require.NotZero(t, observation.PolicyCallMapID)
	require.NotZero(t, observation.EndpointPolicyProgramID)
	require.NotZero(t, observation.FromContainerProgramID)
	require.NotZero(t, observation.FromContainerLinkID)
	require.NotZero(t, observation.ToContainerProgramID)
	require.NotZero(t, observation.ToContainerLinkID)
	require.Equal(t, []uint32{callIPv4FromLXC, callIPv4CTEgress, callIPv4FromLXCCont}, programIndexes(observation.EgressPrograms))
	require.Equal(t, []uint32{callIPv4CTIngress, callIPv4ToEndpoint, callIPv4ToLXCPolicyOnly}, programIndexes(observation.IngressPrograms),
		"a single-stack object inlines the policy-only CT lookup")

	wrongMap := identity
	wrongMap.PolicyMapID++
	_, err = l.VerifyZtunnelPolicyMapReachability(ctx, wrongMap)
	require.ErrorContains(t, err, "endpoint policy map ID changed", "the current endpoint policy-map pin must match the ID from the native policy snapshot")

	originalPolicyMap, err := ebpf.LoadPinnedMap(policyPath, nil)
	require.NoError(t, err)
	replacementPolicyMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "cmtc_policy_alt",
		Type:       ebpf.LPMTrie,
		KeySize:    uint32(unsafe.Sizeof(policymap.PolicyKey{})),
		ValueSize:  uint32(unsafe.Sizeof(policymap.PolicyEntry{})),
		MaxEntries: 64,
		Flags:      unix.BPF_F_NO_PREALLOC | unix.BPF_F_RDONLY_PROG,
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		// Map.Pin is a no-op when the handle already records the same path, so
		// every pin change goes through Unpin on the handle that owns the path.
		require.NoError(t, replacementPolicyMap.Unpin())
		if !originalPolicyMap.IsPinned() {
			require.NoError(t, originalPolicyMap.Pin(policyPath))
		}
		require.NoError(t, replacementPolicyMap.Close())
		require.NoError(t, originalPolicyMap.Close())
	})
	require.NoError(t, originalPolicyMap.Unpin())
	require.ErrorContains(t, verify(), "open endpoint policy map", "a missing endpoint policy-map pin must withhold reachability evidence")
	require.NoError(t, replacementPolicyMap.Pin(policyPath))
	require.ErrorContains(t, verify(), "endpoint policy map ID changed", "a replacement LPM pin at the same endpoint path must not inherit the old map identity")
	require.NoError(t, replacementPolicyMap.Unpin())
	require.NoError(t, originalPolicyMap.Pin(policyPath))
	require.NoError(t, verify(), "restoring the original endpoint policy map must recover")

	calls, _, err := loadKernelMap(l.CallsMapPath(42), ebpf.ProgramArray, 4, 4)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, calls.Close()) })
	rogue := mustTCProgramWithName(t, "rogue_tail")
	for _, index := range []uint32{
		callIPv4FromLXC, callIPv4CTEgress, callIPv4FromLXCCont,
		callIPv4CTIngress, callIPv4ToEndpoint, callIPv4ToLXCPolicyOnly,
	} {
		var original *ebpf.Program
		require.NoError(t, calls.Lookup(&index, &original))
		require.NotNil(t, original)
		t.Cleanup(func() { require.NoError(t, original.Close()) })

		require.NoError(t, calls.Update(&index, rogue, ebpf.UpdateAny))
		require.Errorf(t, verify(), "replacing checked tail-call slot %d must withhold reachability evidence", index)
		require.NoError(t, calls.Update(&index, original, ebpf.UpdateAny))
		require.NoErrorf(t, verify(), "restoring tail-call slot %d must recover", index)

		require.NoError(t, calls.Delete(&index))
		require.Errorf(t, verify(), "an empty checked tail-call slot %d must withhold reachability evidence", index)
		require.NoError(t, calls.Update(&index, original, ebpf.UpdateAny))
		require.NoErrorf(t, verify(), "refilling tail-call slot %d must recover", index)
	}

	policyOnlyCT := callIPv4CTIngressPolicyOnly
	require.NoError(t, calls.Update(&policyOnlyCT, rogue, ebpf.UpdateAny))
	require.ErrorContains(t, verify(), "is populated", "a single-stack object must keep the dual-stack-only policy CT slot empty")
	require.NoError(t, calls.Delete(&policyOnlyCT))
	require.NoError(t, verify(), "clearing the unreachable slot must recover")

	policyCalls, _, err := loadKernelMap(bpf.MapPath(l.logger, policymap.PolicyCallMapName), ebpf.ProgramArray, 4, 4)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, policyCalls.Close()) })
	endpointKey := uint32(identity.EndpointID)
	var originalPolicy *ebpf.Program
	require.NoError(t, policyCalls.Lookup(&endpointKey, &originalPolicy))
	require.NotNil(t, originalPolicy)
	t.Cleanup(func() { require.NoError(t, originalPolicy.Close()) })
	require.NoError(t, policyCalls.Update(&endpointKey, rogue, ebpf.UpdateAny))
	require.Error(t, verify(), "replacing the global destination-policy target must withhold reachability evidence")
	require.NoError(t, policyCalls.Update(&endpointKey, originalPolicy, ebpf.UpdateAny))
	require.NoError(t, verify(), "restoring the real destination-policy target must recover")
	require.NoError(t, policyCalls.Delete(&endpointKey))
	require.Error(t, verify(), "an empty global destination-policy slot must withhold reachability evidence")
	require.NoError(t, policyCalls.Update(&endpointKey, originalPolicy, ebpf.UpdateAny))
	require.NoError(t, verify(), "refilling the destination-policy slot must recover")

	extra, err := link.AttachTCX(link.TCXOptions{Program: rogue, Attach: ebpf.AttachTCXIngress, Interface: ep.GetIfIndex(), Anchor: link.Tail()})
	require.NoError(t, err)
	require.Error(t, verify(), "an extra ingress program makes the observed attachment set unsupported")
	require.NoError(t, extra.Close())
	require.NoError(t, verify(), "the unchanged Cilium path is observable after the extra link is removed")
	extraEgress, err := link.AttachTCX(link.TCXOptions{Program: rogue, Attach: ebpf.AttachTCXEgress, Interface: ep.GetIfIndex(), Anchor: link.Tail()})
	require.NoError(t, err)
	require.Error(t, verify(), "an extra destination-side TCX program makes the observed attachment set unsupported")
	require.NoError(t, extraEgress.Close())
	require.NoError(t, verify(), "the unchanged destination-side path recovers after extra link removal")

	l.Unload(ep)
	require.Error(t, verify(), "endpoint unload must remove the current path")
}
