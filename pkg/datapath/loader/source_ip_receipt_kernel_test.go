// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package loader

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/loader/metrics"
	"github.com/cilium/cilium/pkg/endpoint/types"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
	testnetns "github.com/cilium/cilium/pkg/testutils/netns"
)

type sourceIPReceiptTestEndpoint struct {
	testutils.TestEndpoint
	netNSPath string
	ifName    string
	namespace string
	podUID    string
}

func (e *sourceIPReceiptTestEndpoint) InterfaceName() string { return e.ifName }

func (e *sourceIPReceiptTestEndpoint) SourceIPDatapathIdentity() types.SourceIPDatapathIdentity {
	return types.SourceIPDatapathIdentity{
		EndpointID:      uint16(e.Id),
		NamespaceUID:    e.namespace,
		PodUID:          e.podUID,
		NetNSPath:       e.netNSPath,
		NetNSCookie:     e.NetNsCookie,
		Interface:       e.InterfaceName(),
		IfIndex:         e.IfIndex,
		ConfigHash:      "privileged-cilium-kernel-receipt-fixture",
		IPv4:            e.IPv4Address(),
		IPv6:            e.IPv6Address(),
		SourceIPEnabled: e.Opts.IsEnabled(option.SourceIPVerification),
	}
}

func newSourceIPReceiptTestEndpoint(t *testing.T, id uint64, suffix, namespaceUID, podUID string, sourceIP bool) *sourceIPReceiptTestEndpoint {
	t.Helper()
	ns := testnetns.NewNetNS(t)
	ifName := "cmtc" + suffix
	peerName := "pod" + suffix
	veth := &netlink.Veth{
		LinkAttrs:     netlink.LinkAttrs{Name: ifName},
		PeerName:      peerName,
		PeerNamespace: netlink.NsFd(ns.FD()),
	}
	require.NoError(t, netlink.LinkAdd(veth))
	t.Cleanup(func() { require.NoError(t, netlink.LinkDel(veth)) })
	host, err := safenetlink.LinkByName(ifName)
	require.NoError(t, err)
	require.NoError(t, netlink.LinkSetUp(host))
	var cookie uint64
	require.NoError(t, ns.Do(func() error {
		peer, err := safenetlink.LinkByName(peerName)
		if err != nil {
			return err
		}
		if err := netlink.LinkSetUp(peer); err != nil {
			return err
		}
		cookie, err = netns.GetNetNSCookie()
		return err
	}))
	require.NotZero(t, cookie)

	base := testutils.NewTestEndpoint(t)
	base.Id = id
	base.State = t.TempDir()
	base.IfIndex = host.Attrs().Index
	base.NetNsCookie = cookie
	base.Opts.SetBool(option.SourceIPVerification, sourceIP)
	return &sourceIPReceiptTestEndpoint{
		TestEndpoint: base,
		netNSPath:    fmt.Sprintf("/proc/self/fd/%d", ns.FD()),
		ifName:       ifName,
		namespace:    namespaceUID,
		podUID:       podUID,
	}
}

func TestPrivilegedSourceIPReceiptUsesAttachedCiliumProgramAndKernelConfig(t *testing.T) {
	testutils.PrivilegedTest(t)
	// Template compilation holds existing cache locks beyond the debug logging threshold.
	// Initialize its process-wide test logger before that first compilation.
	lock.SetLogger(slog.Default())
	skipTCXUnsupported(t)
	require.NoError(t, rlimit.RemoveMemlock())
	initBpffs(t)

	oldTCX := option.Config.EnableTCX
	oldL7Proxy := option.Config.EnableL7Proxy
	oldEnvoyConfig := option.Config.EnableEnvoyConfig
	oldPlugins := option.Config.EnableDatapathPlugins
	oldMasq4 := option.Config.EnableIPv4Masquerade
	oldMasq6 := option.Config.EnableIPv6Masquerade
	oldBPFMasq := option.Config.EnableBPFMasquerade
	option.Config.EnableTCX = true
	option.Config.EnableL7Proxy = false
	option.Config.EnableEnvoyConfig = false
	option.Config.EnableDatapathPlugins = false
	option.Config.EnableIPv4Masquerade = false
	option.Config.EnableIPv6Masquerade = false
	option.Config.EnableBPFMasquerade = false
	t.Cleanup(func() {
		option.Config.EnableTCX = oldTCX
		option.Config.EnableL7Proxy = oldL7Proxy
		option.Config.EnableEnvoyConfig = oldEnvoyConfig
		option.Config.EnableDatapathPlugins = oldPlugins
		option.Config.EnableIPv4Masquerade = oldMasq4
		option.Config.EnableIPv6Masquerade = oldMasq6
		option.Config.EnableBPFMasquerade = oldBPFMasq
	})

	l := newTestLoader(t)
	l.logger = hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	lnc := localNodeConfig
	lnc.DeviceMTU = 1500
	stats := &metrics.SpanStat{}

	ep := newSourceIPReceiptTestEndpoint(t, 42, "a", "00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002", true)
	t.Cleanup(func() { l.Unload(ep) })
	_, err := l.ReloadDatapath(ctx, ep, &lnc, stats)
	require.NoError(t, err, "must compile and attach the real Cilium endpoint program")
	identity := ep.SourceIPDatapathIdentity()
	observation, err := l.VerifySourceIPDatapath(ctx, identity)
	require.NoError(t, err)
	require.True(t, sourceIPReceiptComplete(observation))
	pinned, err := link.LoadPinnedLink(filepath.Join(bpf.CiliumPath(), "endpoints", "42", "links", symbolFromEndpoint), nil)
	require.NoError(t, err)
	linkInfo, err := pinned.Info()
	require.NoError(t, err)
	program, err := ebpf.NewProgramFromID(linkInfo.Program)
	require.NoError(t, err)
	programInfo, err := program.Info()
	require.NoError(t, err)
	require.True(t, sourceIPProgramName(programInfo.Name), "exact BTF or legacy UAPI function name required")
	require.NoError(t, program.Close())
	require.NoError(t, pinned.Close())

	wrongPod := identity
	wrongPod.PodUID = "00000000-0000-4000-8000-000000000003"
	_, err = l.VerifySourceIPDatapath(ctx, wrongPod)
	require.Error(t, err, "a receipt cannot be reused for a different Pod incarnation")
	wrongNamespace := identity
	wrongNamespace.NamespaceUID = "00000000-0000-4000-8000-000000000004"
	_, err = l.VerifySourceIPDatapath(ctx, wrongNamespace)
	require.Error(t, err, "a receipt cannot be reused for a different Namespace incarnation")

	configMap, err := ebpf.NewMapFromID(ebpf.MapID(observation.ConfigMapID))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, configMap.Close()) })
	info, err := configMap.Info()
	require.NoError(t, err)
	require.True(t, info.Frozen(), "the real loaded .rodata.config map must be immutable")
	value := make([]byte, int(info.ValueSize))
	key := uint32(0)
	require.NoError(t, configMap.Lookup(&key, &value))
	value[observation.SIPConfigOffset] = 0
	require.Error(t, configMap.Update(&key, value, ebpf.UpdateAny), "kernel must reject changing the frozen source-IP bit")
	_, err = l.VerifySourceIPDatapath(ctx, identity)
	require.NoError(t, err, "the failed mutation must leave the observed config intact")

	rogue := mustTCProgramWithName(t, "cil_test")
	rogueInfo, err := rogue.Info()
	require.NoError(t, err)
	_, err = inspectSourceIPTCX(ctx, identity, rogueInfo)
	require.Error(t, err, "a different live program FD must not qualify the attached Cilium program")
	l.bpfCollectionLoader.pluginsEnabled = true
	_, err = l.VerifySourceIPDatapath(ctx, identity)
	require.Error(t, err, "the actual loader plugin state must close receipt verification independently of global options")
	l.bpfCollectionLoader.pluginsEnabled = false
	_, err = l.VerifySourceIPDatapath(ctx, identity)
	require.NoError(t, err, "an unchanged unmodified loader recovers")
	extra, err := link.AttachTCX(link.TCXOptions{
		Program:   rogue,
		Attach:    ebpf.AttachTCXIngress,
		Interface: ep.GetIfIndex(),
		Anchor:    link.Tail(),
	})
	require.NoError(t, err)
	_, err = l.VerifySourceIPDatapath(ctx, identity)
	require.Error(t, err, "an extra ingress program invalidates the exact Cilium attachment receipt")
	require.NoError(t, extra.Close())
	_, err = l.VerifySourceIPDatapath(ctx, identity)
	require.Error(t, err, "closing the extra program changes the TCX revision; the old receipt must stay stale")
	_, err = l.ReloadDatapath(ctx, ep, &lnc, stats)
	require.NoError(t, err)
	_, err = l.VerifySourceIPDatapath(ctx, identity)
	require.NoError(t, err, "a successful Cilium reload should issue a fresh receipt")

	// Reuse numeric endpoint ID 42 for a different real veth/network-namespace
	// and Kubernetes identity. Unload must revoke the old receipt before the new
	// loader generation can be observed.
	l.Unload(ep)
	_, err = l.VerifySourceIPDatapath(ctx, identity)
	require.Error(t, err)
	replacement := newSourceIPReceiptTestEndpoint(t, 42, "b", "00000000-0000-4000-8000-000000000005", "00000000-0000-4000-8000-000000000006", true)
	t.Cleanup(func() { l.Unload(replacement) })
	_, err = l.ReloadDatapath(ctx, replacement, &lnc, stats)
	require.NoError(t, err)
	replacementIdentity := replacement.SourceIPDatapathIdentity()
	_, err = l.VerifySourceIPDatapath(ctx, replacementIdentity)
	require.NoError(t, err)
	_, err = l.VerifySourceIPDatapath(ctx, identity)
	require.Error(t, err, "endpoint ID reuse must not preserve the previous Pod/Namespace receipt")

	replacement.Opts.SetBool(option.SourceIPVerification, false)
	_, err = l.ReloadDatapath(ctx, replacement, &lnc, stats)
	require.NoError(t, err, "ordinary Cilium regeneration remains available when the option is disabled")
	_, err = l.VerifySourceIPDatapath(ctx, replacement.SourceIPDatapathIdentity())
	require.Error(t, err, "no receipt may be issued when the actual loaded BPF config disables source-IP verification")
	replacement.Opts.SetBool(option.SourceIPVerification, true)
	_, err = l.ReloadDatapath(ctx, replacement, &lnc, stats)
	require.NoError(t, err)
	_, err = l.VerifySourceIPDatapath(ctx, replacement.SourceIPDatapathIdentity())
	require.NoError(t, err, "re-enabling and successfully reloading must recover with a fresh receipt")
}
