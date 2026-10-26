// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package zds

import (
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/ztunnel/config"
)

// directResolverDNS decides whether enrolled Pods send TCP DNS past ztunnel
// (iptables.CreateInPodRules), and gives the reason when they do not.
//
// The in-pod rule matches the destination port the Pod's netns OUTPUT hook
// sees; the BPF HBONE-only gate (bpf/lib/ztunnel_admission.h) judges the port
// after service translation, and admits any TCP 15008 as HBONE. With
// per-packet service translation in bpf_lxc.c, a Service on port 53 with a
// TCP 15008 backend would pass the rule and then the gate in plaintext. So the
// bypass is on only when bpf_lxc.c does no per-packet translation: socket-LB
// then translates a Pod's service connection at connect(), or leaves it
// untranslated (an ExternalIP, a Service with no backend), and the source gate
// sees the port the rule saw. The conditions mirror ENABLE_PER_PACKET_LB in
// bpf/bpf_lxc.c (ENABLE_CLUSTER_AWARE_ADDRESSING is defined only for the BPF
// complexity tests, never by the agent) and the socket_lb flags set in
// pkg/datapath/config/endpoint.go.
//
// Translation on the destination node is outside this check: an ExternalIP
// Service on a resolver's address and port 53 is translated there, after the
// source gate. That applies to UDP DNS as much as TCP and is closed by refusing
// such Services at admission, not here.
func directResolverDNS(cfg config.Config, kprCfg kpr.KPRConfig, dc *option.DaemonConfig) (bool, string) {
	switch {
	case len(cfg.DNSResolverLabels) == 0:
		return false, "no approved DNS resolver (ztunnel-dns-resolver-labels is empty)"
	case dc == nil:
		return false, "no daemon configuration"
	case !kprCfg.EnableSocketLB:
		return false, "socket-LB is disabled, so Pod service traffic is translated per packet"
	case dc.UnsafeDaemonConfigOption.BPFSocketLBHostnsOnly:
		return false, "socket-LB is host-namespace only, so Pod service traffic is translated per packet"
	case dc.EnableEnvoyConfig:
		return false, "L7 load balancing (enable-envoy-config) translates Pod service traffic per packet"
	case dc.EnableSCTP:
		return false, "SCTP enables per-packet service translation"
	}
	return true, "approved resolvers and socket-LB in every Pod: the port the rule sees is the port on the wire"
}
