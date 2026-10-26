// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package iptables

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"slices"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/datapath/linux/route"
)

const (
	InpodPreroutingChain = "CILIUM_PREROUTING"
	InpodOutputChain     = "CILIUM_OUTPUT"

	RouteTableInbound = 100

	InpodRulePriority = 32764

	// InpodTProxyMark and InpodMark are packet mark values used to coordinate traffic
	// redirection between Cilium and ztunnel. These values must remain synchronized
	// with ztunnel's inpod configuration.
	InpodTProxyMark  = 0x111 // Mark for traffic processed by ztunnel
	InpodMark        = 0x539 // Mark set by ztunnel on outbound traffic
	InpodMask        = 0xfff
	InpodRestoreMask = 0xffffffff

	ZtunnelInboundPort          = 15008
	ZtunnelOutboundPort         = 15001
	ZtunnelInboundPlaintextPort = 15006
	// DNSPort is the resolver port. With approved resolvers configured, TCP to it leaves the Pod directly, as UDP
	// does, and the BPF HBONE-only gate admits it only to an approved resolver identity (bpf/lib/ztunnel_admission.h).
	DNSPort = 53

	VersionSpecificPlaceholder = "<VERSION_SPECIFIC>"
)

// CreateInPodRules creates the iptables rules for ztunnels inpod mode.
//
// directResolverDNS is true when ztunnel-dns-resolver-labels approves at least
// one resolver and the port this rule sees is the port on the wire (no
// per-packet service translation; see zds.directResolverDNS). TCP DNS then
// bypasses ztunnel, as UDP DNS always does: strict
// outbound has no verified xDS workload for a resolver outside the mesh and
// refuses the connection, so a truncated (TC=1) answer could never be retried
// over TCP. When it is false, the bypass rule is removed if a previous
// configuration installed it.
//
// Note that this function is supposed to be called from within the pods
// network namespace.
func CreateInPodRules(logger *slog.Logger, ipv4Enabled, ipv6Enabled, directResolverDNS bool) error {
	if err := addLoopbackRoute(logger, ipv4Enabled, ipv6Enabled); err != nil {
		return err
	}

	if err := addInPodMarkRule(ipv4Enabled, ipv6Enabled); err != nil {
		return err
	}

	if err := addInPodRules(logger, ipv4Enabled, ipv6Enabled, directResolverDNS); err != nil {
		return err
	}

	return nil
}

func addLoopbackRoute(logger *slog.Logger, ipv4Enabled, ipv6Enabled bool) error {
	// Set up netlink routes for localhost
	var cidrs []string
	if ipv4Enabled {
		cidrs = append(cidrs, "0.0.0.0/0")
	}
	if ipv6Enabled {
		cidrs = append(cidrs, "0::0/0")
	}
	for _, fullCIDR := range cidrs {
		_, localhostDst, err := net.ParseCIDR(fullCIDR)
		if err != nil {
			return fmt.Errorf("parse CIDR: %w", err)
		}

		// Equiv: "ip route add local 0.0.0.0/0 dev lo table 100"
		ciliumRoute := route.Route{
			Device: "lo",
			Prefix: *localhostDst,
			Scope:  netlink.SCOPE_HOST,
			Type:   unix.RTN_LOCAL,
			Table:  RouteTableInbound,
		}

		if err := route.Upsert(logger, ciliumRoute); err != nil {
			return fmt.Errorf("failed to add route (%+v): %w", ciliumRoute, err)
		}
	}
	return nil
}

func addInPodMarkRule(ipv4Enabled, ipv6Enabled bool) error {
	mask := uint32(InpodMask)

	if ipv4Enabled {
		// IPv4 rule
		ipv4Rule := route.Rule{
			Priority: InpodRulePriority,
			Mark:     InpodTProxyMark,
			Mask:     mask,
			Table:    RouteTableInbound,
		}

		if err := route.ReplaceRule(ipv4Rule); err != nil {
			return fmt.Errorf("failed to configure IPv4 netlink rule: %w", err)
		}
	}

	if ipv6Enabled {
		// IPv6 rule
		ipv6Rule := route.Rule{
			Priority: InpodRulePriority,
			Mark:     InpodTProxyMark,
			Mask:     mask,
			Table:    RouteTableInbound,
		}

		if err := route.ReplaceRuleIPv6(ipv6Rule); err != nil {
			return fmt.Errorf("failed to configure IPv6 netlink rule: %w", err)
		}
	}
	return nil
}

type rule struct {
	ipv4       string
	ipv6       string
	table      string
	chain      string
	parameters []string
	// first keeps exactly one copy of the rule, at the head of its chain, instead of appending it. A rule added to
	// the chain of a Pod enrolled by an earlier agent must still precede that chain's existing REDIRECT, and two
	// concurrent installs (enrollment and snapshot replay) must not leave a second copy.
	first bool
	// absent removes every copy of the rule, so that disabling an option takes effect on enrolled Pods.
	absent bool
}

type ruleManager struct {
	rules  []rule
	logger *slog.Logger
	ipt4   *iptables.IPTables
	ipt6   *iptables.IPTables
}

func (m *ruleManager) add(table, chain string, parameters ...string) {
	m.rules = append(m.rules, rule{table: table, chain: chain, parameters: parameters})
}

func (m *ruleManager) addVersioned(ipv4, ipv6, table, chain string, parameters ...string) {
	m.rules = append(m.rules, rule{ipv4: ipv4, ipv6: ipv6, table: table, chain: chain, parameters: parameters})
}

func (m *ruleManager) addFirst(table, chain string, parameters ...string) {
	m.rules = append(m.rules, rule{table: table, chain: chain, parameters: parameters, first: true})
}

func (m *ruleManager) remove(table, chain string, parameters ...string) {
	m.rules = append(m.rules, rule{table: table, chain: chain, parameters: parameters, absent: true})
}

func replaceIPPlaceholder(args []string, ip string) []string {
	if ip == "" {
		return args
	}
	res := slices.Clone(args)
	for i, arg := range args {
		if arg == VersionSpecificPlaceholder {
			res[i] = ip
		}
	}
	return res
}

func (m *ruleManager) install(ipv4Enabled, ipv6Enabled bool) error {
	for _, rule := range m.rules {
		if ipv4Enabled {
			if err := installRule(m.ipt4, "iptables", rule, replaceIPPlaceholder(rule.parameters, rule.ipv4)); err != nil {
				return err
			}
		}

		if ipv6Enabled && m.ipt6 != nil {
			if err := installRule(m.ipt6, "ip6tables", rule, replaceIPPlaceholder(rule.parameters, rule.ipv6)); err != nil {
				return err
			}
		}
	}
	return nil
}

// installRule makes one rule present (appended, or alone at the head of its chain) or absent.
func installRule(ipt *iptables.IPTables, name string, rule rule, ruleSpec []string) error {
	switch {
	case rule.absent:
		return deleteAllCopies(ipt, name, rule, ruleSpec)
	case rule.first:
		return ensureFirst(ipt, name, rule, ruleSpec)
	}
	exists, err := ipt.Exists(rule.table, rule.chain, ruleSpec...)
	if err != nil {
		return fmt.Errorf("failed to check %s rule existence: %w", name, err)
	}
	if exists {
		return nil
	}
	if err := ipt.Append(rule.table, rule.chain, ruleSpec...); err != nil {
		return fmt.Errorf("failed to insert %s rule (%s %s %v): %w", name, rule.table, rule.chain, ruleSpec, err)
	}
	return nil
}

// ensureFirst leaves the chain with the rule as its first rule and no other copy. A chain that already has that
// shape is not touched, so a repeated install never removes the rule even briefly. A repair deletes every copy
// before it inserts one at the head: in between, TCP DNS meets the REDIRECT and is refused, which fails closed.
// Two repairs racing on one chain can both insert, which leaves two copies at the head; both are ahead of the
// REDIRECT, and the next install removes the extra one.
func ensureFirst(ipt *iptables.IPTables, name string, rule rule, ruleSpec []string) error {
	rules, err := listRules(ipt, name, rule)
	if err != nil {
		return err
	}
	want := ruleLine(rule, ruleSpec)
	if len(rules) > 0 && rules[0] == want && !slices.Contains(rules[1:], want) {
		return nil
	}
	if err := deleteCopies(ipt, name, rule, ruleSpec, countRule(rules, want)); err != nil {
		return err
	}
	if err := ipt.Insert(rule.table, rule.chain, 1, ruleSpec...); err != nil {
		return fmt.Errorf("failed to insert %s rule (%s %s %v): %w", name, rule.table, rule.chain, ruleSpec, err)
	}
	return nil
}

// deleteAllCopies removes every copy of the rule from its chain.
func deleteAllCopies(ipt *iptables.IPTables, name string, rule rule, ruleSpec []string) error {
	rules, err := listRules(ipt, name, rule)
	if err != nil {
		return err
	}
	return deleteCopies(ipt, name, rule, ruleSpec, countRule(rules, ruleLine(rule, ruleSpec)))
}

// deleteCopies deletes the rule as many times as the chain listed it (iptables -D removes one copy per call), then
// checks that none is left. A copy left over was added by a concurrent writer; the error makes the caller retry.
func deleteCopies(ipt *iptables.IPTables, name string, rule rule, ruleSpec []string, copies int) error {
	for range copies {
		if err := ipt.DeleteIfExists(rule.table, rule.chain, ruleSpec...); err != nil {
			return fmt.Errorf("failed to delete %s rule (%s %s %v): %w", name, rule.table, rule.chain, ruleSpec, err)
		}
	}
	exists, err := ipt.Exists(rule.table, rule.chain, ruleSpec...)
	if err != nil {
		return fmt.Errorf("failed to check %s rule existence: %w", name, err)
	}
	if exists {
		return fmt.Errorf("%s rule (%s %s %v) still present after deleting the %d listed copies",
			name, rule.table, rule.chain, ruleSpec, copies)
	}
	return nil
}

// listRules returns the chain's rules in iptables -S form, without its -N or -P line.
func listRules(ipt *iptables.IPTables, name string, rule rule) ([]string, error) {
	listed, err := ipt.List(rule.table, rule.chain)
	if err != nil {
		return nil, fmt.Errorf("failed to list %s chain (%s %s): %w", name, rule.table, rule.chain, err)
	}
	var rules []string
	for _, line := range listed {
		if strings.HasPrefix(line, "-A ") {
			rules = append(rules, line)
		}
	}
	return rules, nil
}

// ruleLine is the rule as iptables -S lists it.
func ruleLine(rule rule, ruleSpec []string) string {
	return "-A " + rule.chain + " " + strings.Join(ruleSpec, " ")
}

func countRule(rules []string, want string) int {
	n := 0
	for _, r := range rules {
		if r == want {
			n++
		}
	}
	return n
}

func (m *ruleManager) createChains(ipv4Enabled, ipv6Enabled bool) error {
	for _, table := range []string{"mangle", "nat"} {
		for _, chain := range []string{InpodPreroutingChain, InpodOutputChain} {
			if ipv4Enabled {
				// Check if chain exists first
				chainExists, err := m.ipt4.ChainExists(table, chain)
				if err != nil {
					return fmt.Errorf("failed to check iptables chain existence: %w", err)
				}

				if !chainExists {
					// Chain doesn't exist, create it
					if err := m.ipt4.NewChain(table, chain); err != nil {
						return fmt.Errorf("failed to create iptables chain %s: %w", chain, err)
					}
				}
			}

			if ipv6Enabled && m.ipt6 != nil {
				// Check if chain exists first
				chainExists, err := m.ipt6.ChainExists(table, chain)
				if err != nil {
					return fmt.Errorf("failed to check ip6tables chain existence: %w", err)
				}

				if !chainExists {
					// Chain doesn't exist, create it
					if err := m.ipt6.NewChain(table, chain); err != nil {
						return fmt.Errorf("failed to create ip6tables chain %s: %w", chain, err)
					}
				}
			}
		}
	}
	return nil
}

// addInPodRules configures iptables rules for ztunnel's inpod mode traffic redirection.
//
// In inpod mode, ztunnel sets up listening sockets on specific ports within the application
// pod's network namespace to handle mTLS encryption/decryption for workload traffic. These
// iptables rules transparently redirect the application's TCP traffic to ztunnel's listening
// ports without requiring changes to the application itself.
//
// The rules implement the following traffic flow:
//
// Inbound Traffic (PREROUTING):
//   - Packets with the inpod mark (0x539) get their connmark set to the tproxy mark (0x111)
//   - Non-localhost TCP traffic without the inpod mark is redirected to ztunnel's inbound
//     plaintext port (15006), except for traffic already destined to port 15008
//
// Outbound Traffic (OUTPUT):
//   - With approved DNS resolvers, TCP to port 53 is accepted first and leaves the Pod
//     without ztunnel, as UDP does; the BPF HBONE-only gate admits it only to an
//     approved resolver identity
//   - Connmarks are restored to packet marks for connection tracking
//   - Traffic with the tproxy mark (0x111) is allowed through (already processed by ztunnel)
//   - Self-addressed traffic on loopback is allowed to bypass ztunnel
//   - All other non-localhost TCP traffic without the inpod mark is redirected to ztunnel's
//     outbound port (15001)
//
// The rules are created in custom chains (CILIUM_PREROUTING, CILIUM_OUTPUT) that are jumped
// to from the standard PREROUTING and OUTPUT chains in both the mangle and nat tables.
// This makes it easier to identify and manage Cilium-created rules.
func addInPodRules(logger *slog.Logger, ipv4Enabled, ipv6Enabled, directResolverDNS bool) error {
	var ipt4, ipt6 *iptables.IPTables
	var err error

	if ipv4Enabled {
		ipt4, err = iptables.New()
		if err != nil {
			return fmt.Errorf("failed to initialize iptables: %w", err)
		}
	}

	if ipv6Enabled {
		ipt6, err = iptables.NewWithProtocol(iptables.ProtocolIPv6)
		if err != nil {
			return fmt.Errorf("failed to initialize ip6tables: %w", err)
		}
	}

	rm := ruleManager{
		logger: logger,
		ipt4:   ipt4,
		ipt6:   ipt6,
	}

	if err := rm.createChains(ipv4Enabled, ipv6Enabled); err != nil {
		return err
	}

	// Jump to custom chains
	// -t mangle -A PREROUTING -j CILIUM_PREROUTING
	rm.add("mangle", "PREROUTING", "-j", InpodPreroutingChain)
	// -t mangle -A OUTPUT -p tcp -j CILIUM_OUTPUT
	rm.add("mangle", "OUTPUT", "-j", InpodOutputChain)
	// -t nat -A PREROUTING -p tcp -j CILIUM_PREROUTING
	rm.add("nat", "PREROUTING", "-j", InpodPreroutingChain)
	// -t nat -A OUTPUT -p tcp -j CILIUM_OUTPUT
	rm.add("nat", "OUTPUT", "-j", InpodOutputChain)

	inpodMark := fmt.Sprintf("0x%x", InpodMark) + "/" + fmt.Sprintf("0x%x", InpodMask)
	inpodTproxyMark := fmt.Sprintf("0x%x", InpodTProxyMark) + "/" + fmt.Sprintf("0x%x", InpodMask)

	// If we have a packet mark, set a connmark.
	// -A CILIUM_PREROUTING -m mark --mark 0x539/0xfff -j CONNMARK --set-xmark 0x111/0xfff
	rm.add("mangle", InpodPreroutingChain, "-m", "mark",
		"--mark", inpodMark,
		"-j", "CONNMARK",
		"--set-xmark", inpodTproxyMark)

	// Anything that is not bound for localhost and does not have the mark, REDIRECT to ztunnel inbound plaintext port <INPLAINPORT>
	// Skip 15008, which will go direct without redirect needed.
	// -A CILIUM_PREROUTING ! -d 127.0.0.1/32 -p tcp ! --dport 15008 -m mark ! --mark 0x539/0xfff -j REDIRECT --to-ports <INPLAINPORT>
	rm.addVersioned(
		"127.0.0.1/32", "::1/128",
		"nat", InpodPreroutingChain,
		"!", "-d", VersionSpecificPlaceholder,
		"-p", "tcp",
		"-m", "tcp",
		"!", "--dport", fmt.Sprint(ZtunnelInboundPort),
		"-m", "mark",
		"!", "--mark", inpodMark,
		"-j", "REDIRECT",
		"--to-ports", fmt.Sprint(ZtunnelInboundPlaintextPort),
	)

	// Propagate/restore connmark (if we had one) for outbound
	// -A CILIUM_OUTPUT -m connmark --mark 0x111/0xfff -j CONNMARK --restore-mark --nfmask 0xffffffff --ctmask 0xffffffff
	rm.add("mangle", InpodOutputChain,
		"-m", "connmark",
		"--mark", inpodTproxyMark,
		"-j", "CONNMARK",
		"--restore-mark",
		"--nfmask", fmt.Sprintf("0x%x", InpodRestoreMask),
		"--ctmask", fmt.Sprintf("0x%x", InpodRestoreMask),
	)

	// If this is outbound and has our mark, let it go.
	// -A CILIUM_OUTPUT -p tcp -m mark --mark 0x111/0xfff -j ACCEPT
	rm.add("nat", InpodOutputChain,
		"-p", "tcp",
		"-m", "mark",
		"--mark", inpodTproxyMark,
		"-j", "ACCEPT")

	// Do not redirect app calls to back itself via Ztunnel when using the endpoint address
	// e.g. appN => appN by lo
	// -A CILIUM_OUTPUT ! -d 127.0.0.1/32 -o lo -j ACCEPT
	rm.addVersioned("127.0.0.1/32", "::1/128",
		"nat", InpodOutputChain,
		"!", "-d", VersionSpecificPlaceholder,
		"-o", "lo",
		"-j", "ACCEPT",
	)
	// TCP DNS goes straight to the resolver, ahead of every other outbound rule. It is the first rule
	// of the chain, so it also precedes the REDIRECT in the chain of a Pod enrolled before this rule existed.
	// The rules ahead of the REDIRECT all ACCEPT, so the head of the chain changes no other verdict.
	// -I CILIUM_OUTPUT 1 -p tcp -m tcp --dport 53 -j ACCEPT
	dnsBypass := []string{"-p", "tcp", "-m", "tcp", "--dport", fmt.Sprint(DNSPort), "-j", "ACCEPT"}
	if directResolverDNS {
		rm.addFirst("nat", InpodOutputChain, dnsBypass...)
	} else {
		rm.remove("nat", InpodOutputChain, dnsBypass...)
	}

	// If this is outbound, not bound for localhost, and does not have our packet mark, redirect to ztunnel proxy <OUTPORT>
	// -A CILIUM_OUTPUT ! -d 127.0.0.1/32 -p tcp -m mark ! --mark 0x539/0xfff -j REDIRECT --to-ports <OUTPORT>
	rm.addVersioned("127.0.0.1/32", "::1/128",
		"nat", InpodOutputChain,
		"!", "-d", VersionSpecificPlaceholder,
		"-p", "tcp",
		"-m", "mark",
		"!", "--mark", inpodMark,
		"-j", "REDIRECT",
		"--to-ports", fmt.Sprintf("%d", ZtunnelOutboundPort),
	)

	return rm.install(ipv4Enabled, ipv6Enabled)
}

// DeleteInPodRules removes the iptables rules for ztunnels inpod mode.
//
// Note that this function is supposed to be called from within the pods
// network namespace.
func DeleteInPodRules(logger *slog.Logger, ipv4Enabled, ipv6Enabled bool) error {
	if err := deleteInPodChains(logger, ipv4Enabled, ipv6Enabled); err != nil {
		return err
	}

	if err := deleteInPodMarkRule(ipv4Enabled, ipv6Enabled); err != nil {
		return err
	}

	if err := deleteLoopbackRoute(ipv4Enabled, ipv6Enabled); err != nil {
		return err
	}

	return nil
}

func deleteLoopbackRoute(ipv4Enabled, ipv6Enabled bool) error {
	var cidrs []string
	if ipv4Enabled {
		cidrs = append(cidrs, "0.0.0.0/0")
	}
	if ipv6Enabled {
		cidrs = append(cidrs, "0::0/0")
	}
	for _, fullCIDR := range cidrs {
		_, localhostDst, err := net.ParseCIDR(fullCIDR)
		if err != nil {
			return fmt.Errorf("parse CIDR: %w", err)
		}

		ciliumRoute := route.Route{
			Device: "lo",
			Prefix: *localhostDst,
			Scope:  netlink.SCOPE_HOST,
			Type:   unix.RTN_LOCAL,
			Table:  RouteTableInbound,
		}

		if err := route.Delete(ciliumRoute); err != nil {
			// Ignore ESRCH (no such process) and ENOENT (no such file or directory) errors,
			// which indicate the route was already deleted
			if !errors.Is(err, unix.ESRCH) && !errors.Is(err, unix.ENOENT) {
				return fmt.Errorf("failed to delete route (%+v): %w", ciliumRoute, err)
			}
		}
	}
	return nil
}

func deleteInPodMarkRule(ipv4Enabled, ipv6Enabled bool) error {
	mask := uint32(InpodMask)

	if ipv4Enabled {
		// IPv4 rule
		ipv4Rule := route.Rule{
			Priority: InpodRulePriority,
			Mark:     InpodTProxyMark,
			Mask:     mask,
			Table:    RouteTableInbound,
		}

		if err := route.DeleteRule(unix.AF_INET, ipv4Rule); err != nil {
			if !os.IsNotExist(err) {
				return fmt.Errorf("failed to delete IPv4 netlink rule: %w", err)
			}
		}
	}

	if ipv6Enabled {
		// IPv6 rule
		ipv6Rule := route.Rule{
			Priority: InpodRulePriority,
			Mark:     InpodTProxyMark,
			Mask:     mask,
			Table:    RouteTableInbound,
		}

		if err := route.DeleteRule(unix.AF_INET6, ipv6Rule); err != nil {
			if !os.IsNotExist(err) {
				return fmt.Errorf("failed to delete IPv6 netlink rule: %w", err)
			}
		}
	}
	return nil
}

func deleteInPodChains(logger *slog.Logger, ipv4Enabled, ipv6Enabled bool) error {
	var ipt4, ipt6 *iptables.IPTables
	var err error

	if ipv4Enabled {
		ipt4, err = iptables.New()
		if err != nil {
			return fmt.Errorf("failed to initialize iptables: %w", err)
		}
	}

	if ipv6Enabled {
		ipt6, err = iptables.NewWithProtocol(iptables.ProtocolIPv6)
		if err != nil {
			return fmt.Errorf("failed to initialize ip6tables: %w", err)
		}
	}

	// First, delete the jump rules from the main chains to our custom chains
	for _, table := range []string{"mangle", "nat"} {
		jumpRules := map[string]string{
			"PREROUTING": InpodPreroutingChain,
			"OUTPUT":     InpodOutputChain,
		}

		for mainChain, customChain := range jumpRules {
			if ipv4Enabled {
				// Ignore errors - rule may not exist
				_ = ipt4.Delete(table, mainChain, "-j", customChain)
			}
			if ipv6Enabled {
				// Ignore errors - rule may not exist
				_ = ipt6.Delete(table, mainChain, "-j", customChain)
			}
		}
	}

	// Then flush and delete the custom chains
	for _, table := range []string{"mangle", "nat"} {
		for _, chain := range []string{InpodPreroutingChain, InpodOutputChain} {
			if ipv4Enabled {
				if err := ipt4.ClearChain(table, chain); err != nil {
					return fmt.Errorf("failed to flush iptables chain %s: %w", chain, err)
				}
				if err := ipt4.DeleteChain(table, chain); err != nil {
					return fmt.Errorf("failed to delete iptables chain %s: %w", chain, err)
				}
			}
			if ipv6Enabled {
				if err := ipt6.ClearChain(table, chain); err != nil {
					return fmt.Errorf("failed to flush ip6tables chain %s: %w", chain, err)
				}
				if err := ipt6.DeleteChain(table, chain); err != nil {
					return fmt.Errorf("failed to delete ip6tables chain %s: %w", chain, err)
				}
			}
		}
	}
	return nil
}
