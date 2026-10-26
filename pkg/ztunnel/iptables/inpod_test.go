// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package iptables

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"testing"

	"github.com/coreos/go-iptables/iptables"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

func TestPrivilegedCreateInPodRules(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		link, err := safenetlink.LinkByName("lo")
		require.NoError(t, err)
		require.NoError(t, netlink.LinkSetUp(link))

		// Create custom chains
		for _, table := range []string{"mangle", "nat"} {
			for _, chain := range []string{InpodPreroutingChain, InpodOutputChain} {
				_, err = runIPTablesCommand(t, "iptables", "-w", "-t", table, "-N", chain)
				require.NoError(t, err)
				_, err = runIPTablesCommand(t, "ip6tables", "-w", "-t", table, "-N", chain)
				require.NoError(t, err)
			}
		}

		err = CreateInPodRules(slog.Default(), true, true, false)
		require.NoError(t, err)

		// Verify IPv4 rules
		mangleRulesV4 := getIPTablesRules(t, "iptables", "mangle")
		requireRule(t, mangleRulesV4, "-A", "PREROUTING", "-j", InpodPreroutingChain)
		requireRule(t, mangleRulesV4, "-A", "OUTPUT", "-j", InpodOutputChain)
		requireRule(t, mangleRulesV4, "-A", InpodPreroutingChain, "-m", "mark", "--mark", fmt.Sprintf("0x%x/0x%x", InpodMark, InpodMask), "-j", "CONNMARK", "--set-xmark", fmt.Sprintf("0x%x/0x%x", InpodTProxyMark, InpodMask))
		requireRule(t, mangleRulesV4, "-A", InpodOutputChain, "-m", "connmark", "--mark", fmt.Sprintf("0x%x/0x%x", InpodTProxyMark, InpodMask), "-j", "CONNMARK", "--restore-mark")

		natRulesV4 := getIPTablesRules(t, "iptables", "nat")
		requireRule(t, natRulesV4, "-A", "PREROUTING", "-j", InpodPreroutingChain)
		requireRule(t, natRulesV4, "-A", "OUTPUT", "-j", InpodOutputChain)
		requireRule(t, natRulesV4, "-A", InpodPreroutingChain, "!", "-d", "127.0.0.1/32", "-p", "tcp", "-m", "tcp", "!", "--dport", fmt.Sprint(ZtunnelInboundPort), "-m", "mark", "!", "--mark", fmt.Sprintf("0x%x/0x%x", InpodMark, InpodMask), "-j", "REDIRECT", "--to-ports", fmt.Sprint(ZtunnelInboundPlaintextPort))
		requireRule(t, natRulesV4, "-A", InpodOutputChain, "-p", "tcp", "-m", "mark", "--mark", fmt.Sprintf("0x%x/0x%x", InpodTProxyMark, InpodMask), "-j", "ACCEPT")
		requireRule(t, natRulesV4, "-A", InpodOutputChain, "!", "-d", "127.0.0.1/32", "-o", "lo", "-j", "ACCEPT")
		requireRule(t, natRulesV4, "-A", InpodOutputChain, "!", "-d", "127.0.0.1/32", "-p", "tcp", "-m", "mark", "!", "--mark", fmt.Sprintf("0x%x/0x%x", InpodMark, InpodMask), "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", ZtunnelOutboundPort))

		// Verify IPv6 rules
		mangleRulesV6 := getIPTablesRules(t, "ip6tables", "mangle")
		requireRule(t, mangleRulesV6, "-A", "PREROUTING", "-j", InpodPreroutingChain)
		requireRule(t, mangleRulesV6, "-A", "OUTPUT", "-j", InpodOutputChain)
		requireRule(t, mangleRulesV6, "-A", InpodPreroutingChain, "-m", "mark", "--mark", fmt.Sprintf("0x%x/0x%x", InpodMark, InpodMask), "-j", "CONNMARK", "--set-xmark", fmt.Sprintf("0x%x/0x%x", InpodTProxyMark, InpodMask))
		requireRule(t, mangleRulesV6, "-A", InpodOutputChain, "-m", "connmark", "--mark", fmt.Sprintf("0x%x/0x%x", InpodTProxyMark, InpodMask), "-j", "CONNMARK", "--restore-mark")

		natRulesV6 := getIPTablesRules(t, "ip6tables", "nat")
		requireRule(t, natRulesV6, "-A", "PREROUTING", "-j", InpodPreroutingChain)
		requireRule(t, natRulesV6, "-A", "OUTPUT", "-j", InpodOutputChain)
		requireRule(t, natRulesV6, "-A", InpodPreroutingChain, "!", "-d", "::1/128", "-p", "tcp", "-m", "tcp", "!", "--dport", fmt.Sprint(ZtunnelInboundPort), "-m", "mark", "!", "--mark", fmt.Sprintf("0x%x/0x%x", InpodMark, InpodMask), "-j", "REDIRECT", "--to-ports", fmt.Sprint(ZtunnelInboundPlaintextPort))
		requireRule(t, natRulesV6, "-A", InpodOutputChain, "-p", "tcp", "-m", "mark", "--mark", fmt.Sprintf("0x%x/0x%x", InpodTProxyMark, InpodMask), "-j", "ACCEPT")
		requireRule(t, natRulesV6, "-A", InpodOutputChain, "!", "-d", "::1/128", "-o", "lo", "-j", "ACCEPT")
		requireRule(t, natRulesV6, "-A", InpodOutputChain, "!", "-d", "::1/128", "-p", "tcp", "-m", "mark", "!", "--mark", fmt.Sprintf("0x%x/0x%x", InpodMark, InpodMask), "-j", "REDIRECT", "--to-ports", fmt.Sprintf("%d", ZtunnelOutboundPort))

		return nil
	})
}

// TestPrivilegedDirectResolverDNS checks the TCP DNS bypass: it is the first nat
// OUTPUT rule when resolvers are approved, also on a Pod whose chain an earlier
// agent built without it, it is installed once however often the rules are
// applied, and it is removed again when no resolver is approved.
func TestPrivilegedDirectResolverDNS(t *testing.T) {
	testutils.PrivilegedTest(t)

	bypass := "-A " + InpodOutputChain + " -p tcp -m tcp --dport 53 -j ACCEPT"
	redirect := fmt.Sprintf("-j REDIRECT --to-ports %d", ZtunnelOutboundPort)
	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		link, err := safenetlink.LinkByName("lo")
		require.NoError(t, err)
		require.NoError(t, netlink.LinkSetUp(link))

		// An agent without approved resolvers builds exactly the chain of the base agent (64a07d46a6).
		require.NoError(t, CreateInPodRules(slog.Default(), true, true, false))
		for cmd, local := range map[string]string{"iptables": "127.0.0.1/32", "ip6tables": "::1/128"} {
			require.Equal(t, baseOutputChain(local), chainRules(t, cmd, "nat", InpodOutputChain), cmd)
		}

		// The upgraded agent re-applies the rules to the enrolled Pod, twice.
		require.NoError(t, CreateInPodRules(slog.Default(), true, true, true))
		require.NoError(t, CreateInPodRules(slog.Default(), true, true, true))
		for _, cmd := range []string{"iptables", "ip6tables"} {
			rules := chainRules(t, cmd, "nat", InpodOutputChain)
			require.Equal(t, bypass, rules[0], "%s: the bypass must be the first rule:\n%s", cmd, strings.Join(rules, "\n"))
			require.Equal(t, 1, countRule(rules, bypass), cmd)
			require.Contains(t, rules[len(rules)-1], redirect, "%s: the REDIRECT stays last", cmd)
			require.Len(t, rules, 4, cmd)
		}

		// Resolvers no longer approved: the bypass goes, the base chain stays.
		require.NoError(t, CreateInPodRules(slog.Default(), true, true, false))
		for cmd, local := range map[string]string{"iptables": "127.0.0.1/32", "ip6tables": "::1/128"} {
			require.Equal(t, baseOutputChain(local), chainRules(t, cmd, "nat", InpodOutputChain), cmd)
		}
		return nil
	})
}

// TestPrivilegedDirectResolverDNSFreshPod checks the bypass on a Pod enrolled
// for the first time with resolvers approved.
func TestPrivilegedDirectResolverDNSFreshPod(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		link, err := safenetlink.LinkByName("lo")
		require.NoError(t, err)
		require.NoError(t, netlink.LinkSetUp(link))

		require.NoError(t, CreateInPodRules(slog.Default(), true, true, true))
		for _, cmd := range []string{"iptables", "ip6tables"} {
			rules := chainRules(t, cmd, "nat", InpodOutputChain)
			require.Equal(t, "-A "+InpodOutputChain+" -p tcp -m tcp --dport 53 -j ACCEPT", rules[0], cmd)
			require.Len(t, rules, 4, cmd)
		}
		// The inbound chain is unchanged: plaintext TCP to the Pod, port 53 included, still goes to ztunnel.
		for cmd, local := range map[string]string{"iptables": "127.0.0.1/32", "ip6tables": "::1/128"} {
			requireRule(t, getIPTablesRules(t, cmd, "nat"), "-A", InpodPreroutingChain, "!", "-d", local, "-p", "tcp", "-m", "tcp", "!", "--dport", fmt.Sprint(ZtunnelInboundPort), "-m", "mark", "!", "--mark", fmt.Sprintf("0x%x/0x%x", InpodMark, InpodMask), "-j", "REDIRECT", "--to-ports", fmt.Sprint(ZtunnelInboundPlaintextPort))
		}
		return nil
	})
}

// TestPrivilegedDirectResolverDNSConverges checks that one install repairs a
// chain left with duplicate or misplaced bypass rules (two concurrent installs,
// or a rule appended by hand), that a correct chain is not rewritten, and that
// one removal deletes every copy.
func TestPrivilegedDirectResolverDNSConverges(t *testing.T) {
	testutils.PrivilegedTest(t)

	spec := []string{"-p", "tcp", "-m", "tcp", "--dport", "53", "-j", "ACCEPT"}
	bypass := "-A " + InpodOutputChain + " " + strings.Join(spec, " ")
	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		link, err := safenetlink.LinkByName("lo")
		require.NoError(t, err)
		require.NoError(t, netlink.LinkSetUp(link))
		require.NoError(t, CreateInPodRules(slog.Default(), true, true, false))

		for _, cmd := range []string{"iptables", "ip6tables"} {
			// A misplaced copy after the REDIRECT, and a duplicate at the head.
			_, err = runIPTablesCommand(t, cmd, append([]string{"-w", "-t", "nat", "-A", InpodOutputChain}, spec...)...)
			require.NoError(t, err)
			_, err = runIPTablesCommand(t, cmd, append([]string{"-w", "-t", "nat", "-I", InpodOutputChain, "1"}, spec...)...)
			require.NoError(t, err)
			_, err = runIPTablesCommand(t, cmd, append([]string{"-w", "-t", "nat", "-I", InpodOutputChain, "1"}, spec...)...)
			require.NoError(t, err)
			require.Equal(t, 3, countRule(chainRules(t, cmd, "nat", InpodOutputChain), bypass), cmd)
		}

		require.NoError(t, CreateInPodRules(slog.Default(), true, true, true))
		before := map[string][]string{}
		for _, cmd := range []string{"iptables", "ip6tables"} {
			rules := chainRules(t, cmd, "nat", InpodOutputChain)
			require.Equal(t, bypass, rules[0], cmd)
			require.Equal(t, 1, countRule(rules, bypass), cmd)
			require.Len(t, rules, 4, cmd)
			before[cmd] = rules
		}

		// A correct chain is left as it is: its packet counters survive a second install.
		for _, cmd := range []string{"iptables", "ip6tables"} {
			_, err = runIPTablesCommand(t, cmd, append([]string{"-w", "-t", "nat", "-R", InpodOutputChain, "1", "-c", "7", "700"}, spec...)...)
			require.NoError(t, err)
		}
		require.NoError(t, CreateInPodRules(slog.Default(), true, true, true))
		for _, cmd := range []string{"iptables", "ip6tables"} {
			require.Equal(t, before[cmd], chainRules(t, cmd, "nat", InpodOutputChain), cmd)
			out, err := runIPTablesCommand(t, cmd, "-w", "-t", "nat", "-S", InpodOutputChain, "1", "-v")
			require.NoError(t, err)
			require.Contains(t, string(out), "-c 7 700", "%s: the bypass was rewritten", cmd)
		}

		// Two copies again, then one removal leaves none.
		for _, cmd := range []string{"iptables", "ip6tables"} {
			_, err = runIPTablesCommand(t, cmd, append([]string{"-w", "-t", "nat", "-I", InpodOutputChain, "1"}, spec...)...)
			require.NoError(t, err)
		}
		require.NoError(t, CreateInPodRules(slog.Default(), true, true, false))
		for cmd, local := range map[string]string{"iptables": "127.0.0.1/32", "ip6tables": "::1/128"} {
			require.Equal(t, baseOutputChain(local), chainRules(t, cmd, "nat", InpodOutputChain), cmd)
		}
		return nil
	})
}

// TestPrivilegedDirectResolverDNSManyCopies repairs and removes any number of copies, including counts at and past
// the bound the first removal loop had (16), which left none behind on an enabled chain.
func TestPrivilegedDirectResolverDNSManyCopies(t *testing.T) {
	testutils.PrivilegedTest(t)

	spec := []string{"-p", "tcp", "-m", "tcp", "--dport", "53", "-j", "ACCEPT"}
	bypass := "-A " + InpodOutputChain + " " + strings.Join(spec, " ")
	for _, copies := range []int{15, 16, 17, 40} {
		t.Run(fmt.Sprint(copies), func(t *testing.T) {
			ns := netns.NewNetNS(t)
			ns.Do(func() error {
				link, err := safenetlink.LinkByName("lo")
				require.NoError(t, err)
				require.NoError(t, netlink.LinkSetUp(link))
				require.NoError(t, CreateInPodRules(slog.Default(), true, true, false))

				// Half the copies at the head, half after the REDIRECT, on top of those already present.
				add := func() {
					for _, cmd := range []string{"iptables", "ip6tables"} {
						present := countRule(chainRules(t, cmd, "nat", InpodOutputChain), bypass)
						for i := range copies {
							op := []string{"-A", InpodOutputChain}
							if i%2 == 0 {
								op = []string{"-I", InpodOutputChain, "1"}
							}
							_, err := runIPTablesCommand(t, cmd, append(append([]string{"-w", "-t", "nat"}, op...), spec...)...)
							require.NoError(t, err)
						}
						require.Equal(t, present+copies, countRule(chainRules(t, cmd, "nat", InpodOutputChain), bypass), cmd)
					}
				}

				add()
				require.NoError(t, CreateInPodRules(slog.Default(), true, true, true))
				for _, cmd := range []string{"iptables", "ip6tables"} {
					rules := chainRules(t, cmd, "nat", InpodOutputChain)
					require.Equal(t, bypass, rules[0], cmd)
					require.Equal(t, 1, countRule(rules, bypass), cmd)
					require.Len(t, rules, 4, cmd)
				}

				add()
				require.NoError(t, CreateInPodRules(slog.Default(), true, true, false))
				for cmd, local := range map[string]string{"iptables": "127.0.0.1/32", "ip6tables": "::1/128"} {
					require.Equal(t, baseOutputChain(local), chainRules(t, cmd, "nat", InpodOutputChain), cmd)
				}
				return nil
			})
		})
	}
}

// TestPrivilegedCreateInPodRulesIdempotency tests that calling CreateInPodRules
// multiple times with existing rules, routes, and chains doesn't cause errors.
func TestPrivilegedCreateInPodRulesIdempotency(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		link, err := safenetlink.LinkByName("lo")
		require.NoError(t, err)
		require.NoError(t, netlink.LinkSetUp(link))

		// First call - creates all rules, routes, and chains
		err = CreateInPodRules(slog.Default(), true, true, false)
		require.NoError(t, err, "First call to CreateInPodRules should succeed")

		// Second call - should handle existing rules/routes/chains without error
		err = CreateInPodRules(slog.Default(), true, true, false)
		require.NoError(t, err, "Second call to CreateInPodRules should succeed (idempotency)")

		// Third call - verify it's truly idempotent
		err = CreateInPodRules(slog.Default(), true, true, false)
		require.NoError(t, err, "Third call to CreateInPodRules should succeed (idempotency)")

		return nil
	})
}

// TestPrivilegedAddExistingChains tests that creating chains that already exist
// doesn't cause errors.
func TestPrivilegedAddExistingChains(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		link, err := safenetlink.LinkByName("lo")
		require.NoError(t, err)
		require.NoError(t, netlink.LinkSetUp(link))

		ipt4, err := iptables.New()
		require.NoError(t, err)

		ipt6, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
		require.NoError(t, err)

		rm := ruleManager{logger: slog.Default(), ipt4: ipt4, ipt6: ipt6}

		// Create chains first time
		err = rm.createChains(true, true)
		require.NoError(t, err, "First call to createChains should succeed")

		// Create chains second time - should not error
		err = rm.createChains(true, true)
		require.NoError(t, err, "Second call to createChains should succeed")

		// Verify chains exist
		for _, table := range []string{"mangle", "nat"} {
			for _, chain := range []string{InpodPreroutingChain, InpodOutputChain} {
				// IPv4
				_, err := runIPTablesCommand(t, "iptables", "-w", "-t", table, "-L", chain, "-n")
				require.NoError(t, err, "Chain %s should exist in IPv4 %s table", chain, table)

				// IPv6
				_, err = runIPTablesCommand(t, "ip6tables", "-w", "-t", table, "-L", chain, "-n")
				require.NoError(t, err, "Chain %s should exist in IPv6 %s table", chain, table)
			}
		}

		return nil
	})
}

// TestPrivilegedAddExistingRoutes tests that adding routes that already exist
// doesn't cause errors due to RouteReplace behavior.
func TestPrivilegedAddExistingRoutes(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		link, err := safenetlink.LinkByName("lo")
		require.NoError(t, err)
		require.NoError(t, netlink.LinkSetUp(link))

		// Add routes first time
		err = addLoopbackRoute(slog.Default(), true, true)
		require.NoError(t, err, "First call to addLoopbackRoute should succeed")

		// Add routes second time - should not error due to RouteReplace
		err = addLoopbackRoute(slog.Default(), true, true)
		require.NoError(t, err, "Second call to addLoopbackRoute should succeed")

		// Verify routes exist
		routes, err := safenetlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{
			Table: RouteTableInbound,
		}, netlink.RT_FILTER_TABLE)
		require.NoError(t, err)
		require.NotEmpty(t, routes, "IPv4 routes should exist in table %d", RouteTableInbound)

		routesV6, err := safenetlink.RouteListFiltered(netlink.FAMILY_V6, &netlink.Route{
			Table: RouteTableInbound,
		}, netlink.RT_FILTER_TABLE)
		require.NoError(t, err)
		require.NotEmpty(t, routesV6, "IPv6 routes should exist in table %d", RouteTableInbound)

		return nil
	})
}

// TestPrivilegedAddExistingMarkRules tests that adding netlink mark rules that
// already exist doesn't cause errors due to ReplaceRule behavior.
func TestPrivilegedAddExistingMarkRules(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		link, err := safenetlink.LinkByName("lo")
		require.NoError(t, err)
		require.NoError(t, netlink.LinkSetUp(link))

		// Add mark rules first time
		err = addInPodMarkRule(true, true)
		require.NoError(t, err, "First call to addInPodMarkRule should succeed")

		// Add mark rules second time - should not error due to ReplaceRule
		err = addInPodMarkRule(true, true)
		require.NoError(t, err, "Second call to addInPodMarkRule should succeed")

		// Verify IPv4 rule exists
		rules, err := safenetlink.RuleList(netlink.FAMILY_V4)
		require.NoError(t, err)
		foundV4 := false
		for _, rule := range rules {
			if rule.Priority == InpodRulePriority && rule.Mark == InpodTProxyMark && rule.Table == RouteTableInbound {
				foundV4 = true
				break
			}
		}
		require.True(t, foundV4, "IPv4 mark rule should exist")

		// Verify IPv6 rule exists
		rulesV6, err := safenetlink.RuleList(netlink.FAMILY_V6)
		require.NoError(t, err)
		foundV6 := false
		for _, rule := range rulesV6 {
			if rule.Priority == InpodRulePriority && rule.Mark == InpodTProxyMark && rule.Table == RouteTableInbound {
				foundV6 = true
				break
			}
		}
		require.True(t, foundV6, "IPv6 mark rule should exist")

		return nil
	})
}

// TestPrivilegedAddExistingIPTablesRules tests that adding iptables rules that
// already exist doesn't cause errors.
func TestPrivilegedAddExistingIPTablesRules(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		link, err := safenetlink.LinkByName("lo")
		require.NoError(t, err)
		require.NoError(t, netlink.LinkSetUp(link))

		ipt4, err := iptables.New()
		require.NoError(t, err)
		ipt6, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
		require.NoError(t, err)

		// Create chains first
		rm := ruleManager{logger: slog.Default(), ipt4: ipt4, ipt6: ipt6}
		err = rm.createChains(true, true)
		require.NoError(t, err)

		// Install rules first time
		err = addInPodRules(slog.Default(), true, true, false)
		require.NoError(t, err, "First call to addInPodRules should succeed")

		// Install rules second time - should not error (rules already exist)
		err = addInPodRules(slog.Default(), true, true, false)
		require.NoError(t, err, "Second call to addInPodRules should succeed")

		// Verify that rules weren't duplicated
		natRulesV4 := getIPTablesRules(t, "iptables", "nat")

		// Count occurrences of a specific rule to ensure no duplication
		jumpCount := 0
		for _, rule := range natRulesV4 {
			if strings.Contains(rule, "-A PREROUTING -j "+InpodPreroutingChain) {
				jumpCount++
			}
		}
		require.Equal(t, 1, jumpCount, "Jump rule should appear exactly once, not duplicated")

		return nil
	})
}

// TestPrivilegedDeleteInPodRules tests that DeleteInPodRules successfully removes
// all iptables rules, chains, routes, and netlink rules.
func TestPrivilegedDeleteInPodRules(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		link, err := safenetlink.LinkByName("lo")
		require.NoError(t, err)
		require.NoError(t, netlink.LinkSetUp(link))

		// First create all rules
		err = CreateInPodRules(slog.Default(), true, true, false)
		require.NoError(t, err, "CreateInPodRules should succeed")

		// Verify rules exist before deletion
		natRulesV4Before := getIPTablesRules(t, "iptables", "nat")
		requireRule(t, natRulesV4Before, "-A", "PREROUTING", "-j", InpodPreroutingChain)

		// Delete all rules
		err = DeleteInPodRules(slog.Default(), true, true)
		require.NoError(t, err, "DeleteInPodRules should succeed")

		// Verify iptables chains are deleted (IPv4)
		for _, table := range []string{"mangle", "nat"} {
			for _, chain := range []string{InpodPreroutingChain, InpodOutputChain} {
				_, err := runIPTablesCommand(t, "iptables", "-w", "-t", table, "-L", chain, "-n")
				require.Error(t, err, "Chain %s should not exist in IPv4 %s table after deletion", chain, table)
			}
		}

		// Verify iptables chains are deleted (IPv6)
		for _, table := range []string{"mangle", "nat"} {
			for _, chain := range []string{InpodPreroutingChain, InpodOutputChain} {
				_, err := runIPTablesCommand(t, "ip6tables", "-w", "-t", table, "-L", chain, "-n")
				require.Error(t, err, "Chain %s should not exist in IPv6 %s table after deletion", chain, table)
			}
		}

		// Verify netlink rules are deleted (IPv4)
		rulesV4, err := safenetlink.RuleList(netlink.FAMILY_V4)
		require.NoError(t, err)
		for _, rule := range rulesV4 {
			require.False(t, rule.Priority == InpodRulePriority && rule.Mark == InpodTProxyMark && rule.Table == RouteTableInbound,
				"IPv4 mark rule should be deleted")
		}

		// Verify netlink rules are deleted (IPv6)
		rulesV6, err := safenetlink.RuleList(netlink.FAMILY_V6)
		require.NoError(t, err)
		for _, rule := range rulesV6 {
			require.False(t, rule.Priority == InpodRulePriority && rule.Mark == InpodTProxyMark && rule.Table == RouteTableInbound,
				"IPv6 mark rule should be deleted")
		}

		// Verify routes are deleted (IPv4)
		routesV4, err := safenetlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{
			Table: RouteTableInbound,
		}, netlink.RT_FILTER_TABLE)
		require.NoError(t, err)
		require.Empty(t, routesV4, "IPv4 routes should be deleted from table %d", RouteTableInbound)

		// Verify routes are deleted (IPv6)
		routesV6, err := safenetlink.RouteListFiltered(netlink.FAMILY_V6, &netlink.Route{
			Table: RouteTableInbound,
		}, netlink.RT_FILTER_TABLE)
		require.NoError(t, err)
		require.Empty(t, routesV6, "IPv6 routes should be deleted from table %d", RouteTableInbound)

		return nil
	})
}

// TestPrivilegedDeleteInPodRulesIdempotency tests that calling DeleteInPodRules
// multiple times doesn't cause errors.
func TestPrivilegedDeleteInPodRulesIdempotency(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		link, err := safenetlink.LinkByName("lo")
		require.NoError(t, err)
		require.NoError(t, netlink.LinkSetUp(link))

		// Create rules
		err = CreateInPodRules(slog.Default(), true, true, false)
		require.NoError(t, err, "CreateInPodRules should succeed")

		// First deletion - should succeed
		err = DeleteInPodRules(slog.Default(), true, true)
		require.NoError(t, err, "First call to DeleteInPodRules should succeed")

		// Second deletion - should handle non-existent rules gracefully
		err = DeleteInPodRules(slog.Default(), true, true)
		require.NoError(t, err, "Second call to DeleteInPodRules should succeed (idempotency)")

		return nil
	})
}

// TestPrivilegedDeleteInPodMarkRule tests the deleteInPodMarkRule function directly.
func TestPrivilegedDeleteInPodMarkRule(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		link, err := safenetlink.LinkByName("lo")
		require.NoError(t, err)
		require.NoError(t, netlink.LinkSetUp(link))

		// Add mark rules first
		err = addInPodMarkRule(true, true)
		require.NoError(t, err, "addInPodMarkRule should succeed")

		// Verify rules exist
		rulesV4Before, err := safenetlink.RuleList(netlink.FAMILY_V4)
		require.NoError(t, err)
		foundV4 := false
		for _, rule := range rulesV4Before {
			if rule.Priority == InpodRulePriority && rule.Mark == InpodTProxyMark && rule.Table == RouteTableInbound {
				foundV4 = true
				break
			}
		}
		require.True(t, foundV4, "IPv4 mark rule should exist before deletion")

		rulesV6Before, err := safenetlink.RuleList(netlink.FAMILY_V6)
		require.NoError(t, err)
		foundV6 := false
		for _, rule := range rulesV6Before {
			if rule.Priority == InpodRulePriority && rule.Mark == InpodTProxyMark && rule.Table == RouteTableInbound {
				foundV6 = true
				break
			}
		}
		require.True(t, foundV6, "IPv6 mark rule should exist before deletion")

		// Delete mark rules
		err = deleteInPodMarkRule(true, true)
		require.NoError(t, err, "deleteInPodMarkRule should succeed")

		// Verify rules are deleted
		rulesV4After, err := safenetlink.RuleList(netlink.FAMILY_V4)
		require.NoError(t, err)
		for _, rule := range rulesV4After {
			require.False(t, rule.Priority == InpodRulePriority && rule.Mark == InpodTProxyMark && rule.Table == RouteTableInbound,
				"IPv4 mark rule should be deleted")
		}

		rulesV6After, err := safenetlink.RuleList(netlink.FAMILY_V6)
		require.NoError(t, err)
		for _, rule := range rulesV6After {
			require.False(t, rule.Priority == InpodRulePriority && rule.Mark == InpodTProxyMark && rule.Table == RouteTableInbound,
				"IPv6 mark rule should be deleted")
		}

		return nil
	})
}

// TestPrivilegedDeleteLoopbackRoute tests the deleteLoopbackRoute function directly.
func TestPrivilegedDeleteLoopbackRoute(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		link, err := safenetlink.LinkByName("lo")
		require.NoError(t, err)
		require.NoError(t, netlink.LinkSetUp(link))

		// Add loopback routes first
		err = addLoopbackRoute(slog.Default(), true, true)
		require.NoError(t, err, "addLoopbackRoute should succeed")

		// Verify routes exist
		routesV4Before, err := safenetlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{
			Table: RouteTableInbound,
		}, netlink.RT_FILTER_TABLE)
		require.NoError(t, err)
		require.NotEmpty(t, routesV4Before, "IPv4 routes should exist before deletion")

		routesV6Before, err := safenetlink.RouteListFiltered(netlink.FAMILY_V6, &netlink.Route{
			Table: RouteTableInbound,
		}, netlink.RT_FILTER_TABLE)
		require.NoError(t, err)
		require.NotEmpty(t, routesV6Before, "IPv6 routes should exist before deletion")

		// Delete loopback routes
		err = deleteLoopbackRoute(true, true)
		require.NoError(t, err, "deleteLoopbackRoute should succeed")

		// Verify routes are deleted
		routesV4After, err := safenetlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{
			Table: RouteTableInbound,
		}, netlink.RT_FILTER_TABLE)
		require.NoError(t, err)
		require.Empty(t, routesV4After, "IPv4 routes should be deleted")

		routesV6After, err := safenetlink.RouteListFiltered(netlink.FAMILY_V6, &netlink.Route{
			Table: RouteTableInbound,
		}, netlink.RT_FILTER_TABLE)
		require.NoError(t, err)
		require.Empty(t, routesV6After, "IPv6 routes should be deleted")

		return nil
	})
}

// TestPrivilegedDeleteInPodChains tests the deleteInPodChains function directly.
func TestPrivilegedDeleteInPodChains(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		link, err := safenetlink.LinkByName("lo")
		require.NoError(t, err)
		require.NoError(t, netlink.LinkSetUp(link))

		// Create chains and add some rules
		err = addInPodRules(slog.Default(), true, true, false)
		require.NoError(t, err, "addInPodRules should succeed")

		// Verify chains exist before deletion
		for _, table := range []string{"mangle", "nat"} {
			for _, chain := range []string{InpodPreroutingChain, InpodOutputChain} {
				_, err := runIPTablesCommand(t, "iptables", "-w", "-t", table, "-L", chain, "-n")
				require.NoError(t, err, "IPv4 chain %s should exist in %s table before deletion", chain, table)

				_, err = runIPTablesCommand(t, "ip6tables", "-w", "-t", table, "-L", chain, "-n")
				require.NoError(t, err, "IPv6 chain %s should exist in %s table before deletion", chain, table)
			}
		}

		// Delete chains
		err = deleteInPodChains(slog.Default(), true, true)
		require.NoError(t, err, "deleteInPodChains should succeed")

		// Verify chains are deleted (IPv4)
		for _, table := range []string{"mangle", "nat"} {
			for _, chain := range []string{InpodPreroutingChain, InpodOutputChain} {
				_, err := runIPTablesCommand(t, "iptables", "-w", "-t", table, "-L", chain, "-n")
				require.Error(t, err, "IPv4 chain %s should not exist in %s table after deletion", chain, table)
			}
		}

		// Verify chains are deleted (IPv6)
		for _, table := range []string{"mangle", "nat"} {
			for _, chain := range []string{InpodPreroutingChain, InpodOutputChain} {
				_, err := runIPTablesCommand(t, "ip6tables", "-w", "-t", table, "-L", chain, "-n")
				require.Error(t, err, "IPv6 chain %s should not exist in %s table after deletion", chain, table)
			}
		}

		return nil
	})
}

func runIPTablesCommand(t *testing.T, cmd string, args ...string) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), defaults.ExecTimeout)
	defer cancel()
	return exec.CommandContext(ctx, cmd, args...).Output()
}

func getIPTablesRules(t *testing.T, cmd, table string) []string {
	out, err := runIPTablesCommand(t, cmd, "-w", "-t", table, "-S")
	require.NoError(t, err, "Failed to get iptables rules for table %s", table)
	return strings.Split(string(out), "\n")
}

// chainRules lists the rules of one chain, in order, without its -N line.
func chainRules(t *testing.T, cmd, table, chain string) []string {
	out, err := runIPTablesCommand(t, cmd, "-w", "-t", table, "-S", chain)
	require.NoError(t, err, "Failed to list %s %s %s", cmd, table, chain)
	var rules []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if strings.HasPrefix(line, "-A ") {
			rules = append(rules, line)
		}
	}
	return rules
}

// baseOutputChain is nat CILIUM_OUTPUT as the base agent (64a07d46a6) builds it, in iptables -S form.
func baseOutputChain(local string) []string {
	mark := fmt.Sprintf("0x%x/0x%x", InpodMark, InpodMask)
	return []string{
		fmt.Sprintf("-A %s -p tcp -m mark --mark 0x%x/0x%x -j ACCEPT", InpodOutputChain, InpodTProxyMark, InpodMask),
		fmt.Sprintf("-A %s ! -d %s -o lo -j ACCEPT", InpodOutputChain, local),
		fmt.Sprintf("-A %s ! -d %s -p tcp -m mark ! --mark %s -j REDIRECT --to-ports %d", InpodOutputChain, local, mark, ZtunnelOutboundPort),
	}
}

func requireRule(t *testing.T, rules []string, expected ...string) {
	expectedRule := strings.Join(expected, " ")
	for _, rule := range rules {
		if strings.Contains(rule, expectedRule) {
			return
		}
	}
	require.Failf(t, "Rule not found", "rule containing '%s' not found in ruleset:\n%s", expectedRule, strings.Join(rules, "\n"))
}
