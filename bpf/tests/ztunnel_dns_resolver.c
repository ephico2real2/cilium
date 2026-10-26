// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Native ztunnel admission: DNS from an HBONE_ONLY endpoint to an approved
 * resolver identity (cilium_ztunnel_dns_resolvers), dual-stack. Each case runs
 * the real bpf_lxc entry programs against real cilium_lxc, ipcache, policy,
 * conntrack, metrics and resolver maps.
 *
 * Cases run in name order and share conntrack state; each case writes the
 * resolver map state it depends on. A reply case reuses the tuple of the query
 * case named just before it.
 */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4 1
#define ENABLE_IPV6 1
#define TUNNEL_MODE 1
#define ENCAP_IFINDEX 1

#define POD_IP			v4_pod_one
#define PEER_IP			v4_pod_two
#define PEER_NODE		v4_node_two
#define OWN_EPID		77

#define RESOLVER_IDENTITY	4242	/* approved in the cases that say so */
#define OTHER_IDENTITY		1230	/* a workload, never approved */

#define DNS_PORT		__bpf_htons(53)
#define HBONE_PORT		__bpf_htons(15008)

static volatile const __u8 *pod_mac = mac_one;
static volatile const __u8 *peer_mac = mac_two;

#include "lib/bpf_lxc.h"

ASSIGN_CONFIG(union v4addr, endpoint_ipv4, { .be32 = v4_pod_one })
ASSIGN_CONFIG(union v6addr, endpoint_ipv6, { .addr = v6_pod_one_addr })
ASSIGN_CONFIG(__u16, endpoint_id, OWN_EPID)

#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/metrics.h"
#include "lib/policy.h"

#define QUARANTINED	(ENDPOINT_F_ZTUNNEL_QUARANTINED | ENDPOINT_F_ZTUNNEL_MESH_ONLY)
#define HBONE_ONLY	ENDPOINT_F_ZTUNNEL_MESH_ONLY
#define ORDINARY	0

#define ZT_CAT2(a, b) a##b
#define ZT_CAT(a, b) ZT_CAT2(a, b)

enum resolvers {
	RESOLVERS_EMPTY,	/* nothing approved (the default) */
	RESOLVERS_APPROVED,	/* RESOLVER_IDENTITY approved */
	RESOLVERS_RESERVED,	/* only reserved identities written (never valid) */
};

static __always_inline void set_resolvers(enum resolvers state)
{
	__u8 approved = ZTUNNEL_DNS_RESOLVER_APPROVED;
	__u32 ids[] = { RESOLVER_IDENTITY, OTHER_IDENTITY, WORLD_ID, HOST_ID, WORLD_IPV4_ID };
	__u32 id;
	int i;

#pragma unroll
	for (i = 0; i < 5; i++) {
		id = ids[i];
		map_delete_elem(&cilium_ztunnel_dns_resolvers, &id);
	}
	switch (state) {
	case RESOLVERS_APPROVED:
		id = RESOLVER_IDENTITY;
		map_update_elem(&cilium_ztunnel_dns_resolvers, &id, &approved, BPF_ANY);
		break;
	case RESOLVERS_RESERVED:
		id = WORLD_ID;
		map_update_elem(&cilium_ztunnel_dns_resolvers, &id, &approved, BPF_ANY);
		id = HOST_ID;
		map_update_elem(&cilium_ztunnel_dns_resolvers, &id, &approved, BPF_ANY);
		id = WORLD_IPV4_ID;
		map_update_elem(&cilium_ztunnel_dns_resolvers, &id, &approved, BPF_ANY);
		break;
	case RESOLVERS_EMPTY:
		break;
	}
}

/* Own endpoint entries for both families, the peer's identity, allow-all
 * native policy unless a case narrows it, and fresh drop counters.
 */
static __always_inline void
prepare(__u32 own_flags, __u32 peer_identity, enum resolvers state)
{
	union v6addr own6 = { .addr = v6_pod_one_addr };
	union v6addr peer6 = { .addr = v6_pod_two_addr };

	endpoint_v4_add_entry(POD_IP, 0, OWN_EPID, own_flags, 0, 0, (__u8 *)pod_mac, NULL);
	endpoint_v6_add_entry(&own6, 0, OWN_EPID, own_flags, 0, (__u8 *)pod_mac, NULL);
	ipcache_v4_add_entry(PEER_IP, 0, peer_identity, PEER_NODE, 0);
	ipcache_v6_add_entry(&peer6, 0, peer_identity, PEER_NODE, 0);
	policy_add_egress_allow_all_entry();
	policy_add_ingress_allow_all_entry();
	set_resolvers(state);
	metrics_del_entry((__u8)-DROP_POLICY, METRIC_EGRESS);
	metrics_del_entry((__u8)-DROP_POLICY, METRIC_INGRESS);
	metrics_del_entry((__u8)-DROP_POLICY_DENY, METRIC_EGRESS);
}

static __always_inline int
build(struct __ctx_buff *ctx, bool v6, bool udp, __be16 sport, __be16 dport, bool from_pod)
{
	__u8 *smac = from_pod ? (__u8 *)pod_mac : (__u8 *)peer_mac;
	__u8 *dmac = from_pod ? (__u8 *)peer_mac : (__u8 *)pod_mac;
	struct pktgen builder;
	void *l4, *data;

	pktgen__init(&builder, ctx);
	if (v6) {
		__u8 *src = from_pod ? (__u8 *)v6_pod_one : (__u8 *)v6_pod_two;
		__u8 *dst = from_pod ? (__u8 *)v6_pod_two : (__u8 *)v6_pod_one;

		if (udp)
			l4 = pktgen__push_ipv6_udp_packet(&builder, smac, dmac, src, dst,
							  sport, dport);
		else
			l4 = pktgen__push_ipv6_tcp_packet(&builder, smac, dmac, src, dst,
							  sport, dport);
	} else {
		__be32 src = from_pod ? POD_IP : PEER_IP;
		__be32 dst = from_pod ? PEER_IP : POD_IP;

		if (udp)
			l4 = pktgen__push_ipv4_udp_packet(&builder, smac, dmac, src, dst,
							  sport, dport);
		else
			l4 = pktgen__push_ipv4_tcp_packet(&builder, smac, dmac, src, dst,
							  sport, dport);
	}
	if (!l4)
		return TEST_ERROR;
	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;
	pktgen__finish(&builder);
	return 0;
}

static __always_inline int status_of(const struct __ctx_buff *ctx, __u32 *status)
{
	void *data = (void *)(long)ctx_data(ctx);
	void *data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		return -1;
	*status = *(__u32 *)data;
	return 0;
}

static __always_inline __u64 drops(int reason, __u8 dir)
{
	struct metrics_key key = { .reason = (__u8)-reason, .dir = dir };
	struct metrics_value *entry = map_lookup_elem(&cilium_metrics, &key);

	return entry ? entry->count : 0;
}

/* SEND: the endpoint sends (from-container). RECV: delivered to the endpoint
 * by the local-delivery policy tail call with the given source identity.
 */
#define SEND(name, v6, udp, sport, dport, flags, peer_id, state)		\
PKTGEN("tc", name)								\
int ZT_CAT(pktgen_, __LINE__)(struct __ctx_buff *ctx)				\
{										\
	return build(ctx, v6, udp, __bpf_htons(sport), dport, true);		\
}										\
SETUP("tc", name)								\
int ZT_CAT(setup_, __LINE__)(struct __ctx_buff *ctx)				\
{										\
	prepare(flags, peer_id, state);						\
	return pod_send_packet(ctx);						\
}

#define RECV(name, v6, udp, sport, dport, flags, peer_id, state)		\
PKTGEN("tc", name)								\
int ZT_CAT(pktgen_, __LINE__)(struct __ctx_buff *ctx)				\
{										\
	return build(ctx, v6, udp, sport, __bpf_htons(dport), false);		\
}										\
SETUP("tc", name)								\
int ZT_CAT(setup_, __LINE__)(struct __ctx_buff *ctx)				\
{										\
	prepare(flags, peer_id, state);						\
	ctx_store_meta(ctx, CB_SRC_LABEL, peer_id);				\
	return pod_receive_packet_by_tailcall(ctx);				\
}

#define EXPECT(name, want_status, reason, dir, want_drops)			\
CHECK("tc", name)								\
int ZT_CAT(check_, __LINE__)(const struct __ctx_buff *ctx)			\
{										\
	__u32 status;								\
										\
	test_init();								\
	if (status_of(ctx, &status))						\
		test_fatal("status code out of bounds");			\
	assert(status == (want_status));					\
	assert(drops(reason, dir) == (want_drops));				\
	test_finish();								\
}

#define EXPECT_NOT_DROPPED(name, dir)						\
CHECK("tc", name)								\
int ZT_CAT(check_, __LINE__)(const struct __ctx_buff *ctx)			\
{										\
	__u32 status;								\
										\
	test_init();								\
	if (status_of(ctx, &status))						\
		test_fatal("status code out of bounds");			\
	assert(status != CTX_ACT_DROP);						\
	assert(drops(DROP_POLICY, dir) == 0);					\
	test_finish();								\
}

/* Pure decision table: the egress verdict with each map state. */
CHECK("tc", "ztunnel_dns_00_decision_table")
int ztunnel_dns_00_decision_table(__maybe_unused struct __ctx_buff *ctx)
{
	test_init();

	TEST("empty map approves nothing", {
		set_resolvers(RESOLVERS_EMPTY);
		assert(ztunnel_hbone_egress_verdict(IPPROTO_UDP, DNS_PORT, RESOLVER_IDENTITY) ==
		       DROP_POLICY);
		assert(ztunnel_hbone_egress_verdict(IPPROTO_TCP, DNS_PORT, RESOLVER_IDENTITY) ==
		       DROP_POLICY);
		assert(ztunnel_hbone_egress_verdict(IPPROTO_TCP, HBONE_PORT, RESOLVER_IDENTITY) ==
		       CTX_ACT_OK);
	});

	TEST("approved identity: UDP/TCP 53 only", {
		set_resolvers(RESOLVERS_APPROVED);
		assert(ztunnel_hbone_egress_verdict(IPPROTO_UDP, DNS_PORT, RESOLVER_IDENTITY) ==
		       CTX_ACT_OK);
		assert(ztunnel_hbone_egress_verdict(IPPROTO_TCP, DNS_PORT, RESOLVER_IDENTITY) ==
		       CTX_ACT_OK);
		assert(ztunnel_hbone_egress_verdict(IPPROTO_UDP, __bpf_htons(5353),
						    RESOLVER_IDENTITY) == DROP_POLICY);
		assert(ztunnel_hbone_egress_verdict(IPPROTO_TCP, __bpf_htons(9153),
						    RESOLVER_IDENTITY) == DROP_POLICY);
		assert(ztunnel_hbone_egress_verdict(IPPROTO_TCP, __bpf_htons(8080),
						    RESOLVER_IDENTITY) == DROP_POLICY);
		assert(ztunnel_hbone_egress_verdict(IPPROTO_SCTP, DNS_PORT, RESOLVER_IDENTITY) ==
		       DROP_POLICY);
		assert(ztunnel_hbone_egress_verdict(IPPROTO_ICMP, 0, RESOLVER_IDENTITY) ==
		       DROP_POLICY);
	});

	TEST("never by port alone: other identities stay dropped", {
		set_resolvers(RESOLVERS_APPROVED);
		assert(ztunnel_hbone_egress_verdict(IPPROTO_UDP, DNS_PORT, OTHER_IDENTITY) ==
		       DROP_POLICY);
		assert(ztunnel_hbone_egress_verdict(IPPROTO_UDP, DNS_PORT, WORLD_ID) ==
		       DROP_POLICY);
		assert(ztunnel_hbone_egress_verdict(IPPROTO_UDP, DNS_PORT, HOST_ID) ==
		       DROP_POLICY);
	});

	TEST("reserved and node-local identities are never resolvers", {
		set_resolvers(RESOLVERS_RESERVED);
		assert(ztunnel_hbone_egress_verdict(IPPROTO_UDP, DNS_PORT, WORLD_ID) ==
		       DROP_POLICY);
		assert(ztunnel_hbone_egress_verdict(IPPROTO_UDP, DNS_PORT, HOST_ID) ==
		       DROP_POLICY);
		assert(ztunnel_hbone_egress_verdict(IPPROTO_UDP, DNS_PORT, WORLD_IPV4_ID) ==
		       DROP_POLICY);
		assert(!ztunnel_is_approved_resolver(IDENTITY_LOCAL_SCOPE_CIDR | 1));
		assert(!ztunnel_is_approved_resolver(ZTUNNEL_DNS_RESOLVER_MIN_IDENTITY - 1));
	});

	set_resolvers(RESOLVERS_EMPTY);
	test_finish();
}

/* 01. Approved resolver: an IPv4 UDP/53 query is forwarded (through the
 * tunnel, cross-node) and native policy is evaluated (allow-all here).
 */
SEND("ztunnel_dns_01_v4_udp53_approved_forwarded", false, true, 43001, DNS_PORT,
     HBONE_ONLY, RESOLVER_IDENTITY, RESOLVERS_APPROVED)
EXPECT("ztunnel_dns_01_v4_udp53_approved_forwarded", CTX_ACT_REDIRECT, DROP_POLICY,
       METRIC_EGRESS, 0)

/* 02. The resolver's answer to 01 (CT_REPLY, sport 53, resolver identity) is
 * delivered.
 */
RECV("ztunnel_dns_02_v4_udp53_reply_delivered", false, true, DNS_PORT, 43001,
     HBONE_ONLY, RESOLVER_IDENTITY, RESOLVERS_APPROVED)
EXPECT_NOT_DROPPED("ztunnel_dns_02_v4_udp53_reply_delivered", METRIC_INGRESS)

/* 03. TCP/53 (truncated-answer retry) to the approved resolver is forwarded. */
SEND("ztunnel_dns_03_v4_tcp53_approved_forwarded", false, false, 43003, DNS_PORT,
     HBONE_ONLY, RESOLVER_IDENTITY, RESOLVERS_APPROVED)
EXPECT("ztunnel_dns_03_v4_tcp53_approved_forwarded", CTX_ACT_REDIRECT, DROP_POLICY,
       METRIC_EGRESS, 0)

/* 04. UDP/53 to a workload that is not an approved resolver: dropped. */
SEND("ztunnel_dns_04_v4_udp53_not_resolver_dropped", false, true, 43004, DNS_PORT,
     HBONE_ONLY, OTHER_IDENTITY, RESOLVERS_APPROVED)
EXPECT("ztunnel_dns_04_v4_udp53_not_resolver_dropped", CTX_ACT_DROP, DROP_POLICY,
       METRIC_EGRESS, 1)

/* 05-06. Plaintext to the resolver on a non-DNS port (metrics 9153, health
 * 8080): dropped.
 */
SEND("ztunnel_dns_05_v4_tcp9153_resolver_dropped", false, false, 43005, __bpf_htons(9153),
     HBONE_ONLY, RESOLVER_IDENTITY, RESOLVERS_APPROVED)
EXPECT("ztunnel_dns_05_v4_tcp9153_resolver_dropped", CTX_ACT_DROP, DROP_POLICY,
       METRIC_EGRESS, 1)

SEND("ztunnel_dns_06_v4_tcp8080_resolver_dropped", false, false, 43006, __bpf_htons(8080),
     HBONE_ONLY, RESOLVER_IDENTITY, RESOLVERS_APPROVED)
EXPECT("ztunnel_dns_06_v4_tcp8080_resolver_dropped", CTX_ACT_DROP, DROP_POLICY,
       METRIC_EGRESS, 1)

/* 07. Empty resolver map (fail closed): UDP/53 to the resolver is dropped. */
SEND("ztunnel_dns_07_v4_udp53_empty_map_dropped", false, true, 43007, DNS_PORT,
     HBONE_ONLY, RESOLVER_IDENTITY, RESOLVERS_EMPTY)
EXPECT("ztunnel_dns_07_v4_udp53_empty_map_dropped", CTX_ACT_DROP, DROP_POLICY,
       METRIC_EGRESS, 1)

/* 08. QUARANTINED drops DNS to an approved resolver. */
SEND("ztunnel_dns_08_v4_udp53_quarantined_dropped", false, true, 43008, DNS_PORT,
     QUARANTINED, RESOLVER_IDENTITY, RESOLVERS_APPROVED)
EXPECT("ztunnel_dns_08_v4_udp53_quarantined_dropped", CTX_ACT_DROP, DROP_POLICY,
       METRIC_EGRESS, 1)

/* 09. Reserved identities written into the map are still not resolvers:
 * UDP/53 to world is dropped.
 */
SEND("ztunnel_dns_09_v4_udp53_world_in_map_dropped", false, true, 43009, DNS_PORT,
     HBONE_ONLY, WORLD_ID, RESOLVERS_RESERVED)
EXPECT("ztunnel_dns_09_v4_udp53_world_in_map_dropped", CTX_ACT_DROP, DROP_POLICY,
       METRIC_EGRESS, 1)

/* 10. Forged answer without conntrack (sport 53 from the resolver identity,
 * no query sent): CT_NEW ingress, dropped.
 */
RECV("ztunnel_dns_10_v4_forged_reply_no_ct_dropped", false, true, DNS_PORT, 43010,
     HBONE_ONLY, RESOLVER_IDENTITY, RESOLVERS_APPROVED)
EXPECT("ztunnel_dns_10_v4_forged_reply_no_ct_dropped", CTX_ACT_DROP, DROP_POLICY,
       METRIC_INGRESS, 1)

/* 11-12. Conntrack from before release to a non-resolver on UDP/53
 * (ORDINARY), then its answer after release: the source identity is not an
 * approved resolver, so the CT_REPLY is dropped.
 */
SEND("ztunnel_dns_11_v4_ordinary_query_to_workload", false, true, 43011, DNS_PORT,
     ORDINARY, OTHER_IDENTITY, RESOLVERS_APPROVED)
EXPECT("ztunnel_dns_11_v4_ordinary_query_to_workload", CTX_ACT_REDIRECT, DROP_POLICY,
       METRIC_EGRESS, 0)

RECV("ztunnel_dns_12_v4_reply_from_workload_dropped", false, true, DNS_PORT, 43011,
     HBONE_ONLY, OTHER_IDENTITY, RESOLVERS_APPROVED)
EXPECT("ztunnel_dns_12_v4_reply_from_workload_dropped", CTX_ACT_DROP, DROP_POLICY,
       METRIC_INGRESS, 1)

/* 13-14. A query accepted while approved, then the approval is withdrawn:
 * its answer (CT_REPLY) is dropped.
 */
SEND("ztunnel_dns_13_v4_query_while_approved", false, true, 43013, DNS_PORT,
     HBONE_ONLY, RESOLVER_IDENTITY, RESOLVERS_APPROVED)
EXPECT("ztunnel_dns_13_v4_query_while_approved", CTX_ACT_REDIRECT, DROP_POLICY,
       METRIC_EGRESS, 0)

RECV("ztunnel_dns_14_v4_reply_after_withdrawal_dropped", false, true, DNS_PORT, 43013,
     HBONE_ONLY, RESOLVER_IDENTITY, RESOLVERS_EMPTY)
EXPECT("ztunnel_dns_14_v4_reply_after_withdrawal_dropped", CTX_ACT_DROP, DROP_POLICY,
       METRIC_INGRESS, 1)

/* 15. The endpoint does not serve DNS: a query from the resolver identity
 * into the endpoint's UDP/53 is dropped (ingress stays HBONE-only).
 */
RECV("ztunnel_dns_15_v4_inbound_udp53_dropped", false, true, __bpf_htons(43015), 53,
     HBONE_ONLY, RESOLVER_IDENTITY, RESOLVERS_APPROVED)
EXPECT("ztunnel_dns_15_v4_inbound_udp53_dropped", CTX_ACT_DROP, DROP_POLICY,
       METRIC_INGRESS, 1)

/* 16-17. IPv6: an approved UDP/53 query is forwarded and its answer
 * delivered.
 */
SEND("ztunnel_dns_16_v6_udp53_approved_forwarded", true, true, 43016, DNS_PORT,
     HBONE_ONLY, RESOLVER_IDENTITY, RESOLVERS_APPROVED)
EXPECT("ztunnel_dns_16_v6_udp53_approved_forwarded", CTX_ACT_REDIRECT, DROP_POLICY,
       METRIC_EGRESS, 0)

RECV("ztunnel_dns_17_v6_udp53_reply_delivered", true, true, DNS_PORT, 43016,
     HBONE_ONLY, RESOLVER_IDENTITY, RESOLVERS_APPROVED)
EXPECT_NOT_DROPPED("ztunnel_dns_17_v6_udp53_reply_delivered", METRIC_INGRESS)

/* 18-20. IPv6 negatives: not a resolver, non-DNS port, empty map. */
SEND("ztunnel_dns_18_v6_udp53_not_resolver_dropped", true, true, 43018, DNS_PORT,
     HBONE_ONLY, OTHER_IDENTITY, RESOLVERS_APPROVED)
EXPECT("ztunnel_dns_18_v6_udp53_not_resolver_dropped", CTX_ACT_DROP, DROP_POLICY,
       METRIC_EGRESS, 1)

SEND("ztunnel_dns_19_v6_tcp9153_resolver_dropped", true, false, 43019, __bpf_htons(9153),
     HBONE_ONLY, RESOLVER_IDENTITY, RESOLVERS_APPROVED)
EXPECT("ztunnel_dns_19_v6_tcp9153_resolver_dropped", CTX_ACT_DROP, DROP_POLICY,
       METRIC_EGRESS, 1)

SEND("ztunnel_dns_20_v6_udp53_empty_map_dropped", true, true, 43020, DNS_PORT,
     HBONE_ONLY, RESOLVER_IDENTITY, RESOLVERS_EMPTY)
EXPECT("ztunnel_dns_20_v6_udp53_empty_map_dropped", CTX_ACT_DROP, DROP_POLICY,
       METRIC_EGRESS, 1)

/* 21. IPv6 forged answer from a non-resolver without conntrack: dropped. */
RECV("ztunnel_dns_21_v6_forged_reply_dropped", true, true, DNS_PORT, 43021,
     HBONE_ONLY, OTHER_IDENTITY, RESOLVERS_APPROVED)
EXPECT("ztunnel_dns_21_v6_forged_reply_dropped", CTX_ACT_DROP, DROP_POLICY,
       METRIC_INGRESS, 1)

/* 22. Native policy still applies after the admission check: an explicit
 * egress deny of UDP/53 to the resolver drops the query with the policy-deny
 * reason, not the admission reason. Runs last: it narrows egress policy.
 */
PKTGEN("tc", "ztunnel_dns_22_v4_native_deny_still_denies")
int pktgen_22(struct __ctx_buff *ctx)
{
	return build(ctx, false, true, __bpf_htons(43022), DNS_PORT, true);
}

SETUP("tc", "ztunnel_dns_22_v4_native_deny_still_denies")
int setup_22(struct __ctx_buff *ctx)
{
	prepare(HBONE_ONLY, RESOLVER_IDENTITY, RESOLVERS_APPROVED);
	policy_add_entry(true, RESOLVER_IDENTITY, IPPROTO_UDP, DNS_PORT, 0, true, 0);
	return pod_send_packet(ctx);
}

CHECK("tc", "ztunnel_dns_22_v4_native_deny_still_denies")
int check_22(const struct __ctx_buff *ctx)
{
	__u32 status;

	test_init();
	if (status_of(ctx, &status))
		test_fatal("status code out of bounds");
	assert(status == CTX_ACT_DROP);
	assert(drops(DROP_POLICY_DENY, METRIC_EGRESS) == 1);
	assert(drops(DROP_POLICY, METRIC_EGRESS) == 0);
	test_finish();
}
