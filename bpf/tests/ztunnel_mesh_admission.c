// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Native ztunnel datapath admission, map-driven modes (load-time
 * ztunnel_required=false). Each case runs the real bpf_lxc entry programs
 * (from-container, to-container, local-delivery policy tail call) against real
 * cilium_lxc, ipcache, policy, conntrack and metrics maps.
 *
 * HBONE_ONLY is a transport-shape condition (TCP/15008); it does not verify
 * TLS. These tests prove only the datapath shape, never authentication.
 */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4 1
#define TUNNEL_MODE 1
#define ENCAP_IFINDEX 1

#define POD_IP		v4_pod_one
#define PEER_IP		v4_pod_two
#define PEER_NODE	v4_node_two
#define PEER_IDENTITY	1230
#define OWN_EPID	77

#define APP_PORT	__bpf_htons(8080)
#define HBONE_PORT	__bpf_htons(15008)

static volatile const __u8 *pod_mac = mac_one;
static volatile const __u8 *peer_mac = mac_two;

#include "lib/bpf_lxc.h"

ASSIGN_CONFIG(union v4addr, endpoint_ipv4, { .be32 = v4_pod_one })
ASSIGN_CONFIG(__u16, endpoint_id, OWN_EPID)

#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/metrics.h"
#include "lib/policy.h"

#define QUARANTINED	(ENDPOINT_F_ZTUNNEL_QUARANTINED | ENDPOINT_F_ZTUNNEL_MESH_ONLY)
#define HBONE_ONLY	ENDPOINT_F_ZTUNNEL_MESH_ONLY
#define ORDINARY	0

static __always_inline int
build_l4(struct __ctx_buff *ctx, bool udp, __be32 saddr, __be32 daddr, __be16 sport,
	 __be16 dport, bool from_pod)
{
	__u8 *smac = from_pod ? (__u8 *)pod_mac : (__u8 *)peer_mac;
	__u8 *dmac = from_pod ? (__u8 *)peer_mac : (__u8 *)pod_mac;
	struct pktgen builder;
	void *l4, *data;

	pktgen__init(&builder, ctx);
	if (udp)
		l4 = pktgen__push_ipv4_udp_packet(&builder, smac, dmac, saddr, daddr, sport, dport);
	else
		l4 = pktgen__push_ipv4_tcp_packet(&builder, smac, dmac, saddr, daddr, sport, dport);
	if (!l4)
		return TEST_ERROR;
	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;
	pktgen__finish(&builder);
	return 0;
}

static __always_inline void prepare(__u32 own_flags, __u32 peer_identity)
{
	endpoint_v4_add_entry(POD_IP, 0, OWN_EPID, own_flags, 0, 0, (__u8 *)pod_mac, NULL);
	ipcache_v4_add_entry(PEER_IP, 0, peer_identity, PEER_NODE, 0);
	policy_add_egress_allow_all_entry();
	policy_add_ingress_allow_all_entry();
	metrics_del_entry((__u8)-DROP_POLICY, METRIC_EGRESS);
	metrics_del_entry((__u8)-DROP_POLICY, METRIC_INGRESS);
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

static __always_inline __u64 policy_drops(__u8 dir)
{
	struct metrics_key key = { .reason = (__u8)-DROP_POLICY, .dir = dir };
	struct metrics_value *entry = map_lookup_elem(&cilium_metrics, &key);

	return entry ? entry->count : 0;
}

#define ZT_CAT2(a, b) a##b
#define ZT_CAT(a, b) ZT_CAT2(a, b)

#define EXPECT(name, want_status, dir, want_drops)				\
CHECK("tc", name)								\
int ZT_CAT(check_, __LINE__)(const struct __ctx_buff *ctx)				\
{										\
	__u32 status;								\
										\
	test_init();								\
	if (status_of(ctx, &status))						\
		test_fatal("status code out of bounds");			\
	assert(status == (want_status));					\
	assert(policy_drops(dir) == (want_drops));				\
	test_finish();								\
}

#define EXPECT_NOT_DROPPED(name, dir)						\
CHECK("tc", name)								\
int ZT_CAT(check_, __LINE__)(const struct __ctx_buff *ctx)				\
{										\
	__u32 status;								\
										\
	test_init();								\
	if (status_of(ctx, &status))						\
		test_fatal("status code out of bounds");			\
	assert(status != CTX_ACT_DROP);						\
	assert(policy_drops(dir) == 0);						\
	test_finish();								\
}

/* Pure decision table, independent of packet plumbing. */
CHECK("tc", "ztunnel_admission_decision_table")
int ztunnel_admission_decision_table(__maybe_unused struct __ctx_buff *ctx)
{
	test_init();

	TEST("mode: quarantine overrides; sticky Required never ordinary", {
		assert(ztunnel_mode_decide(false, false, true, ORDINARY) == ZTUNNEL_MODE_ORDINARY);
		assert(ztunnel_mode_decide(false, false, false, ORDINARY) == ZTUNNEL_MODE_ORDINARY);
		assert(ztunnel_mode_decide(false, false, true, HBONE_ONLY) == ZTUNNEL_MODE_HBONE_ONLY);
		assert(ztunnel_mode_decide(false, false, true, QUARANTINED) == ZTUNNEL_MODE_QUARANTINED);
		assert(ztunnel_mode_decide(false, true, true, ORDINARY) == ZTUNNEL_MODE_QUARANTINED);
		assert(ztunnel_mode_decide(true, false, true, ORDINARY) == ZTUNNEL_MODE_HBONE_ONLY);
		assert(ztunnel_mode_decide(true, false, false, ORDINARY) == ZTUNNEL_MODE_QUARANTINED);
		assert(ztunnel_mode_decide(true, false, false, HBONE_ONLY) == ZTUNNEL_MODE_QUARANTINED);
		assert(ztunnel_mode_decide(true, false, true, QUARANTINED) == ZTUNNEL_MODE_QUARANTINED);
	});

	TEST("verdicts: only TCP/15008 in either direction", {
		assert(ztunnel_hbone_egress_verdict(IPPROTO_TCP, HBONE_PORT) == CTX_ACT_OK);
		assert(ztunnel_hbone_egress_verdict(IPPROTO_TCP, APP_PORT) == DROP_POLICY);
		assert(ztunnel_hbone_egress_verdict(IPPROTO_TCP, __bpf_htons(31337)) == DROP_POLICY);
		assert(ztunnel_hbone_egress_verdict(IPPROTO_UDP, HBONE_PORT) == DROP_POLICY);
		assert(ztunnel_hbone_egress_verdict(IPPROTO_UDP, __bpf_htons(53)) == DROP_POLICY);
		assert(ztunnel_hbone_egress_verdict(IPPROTO_TCP, __bpf_htons(53)) == DROP_POLICY);
		assert(ztunnel_hbone_ingress_verdict(IPPROTO_TCP, HBONE_PORT) == CTX_ACT_OK);
		assert(ztunnel_hbone_ingress_verdict(IPPROTO_TCP, APP_PORT) == DROP_POLICY);
		assert(ztunnel_hbone_ingress_verdict(IPPROTO_UDP, HBONE_PORT) == DROP_POLICY);
	});

	test_finish();
}

/* 1. Ordinary endpoint (control): the application port is forwarded. */
PKTGEN("tc", "ztunnel_01_egress_ordinary_app_port")
int pktgen_01(struct __ctx_buff *ctx) { return build_l4(ctx, false, POD_IP, PEER_IP, __bpf_htons(40001), APP_PORT, true); }
SETUP("tc", "ztunnel_01_egress_ordinary_app_port")
int setup_01(struct __ctx_buff *ctx) { prepare(ORDINARY, PEER_IDENTITY); return pod_send_packet(ctx); }
EXPECT("ztunnel_01_egress_ordinary_app_port", CTX_ACT_REDIRECT, METRIC_EGRESS, 0)

/* 2. Quarantined endpoint drops even HBONE egress. */
PKTGEN("tc", "ztunnel_02_egress_quarantined_hbone")
int pktgen_02(struct __ctx_buff *ctx) { return build_l4(ctx, false, POD_IP, PEER_IP, __bpf_htons(40002), HBONE_PORT, true); }
SETUP("tc", "ztunnel_02_egress_quarantined_hbone")
int setup_02(struct __ctx_buff *ctx) { prepare(QUARANTINED, PEER_IDENTITY); return pod_send_packet(ctx); }
EXPECT("ztunnel_02_egress_quarantined_hbone", CTX_ACT_DROP, METRIC_EGRESS, 1)

/* 3. HBONE-only: plaintext to a workload application port is dropped. */
PKTGEN("tc", "ztunnel_03_egress_hbone_only_app_port")
int pktgen_03(struct __ctx_buff *ctx) { return build_l4(ctx, false, POD_IP, PEER_IP, __bpf_htons(40003), APP_PORT, true); }
SETUP("tc", "ztunnel_03_egress_hbone_only_app_port")
int setup_03(struct __ctx_buff *ctx) { prepare(HBONE_ONLY, PEER_IDENTITY); return pod_send_packet(ctx); }
EXPECT("ztunnel_03_egress_hbone_only_app_port", CTX_ACT_DROP, METRIC_EGRESS, 1)

/* 4. HBONE-only: TCP/15008 to the workload is forwarded through the tunnel. */
PKTGEN("tc", "ztunnel_04_egress_hbone_only_hbone")
int pktgen_04(struct __ctx_buff *ctx) { return build_l4(ctx, false, POD_IP, PEER_IP, __bpf_htons(40004), HBONE_PORT, true); }
SETUP("tc", "ztunnel_04_egress_hbone_only_hbone")
int setup_04(struct __ctx_buff *ctx) { prepare(HBONE_ONLY, PEER_IDENTITY); return pod_send_packet(ctx); }
EXPECT("ztunnel_04_egress_hbone_only_hbone", CTX_ACT_REDIRECT, METRIC_EGRESS, 0)

/* 5. HBONE-only: a destination resolved as world (missing/stale identity in a
 * protected range is indistinguishable) never becomes a plaintext exception.
 */
PKTGEN("tc", "ztunnel_05_egress_hbone_only_world_plaintext")
int pktgen_05(struct __ctx_buff *ctx) { return build_l4(ctx, false, POD_IP, PEER_IP, __bpf_htons(40005), APP_PORT, true); }
SETUP("tc", "ztunnel_05_egress_hbone_only_world_plaintext")
int setup_05(struct __ctx_buff *ctx) { prepare(HBONE_ONLY, WORLD_ID); return pod_send_packet(ctx); }
EXPECT("ztunnel_05_egress_hbone_only_world_plaintext", CTX_ACT_DROP, METRIC_EGRESS, 1)

/* 6. HBONE-only: UDP/53 to an arbitrary workload is not a DNS exception. */
PKTGEN("tc", "ztunnel_06_egress_hbone_only_udp53")
int pktgen_06(struct __ctx_buff *ctx) { return build_l4(ctx, true, POD_IP, PEER_IP, __bpf_htons(40006), __bpf_htons(53), true); }
SETUP("tc", "ztunnel_06_egress_hbone_only_udp53")
int setup_06(struct __ctx_buff *ctx) { prepare(HBONE_ONLY, PEER_IDENTITY); return pod_send_packet(ctx); }
EXPECT("ztunnel_06_egress_hbone_only_udp53", CTX_ACT_DROP, METRIC_EGRESS, 1)

/* 7. HBONE-only: plaintext from a workload to the application port is dropped
 * at the local-delivery policy tail call (cross-node/overlay path).
 */
PKTGEN("tc", "ztunnel_07_ingress_hbone_only_app_port")
int pktgen_07(struct __ctx_buff *ctx) { return build_l4(ctx, false, PEER_IP, POD_IP, __bpf_htons(41007), APP_PORT, false); }
SETUP("tc", "ztunnel_07_ingress_hbone_only_app_port")
int setup_07(struct __ctx_buff *ctx)
{
	prepare(HBONE_ONLY, PEER_IDENTITY);
	ctx_store_meta(ctx, CB_SRC_LABEL, PEER_IDENTITY);
	return pod_receive_packet_by_tailcall(ctx);
}
EXPECT("ztunnel_07_ingress_hbone_only_app_port", CTX_ACT_DROP, METRIC_INGRESS, 1)

/* 8. HBONE-only: TCP/15008 from a workload is accepted on the same path. */
PKTGEN("tc", "ztunnel_08_ingress_hbone_only_hbone")
int pktgen_08(struct __ctx_buff *ctx) { return build_l4(ctx, false, PEER_IP, POD_IP, __bpf_htons(41008), HBONE_PORT, false); }
SETUP("tc", "ztunnel_08_ingress_hbone_only_hbone")
int setup_08(struct __ctx_buff *ctx)
{
	prepare(HBONE_ONLY, PEER_IDENTITY);
	ctx_store_meta(ctx, CB_SRC_LABEL, PEER_IDENTITY);
	return pod_receive_packet_by_tailcall(ctx);
}
EXPECT_NOT_DROPPED("ztunnel_08_ingress_hbone_only_hbone", METRIC_INGRESS)

/* 9. HBONE-only: the egress reply from the endpoint's HBONE listener for the
 * flow accepted in case 8 is forwarded (positive reply path).
 */
PKTGEN("tc", "ztunnel_09_egress_hbone_listener_reply")
int pktgen_09(struct __ctx_buff *ctx) { return build_l4(ctx, false, POD_IP, PEER_IP, HBONE_PORT, __bpf_htons(41008), true); }
SETUP("tc", "ztunnel_09_egress_hbone_listener_reply")
int setup_09(struct __ctx_buff *ctx) { prepare(HBONE_ONLY, PEER_IDENTITY); return pod_send_packet(ctx); }
EXPECT("ztunnel_09_egress_hbone_listener_reply", CTX_ACT_REDIRECT, METRIC_EGRESS, 0)

/* 10. HBONE-only: host-sourced plaintext to the application port is dropped;
 * there is no host exception that could reopen a plaintext bypass.
 */
PKTGEN("tc", "ztunnel_10_ingress_hbone_only_host_plaintext")
int pktgen_10(struct __ctx_buff *ctx) { return build_l4(ctx, false, v4_node_one, POD_IP, __bpf_htons(41010), APP_PORT, false); }
SETUP("tc", "ztunnel_10_ingress_hbone_only_host_plaintext")
int setup_10(struct __ctx_buff *ctx)
{
	prepare(HBONE_ONLY, PEER_IDENTITY);
	ctx->mark = MARK_MAGIC_HOST;
	return pod_receive_packet(ctx);
}
EXPECT("ztunnel_10_ingress_hbone_only_host_plaintext", CTX_ACT_DROP, METRIC_INGRESS, 1)

/* 11-12. Quarantined endpoint drops HBONE ingress on both delivery paths. */
PKTGEN("tc", "ztunnel_11_ingress_quarantined_tailcall")
int pktgen_11(struct __ctx_buff *ctx) { return build_l4(ctx, false, PEER_IP, POD_IP, __bpf_htons(41011), HBONE_PORT, false); }
SETUP("tc", "ztunnel_11_ingress_quarantined_tailcall")
int setup_11(struct __ctx_buff *ctx)
{
	prepare(QUARANTINED, PEER_IDENTITY);
	ctx_store_meta(ctx, CB_SRC_LABEL, PEER_IDENTITY);
	return pod_receive_packet_by_tailcall(ctx);
}
EXPECT("ztunnel_11_ingress_quarantined_tailcall", CTX_ACT_DROP, METRIC_INGRESS, 1)

PKTGEN("tc", "ztunnel_12_ingress_quarantined_to_container")
int pktgen_12(struct __ctx_buff *ctx) { return build_l4(ctx, false, PEER_IP, POD_IP, __bpf_htons(41012), HBONE_PORT, false); }
SETUP("tc", "ztunnel_12_ingress_quarantined_to_container")
int setup_12(struct __ctx_buff *ctx) { prepare(QUARANTINED, PEER_IDENTITY); return pod_receive_packet(ctx); }
EXPECT("ztunnel_12_ingress_quarantined_to_container", CTX_ACT_DROP, METRIC_INGRESS, 1)

/* 13-15. Transition ORDINARY -> HBONE_ONLY with conntrack already holding a
 * plaintext flow. 13 opens an inbound plaintext flow while ORDINARY.
 */
PKTGEN("tc", "ztunnel_13_transition_ordinary_inbound_plaintext")
int pktgen_13(struct __ctx_buff *ctx) { return build_l4(ctx, false, PEER_IP, POD_IP, __bpf_htons(41013), APP_PORT, false); }
SETUP("tc", "ztunnel_13_transition_ordinary_inbound_plaintext")
int setup_13(struct __ctx_buff *ctx)
{
	prepare(ORDINARY, PEER_IDENTITY);
	ctx_store_meta(ctx, CB_SRC_LABEL, PEER_IDENTITY);
	return pod_receive_packet_by_tailcall(ctx);
}
EXPECT_NOT_DROPPED("ztunnel_13_transition_ordinary_inbound_plaintext", METRIC_INGRESS)

/* 14. Same tuple after the map write to HBONE_ONLY (CT_ESTABLISHED): dropped. */
PKTGEN("tc", "ztunnel_14_transition_established_plaintext_dropped")
int pktgen_14(struct __ctx_buff *ctx) { return build_l4(ctx, false, PEER_IP, POD_IP, __bpf_htons(41013), APP_PORT, false); }
SETUP("tc", "ztunnel_14_transition_established_plaintext_dropped")
int setup_14(struct __ctx_buff *ctx)
{
	prepare(HBONE_ONLY, PEER_IDENTITY);
	ctx_store_meta(ctx, CB_SRC_LABEL, PEER_IDENTITY);
	return pod_receive_packet_by_tailcall(ctx);
}
EXPECT("ztunnel_14_transition_established_plaintext_dropped", CTX_ACT_DROP, METRIC_INGRESS, 1)

/* 15. The endpoint's plaintext reply for that old flow (CT_REPLY): dropped. */
PKTGEN("tc", "ztunnel_15_transition_reply_plaintext_dropped")
int pktgen_15(struct __ctx_buff *ctx) { return build_l4(ctx, false, POD_IP, PEER_IP, APP_PORT, __bpf_htons(41013), true); }
SETUP("tc", "ztunnel_15_transition_reply_plaintext_dropped")
int setup_15(struct __ctx_buff *ctx) { prepare(HBONE_ONLY, PEER_IDENTITY); return pod_send_packet(ctx); }
EXPECT("ztunnel_15_transition_reply_plaintext_dropped", CTX_ACT_DROP, METRIC_EGRESS, 1)

/* 16-17. An ordinary outbound UDP flow, then a UDP reply into the endpoint
 * after the transition: the CT_REPLY entry cannot carry plaintext data.
 */
PKTGEN("tc", "ztunnel_16_transition_ordinary_outbound_udp")
int pktgen_16(struct __ctx_buff *ctx) { return build_l4(ctx, true, POD_IP, PEER_IP, __bpf_htons(40016), __bpf_htons(5353), true); }
SETUP("tc", "ztunnel_16_transition_ordinary_outbound_udp")
int setup_16(struct __ctx_buff *ctx) { prepare(ORDINARY, PEER_IDENTITY); return pod_send_packet(ctx); }
EXPECT("ztunnel_16_transition_ordinary_outbound_udp", CTX_ACT_REDIRECT, METRIC_EGRESS, 0)

PKTGEN("tc", "ztunnel_17_transition_udp_reply_dropped")
int pktgen_17(struct __ctx_buff *ctx) { return build_l4(ctx, true, PEER_IP, POD_IP, __bpf_htons(5353), __bpf_htons(40016), false); }
SETUP("tc", "ztunnel_17_transition_udp_reply_dropped")
int setup_17(struct __ctx_buff *ctx)
{
	prepare(HBONE_ONLY, PEER_IDENTITY);
	ctx_store_meta(ctx, CB_SRC_LABEL, PEER_IDENTITY);
	return pod_receive_packet_by_tailcall(ctx);
}
EXPECT("ztunnel_17_transition_udp_reply_dropped", CTX_ACT_DROP, METRIC_INGRESS, 1)

/* 18. One map write moves a released endpoint back to quarantine with no
 * program reload: the flow accepted in case 4 is now dropped.
 */
PKTGEN("tc", "ztunnel_18_rewrite_requarantines_established_hbone")
int pktgen_18(struct __ctx_buff *ctx) { return build_l4(ctx, false, POD_IP, PEER_IP, __bpf_htons(40004), HBONE_PORT, true); }
SETUP("tc", "ztunnel_18_rewrite_requarantines_established_hbone")
int setup_18(struct __ctx_buff *ctx) { prepare(QUARANTINED, PEER_IDENTITY); return pod_send_packet(ctx); }
EXPECT("ztunnel_18_rewrite_requarantines_established_hbone", CTX_ACT_DROP, METRIC_EGRESS, 1)

/* 19. Native policy on the outer TCP/15008 flow is not widened: an ingress
 * policy that allows the peer only on 8080 also blocks its HBONE. Original
 * application-tuple authorization is a separate (ztunnel) dependency.
 * Runs last: it removes the allow-all ingress entry.
 */
PKTGEN("tc", "ztunnel_19_native_policy_not_widened_for_hbone")
int pktgen_19(struct __ctx_buff *ctx) { return build_l4(ctx, false, PEER_IP, POD_IP, __bpf_htons(41019), HBONE_PORT, false); }
SETUP("tc", "ztunnel_19_native_policy_not_widened_for_hbone")
int setup_19(struct __ctx_buff *ctx)
{
	prepare(HBONE_ONLY, PEER_IDENTITY);
	policy_delete_ingress_all_entry();
	policy_add_ingress_allow_l3_l4_entry(PEER_IDENTITY, IPPROTO_TCP, APP_PORT, 0);
	ctx_store_meta(ctx, CB_SRC_LABEL, PEER_IDENTITY);
	return pod_receive_packet_by_tailcall(ctx);
}
EXPECT("ztunnel_19_native_policy_not_widened_for_hbone", CTX_ACT_DROP, METRIC_INGRESS, 1)
