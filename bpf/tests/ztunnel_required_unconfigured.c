// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Native ztunnel admission with the sticky load-time Required obligation and
 * NO compiled endpoint address in either family (endpoint_ipv4 = 0,
 * endpoint_ipv6 = ::), ztunnel_quarantined = false. Such a program has no own
 * endpoint-map entry it could check, so it must be QUARANTINED: every packet
 * is dropped in both directions, including TCP/15008, even when some
 * cilium_lxc row carries this endpoint ID. Real bpf_lxc programs and maps.
 */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4 1
#define ENABLE_IPV6 1
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

ASSIGN_CONFIG(union v4addr, endpoint_ipv4, { .be32 = 0 })
ASSIGN_CONFIG(union v6addr, endpoint_ipv6, { .d1 = 0, .d2 = 0 })
ASSIGN_CONFIG(__u16, endpoint_id, OWN_EPID)
ASSIGN_CONFIG(bool, ztunnel_required, true)
ASSIGN_CONFIG(bool, ztunnel_quarantined, false)

#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/metrics.h"
#include "lib/policy.h"

#define ZT_CAT2(a, b) a##b
#define ZT_CAT(a, b) ZT_CAT2(a, b)

/* rows: also install cilium_lxc rows with this endpoint ID for the pod
 * addresses the packets use. The program has no compiled address, so it can
 * never look them up; they must not make it complete.
 */
static __always_inline void prepare(bool rows)
{
	union v6addr own6 = { .addr = v6_pod_one_addr };

	endpoint_v4_del_entry(POD_IP);
	endpoint_v6_del_entry(&own6);
	if (rows) {
		endpoint_v4_add_entry(POD_IP, 0, OWN_EPID, 0, 0, 0, (__u8 *)pod_mac, NULL);
		endpoint_v6_add_entry(&own6, 0, OWN_EPID, 0, 0, (__u8 *)pod_mac, NULL);
	}
	ipcache_v4_add_entry(PEER_IP, 0, PEER_IDENTITY, PEER_NODE, 0);
	policy_add_egress_allow_all_entry();
	policy_add_ingress_allow_all_entry();
	metrics_del_entry((__u8)-DROP_POLICY, METRIC_EGRESS);
	metrics_del_entry((__u8)-DROP_POLICY, METRIC_INGRESS);
}

static __always_inline int build4(struct __ctx_buff *ctx, bool from_pod, __be16 sport, __be16 dport)
{
	struct pktgen builder;
	void *l4, *data;

	pktgen__init(&builder, ctx);
	if (from_pod)
		l4 = pktgen__push_ipv4_tcp_packet(&builder, (__u8 *)pod_mac, (__u8 *)peer_mac,
						  POD_IP, PEER_IP, sport, dport);
	else
		l4 = pktgen__push_ipv4_tcp_packet(&builder, (__u8 *)peer_mac, (__u8 *)pod_mac,
						  PEER_IP, POD_IP, sport, dport);
	if (!l4)
		return TEST_ERROR;
	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;
	pktgen__finish(&builder);
	return 0;
}

static __always_inline int build6(struct __ctx_buff *ctx, __be16 sport, __be16 dport)
{
	struct pktgen builder;
	void *l4, *data;

	pktgen__init(&builder, ctx);
	l4 = pktgen__push_ipv6_tcp_packet(&builder, (__u8 *)pod_mac, (__u8 *)peer_mac,
					  (__u8 *)v6_pod_one, (__u8 *)v6_pod_two, sport, dport);
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

static __always_inline __u64 policy_drops(__u8 dir)
{
	struct metrics_key key = { .reason = (__u8)-DROP_POLICY, .dir = dir };
	struct metrics_value *entry = map_lookup_elem(&cilium_metrics, &key);

	return entry ? entry->count : 0;
}

/* Every case: dropped, counted once as a policy drop in its direction. */
#define EXPECT_DROPPED(name, dir)						\
CHECK("tc", name)								\
int ZT_CAT(check_, __LINE__)(const struct __ctx_buff *ctx)			\
{										\
	__u32 status;								\
										\
	test_init();								\
	if (status_of(ctx, &status))						\
		test_fatal("status code out of bounds");			\
	assert(status == CTX_ACT_DROP);						\
	assert(policy_drops(dir) == 1);						\
	test_finish();								\
}

/* 01. Egress IPv4 TCP/15008, no rows. */
PKTGEN("tc", "ztunnel_unconfigured_01_egress4_hbone_no_rows")
int pktgen_01(struct __ctx_buff *ctx) { return build4(ctx, true, __bpf_htons(43001), HBONE_PORT); }
SETUP("tc", "ztunnel_unconfigured_01_egress4_hbone_no_rows")
int setup_01(struct __ctx_buff *ctx) { prepare(false); return pod_send_packet(ctx); }
EXPECT_DROPPED("ztunnel_unconfigured_01_egress4_hbone_no_rows", METRIC_EGRESS)

/* 02. Egress IPv4 TCP/15008 with rows carrying this endpoint ID. */
PKTGEN("tc", "ztunnel_unconfigured_02_egress4_hbone_rows_present")
int pktgen_02(struct __ctx_buff *ctx) { return build4(ctx, true, __bpf_htons(43002), HBONE_PORT); }
SETUP("tc", "ztunnel_unconfigured_02_egress4_hbone_rows_present")
int setup_02(struct __ctx_buff *ctx) { prepare(true); return pod_send_packet(ctx); }
EXPECT_DROPPED("ztunnel_unconfigured_02_egress4_hbone_rows_present", METRIC_EGRESS)

/* 03. Egress IPv6 TCP/15008, no rows. */
PKTGEN("tc", "ztunnel_unconfigured_03_egress6_hbone_no_rows")
int pktgen_03(struct __ctx_buff *ctx) { return build6(ctx, __bpf_htons(43003), HBONE_PORT); }
SETUP("tc", "ztunnel_unconfigured_03_egress6_hbone_no_rows")
int setup_03(struct __ctx_buff *ctx) { prepare(false); return pod_send_packet(ctx); }
EXPECT_DROPPED("ztunnel_unconfigured_03_egress6_hbone_no_rows", METRIC_EGRESS)

/* 04. Ingress IPv4 TCP/15008 on the local-delivery policy tail call. */
PKTGEN("tc", "ztunnel_unconfigured_04_ingress4_hbone_tailcall")
int pktgen_04(struct __ctx_buff *ctx) { return build4(ctx, false, __bpf_htons(43004), HBONE_PORT); }
SETUP("tc", "ztunnel_unconfigured_04_ingress4_hbone_tailcall")
int setup_04(struct __ctx_buff *ctx)
{
	prepare(true);
	ctx_store_meta(ctx, CB_SRC_LABEL, PEER_IDENTITY);
	return pod_receive_packet_by_tailcall(ctx);
}
EXPECT_DROPPED("ztunnel_unconfigured_04_ingress4_hbone_tailcall", METRIC_INGRESS)

/* 05. Ingress IPv4 TCP/15008 on to-container. */
PKTGEN("tc", "ztunnel_unconfigured_05_ingress4_hbone_to_container")
int pktgen_05(struct __ctx_buff *ctx) { return build4(ctx, false, __bpf_htons(43005), HBONE_PORT); }
SETUP("tc", "ztunnel_unconfigured_05_ingress4_hbone_to_container")
int setup_05(struct __ctx_buff *ctx) { prepare(true); return pod_receive_packet(ctx); }
EXPECT_DROPPED("ztunnel_unconfigured_05_ingress4_hbone_to_container", METRIC_INGRESS)

/* 06. Egress IPv4 plaintext application port. */
PKTGEN("tc", "ztunnel_unconfigured_06_egress4_app_port")
int pktgen_06(struct __ctx_buff *ctx) { return build4(ctx, true, __bpf_htons(43006), APP_PORT); }
SETUP("tc", "ztunnel_unconfigured_06_egress4_app_port")
int setup_06(struct __ctx_buff *ctx) { prepare(true); return pod_send_packet(ctx); }
EXPECT_DROPPED("ztunnel_unconfigured_06_egress4_app_port", METRIC_EGRESS)
