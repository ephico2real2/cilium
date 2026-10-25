// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Native ztunnel admission with the sticky load-time Required obligation for
 * a single-stack endpoint: IPv4 compiled, IPv6 support built in but no IPv6
 * endpoint address (endpoint_ipv6 = ::). The one configured family decides:
 * an own IPv4 row makes the endpoint HBONE-only (TCP/15008 in both
 * directions, nothing else), a missing or foreign row quarantines it, a
 * quarantine flag on the row quarantines it without a reload, and restoring
 * the own row recovers HBONE-only. Real bpf_lxc programs and maps.
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
#define FOREIGN_EPID	78

#define APP_PORT	__bpf_htons(8080)
#define HBONE_PORT	__bpf_htons(15008)

static volatile const __u8 *pod_mac = mac_one;
static volatile const __u8 *peer_mac = mac_two;

#include "lib/bpf_lxc.h"

ASSIGN_CONFIG(union v4addr, endpoint_ipv4, { .be32 = v4_pod_one })
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

enum own_row {
	ROW_NONE,
	ROW_OWN,
	ROW_FOREIGN,
	ROW_OWN_QUARANTINED,
};

static __always_inline void prepare(enum own_row row)
{
	__u16 epid = row == ROW_FOREIGN ? FOREIGN_EPID : OWN_EPID;
	__u32 flags = row == ROW_OWN_QUARANTINED ? ENDPOINT_F_ZTUNNEL_QUARANTINED : 0;

	endpoint_v4_del_entry(POD_IP);
	if (row != ROW_NONE)
		endpoint_v4_add_entry(POD_IP, 0, epid, flags, 0, 0, (__u8 *)pod_mac, NULL);
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

#define EXPECT(name, want_status, dir, want_drops)				\
CHECK("tc", name)								\
int ZT_CAT(check_, __LINE__)(const struct __ctx_buff *ctx)			\
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
int ZT_CAT(check_, __LINE__)(const struct __ctx_buff *ctx)			\
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

#define EGRESS(name, row, sport, dport)						\
PKTGEN("tc", name)								\
int ZT_CAT(pktgen_, __LINE__)(struct __ctx_buff *ctx)				\
{										\
	return build4(ctx, true, __bpf_htons(sport), dport);			\
}										\
SETUP("tc", name)								\
int ZT_CAT(setup_, __LINE__)(struct __ctx_buff *ctx)				\
{										\
	prepare(row);								\
	return pod_send_packet(ctx);						\
}

#define INGRESS(name, row, sport, dport)					\
PKTGEN("tc", name)								\
int ZT_CAT(pktgen_, __LINE__)(struct __ctx_buff *ctx)				\
{										\
	return build4(ctx, false, __bpf_htons(sport), dport);			\
}										\
SETUP("tc", name)								\
int ZT_CAT(setup_, __LINE__)(struct __ctx_buff *ctx)				\
{										\
	prepare(row);								\
	ctx_store_meta(ctx, CB_SRC_LABEL, PEER_IDENTITY);			\
	return pod_receive_packet_by_tailcall(ctx);				\
}

/* 01-04. Own IPv4 row: HBONE-only in both directions. */
EGRESS("ztunnel_single_01_own_egress_hbone", ROW_OWN, 44001, HBONE_PORT)
EXPECT("ztunnel_single_01_own_egress_hbone", CTX_ACT_REDIRECT, METRIC_EGRESS, 0)
EGRESS("ztunnel_single_02_own_egress_app_port", ROW_OWN, 44002, APP_PORT)
EXPECT("ztunnel_single_02_own_egress_app_port", CTX_ACT_DROP, METRIC_EGRESS, 1)
INGRESS("ztunnel_single_03_own_ingress_hbone", ROW_OWN, 44003, HBONE_PORT)
EXPECT_NOT_DROPPED("ztunnel_single_03_own_ingress_hbone", METRIC_INGRESS)
INGRESS("ztunnel_single_04_own_ingress_app_port", ROW_OWN, 44004, APP_PORT)
EXPECT("ztunnel_single_04_own_ingress_app_port", CTX_ACT_DROP, METRIC_INGRESS, 1)

/* 05-08. Missing, foreign or quarantine-flagged row: quarantined. */
EGRESS("ztunnel_single_05_missing_egress_hbone", ROW_NONE, 44005, HBONE_PORT)
EXPECT("ztunnel_single_05_missing_egress_hbone", CTX_ACT_DROP, METRIC_EGRESS, 1)
INGRESS("ztunnel_single_06_missing_ingress_hbone", ROW_NONE, 44006, HBONE_PORT)
EXPECT("ztunnel_single_06_missing_ingress_hbone", CTX_ACT_DROP, METRIC_INGRESS, 1)
EGRESS("ztunnel_single_07_foreign_egress_hbone", ROW_FOREIGN, 44007, HBONE_PORT)
EXPECT("ztunnel_single_07_foreign_egress_hbone", CTX_ACT_DROP, METRIC_EGRESS, 1)
EGRESS("ztunnel_single_08_flag_quarantined_egress_hbone", ROW_OWN_QUARANTINED, 44008, HBONE_PORT)
EXPECT("ztunnel_single_08_flag_quarantined_egress_hbone", CTX_ACT_DROP, METRIC_EGRESS, 1)

/* 09. Recovery: the own row restored after the quarantined cases. */
EGRESS("ztunnel_single_09_recovered_egress_hbone", ROW_OWN, 44009, HBONE_PORT)
EXPECT("ztunnel_single_09_recovered_egress_hbone", CTX_ACT_REDIRECT, METRIC_EGRESS, 0)
