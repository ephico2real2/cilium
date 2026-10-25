// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Native ztunnel admission with the sticky load-time Required obligation
 * (ztunnel_required=true), dual-stack. A Required program never forwards as an
 * ordinary endpoint: a missing, foreign (wrong lxc_id) or partial-family own
 * endpoint-map entry is QUARANTINED. Real bpf_lxc programs and maps.
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
ASSIGN_CONFIG(union v6addr, endpoint_ipv6, { .addr = v6_pod_one_addr })
ASSIGN_CONFIG(__u16, endpoint_id, OWN_EPID)
ASSIGN_CONFIG(bool, ztunnel_required, true)

#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/metrics.h"
#include "lib/policy.h"

#define ZT_CAT2(a, b) a##b
#define ZT_CAT(a, b) ZT_CAT2(a, b)

enum own_entries {
	OWN_NONE,		/* neither family has an entry */
	OWN_FOREIGN,		/* both entries belong to another endpoint ID */
	OWN_V4_ONLY,		/* IPv6 entry missing */
	OWN_BOTH_PLAIN,		/* both entries, no admission bits */
	OWN_V6_QUARANTINED,	/* both entries, only IPv6 carries quarantine */
};

static __always_inline void prepare(enum own_entries entries)
{
	union v6addr own6 = { .addr = v6_pod_one_addr };
	__u16 v4id = OWN_EPID, v6id = OWN_EPID;
	__u32 v6flags = 0;

	endpoint_v4_del_entry(POD_IP);
	endpoint_v6_del_entry(&own6);
	if (entries == OWN_FOREIGN)
		v4id = v6id = FOREIGN_EPID;
	if (entries == OWN_V6_QUARANTINED)
		v6flags = ENDPOINT_F_ZTUNNEL_QUARANTINED;
	if (entries != OWN_NONE)
		endpoint_v4_add_entry(POD_IP, 0, v4id, 0, 0, 0, (__u8 *)pod_mac, NULL);
	if (entries != OWN_NONE && entries != OWN_V4_ONLY)
		endpoint_v6_add_entry(&own6, 0, v6id, v6flags, 0, (__u8 *)pod_mac, NULL);
	ipcache_v4_add_entry(PEER_IP, 0, PEER_IDENTITY, PEER_NODE, 0);
	policy_add_egress_allow_all_entry();
	policy_add_ingress_allow_all_entry();
	metrics_del_entry((__u8)-DROP_POLICY, METRIC_EGRESS);
}

static __always_inline int build(struct __ctx_buff *ctx, __be16 sport, __be16 dport)
{
	struct pktgen builder;
	void *l4, *data;

	pktgen__init(&builder, ctx);
	l4 = pktgen__push_ipv4_tcp_packet(&builder, (__u8 *)pod_mac, (__u8 *)peer_mac,
					  POD_IP, PEER_IP, sport, dport);
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

static __always_inline __u64 egress_policy_drops(void)
{
	struct metrics_key key = { .reason = (__u8)-DROP_POLICY, .dir = METRIC_EGRESS };
	struct metrics_value *entry = map_lookup_elem(&cilium_metrics, &key);

	return entry ? entry->count : 0;
}

#define CASE(name, entries, sport, dport, want_status, want_drops)		\
PKTGEN("tc", name)								\
int ZT_CAT(pktgen_, __LINE__)(struct __ctx_buff *ctx)				\
{										\
	return build(ctx, __bpf_htons(sport), dport);				\
}										\
SETUP("tc", name)								\
int ZT_CAT(setup_, __LINE__)(struct __ctx_buff *ctx)				\
{										\
	prepare(entries);							\
	return pod_send_packet(ctx);						\
}										\
CHECK("tc", name)								\
int ZT_CAT(check_, __LINE__)(const struct __ctx_buff *ctx)			\
{										\
	__u32 status;								\
										\
	test_init();								\
	if (status_of(ctx, &status))						\
		test_fatal("status code out of bounds");			\
	assert(status == (want_status));					\
	assert(egress_policy_drops() == (want_drops));				\
	test_finish();								\
}

/* Missing own entries: never ordinary, even for HBONE. */
CASE("ztunnel_required_01_missing_entries_quarantined", OWN_NONE, 42001, HBONE_PORT, CTX_ACT_DROP, 1)
/* Entries owned by another endpoint ID (reuse) are not this endpoint's. */
CASE("ztunnel_required_02_foreign_epid_quarantined", OWN_FOREIGN, 42002, HBONE_PORT, CTX_ACT_DROP, 1)
/* Partial family: the configured IPv6 entry is missing. */
CASE("ztunnel_required_03_partial_family_quarantined", OWN_V4_ONLY, 42003, HBONE_PORT, CTX_ACT_DROP, 1)
/* Complete own entries without bits: HBONE-only, never ordinary. */
CASE("ztunnel_required_04_complete_hbone_forwarded", OWN_BOTH_PLAIN, 42004, HBONE_PORT, CTX_ACT_REDIRECT, 0)
CASE("ztunnel_required_05_complete_app_port_dropped", OWN_BOTH_PLAIN, 42005, APP_PORT, CTX_ACT_DROP, 1)
CASE("ztunnel_required_06_complete_31337_dropped", OWN_BOTH_PLAIN, 42006, __bpf_htons(31337), CTX_ACT_DROP, 1)
/* Mixed family: quarantine on one family quarantines the endpoint. */
CASE("ztunnel_required_07_one_family_quarantined", OWN_V6_QUARANTINED, 42007, HBONE_PORT, CTX_ACT_DROP, 1)
