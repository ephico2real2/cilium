// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Native ztunnel datapath admission: quarantine and mesh-only forwarding.
 *
 * Each case runs the real bpf_lxc entry programs (from-container, to-container
 * and the local-delivery policy tail call) against real cilium_lxc, ipcache,
 * policy and metrics maps. The endpoint's own cilium_lxc flags select the mode.
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

#define APP_PORT	__bpf_htons(8080)
#define HBONE_PORT	__bpf_htons(15008)

static volatile const __u8 *pod_mac = mac_one;
static volatile const __u8 *peer_mac = mac_two;

#include "lib/bpf_lxc.h"

ASSIGN_CONFIG(union v4addr, endpoint_ipv4, { .be32 = v4_pod_one })

#include "lib/endpoint.h"
#include "lib/ipcache.h"
#include "lib/metrics.h"
#include "lib/policy.h"

#define QUARANTINED	(ENDPOINT_F_ZTUNNEL_QUARANTINED | ENDPOINT_F_ZTUNNEL_MESH_ONLY)
#define MESH_ONLY	ENDPOINT_F_ZTUNNEL_MESH_ONLY
#define ORDINARY	0

static __always_inline int
build_tcp(struct __ctx_buff *ctx, __be32 saddr, __be32 daddr, __be16 sport, __be16 dport,
	  bool egress)
{
	struct pktgen builder;
	struct tcphdr *l4;
	void *data;

	pktgen__init(&builder, ctx);
	if (egress)
		l4 = pktgen__push_ipv4_tcp_packet(&builder, (__u8 *)pod_mac, (__u8 *)peer_mac,
						  saddr, daddr, sport, dport);
	else
		l4 = pktgen__push_ipv4_tcp_packet(&builder, (__u8 *)peer_mac, (__u8 *)pod_mac,
						  saddr, daddr, sport, dport);
	if (!l4)
		return TEST_ERROR;
	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;
	pktgen__finish(&builder);
	return 0;
}

static __always_inline void
prepare(__u32 own_flags, __u32 peer_identity)
{
	endpoint_v4_add_entry(POD_IP, 0, 0, own_flags, 0, 0, (__u8 *)pod_mac, NULL);
	ipcache_v4_add_entry(PEER_IP, 0, peer_identity, PEER_NODE, 0);
	policy_add_egress_allow_all_entry();
	policy_add_ingress_allow_all_entry();
	metrics_del_entry((__u8)-DROP_POLICY, METRIC_EGRESS);
	metrics_del_entry((__u8)-DROP_POLICY, METRIC_INGRESS);
}

static __always_inline int
status_of(const struct __ctx_buff *ctx, __u32 *status)
{
	void *data = (void *)(long)ctx_data(ctx);
	void *data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		return -1;
	*status = *(__u32 *)data;
	return 0;
}

static __always_inline __u64
policy_drops(__u8 dir)
{
	struct metrics_key key = { .reason = (__u8)-DROP_POLICY, .dir = dir };
	struct metrics_value *entry = map_lookup_elem(&cilium_metrics, &key);

	return entry ? entry->count : 0;
}

/* Pure decision table, independent of packet plumbing. */
CHECK("tc", "ztunnel_admission_decision_table")
int ztunnel_admission_decision_table(__maybe_unused struct __ctx_buff *ctx)
{
	test_init();

	TEST("mode: quarantine overrides mesh-only and the config only tightens", {
		assert(ztunnel_mode_from_flags(ORDINARY, false) == ZTUNNEL_MODE_ORDINARY);
		assert(ztunnel_mode_from_flags(MESH_ONLY, false) == ZTUNNEL_MODE_MESH_ONLY);
		assert(ztunnel_mode_from_flags(QUARANTINED, false) == ZTUNNEL_MODE_QUARANTINED);
		assert(ztunnel_mode_from_flags(ENDPOINT_F_ZTUNNEL_QUARANTINED, false) ==
		       ZTUNNEL_MODE_QUARANTINED);
		assert(ztunnel_mode_from_flags(MESH_ONLY, true) == ZTUNNEL_MODE_QUARANTINED);
		assert(ztunnel_mode_from_flags(ORDINARY, true) == ZTUNNEL_MODE_QUARANTINED);
	});

	TEST("egress: workloads only via HBONE or DNS; platform keeps native policy", {
		assert(ztunnel_mesh_egress_verdict(IPPROTO_TCP, HBONE_PORT, PEER_IDENTITY) == CTX_ACT_OK);
		assert(ztunnel_mesh_egress_verdict(IPPROTO_TCP, APP_PORT, PEER_IDENTITY) == DROP_POLICY);
		assert(ztunnel_mesh_egress_verdict(IPPROTO_TCP, __bpf_htons(31337), PEER_IDENTITY) ==
		       DROP_POLICY);
		assert(ztunnel_mesh_egress_verdict(IPPROTO_UDP, HBONE_PORT, PEER_IDENTITY) == DROP_POLICY);
		assert(ztunnel_mesh_egress_verdict(IPPROTO_UDP, __bpf_htons(53), PEER_IDENTITY) == CTX_ACT_OK);
		assert(ztunnel_mesh_egress_verdict(IPPROTO_TCP, __bpf_htons(53), PEER_IDENTITY) == CTX_ACT_OK);
		/* Remote-cluster workload identity (cluster 2). */
		assert(ztunnel_mesh_egress_verdict(IPPROTO_TCP, APP_PORT, (2 << 16) | 300) == DROP_POLICY);
		assert(ztunnel_mesh_egress_verdict(IPPROTO_TCP, APP_PORT, WORLD_ID) == CTX_ACT_OK);
		assert(ztunnel_mesh_egress_verdict(IPPROTO_TCP, APP_PORT, HOST_ID) == CTX_ACT_OK);
		assert(ztunnel_mesh_egress_verdict(IPPROTO_TCP, APP_PORT, REMOTE_NODE_ID) == CTX_ACT_OK);
		assert(ztunnel_mesh_egress_verdict(IPPROTO_TCP, APP_PORT,
						   IDENTITY_LOCAL_SCOPE_CIDR | 5) == CTX_ACT_OK);
	});

	TEST("ingress: workloads only via HBONE; host probes keep native policy", {
		assert(ztunnel_mesh_ingress_verdict(IPPROTO_TCP, HBONE_PORT, PEER_IDENTITY) == CTX_ACT_OK);
		assert(ztunnel_mesh_ingress_verdict(IPPROTO_TCP, APP_PORT, PEER_IDENTITY) == DROP_POLICY);
		assert(ztunnel_mesh_ingress_verdict(IPPROTO_UDP, HBONE_PORT, PEER_IDENTITY) == DROP_POLICY);
		assert(ztunnel_mesh_ingress_verdict(IPPROTO_TCP, APP_PORT, WORLD_ID) == DROP_POLICY);
		assert(ztunnel_mesh_ingress_verdict(IPPROTO_TCP, APP_PORT, HOST_ID) == CTX_ACT_OK);
	});

	test_finish();
}

/* 1. Ordinary endpoint (control): application port is forwarded. */
PKTGEN("tc", "ztunnel_egress_ordinary_app_port")
int ztunnel_egress_ordinary_app_port_pktgen(struct __ctx_buff *ctx)
{
	return build_tcp(ctx, POD_IP, PEER_IP, __bpf_htons(40001), APP_PORT, true);
}

SETUP("tc", "ztunnel_egress_ordinary_app_port")
int ztunnel_egress_ordinary_app_port_setup(struct __ctx_buff *ctx)
{
	prepare(ORDINARY, PEER_IDENTITY);
	return pod_send_packet(ctx);
}

CHECK("tc", "ztunnel_egress_ordinary_app_port")
int ztunnel_egress_ordinary_app_port_check(const struct __ctx_buff *ctx)
{
	__u32 status;

	test_init();
	if (status_of(ctx, &status))
		test_fatal("status code out of bounds");
	assert(status == CTX_ACT_REDIRECT);
	assert(policy_drops(METRIC_EGRESS) == 0);
	test_finish();
}

/* 2. Quarantined endpoint drops even HBONE egress. */
PKTGEN("tc", "ztunnel_egress_quarantined_hbone")
int ztunnel_egress_quarantined_hbone_pktgen(struct __ctx_buff *ctx)
{
	return build_tcp(ctx, POD_IP, PEER_IP, __bpf_htons(40002), HBONE_PORT, true);
}

SETUP("tc", "ztunnel_egress_quarantined_hbone")
int ztunnel_egress_quarantined_hbone_setup(struct __ctx_buff *ctx)
{
	prepare(QUARANTINED, PEER_IDENTITY);
	return pod_send_packet(ctx);
}

CHECK("tc", "ztunnel_egress_quarantined_hbone")
int ztunnel_egress_quarantined_hbone_check(const struct __ctx_buff *ctx)
{
	__u32 status;

	test_init();
	if (status_of(ctx, &status))
		test_fatal("status code out of bounds");
	assert(status == CTX_ACT_DROP);
	assert(policy_drops(METRIC_EGRESS) == 1);
	test_finish();
}

/* 3. Mesh-only endpoint: plaintext to a workload application port is dropped. */
PKTGEN("tc", "ztunnel_egress_mesh_only_app_port")
int ztunnel_egress_mesh_only_app_port_pktgen(struct __ctx_buff *ctx)
{
	return build_tcp(ctx, POD_IP, PEER_IP, __bpf_htons(40003), APP_PORT, true);
}

SETUP("tc", "ztunnel_egress_mesh_only_app_port")
int ztunnel_egress_mesh_only_app_port_setup(struct __ctx_buff *ctx)
{
	prepare(MESH_ONLY, PEER_IDENTITY);
	return pod_send_packet(ctx);
}

CHECK("tc", "ztunnel_egress_mesh_only_app_port")
int ztunnel_egress_mesh_only_app_port_check(const struct __ctx_buff *ctx)
{
	__u32 status;

	test_init();
	if (status_of(ctx, &status))
		test_fatal("status code out of bounds");
	assert(status == CTX_ACT_DROP);
	assert(policy_drops(METRIC_EGRESS) == 1);
	test_finish();
}

/* 4. Mesh-only endpoint: HBONE to the workload is forwarded through the tunnel. */
PKTGEN("tc", "ztunnel_egress_mesh_only_hbone")
int ztunnel_egress_mesh_only_hbone_pktgen(struct __ctx_buff *ctx)
{
	return build_tcp(ctx, POD_IP, PEER_IP, __bpf_htons(40004), HBONE_PORT, true);
}

SETUP("tc", "ztunnel_egress_mesh_only_hbone")
int ztunnel_egress_mesh_only_hbone_setup(struct __ctx_buff *ctx)
{
	prepare(MESH_ONLY, PEER_IDENTITY);
	return pod_send_packet(ctx);
}

CHECK("tc", "ztunnel_egress_mesh_only_hbone")
int ztunnel_egress_mesh_only_hbone_check(const struct __ctx_buff *ctx)
{
	__u32 status;

	test_init();
	if (status_of(ctx, &status))
		test_fatal("status code out of bounds");
	assert(status == CTX_ACT_REDIRECT);
	assert(policy_drops(METRIC_EGRESS) == 0);
	test_finish();
}

/* 5. Mesh-only endpoint: a world destination keeps native policy. */
PKTGEN("tc", "ztunnel_egress_mesh_only_world")
int ztunnel_egress_mesh_only_world_pktgen(struct __ctx_buff *ctx)
{
	return build_tcp(ctx, POD_IP, PEER_IP, __bpf_htons(40005), APP_PORT, true);
}

SETUP("tc", "ztunnel_egress_mesh_only_world")
int ztunnel_egress_mesh_only_world_setup(struct __ctx_buff *ctx)
{
	prepare(MESH_ONLY, WORLD_ID);
	return pod_send_packet(ctx);
}

CHECK("tc", "ztunnel_egress_mesh_only_world")
int ztunnel_egress_mesh_only_world_check(const struct __ctx_buff *ctx)
{
	__u32 status;

	test_init();
	if (status_of(ctx, &status))
		test_fatal("status code out of bounds");
	assert(status != CTX_ACT_DROP);
	assert(policy_drops(METRIC_EGRESS) == 0);
	test_finish();
}

/* 6. Mesh-only endpoint: plaintext from a workload to the application port is
 * dropped at the local-delivery policy tail call (cross-node/overlay path).
 */
PKTGEN("tc", "ztunnel_ingress_mesh_only_app_port")
int ztunnel_ingress_mesh_only_app_port_pktgen(struct __ctx_buff *ctx)
{
	return build_tcp(ctx, PEER_IP, POD_IP, __bpf_htons(41006), APP_PORT, false);
}

SETUP("tc", "ztunnel_ingress_mesh_only_app_port")
int ztunnel_ingress_mesh_only_app_port_setup(struct __ctx_buff *ctx)
{
	prepare(MESH_ONLY, PEER_IDENTITY);
	ctx_store_meta(ctx, CB_SRC_LABEL, PEER_IDENTITY);
	return pod_receive_packet_by_tailcall(ctx);
}

CHECK("tc", "ztunnel_ingress_mesh_only_app_port")
int ztunnel_ingress_mesh_only_app_port_check(const struct __ctx_buff *ctx)
{
	__u32 status;

	test_init();
	if (status_of(ctx, &status))
		test_fatal("status code out of bounds");
	assert(status == CTX_ACT_DROP);
	assert(policy_drops(METRIC_INGRESS) == 1);
	test_finish();
}

/* 7. Mesh-only endpoint: HBONE from a workload is accepted on the same path. */
PKTGEN("tc", "ztunnel_ingress_mesh_only_hbone")
int ztunnel_ingress_mesh_only_hbone_pktgen(struct __ctx_buff *ctx)
{
	return build_tcp(ctx, PEER_IP, POD_IP, __bpf_htons(41007), HBONE_PORT, false);
}

SETUP("tc", "ztunnel_ingress_mesh_only_hbone")
int ztunnel_ingress_mesh_only_hbone_setup(struct __ctx_buff *ctx)
{
	prepare(MESH_ONLY, PEER_IDENTITY);
	ctx_store_meta(ctx, CB_SRC_LABEL, PEER_IDENTITY);
	return pod_receive_packet_by_tailcall(ctx);
}

CHECK("tc", "ztunnel_ingress_mesh_only_hbone")
int ztunnel_ingress_mesh_only_hbone_check(const struct __ctx_buff *ctx)
{
	__u32 status;

	test_init();
	if (status_of(ctx, &status))
		test_fatal("status code out of bounds");
	assert(status != CTX_ACT_DROP);
	assert(policy_drops(METRIC_INGRESS) == 0);
	test_finish();
}

/* 8. Mesh-only endpoint: a host-sourced probe to the application port keeps
 * native policy (cil_to_container, identity from the host mark).
 */
PKTGEN("tc", "ztunnel_ingress_mesh_only_host_probe")
int ztunnel_ingress_mesh_only_host_probe_pktgen(struct __ctx_buff *ctx)
{
	return build_tcp(ctx, v4_node_one, POD_IP, __bpf_htons(41008), APP_PORT, false);
}

SETUP("tc", "ztunnel_ingress_mesh_only_host_probe")
int ztunnel_ingress_mesh_only_host_probe_setup(struct __ctx_buff *ctx)
{
	prepare(MESH_ONLY, PEER_IDENTITY);
	ctx->mark = MARK_MAGIC_HOST;
	return pod_receive_packet(ctx);
}

CHECK("tc", "ztunnel_ingress_mesh_only_host_probe")
int ztunnel_ingress_mesh_only_host_probe_check(const struct __ctx_buff *ctx)
{
	__u32 status;

	test_init();
	if (status_of(ctx, &status))
		test_fatal("status code out of bounds");
	assert(status != CTX_ACT_DROP);
	assert(policy_drops(METRIC_INGRESS) == 0);
	test_finish();
}

/* 9. Quarantined endpoint drops HBONE ingress on both delivery paths. */
PKTGEN("tc", "ztunnel_ingress_quarantined_hbone")
int ztunnel_ingress_quarantined_hbone_pktgen(struct __ctx_buff *ctx)
{
	return build_tcp(ctx, PEER_IP, POD_IP, __bpf_htons(41009), HBONE_PORT, false);
}

SETUP("tc", "ztunnel_ingress_quarantined_hbone")
int ztunnel_ingress_quarantined_hbone_setup(struct __ctx_buff *ctx)
{
	prepare(QUARANTINED, PEER_IDENTITY);
	ctx_store_meta(ctx, CB_SRC_LABEL, PEER_IDENTITY);
	return pod_receive_packet_by_tailcall(ctx);
}

CHECK("tc", "ztunnel_ingress_quarantined_hbone")
int ztunnel_ingress_quarantined_hbone_check(const struct __ctx_buff *ctx)
{
	__u32 status;

	test_init();
	if (status_of(ctx, &status))
		test_fatal("status code out of bounds");
	assert(status == CTX_ACT_DROP);
	test_finish();
}

PKTGEN("tc", "ztunnel_ingress_quarantined_to_container")
int ztunnel_ingress_quarantined_to_container_pktgen(struct __ctx_buff *ctx)
{
	return build_tcp(ctx, PEER_IP, POD_IP, __bpf_htons(41010), HBONE_PORT, false);
}

SETUP("tc", "ztunnel_ingress_quarantined_to_container")
int ztunnel_ingress_quarantined_to_container_setup(struct __ctx_buff *ctx)
{
	prepare(QUARANTINED, PEER_IDENTITY);
	return pod_receive_packet(ctx);
}

CHECK("tc", "ztunnel_ingress_quarantined_to_container")
int ztunnel_ingress_quarantined_to_container_check(const struct __ctx_buff *ctx)
{
	__u32 status;

	test_init();
	if (status_of(ctx, &status))
		test_fatal("status code out of bounds");
	assert(status == CTX_ACT_DROP);
	assert(policy_drops(METRIC_INGRESS) == 1);
	test_finish();
}

/* 10. A single map write moves a released endpoint back to quarantine with no
 * program reload: the same program drops the previously accepted HBONE flow.
 */
PKTGEN("tc", "ztunnel_egress_rewrite_requarantines")
int ztunnel_egress_rewrite_requarantines_pktgen(struct __ctx_buff *ctx)
{
	/* Same 5-tuple as case 4, so conntrack already has the flow. */
	return build_tcp(ctx, POD_IP, PEER_IP, __bpf_htons(40004), HBONE_PORT, true);
}

SETUP("tc", "ztunnel_egress_rewrite_requarantines")
int ztunnel_egress_rewrite_requarantines_setup(struct __ctx_buff *ctx)
{
	prepare(QUARANTINED, PEER_IDENTITY);
	return pod_send_packet(ctx);
}

CHECK("tc", "ztunnel_egress_rewrite_requarantines")
int ztunnel_egress_rewrite_requarantines_check(const struct __ctx_buff *ctx)
{
	__u32 status;

	test_init();
	if (status_of(ctx, &status))
		test_fatal("status code out of bounds");
	assert(status == CTX_ACT_DROP);
	assert(policy_drops(METRIC_EGRESS) == 1);
	test_finish();
}
