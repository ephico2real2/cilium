/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "common.h"
#include "eps.h"
#include "identity.h"
#include "l4.h"

/* Native ztunnel datapath admission for Required endpoints.
 *
 * A Required endpoint has exactly two modes and is never in ordinary
 * forwarding:
 *
 *   QUARANTINED  drop every packet in both directions.
 *   HBONE_ONLY   the only workload transport is TCP/15008. This is a
 *                transport-shape condition, NOT authentication: the BPF does
 *                not verify TLS. ztunnel's strict inbound/outbound checks and
 *                mandatory capture supply the cryptographic proof. Native
 *                policy still applies to the outer TCP/15008 flow and is not
 *                widened; it does not authorize the original application tuple.
 *                DNS to an approved resolver is the one exception (below).
 *
 * Inputs:
 *   - load-time ztunnel_required (sticky): the program never runs ORDINARY;
 *     a missing, partial-family or foreign (wrong lxc_id) own entry is
 *     QUARANTINED;
 *   - load-time ztunnel_quarantined: the fail-closed default before release;
 *   - own cilium_lxc flags: QUARANTINED overrides HBONE_ONLY. One map write
 *     changes both directions without a program reload.
 *
 * The one plaintext exception is DNS to an approved resolver: egress UDP or
 * TCP to port 53 whose destination security identity is in
 * cilium_ztunnel_dns_resolvers, and the conntrack replies to it (CT_REPLY,
 * source port 53, source identity approved). The agent writes that map from
 * ztunnel-dns-resolver-labels (pkg/ztunnel/resolver): only cluster-wide
 * identities of the local cluster, never a reserved (host, world), CIDR or
 * remote-cluster identity, and never by port alone. An empty map, the
 * default, approves nothing, so DNS is dropped. Native egress policy still
 * applies to the DNS flow after this check. QUARANTINED drops DNS too.
 *
 * There is no other plaintext exception: no host (kubelet probe), world,
 * CIDR or remote-node exception in either direction. A native probe-port
 * source and a typed egress exception map are separate open dependencies;
 * until then those flows are dropped.
 * Programs that predate these checks ignore all of this; a staged upgrade
 * remains required.
 */

#define ZTUNNEL_HBONE_PORT	15008
#define ZTUNNEL_DNS_PORT	53

/* Approved DNS resolver security identities, keyed by identity. Only the agent
 * writes it; the datapath only reads it.
 */
#define ZTUNNEL_DNS_RESOLVER_MAP_SIZE	64
#define ZTUNNEL_DNS_RESOLVER_APPROVED	1

/* Lowest cluster-wide (allocator) identity; matches
 * identity.MinimalNumericIdentity. Everything below is reserved.
 */
#define ZTUNNEL_DNS_RESOLVER_MIN_IDENTITY	256

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);	/* security identity */
	__type(value, __u8);	/* ZTUNNEL_DNS_RESOLVER_APPROVED */
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, ZTUNNEL_DNS_RESOLVER_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_RDONLY_PROG_COND);
} cilium_ztunnel_dns_resolvers __section_maps_btf;

enum ztunnel_mode {
	ZTUNNEL_MODE_ORDINARY = 0,
	ZTUNNEL_MODE_HBONE_ONLY = 1,
	ZTUNNEL_MODE_QUARANTINED = 2,
};

/* Pure decision from the collected inputs. */
static __always_inline enum ztunnel_mode
ztunnel_mode_decide(bool cfg_required, bool cfg_quarantined, bool own_entry_complete,
		    __u32 flags)
{
	if (cfg_quarantined || (flags & ENDPOINT_F_ZTUNNEL_QUARANTINED))
		return ZTUNNEL_MODE_QUARANTINED;
	if (cfg_required) {
		if (!own_entry_complete)
			return ZTUNNEL_MODE_QUARANTINED;
		return ZTUNNEL_MODE_HBONE_ONLY;
	}
	if (flags & ENDPOINT_F_ZTUNNEL_MESH_ONLY)
		return ZTUNNEL_MODE_HBONE_ONLY;
	return ZTUNNEL_MODE_ORDINARY;
}

static __always_inline bool ztunnel_is_hbone(__u8 nexthdr, __be16 port)
{
	return nexthdr == IPPROTO_TCP && port == bpf_htons(ZTUNNEL_HBONE_PORT);
}

/* The peer is an approved resolver. A reserved or node-local (CIDR/FQDN)
 * identity is never one, whatever the map holds.
 */
static __always_inline bool ztunnel_is_approved_resolver(__u32 identity)
{
	const __u8 *approved;

	if (identity < ZTUNNEL_DNS_RESOLVER_MIN_IDENTITY ||
	    (identity & IDENTITY_LOCAL_SCOPE_MASK))
		return false;
	approved = map_lookup_elem(&cilium_ztunnel_dns_resolvers, &identity);
	return approved && *approved == ZTUNNEL_DNS_RESOLVER_APPROVED;
}

/* DNS with an approved resolver: UDP or TCP, the resolver side on port 53
 * (the destination port of a query, the source port of a reply), and the
 * resolver's security identity approved.
 */
static __always_inline bool
ztunnel_is_resolver_dns(__u8 nexthdr, __be16 resolver_port, __u32 resolver_identity)
{
	if (nexthdr != IPPROTO_UDP && nexthdr != IPPROTO_TCP)
		return false;
	if (resolver_port != bpf_htons(ZTUNNEL_DNS_PORT))
		return false;
	return ztunnel_is_approved_resolver(resolver_identity);
}

/* New or established egress from an HBONE_ONLY endpoint: the HBONE transport,
 * or a DNS query to an approved resolver. dport and dst_identity are the
 * backend's, after service translation.
 */
static __always_inline int
ztunnel_hbone_egress_verdict(__u8 nexthdr, __be16 dport, __u32 dst_identity)
{
	if (ztunnel_is_hbone(nexthdr, dport) ||
	    ztunnel_is_resolver_dns(nexthdr, dport, dst_identity))
		return CTX_ACT_OK;
	return DROP_POLICY;
}

/* New or established ingress to an HBONE_ONLY endpoint, from any source. */
static __always_inline int ztunnel_hbone_ingress_verdict(__u8 nexthdr, __be16 dport)
{
	return ztunnel_is_hbone(nexthdr, dport) ? CTX_ACT_OK : DROP_POLICY;
}

#ifdef IS_BPF_LXC
/* Egress reply packets (the endpoint answering a flow it accepted). A
 * conntrack entry that predates HBONE_ONLY cannot keep a plaintext flow
 * alive: the actual packet source port must be the HBONE port of the
 * endpoint's listener. The endpoint never answers DNS.
 */
static __always_inline int
ztunnel_hbone_reply_verdict(const struct __ctx_buff *ctx, __u8 nexthdr, int l4_off)
{
	__be16 ports[2];

	if (nexthdr != IPPROTO_TCP)
		return DROP_POLICY;
	if (l4_load_ports(ctx, l4_off, ports) < 0)
		return DROP_INVALID;
	return ports[0] == bpf_htons(ZTUNNEL_HBONE_PORT) ? CTX_ACT_OK : DROP_POLICY;
}

/* Ingress reply packets (answers to a flow the endpoint opened): from a peer
 * HBONE listener, or a DNS answer from an approved resolver. CT_REPLY binds
 * the packet to an egress entry of this endpoint; the source port and source
 * identity are still checked on the actual packet, because an entry created
 * before release (or to another destination) is not proof of a resolver.
 */
static __always_inline int
ztunnel_hbone_ingress_reply_verdict(const struct __ctx_buff *ctx, __u8 nexthdr, int l4_off,
				    __u32 src_identity)
{
	__be16 ports[2];

	if (nexthdr != IPPROTO_TCP && nexthdr != IPPROTO_UDP)
		return DROP_POLICY;
	if (l4_load_ports(ctx, l4_off, ports) < 0)
		return DROP_INVALID;
	if (ztunnel_is_hbone(nexthdr, ports[0]) ||
	    ztunnel_is_resolver_dns(nexthdr, ports[0], src_identity))
		return CTX_ACT_OK;
	return DROP_POLICY;
}

/* Collect the endpoint's own admission inputs. Every configured family must
 * have an entry owned by this program's endpoint ID, and at least one family
 * must be configured: a program compiled without any endpoint address has no
 * own entry to check, so it is never complete.
 */
static __always_inline enum ztunnel_mode ztunnel_own_mode(void)
{
	const struct endpoint_info *ep __maybe_unused;
	bool configured = false;
	bool complete = true;
	__u32 flags = 0;

#ifdef ENABLE_IPV4
	if (CONFIG(endpoint_ipv4).be32) {
		configured = true;
		ep = __lookup_ip4_endpoint(CONFIG(endpoint_ipv4).be32);
		if (ep && ep->lxc_id == LXC_ID)
			flags |= ep->flags;
		else
			complete = false;
	}
#endif
#ifdef ENABLE_IPV6
	{
		union v6addr own = CONFIG(endpoint_ipv6);

		if (own.d1 || own.d2) {
			configured = true;
			ep = __lookup_ip6_endpoint(&own);
			if (ep && ep->lxc_id == LXC_ID)
				flags |= ep->flags;
			else
				complete = false;
		}
	}
#endif
	return ztunnel_mode_decide(CONFIG(ztunnel_required), CONFIG(ztunnel_quarantined),
				   configured && complete, flags);
}
#endif /* IS_BPF_LXC */
