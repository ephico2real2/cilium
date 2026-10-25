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
 *
 * Inputs:
 *   - load-time ztunnel_required (sticky): the program never runs ORDINARY;
 *     a missing, partial-family or foreign (wrong lxc_id) own entry is
 *     QUARANTINED;
 *   - load-time ztunnel_quarantined: the fail-closed default before release;
 *   - own cilium_lxc flags: QUARANTINED overrides HBONE_ONLY. One map write
 *     changes both directions without a program reload.
 *
 * There are no plaintext exceptions: no host (kubelet probe), DNS, world,
 * CIDR or remote-node exception in either direction. An approved resolver or
 * service binding, a native probe-port source and a typed egress exception
 * map are separate open dependencies; until then those flows are dropped.
 * Programs that predate these checks ignore all of this; a staged upgrade
 * remains required.
 */

#define ZTUNNEL_HBONE_PORT	15008

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

/* New or established egress from an HBONE_ONLY endpoint. */
static __always_inline int ztunnel_hbone_egress_verdict(__u8 nexthdr, __be16 dport)
{
	return ztunnel_is_hbone(nexthdr, dport) ? CTX_ACT_OK : DROP_POLICY;
}

/* New or established ingress to an HBONE_ONLY endpoint, from any source. */
static __always_inline int ztunnel_hbone_ingress_verdict(__u8 nexthdr, __be16 dport)
{
	return ztunnel_is_hbone(nexthdr, dport) ? CTX_ACT_OK : DROP_POLICY;
}

#ifdef IS_BPF_LXC
/* Reply packets. A conntrack entry that predates HBONE_ONLY cannot keep a
 * plaintext flow alive: the actual packet source port must be the HBONE
 * port (a reply from the endpoint's listener or from a peer listener).
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

/* Collect the endpoint's own admission inputs. Every configured family must
 * have an entry owned by this program's endpoint ID.
 */
static __always_inline enum ztunnel_mode ztunnel_own_mode(void)
{
	const struct endpoint_info *ep __maybe_unused;
	bool complete = true;
	__u32 flags = 0;

#ifdef ENABLE_IPV4
	if (CONFIG(endpoint_ipv4).be32) {
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
			ep = __lookup_ip6_endpoint(&own);
			if (ep && ep->lxc_id == LXC_ID)
				flags |= ep->flags;
			else
				complete = false;
		}
	}
#endif
	return ztunnel_mode_decide(CONFIG(ztunnel_required), CONFIG(ztunnel_quarantined),
				   complete, flags);
}
#endif /* IS_BPF_LXC */
