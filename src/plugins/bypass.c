/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#include <netinet/icmp6.h>
#include <stdint.h>

#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_ether.h>
#include <rte_icmp.h>
#include <rte_ip.h>

#include "../lib/utils/packet.h"
#include "../worker.h"
#include "plugins.h"

#define LF_BP_LOG(level, ...)                                             \
	LF_PLUGINS_LOG(level, RTE_FMT("Bypass: " RTE_FMT_HEAD(__VA_ARGS__, ), \
								  RTE_FMT_TAIL(__VA_ARGS__, )))

#define LF_BP_LOG_DP(level, ...)                                             \
	LF_PLUGINS_LOG_DP(level, RTE_FMT("Bypass: " RTE_FMT_HEAD(__VA_ARGS__, ), \
									 RTE_FMT_TAIL(__VA_ARGS__, )))
/**
 * The bypass plugin forwards network control packets directly without them
 * going through the other processing steps. Currently, the following packets
 * are considered network control packets:
 * - ARP
 * - IPv6 ICMP Neighboor Discovery
 */
static inline enum lf_pkt_action
lf_bp_pre(struct lf_worker_context *worker_context, struct rte_mbuf *m,
		enum lf_pkt_action pkt_action)
{
	int res;
	struct rte_ether_hdr *ether_hdr;
	struct rte_ipv6_hdr *ipv6_hdr;
	unsigned int offset = 0;

	if (pkt_action != LF_PKT_UNKNOWN) {
		return pkt_action;
	}

	offset = lf_get_eth_hdr(worker_context, m, offset, &ether_hdr);
	if (offset == 0) {
		return pkt_action;
	}

	res = is_arp(worker_context, m, ether_hdr);
	res |= is_ipv6_neighbor_discovery(worker_context, m, ether_hdr, offset);
	if (res > 0) {
		return LF_PKT_UNKNOWN_FORWARD;
	} else if (res < 0) {
		return LF_PKT_UNKNOWN_DROP;
	}

	return LF_PKT_UNKNOWN;
}

static inline int
is_arp(struct lf_worker_context *worker_context, struct rte_mbuf *m,
		struct rte_ether_hdr *ether_hdr)
{
	if (rte_be_to_cpu_16(ether_hdr->ether_type) == RTE_ETHER_TYPE_ARP) {
		return 1;
	}
	return 0;
}

static inline int
is_ipv6_neighbor_discovery(struct lf_worker_context *worker_context,
		struct rte_mbuf *m, struct rte_ether_hdr *ether_hdr, int offset)
{
	struct rte_ipv6_hdr *ipv6_hdr;
	struct lf_icmpv6_hdr *icmpv6_hdr;

	/* Check EtherType for IPv6 */
	if (rte_be_to_cpu_16(ether_hdr->ether_type) != RTE_ETHER_TYPE_IPV6) {
		return 0;
	}

	/* Get IPv6 header */
	offset = lf_get_ipv6_hdr(worker_context, m, offset, &ipv6_hdr);
	if (offset == 0) {
		return -1;
	}

	/* Check Next Header for ICMPv6 */
	if (ipv6_hdr->proto != IPPROTO_ICMPV6) {
		return 0;
	}

	/* Get ICMPv6 header */
	offset = lf_get_icmpv6_hdr(worker_context, m, offset, &icmpv6_hdr);
	if (offset == 0) {
		return -1;
	}

	// Check ICMPv6 Type for Neighbor Discovery
	if (icmpv6_hdr->type == ND_ROUTER_SOLICIT ||
			icmpv6_hdr->type == ND_ROUTER_ADVERT ||
			icmpv6_hdr->type == ND_NEIGHBOR_SOLICIT ||
			icmpv6_hdr->type == ND_NEIGHBOR_ADVERT) {
		return 1;
	}

	return 0;
}
