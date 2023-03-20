/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#include <stdint.h>

#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include "../config.h"
#include "../configmanager.h"
#include "../lf.h"
#include "../lib/utils/packet.h"
#include "../worker.h"

/* Include generic worker source */
#include "../worker.c"

static enum lf_pkt_action
handle_pkt(struct lf_worker_context *worker_context, struct rte_mbuf *m)
{
	static enum lf_pkt_action pkt_action;
	unsigned int offset;
	struct rte_ether_hdr *ether_hdr;
	struct rte_ipv4_hdr *ipv4_hdr;

	const enum lf_forwarding_direction forwarding_direction =
			worker_context->forwarding_direction;

	if (unlikely(m->data_len != m->pkt_len)) {
		LF_WORKER_LOG(NOTICE,
				"Not yet implemented: buffer with multiple segments "
				"received.\n");
		return LF_PKT_UNKNOWN_DROP;
	}

	offset = 0;
	offset = lf_get_eth_hdr(worker_context, m, offset, &ether_hdr);
	if (offset == 0) {
		return LF_PKT_UNKNOWN_DROP;
	}

	if (unlikely(ether_hdr->ether_type !=
				 rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))) {
		LF_WORKER_LOG(NOTICE, "Unsupported packet type: must be IPv4.\n");
		return LF_PKT_UNKNOWN_DROP;
	}

	offset = lf_get_ip_hdr(worker_context, m, offset, &ipv4_hdr);
	if (offset == 0) {
		return LF_PKT_UNKNOWN_DROP;
	}

	if (forwarding_direction == LF_FORWARDING_DIRECTION_INBOUND) {
		LF_WORKER_LOG(DEBUG, "Inbound packet\n");
		pkt_action = LF_PKT_INBOUND_FORWARD;

		(void)lf_worker_pkt_mod(worker_context, m, ether_hdr, ipv4_hdr,
				lf_configmanager_worker_get_inbound_pkt_mod(
						worker_context->config));
	} else if (forwarding_direction == LF_FORWARDING_DIRECTION_OUTBOUND) {
		LF_WORKER_LOG(DEBUG, "Outbound packet\n");
		pkt_action = LF_PKT_OUTBOUND_FORWARD;

		(void)lf_worker_pkt_mod(worker_context, m, ether_hdr, ipv4_hdr,
				lf_configmanager_worker_get_outbound_pkt_mod(
						worker_context->config));

	} else {
		/* Consider the packet as inbound if the direction is unknown */
		pkt_action = LF_PKT_INBOUND_FORWARD;

		(void)lf_worker_pkt_mod(worker_context, m, ether_hdr, ipv4_hdr,
				lf_configmanager_worker_get_inbound_pkt_mod(
						worker_context->config));
	}

	return pkt_action;
}

void
lf_worker_handle_pkt(struct lf_worker_context *worker_context,
		struct rte_mbuf **pkt_burst, uint16_t nb_pkts,
		enum lf_pkt_action *pkt_res)
{
	int i;

	/* Prefetch first packets */
	for (i = 0; i < LF_WORKER_PREFETCH_OFFSET && i < nb_pkts; i++) {
		rte_prefetch0(rte_pktmbuf_mtod(pkt_burst[i], void *));
	}

	/* Prefetch and forward already prefetched packets */
	for (i = 0; i < (nb_pkts - LF_WORKER_PREFETCH_OFFSET); i++) {
		rte_prefetch0(rte_pktmbuf_mtod(pkt_burst[i + LF_WORKER_PREFETCH_OFFSET],
				void *));
		pkt_res[i] = handle_pkt(worker_context, pkt_burst[i]);
	}

	/* Forward remaining prefetched packets */
	for (; i < nb_pkts; i++) {
		pkt_res[i] = handle_pkt(worker_context, pkt_burst[i]);
	}
}