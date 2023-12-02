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

static enum lf_pkt_action
handle_pkt(struct lf_worker_context *worker_context, struct rte_mbuf *m)
{
	static enum lf_pkt_action pkt_action;
	unsigned int offset;
	struct rte_ether_hdr *ether_hdr;
	struct rte_ipv4_hdr *ipv4_hdr;

	if (unlikely(m->data_len != m->pkt_len)) {
		LF_WORKER_LOG_DP(NOTICE,
				"Not yet implemented: buffer with multiple segments "
				"received.\n");
		return LF_PKT_UNKNOWN_DROP;
	}

	offset = 0;
	offset = lf_get_eth_hdr(m, offset, &ether_hdr);
	if (offset == 0) {
		return LF_PKT_UNKNOWN_DROP;
	}

	if (unlikely(ether_hdr->ether_type !=
				 rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))) {
		LF_WORKER_LOG_DP(NOTICE, "Unsupported packet type: must be IPv4.\n");
		return LF_PKT_UNKNOWN_DROP;
	}

	offset = lf_get_ip_hdr(m, offset, &ipv4_hdr);
	if (offset == 0) {
		return LF_PKT_UNKNOWN_DROP;
	}

	/* Consider the packet as inbound */
	pkt_action = LF_PKT_INBOUND_FORWARD;

	(void)lf_worker_pkt_mod(m, ether_hdr, ipv4_hdr,
			lf_configmanager_worker_get_inbound_pkt_mod(
					worker_context->config));

	return pkt_action;
}

void
lf_worker_handle_pkt(struct lf_worker_context *worker_context,
		struct rte_mbuf **pkt_burst, uint16_t nb_pkts,
		enum lf_pkt_action *pkt_res)
{
	int i;

	for (i = 0; i < nb_pkts; i++) {
		if (pkt_res[i] != LF_PKT_UNKNOWN) {
			/* If packet action is already determined, do not process it */
			continue;
		}

		pkt_res[i] = handle_pkt(worker_context, pkt_burst[i]);
	}
}
