/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#include <stdatomic.h>

#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_rcu_qsbr.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include "config.h"
#include "duplicate_filter.h"
#include "lf.h"
#include "lib/log/log.h"
#include "lib/mirror/mirror.h"
#include "lib/utils/packet.h"
#include "plugins/plugins.h"
#include "ratelimiter.h"
#include "statistics.h"
#include "worker.h"

/**
 * This file contains the main processing loop of the worker and handles the
 * receving and transmitting of packets. Furthermore, it contains the
 * implementation of the mirror filter, which is used to forward local network
 * control plane packets to the port's mirror.
 *
 * This file is missing the packet parsing, the processing pipeline for incoming
 * and outoing LF packets. These functionalities are provided either by
 * worker_checks.c and worker_scion.c/worker_ip.c.
 */

#ifndef LF_OFFLOAD_CKSUM
#define LF_OFFLOAD_CKSUM 0
#endif

int
lf_worker_init(bool worker_lcores[RTE_MAX_LCORE],
		struct lf_worker_context worker_contexts[RTE_MAX_LCORE])
{
	uint16_t lcore_id;
	RTE_LCORE_FOREACH(lcore_id) {
		if (!worker_lcores[lcore_id]) {
			continue;
		}
		memset(&worker_contexts[lcore_id], 0, sizeof(struct lf_worker_context));
		worker_contexts[lcore_id].lcore_id = lcore_id;
	}

	return 0;
}

void
lf_worker_pkt_mod(struct rte_mbuf *m, struct rte_ether_hdr *ether_hdr,
		void *l3_hdr, const struct lf_config_pkt_mod *pkt_mod)
{
	uint8_t tmp[RTE_ETHER_ADDR_LEN];

	if (ether_hdr != NULL && pkt_mod->ether_switch) {
		/* switch destination and source Ethernet address */
		(void)rte_memcpy(&tmp, &(ether_hdr->dst_addr), RTE_ETHER_ADDR_LEN);
		(void)rte_memcpy(&(ether_hdr->dst_addr), &(ether_hdr->src_addr),
				RTE_ETHER_ADDR_LEN);
	} else if (ether_hdr != NULL && pkt_mod->ether_option) {
		/* set destination Ethernet address*/
		(void)rte_memcpy(&(ether_hdr->dst_addr), pkt_mod->ether,
				RTE_ETHER_ADDR_LEN);
	}

#if LF_IPV6
	struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)l3_hdr;
	if (ipv6_hdr != NULL && pkt_mod->ip_option) {
		memcpy(ipv6_hdr->dst_addr, pkt_mod->ipv6, sizeof(pkt_mod->ipv6));
	}
	if (ipv6_hdr != NULL) {
		(void)lf_pktv6_set_cksum(m, ether_hdr, ipv6_hdr, LF_OFFLOAD_CKSUM);
	}
#else
	struct rte_ipv4_hdr *ipv4_hdr = (struct rte_ipv4_hdr *)l3_hdr;
	if (ipv4_hdr != NULL && pkt_mod->ip_option) {
		ipv4_hdr->dst_addr = pkt_mod->ip;
	}
	if (ipv4_hdr != NULL) {
		(void)lf_pkt_set_cksum(m, ether_hdr, ipv4_hdr, LF_OFFLOAD_CKSUM);
	}
#endif /* LF_IPV6 */
}

static void
update_pkt_statistics(struct lf_statistics_worker *stats, struct rte_mbuf *pkt,
		enum lf_pkt_action pkt_action)
{
	lf_statistics_worker_counter_add(stats, rx_bytes, pkt->pkt_len);
	lf_statistics_worker_counter_add(stats, rx_pkts, 1);

	switch (pkt_action) {
	case LF_PKT_UNKNOWN_DROP:
		lf_statistics_worker_counter_inc(stats, unknown_drop);
		break;
	case LF_PKT_UNKNOWN_FORWARD:
		lf_statistics_worker_counter_inc(stats, unknown_forward);
		break;
	case LF_PKT_OUTBOUND_DROP:
		lf_statistics_worker_counter_inc(stats, outbound_drop);
		break;
	case LF_PKT_OUTBOUND_FORWARD:
		lf_statistics_worker_counter_inc(stats, outbound_forward);
		break;
	case LF_PKT_INBOUND_DROP:
		lf_statistics_worker_counter_inc(stats, inbound_drop);
		break;
	case LF_PKT_INBOUND_FORWARD:
		lf_statistics_worker_counter_inc(stats, inbound_forward);
		break;
	default:
		break;
	}
}

static void
set_pkt_action(struct rte_mbuf *pkt, enum lf_pkt_action pkt_action)
{
	switch (pkt_action) {
	case LF_PKT_UNKNOWN_DROP:
	case LF_PKT_INBOUND_DROP:
	case LF_PKT_OUTBOUND_DROP:
		*lf_pkt_action(pkt) = LF_PKT_ACTION_DROP;
		break;
	case LF_PKT_UNKNOWN_FORWARD:
	case LF_PKT_OUTBOUND_FORWARD:
	case LF_PKT_INBOUND_FORWARD:
		*lf_pkt_action(pkt) = LF_PKT_ACTION_FORWARD;
		break;
	default:
		*lf_pkt_action(pkt) = LF_PKT_ACTION_DROP;
		LF_WORKER_LOG_DP(ERR, "Unknown packet action (%u)\n", pkt_action);
		break;
	}
}

/**
 * Filters a list of packets, forwarding local network control plane packets to
 * the port's mirror and adding non-control plane packets to the filtered
 * packets list.
 *
 * @param worker The worker context.
 * @param port_id The ID of the port from which the packets came.
 * @param nb_pkts The number of packets in the `pkts` array.
 * @param pkts The array of packets to filter.
 * @param filtered_pkts The array of packets that are not forwarded to the
 * mirror.
 *
 * @return The number of packets added to `filtered_pkts`.
 */
inline static int
mirror_filter(struct lf_worker_context *worker, uint16_t port_id,
		uint16_t nb_pkts, struct rte_mbuf *pkts[LF_MAX_PKT_BURST],
		struct rte_mbuf *filtered_pkts[LF_MAX_PKT_BURST])
{
	bool forward_to_mirror;
	int i, nb_filtered_pkts, nb_mirrored_pkts, nb_fwd;
	unsigned int offset;
	struct rte_mbuf *m;
	struct rte_mbuf *mirrored_pkts[LF_MAX_PKT_BURST];
	struct rte_ether_hdr *ether_hdr;
	struct rte_ipv6_hdr *ipv6_hdr;

	nb_filtered_pkts = 0;
	nb_mirrored_pkts = 0;
	for (i = 0; i < nb_pkts; i++) {
		offset = 0;
		m = pkts[i];
		forward_to_mirror = false;

		if (m == NULL) {
			LF_WORKER_LOG_DP(ERR, "Packet is NULL\n");
			continue;
		}

		offset = lf_get_eth_hdr(m, offset, &ether_hdr);
		if (unlikely(offset == 0)) {
			goto next;
		}

		forward_to_mirror = (ether_hdr->ether_type ==
									rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) |
		                    (ether_hdr->ether_type ==
									rte_cpu_to_be_16(RTE_ETHER_TYPE_LLDP));

		if (ether_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6)) {
			offset = lf_get_ipv6_hdr(m, offset, &ipv6_hdr);
			if (unlikely(offset == 0)) {
				goto next;
			}
			forward_to_mirror =
					forward_to_mirror | (ipv6_hdr->proto == IP_PROTO_ID_ICMP6);
		}

	next:
		if (forward_to_mirror) {
			mirrored_pkts[nb_mirrored_pkts] = m;
			nb_mirrored_pkts++;
		} else {
			filtered_pkts[nb_filtered_pkts] = m;
			nb_filtered_pkts++;
		}
	}

	if (nb_mirrored_pkts > 0) {
		LF_WORKER_LOG_DP(DEBUG,
				"%u packets to be forwarded to mirror (port %u)\n",
				nb_mirrored_pkts, port_id);
	}

	nb_fwd = lf_mirror_worker_tx(worker->mirror_ctx, port_id, mirrored_pkts,
			nb_mirrored_pkts);
	if (nb_fwd < nb_mirrored_pkts) {
		rte_pktmbuf_free_bulk(mirrored_pkts, nb_mirrored_pkts - nb_fwd);
		LF_WORKER_LOG_DP(DEBUG,
				"%u packets dropped instead forwarded to mirror (port %u)\n",
				nb_mirrored_pkts - nb_fwd, port_id);
	}
	return nb_filtered_pkts;
}

inline static int
lf_worker_rx(struct lf_worker_context *worker,
		struct rte_mbuf *pkts[LF_MAX_PKT_BURST])
{
	uint16_t rx_port_id, rx_queue_id;
	uint16_t nb_rx, nb_fwd, nb_pkts;
	struct rte_mbuf *rx_pkts[LF_MAX_PKT_BURST];
	struct rte_mbuf *rx_mirror_pkts[LF_MAX_PKT_BURST];

	/* Increase current rx/tx iteration index and reset it at max */
	worker->current_rx_tx_index++;
	if (worker->current_rx_tx_index >= worker->max_rx_tx_index) {
		worker->current_rx_tx_index = 0;
	}

	// Port (and queue) to fetch packets from in this iteration.
	rx_port_id = worker->rx_port_id[worker->current_rx_tx_index];
	rx_queue_id = worker->rx_queue_id[worker->current_rx_tx_index];

	/* Forward packets from the mirror to its port. */
	if (lf_mirror_exists(worker->mirror_ctx->ctx, rx_port_id)) {
		nb_rx = lf_mirror_worker_rx(worker->mirror_ctx, rx_port_id,
				rx_mirror_pkts, LF_MAX_PKT_BURST);
		if (nb_rx > 0) {
			LF_WORKER_LOG_DP(DEBUG,
					"%u packets received from mirror (port %u)\n", nb_rx,
					rx_port_id);
		}
		nb_fwd = rte_eth_tx_burst(rx_port_id,
				worker->tx_queue_id_by_port[rx_port_id], rx_mirror_pkts, nb_rx);
		if (nb_fwd < nb_rx) {
			rte_pktmbuf_free_bulk(rx_mirror_pkts, nb_rx - nb_fwd);
			LF_WORKER_LOG_DP(DEBUG,
					"%u packets dropped instead forwarded to mirror "
					"(port %u)\n",
					nb_rx - nb_fwd, rx_port_id);
		}
	}

	/* Receive packets from the port. */
	nb_rx = rte_eth_rx_burst(rx_port_id, rx_queue_id, rx_pkts,
			LF_MAX_PKT_BURST);
	if (nb_rx > 0) {
		LF_WORKER_LOG_DP(DEBUG, "%u packets received (port %u, queue %u)\n",
				nb_rx, rx_port_id, rx_queue_id);
		(void)lf_statistics_worker_add_burst(worker->statistics, nb_rx);
	}

	/* Apply mirror filter only if mirror exists for the port. */
	if (lf_mirror_exists(worker->mirror_ctx->ctx, rx_port_id)) {
		nb_pkts = mirror_filter(worker, rx_port_id, nb_rx, rx_pkts, pkts);
	} else {
		nb_pkts = nb_rx;
		for (int i = 0; i < nb_rx; i++) {
			pkts[i] = rx_pkts[i];
		}
	}

	if (nb_pkts > 0) {
		LF_WORKER_LOG_DP(DEBUG,
				"%u packets to be processed (port %u, queue %u)\n", nb_pkts,
				rx_port_id, rx_queue_id);
	}

	return nb_pkts;
}

inline static int
lf_worker_tx(struct lf_worker_context *worker,
		struct rte_mbuf *pkts[LF_MAX_PKT_BURST], int nb_pkts)
{
	int i;
	struct rte_ether_hdr *ether_hdr;
	uint16_t tx_port;
	uint16_t nb_fwd = 0;
	uint16_t nb_drop = 0;
	uint16_t nb_sent = 0;

	/* Add forwarding packets to the transmit buffers. All other packets are
	 * dropped. */
	for (i = 0; i < nb_pkts; ++i) {
		if (*lf_pkt_action(pkts[i]) == LF_PKT_ACTION_FORWARD) {
			nb_fwd++;
			tx_port = worker->port_pair[pkts[i]->port];
			ether_hdr =
					rte_pktmbuf_mtod_offset(pkts[i], struct rte_ether_hdr *, 0);
			(void)rte_eth_macaddr_get(tx_port, &ether_hdr->src_addr);

			rte_eth_tx_buffer(tx_port, worker->tx_queue_id_by_port[tx_port],
					worker->tx_buffer_by_port[tx_port], pkts[i]);
		} else {
			nb_drop++;
			rte_pktmbuf_free(pkts[i]);
		}
	}

	/* TODO: add statistics for dropped and forwarded pkts/bytes */
	if ((nb_fwd > 0) | (nb_drop > 0)) {
		LF_WORKER_LOG_DP(DEBUG, "%u packets forwarded. \n", nb_fwd);
		LF_WORKER_LOG_DP(DEBUG, "%u packets dropped\n", nb_drop);
	}

	/* flush all tx buffers */
	for (i = 0; i < worker->max_rx_tx_index; i++) {
		nb_sent = rte_eth_tx_buffer_flush(worker->tx_port_id[i],
				worker->tx_queue_id[i], worker->tx_buffer[i]);
		LF_WORKER_LOG_DP(DEBUG, "%u packets sent (port %u, queue %u)\n",
				nb_sent, worker->tx_port_id[i], worker->tx_queue_id[i]);
	}

	return nb_fwd;
}

/* main processing loop */
static void
lf_worker_main_loop(struct lf_worker_context *worker_context)
{
	unsigned int i;
	uint16_t nb_rx;

	/* packet buffers */
	struct rte_mbuf *rx_pkts[LF_MAX_PKT_BURST];
	enum lf_pkt_action pkt_res[LF_MAX_PKT_BURST];

	/* worker constants */
	struct rte_rcu_qsbr *qsv = worker_context->qsv;
	struct lf_time_worker *time = &worker_context->time;
	struct lf_statistics_worker *stats = worker_context->statistics;

	LF_WORKER_LOG_DP(INFO, "enter main loop\n");
	while (likely(!lf_force_quit)) {
		/*
		 * Update Quiescent State
		 * This indicates that the worker does not reference memory shared with
		 * services, such as the key manager or ratelimiter, at this moment.
		 */
		(void)rte_rcu_qsbr_quiescent(qsv, worker_context->qsv_id);

		/*
		 * Update current time
		 * A worker keeps its own nanosecond timestamp, caches it and regularly
		 * updates it.
		 */
		(void)lf_time_worker_update(time);
		nb_rx = lf_worker_rx(worker_context, rx_pkts);

		if (unlikely(nb_rx <= 0)) {
			continue;
		}

		(void)lf_statistics_worker_add_burst(stats, nb_rx);

		for (i = 0; i < nb_rx; ++i) {
			pkt_res[i] = LF_PKT_UNKNOWN;
			pkt_res[i] = lf_plugins_pre(worker_context, rx_pkts[i], pkt_res[i]);
		}

		lf_worker_handle_pkt(worker_context, rx_pkts, nb_rx, pkt_res);

		for (i = 0; i < nb_rx; ++i) {
			pkt_res[i] =
					lf_plugins_post(worker_context, rx_pkts[i], pkt_res[i]);
		}

		for (i = 0; i < nb_rx; ++i) {
			update_pkt_statistics(stats, rx_pkts[i], pkt_res[i]);
			set_pkt_action(rx_pkts[i], pkt_res[i]);
		}

		lf_worker_tx(worker_context, rx_pkts, nb_rx);
	}
}

int
lf_worker_run(struct lf_worker_context *worker_context)
{
	int res;
	LF_WORKER_LOG_DP(DEBUG, "run\n");

	/* register and start reporting quiescent state */
	res = rte_rcu_qsbr_thread_register(worker_context->qsv,
			worker_context->qsv_id);
	if (res != 0) {
		LF_WORKER_LOG_DP(ERR,
				"Register for QS Variable failed. gsv: %p, qsv_id: %u\n",
				worker_context->qsv, worker_context->qsv_id);
		return -1;
	}
	(void)rte_rcu_qsbr_thread_online(worker_context->qsv,
			worker_context->qsv_id);

	(void)lf_worker_main_loop(worker_context);

	/* stop reporting quiescent state and unregister */
	(void)rte_rcu_qsbr_thread_offline(worker_context->qsv,
			worker_context->qsv_id);
	(void)rte_rcu_qsbr_thread_unregister(worker_context->qsv,
			worker_context->qsv_id);

	LF_WORKER_LOG_DP(DEBUG, "terminate\n");
	return 0;
}
