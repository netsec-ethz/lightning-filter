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
#include "lib/utils/packet.h"
#include "plugins/plugins.h"
#include "ratelimiter.h"
#include "statistics.h"
#include "worker.h"

/**
 * This file contains basic functionalities that all different kind of workers
 * require. This includes the receiving and transmitting of packets, the
 * processing pipeline for inbound packets, and the packet modifications for
 * forwarded packets.
 *
 * This file is missing the packet parsing, the packet hash calculation, and the
 * processing pipeline for outbound packets. These functionalities are provided
 * either by worker_scion.c, by worker_ip.c, or by a custom worker
 * implementation.
 */

#ifndef LF_OFFLOAD_CKSUM
#define LF_OFFLOAD_CKSUM 0
#endif

/**
 * Initialize an array of worker contexts.
 *
 * @param nb_workers Size of array, i.e., number of workers.
 * @param worker_lcores Array containing the assigned lcore for each worker.
 * @param worker_contexts Returns the initialized worker contexts.
 * @return Returns 0 on success.
 */
int
lf_worker_init(uint16_t nb_workers, uint16_t *worker_lcores,
		struct lf_worker_context *worker_contexts)
{
	uint16_t worker_id;
	for (worker_id = 0; worker_id < nb_workers; ++worker_id) {
		memset(&worker_contexts[worker_id], 0,
				sizeof(struct lf_worker_context));
		worker_contexts[worker_id].worker_id = worker_id;
		worker_contexts[worker_id].lcore_id = worker_lcores[worker_id];

		worker_contexts[worker_id].forwarding_direction =
				LF_FORWARDING_DIRECTION_BOTH;
		worker_contexts[worker_id].timestamp_threshold = 0;
	}

	return 0;
}

void
lf_worker_pkt_mod(const struct lf_worker_context *worker_context,
		struct rte_mbuf *m, struct rte_ether_hdr *ether_hdr, void *l3_hdr,
		const struct lf_config_pkt_mod *pkt_mod)
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
		(void)lf_pktv6_set_cksum(worker_context, m, ether_hdr, ipv6_hdr,
				LF_OFFLOAD_CKSUM);
	}
#else
	struct rte_ipv4_hdr *ipv4_hdr = (struct rte_ipv4_hdr *)l3_hdr;
	if (ipv4_hdr != NULL && pkt_mod->ip_option) {
		ipv4_hdr->dst_addr = pkt_mod->ip;
	}
	if (ipv4_hdr != NULL) {
		(void)lf_pkt_set_cksum(worker_context, m, ether_hdr, ipv4_hdr,
				LF_OFFLOAD_CKSUM);
	}
#endif /* LF_IPV6 */

	(void)worker_context;
}

/**
 * Check if the packet is within the rate limit (without consuming tokens).
 * If this check is disable, the check is not performed and the function just
 * returns 0.
 *
 * @param rl_pkt_ctx Returns the rate limiter context for this specific packet.
 * @return Returns 0 if withing the rate limit. Otherwise, returns > 0 if AS
 * rate limiter, or < 0 if overall rate limited.
 */
static inline int
lf_worker_check_ratelimit(struct lf_worker_context *worker_context,
		uint64_t src_as, uint16_t drkey_protocol, uint32_t pkt_len,
		uint64_t ns_now, struct lf_ratelimiter_pkt_ctx *rl_pkt_ctx)
{
#if LF_WORKER_OMIT_RATELIMIT_CHECK
	return 0;
#endif
	int res;

	/* get packet rate limit context */
	res = lf_ratelimiter_worker_get_pkt_ctx(&worker_context->ratelimiter,
			src_as, drkey_protocol, rl_pkt_ctx);
	if (res != 0) {
		LF_WORKER_LOG(DEBUG,
				"Failed to get packet rate limit context for " PRIISDAS
				" and DRKey protocol %u (res = %d).\n",
				PRIISDAS_VAL(rte_be_to_cpu_64(src_as)),
				rte_be_to_cpu_16(drkey_protocol), res);
		lf_statistics_worker_counter_inc(worker_context->statistics, error);
		return 1;
	}

	res = lf_ratelimiter_worker_check(rl_pkt_ctx, pkt_len, ns_now);
	if (likely(res != 0)) {
		LF_WORKER_LOG(DEBUG,
				"Rate limit filter check failed for " PRIISDAS
				" and DRKey protocol %u (res = %d).\n",
				PRIISDAS_VAL(rte_be_to_cpu_64(src_as)),
				rte_be_to_cpu_16(drkey_protocol), res);

		if (res & (LF_RATELIMITER_RES_BYTES | LF_RATELIMITER_RES_PKTS)) {
			lf_statistics_worker_counter_inc(worker_context->statistics,
					ratelimit_as);
		}
		if (res & (LF_RATELIMITER_RES_BYTES | LF_RATELIMITER_RES_PKTS)) {
			lf_statistics_worker_counter_inc(worker_context->statistics,
					ratelimit_system);
		}
	} else {
		LF_WORKER_LOG(DEBUG, "Rate limit check pass (res=%d).\n", res);
	}

	return res;
}

/**
 * Add the packet to the rate and update the rate limiter state (consume
 * tokens). If the rate limiter check is disable, this function does not do
 * anything.
 *
 * @param rl_pkt_ctx The rate limiter context for this specific packet.
 */
static inline void
lf_worker_consume_ratelimit(struct lf_worker_context *worker_context,
		uint32_t pkt_len, struct lf_ratelimiter_pkt_ctx *rl_pkt_ctx)
{
#if LF_WORKER_OMIT_RATELIMIT_CHECK
	return 0;
#endif
	(void)worker_context;
	lf_ratelimiter_worker_consume(rl_pkt_ctx, pkt_len);
}

/**
 * Check if a valid DRKey is available and get it.
 * If this check is disable, the check is not performed and the function just
 * returns 0.
 *
 * @param drkey: Returns a DRKey if it is valid.
 * @return Returns 0 if a valid DRKey is available.
 */
static inline int
lf_worker_get_drkey(struct lf_worker_context *worker_context, uint64_t src_as,
		const struct lf_host_addr *src_addr,
		const struct lf_host_addr *dst_addr, uint16_t drkey_protocol,
		uint64_t timestamp, bool grace_period, struct lf_crypto_drkey *drkey)
{
#if LF_WORKER_OMIT_KEY_GET
	for (int i = 0; i < LF_CRYPTO_DRKEY_SIZE; i++) {
		drkey->key[i] = 0;
	}
	return 0;
#endif

	int res;
	res = lf_keymanager_worker_inbound_get_drkey(worker_context->key_manager,
			src_as, src_addr, dst_addr, drkey_protocol, timestamp, grace_period,
			drkey);
	if (unlikely(res < 0)) {
		LF_WORKER_LOG(INFO,
				"Inbound DRKey not found for AS " PRIISDAS
				" and drkey_protocol %d (timestamp = %" PRIu64
				", grace_period = %d, res = %d)\n",
				PRIISDAS_VAL(rte_be_to_cpu_64(src_as)),
				rte_be_to_cpu_16(drkey_protocol), timestamp, grace_period, res);
		lf_statistics_worker_counter_inc(worker_context->statistics, no_key);
	} else {
		LF_WORKER_LOG(DEBUG,
				"DRKey [XX]: " PRIIP ",[" PRIISDAS "]:" PRIIP
				" and drkey_protocol %d (timestamp = %" PRIu64
				", grace_period = %d) is %x\n",
				PRIIP_VAL(*(uint32_t *)dst_addr->addr),
				PRIISDAS_VAL(rte_be_to_cpu_64(src_as)),
				PRIIP_VAL(*(uint32_t *)src_addr->addr),
				rte_be_to_cpu_16(drkey_protocol), timestamp, grace_period,
				drkey->key[0]);
	}

	return res;
}

/**
 * Perform MAC check.
 * If this check is disable, the check is not performed and the function just
 * returns 0.
 * If this check is ignored, the check is performed but the function
 * always return 0.
 *
 * @param drkey DRKey corresponding to peer identified in packet.
 * @param mac The packet's MAC.
 * @param auth_data Data supposed to be authenticated with the MAC.
 * @return Returns 0 if the MAC is valid.
 */
static inline int
lf_worker_check_mac(struct lf_worker_context *worker_context,
		const struct lf_crypto_drkey *drkey, const uint8_t *mac,
		const uint8_t *auth_data)
{
#if LF_WORKER_OMIT_MAC_CHECK
	return 0;
#endif

	int res;

	res = lf_crypto_drkey_check_mac(&worker_context->crypto_drkey_ctx, drkey,
			auth_data, mac);
	if (likely(res != 0)) {
		LF_WORKER_LOG(DEBUG, "MAC check failed.\n");
		lf_statistics_worker_counter_inc(worker_context->statistics,
				invalid_mac);
	} else {
		LF_WORKER_LOG(DEBUG, "MAC check passed.\n");
	}

#if LF_WORKER_IGNORE_MAC_CHECK
	res = 0;
#endif

	return res;
}

/**
 * Perform timestamp check, i.e., check if the given timestamp is within
 * (ns_now - timestamp_threshold, ns_now + timestamp_threshold). If this check
 * is disable, the check is not performed and the function just returns 0. If
 * this check is ignored, the check is performed but the function always return
 * 0.
 *
 * @param timestamp Packet timestamp (nanoseconds).
 * @param ns_now Current timestamp (nanoseconds).
 * @return Returns 0 if the packet timestamp is within the timestamp threshold.
 */
static inline int
lf_worker_check_timestamp(struct lf_worker_context *worker_context,
		uint64_t timestamp, uint64_t ns_now)
{
#if LF_WORKER_OMIT_TIMESTAMP_CHECK
	return 0;
#endif

	int res;

	res = timestamp < (ns_now - worker_context->timestamp_threshold) ||
	      timestamp > (ns_now + worker_context->timestamp_threshold);

	if (unlikely(res)) {
		LF_WORKER_LOG(DEBUG, "Timestamp check failed.\n");
		lf_statistics_worker_counter_inc(worker_context->statistics,
				outdated_timestamp);
	} else {
		LF_WORKER_LOG(DEBUG, "Timestamp check passed.\n");
	}

#if LF_WORKER_IGNORE_TIMESTAMP_CHECK
	res = 0;
#endif

	return res;
}

/**
 * Perform duplicate check.
 * If this check is disable, the check is not performed and the function just
 * returns 0.
 * If this check is ignored, the check is performed but the function
 * always return 0.
 *
 * @param mac Packet MAC used to identify packet.
 * @param ns_now Current timestamp.
 * @return Returns 0 if the packet is not a duplicate.
 */
static inline int
lf_worker_check_duplicate(struct lf_worker_context *worker_context,
		const uint8_t *mac, uint64_t ns_now)
{
#if LF_WORKER_OMIT_DUPLICATE_CHECK
	return 0;
#endif

	int res;

	res = lf_duplicate_filter_apply(worker_context->duplicate_filter, mac,
			ns_now);
	if (likely(res != 0)) {
		LF_WORKER_LOG(DEBUG, "Duplicate check failed.\n");
		lf_statistics_worker_counter_inc(worker_context->statistics, duplicate);
	} else {
		LF_WORKER_LOG(DEBUG, "Duplicate check passed.\n");
	}

#if LF_WORKER_IGNORE_DUPLICATE_CHECK
	res = 0;
#endif

	return res;
}

enum lf_check_state
lf_worker_check_pkt(struct lf_worker_context *worker_context,
		const struct lf_pkt_data *pkt_data)
{
	int res = 0;
	uint64_t ns_now;
	struct lf_crypto_drkey drkey;
	struct lf_ratelimiter_pkt_ctx rl_pkt_ctx;

	/*
	 * Obtain Current time (in ms)
	 * Almost all modules require the current time, hence, it is obtained here
	 * and reused for all modules.
	 */
	res = lf_time_worker_get(&worker_context->time, &ns_now);
	if (unlikely(res != 0)) {
		lf_statistics_worker_counter_inc(worker_context->statistics, error);
		return LF_CHECK_ERROR;
	}

	/*
	 * Rate Limit Check
	 * First check if the rate limit would allow this packet such that
	 * unecessary MAC and duplicate checks can be avoided.
	 */
	res = lf_worker_check_ratelimit(worker_context, pkt_data->src_as,
			pkt_data->drkey_protocol, pkt_data->pkt_len, ns_now, &rl_pkt_ctx);
	if (unlikely(res > 0)) {
		return LF_CHECK_AS_RATELIMITED;
	} else if (unlikely(res < 0)) {
		return LF_CHECK_SYSTEM_RATELIMITED;
	}

	/*
	 * MAC Check
	 */
	res = lf_worker_get_drkey(worker_context, pkt_data->src_as,
			&pkt_data->src_addr, &pkt_data->dst_addr, pkt_data->drkey_protocol,
			pkt_data->timestamp, pkt_data->grace_period, &drkey);
	if (unlikely(res != 0)) {
		return LF_CHECK_NO_KEY;
	}
	res = lf_worker_check_mac(worker_context, &drkey, pkt_data->mac,
			pkt_data->auth_data);
	if (unlikely(res != 0)) {
		return LF_CHECK_INVALID_MAC;
	}

	/*
	 * Timestamp Check
	 */
	res = lf_worker_check_timestamp(worker_context, pkt_data->timestamp,
			ns_now);
	if (likely(res != 0)) {
		return LF_CHECK_OUTDATED_TIMESTAMP;
	}

	/*
	 * Duplicate Check and Update
	 * Check that the packet is not a duplicate and update the bloom filter
	 * structure.
	 */
	res = lf_worker_check_duplicate(worker_context, pkt_data->mac, ns_now);
	if (likely(res != 0)) {
		return LF_CHECK_DUPLICATE;
	}

	/*
	 * Rate Limit Update
	 * Consider the packet to be forwarded and update the rate limiter state.
	 */
	lf_worker_consume_ratelimit(worker_context, pkt_data->pkt_len, &rl_pkt_ctx);

	/*
	 * The Packet has passed all checks and can be considered valid.
	 */
	lf_statistics_worker_counter_inc(worker_context->statistics, valid);
	return LF_CHECK_VALID;
}

enum lf_check_state
lf_worker_check_best_effort_pkt(struct lf_worker_context *worker_context,
		const uint32_t pkt_len)
{
	int res;
	uint64_t ns_now;

	/* get current time (in ms) */
	res = lf_time_worker_get(&worker_context->time, &ns_now);
	if (unlikely(res != 0)) {
		lf_statistics_worker_counter_inc(worker_context->statistics, error);
		return LF_CHECK_ERROR;
	}

#if !LF_WORKER_OMIT_RATELIMIT_CHECK
	res = lf_ratelimiter_worker_apply_best_effort(&worker_context->ratelimiter,
			pkt_len, ns_now);
	if (likely(res > 0)) {
		LF_WORKER_LOG(DEBUG,
				"Best-effort rate limit filter check failed (res=%d).\n", res);
		lf_statistics_worker_counter_inc(worker_context->statistics,
				ratelimit_be);
		return LF_CHECK_BE_RATELIMITED;
	} else if (res < 0) {
		LF_WORKER_LOG(DEBUG,
				"System rate limit filter check failed (res=%d).\n", res);
		lf_statistics_worker_counter_inc(worker_context->statistics,
				ratelimit_system);
		return LF_CHECK_SYSTEM_RATELIMITED;
	}
#endif /* !LF_WORKER_OMIT_RATELIMIT_CHECK */
	return LF_CHECK_BE;
}

static inline uint16_t
receive_pkts(const struct lf_worker_context *worker_context,
		struct rte_mbuf *rx_pkts[LF_MAX_PKT_BURST])
{
#if LF_DISTRIBUTOR
	return rte_ring_dequeue_burst(worker_context->queues.rx_ring,
			(void **)rx_pkts, LF_MAX_PKT_BURST, NULL);
#else
	return rte_eth_rx_burst(worker_context->queues.rx_port_id,
			worker_context->queues.rx_queue_id, rx_pkts, LF_MAX_PKT_BURST);
#endif
}

static void
update_pkt_action_statistics(struct lf_statistics_worker *stats,
		enum lf_pkt_action pkt_action)
{
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

/* main processing loop */
static void
lf_worker_main_loop(struct lf_worker_context *worker_context)
{
	unsigned int i;
	uint16_t nb_rx, nb_tx, nb_fwd, nb_drop;

	/* packet buffers */
	struct rte_mbuf *rx_pkts[LF_MAX_PKT_BURST];
	enum lf_pkt_action pkt_res[LF_MAX_PKT_BURST];

	/* worker constants */
	const uint16_t worker_id = worker_context->worker_id;
	struct rte_rcu_qsbr *qsv = worker_context->qsv;
	struct lf_time_worker *time = &worker_context->time;
	struct lf_statistics_worker *stats = worker_context->statistics;

	LF_WORKER_LOG(INFO, "enter main loop\n");
	while (likely(!lf_force_quit)) {
		/*
		 * Update Quiescent State
		 * This indicates that the worker does not reference memory shared with
		 * services, such as the key manager or ratelimiter, at this moment.
		 */
		(void)rte_rcu_qsbr_quiescent(qsv, worker_id);

		/*
		 * Update current time
		 * A worker keeps its own nanosecond timestamp, caches it and regularly
		 * updates it.
		 */
#if !LF_WORKER_OMIT_TIME_UPDATE
		(void)lf_time_worker_update(time);
#else
		(void)time;
#endif /* !LF_WORKER_OMIT_TIMES_UPDATE */

		nb_rx = receive_pkts(worker_context, rx_pkts);

		if (unlikely(nb_rx <= 0)) {
			continue;
		}

		LF_WORKER_LOG(DEBUG, "%u packets received\n", nb_rx);
		(void)lf_statistics_worker_add_burst(stats, nb_rx);

		for (i = 0; i < nb_rx; ++i) {
			pkt_res[i] = lf_plugins_pre(worker_context, rx_pkts[i], pkt_res[i]);
		}

		lf_worker_handle_pkt(worker_context, rx_pkts, nb_rx, pkt_res);


		for (i = 0; i < nb_rx; ++i) {
			lf_statistics_worker_counter_add(stats, rx_bytes,
					rx_pkts[i]->pkt_len);
			lf_statistics_worker_counter_add(stats, rx_pkts, 1);

			pkt_res[i] =
					lf_plugins_post(worker_context, rx_pkts[i], pkt_res[i]);

			update_pkt_action_statistics(stats, pkt_res[i]);
		}

		nb_fwd = 0;
		nb_drop = 0;
#if LF_DISTRIBUTOR
		for (i = 0; i < nb_rx; ++i) {
			switch (pkt_res[i]) {
			case LF_PKT_UNKNOWN_DROP:
			case LF_PKT_INBOUND_DROP:
			case LF_PKT_OUTBOUND_DROP:
				*lf_distributor_action(rx_pkts[i]) = LF_DISTRIBUTOR_ACTION_DROP;
				nb_drop++;
				lf_statistics_worker_counter_add(stats, drop_bytes,
						rx_pkts[i]->pkt_len);
				lf_statistics_worker_counter_add(stats, drop_pkts, 1);
				break;
			case LF_PKT_UNKNOWN_FORWARD:
			case LF_PKT_OUTBOUND_FORWARD:
			case LF_PKT_INBOUND_FORWARD:
				*lf_distributor_action(rx_pkts[i]) = LF_DISTRIBUTOR_ACTION_FWD;
				nb_fwd++;
				lf_statistics_worker_counter_add(stats, tx_bytes,
						rx_pkts[i]->pkt_len);
				lf_statistics_worker_counter_add(stats, tx_pkts, 1);
				break;
			default:
				*lf_distributor_action(rx_pkts[i]) = LF_DISTRIBUTOR_ACTION_DROP;
				LF_WORKER_LOG(ERR, "Unknown packet action (%u)\n", pkt_res[i]);
				break;
			}
		}

		nb_tx = 0;
		do {
			nb_tx += rte_ring_enqueue_burst(worker_context->queues.tx_ring,
					(void **)rx_pkts + nb_tx, nb_rx - nb_tx, NULL);
		} while (unlikely(nb_tx < nb_fwd));
#else
		/* buffers to transmit and drop packets in burst */
		struct rte_mbuf *tx_pkts[LF_MAX_PKT_BURST];
		struct rte_mbuf *drop_pkts[LF_MAX_PKT_BURST];
		for (i = 0; i < nb_rx; ++i) {
			switch (pkt_res[i]) {
			case LF_PKT_UNKNOWN_DROP:
			case LF_PKT_INBOUND_DROP:
			case LF_PKT_OUTBOUND_DROP:
				drop_pkts[nb_drop] = rx_pkts[i];
				nb_drop++;
				lf_statistics_worker_counter_add(stats, drop_bytes,
						rx_pkts[i]->pkt_len);
				lf_statistics_worker_counter_add(stats, drop_pkts, 1);
				break;
			case LF_PKT_UNKNOWN_FORWARD:
			case LF_PKT_OUTBOUND_FORWARD:
			case LF_PKT_INBOUND_FORWARD:
				tx_pkts[nb_fwd] = rx_pkts[i];
				nb_fwd++;
				lf_statistics_worker_counter_add(stats, tx_bytes,
						rx_pkts[i]->pkt_len);
				lf_statistics_worker_counter_add(stats, tx_pkts, 1);
				break;
			default:
				LF_WORKER_LOG(ERR, "Unknown packet action (%u)\n", pkt_res[i]);
				drop_pkts[nb_drop] = rx_pkts[i];
				nb_drop++;
				break;
			}
		}

		/* Drop Rejected Packets */
		(void)rte_pktmbuf_free_bulk(drop_pkts, nb_drop);

		/* Forward Valid Packets */
		struct rte_ether_hdr *ether_hdr;
		for (i = 0; i < nb_fwd; ++i) {
			ether_hdr = rte_pktmbuf_mtod_offset(tx_pkts[i],
					struct rte_ether_hdr *, 0);
			(void)rte_eth_macaddr_get(worker_context->queues.tx_port_id,
					&ether_hdr->src_addr);
		}
		nb_tx = 0;
		do {
			nb_tx += rte_eth_tx_burst(worker_context->queues.tx_port_id,
					worker_context->queues.tx_queue_id, &tx_pkts[nb_tx],
					nb_fwd - nb_tx);
		} while (unlikely(nb_tx < nb_fwd));
#endif /* LF_DISTRIBUTOR */

		if (likely(nb_drop > 0 || nb_tx > 0)) {
			LF_WORKER_LOG(DEBUG, "%u packets sent\n", nb_tx);
			LF_WORKER_LOG(DEBUG, "%d packets dropped\n", nb_drop);
		}
	}
}

int
lf_worker_run(struct lf_worker_context *worker_context)
{
	int res;
	LF_WORKER_LOG(DEBUG, "run\n");

	/* register and start reporting quiescent state */
	res = rte_rcu_qsbr_thread_register(worker_context->qsv,
			worker_context->worker_id);
	if (res != 0) {
		LF_WORKER_LOG(ERR, "Register for QS Variable failed\n");
		return -1;
	}
	(void)rte_rcu_qsbr_thread_online(worker_context->qsv,
			worker_context->worker_id);

	(void)lf_worker_main_loop(worker_context);

	/* stop reporting quiescent state and unregister */
	(void)rte_rcu_qsbr_thread_offline(worker_context->qsv,
			worker_context->worker_id);
	(void)rte_rcu_qsbr_thread_unregister(worker_context->qsv,
			worker_context->worker_id);

	LF_WORKER_LOG(DEBUG, "terminate\n");
	return 0;
}
