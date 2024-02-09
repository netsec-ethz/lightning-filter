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
 * This file contains the implementation of the packet check function:
 * lf_worker_check_pkt().
 * This function is called by the worker thread for each inbound LF packet
 * and performs the following checks:
 * 1. Rate limit check
 * 2. MAC check (and DRKey get)
 * 3. Timestamp check
 * 4. Duplicate check
 *
 * The function returns the result of the checks as an enum lf_check_state.
 * The function also updates the rate limiter state and the duplicate filter
 * state.
 */

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
check_ratelimit(struct lf_worker_context *worker_context, uint64_t src_as,
		uint16_t drkey_protocol, uint32_t pkt_len, uint64_t ns_now,
		struct lf_ratelimiter_pkt_ctx *rl_pkt_ctx)
{
#if LF_WORKER_OMIT_RATELIMIT_CHECK
	return 0;
#endif
	int res;

	/* get packet rate limit context */
	res = lf_ratelimiter_worker_get_pkt_ctx(&worker_context->ratelimiter,
			src_as, drkey_protocol, rl_pkt_ctx);
	if (res != 0) {
		LF_WORKER_LOG_DP(DEBUG,
				"Failed to get packet rate limit context for " PRIISDAS
				" and DRKey protocol %u (res = %d).\n",
				PRIISDAS_VAL(rte_be_to_cpu_64(src_as)),
				rte_be_to_cpu_16(drkey_protocol), res);
		lf_statistics_worker_counter_inc(worker_context->statistics, error);
		return 1;
	}

	res = lf_ratelimiter_worker_check(rl_pkt_ctx, pkt_len, ns_now);
	if (likely(res != 0)) {
		LF_WORKER_LOG_DP(DEBUG,
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
		LF_WORKER_LOG_DP(DEBUG, "Rate limit check pass (res=%d).\n", res);
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
consume_ratelimit(uint32_t pkt_len, struct lf_ratelimiter_pkt_ctx *rl_pkt_ctx)
{
#if LF_WORKER_OMIT_RATELIMIT_CHECK
	return;
#endif
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
get_drkey(struct lf_worker_context *worker_context, uint64_t src_as,
		const struct lf_host_addr *src_addr,
		const struct lf_host_addr *dst_addr, uint16_t drkey_protocol,
		uint64_t timestamp, bool grace_period, uint64_t *drkey_epoch_start_ns,
		struct lf_crypto_drkey *drkey)
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
			drkey_epoch_start_ns, drkey);
	if (unlikely(res < 0)) {
		LF_WORKER_LOG_DP(INFO,
				"Inbound DRKey not found for AS " PRIISDAS
				" and drkey_protocol %d (timestamp = %" PRIu64
				", grace_period = %d, res = %d)\n",
				PRIISDAS_VAL(rte_be_to_cpu_64(src_as)),
				rte_be_to_cpu_16(drkey_protocol), timestamp, grace_period, res);
		lf_statistics_worker_counter_inc(worker_context->statistics, no_key);
	} else {
		LF_WORKER_LOG_DP(DEBUG,
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
check_mac(struct lf_worker_context *worker_context,
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
		LF_WORKER_LOG_DP(DEBUG, "MAC check failed.\n");
		lf_statistics_worker_counter_inc(worker_context->statistics,
				invalid_mac);
	} else {
		LF_WORKER_LOG_DP(DEBUG, "MAC check passed.\n");
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
check_timestamp(struct lf_worker_context *worker_context, uint64_t timestamp,
		uint64_t ns_now)
{
#if LF_WORKER_OMIT_TIMESTAMP_CHECK
	return 0;
#endif

	int res;

	res = timestamp < (ns_now - worker_context->timestamp_threshold) ||
	      timestamp > (ns_now + worker_context->timestamp_threshold);

	if (unlikely(res)) {
		LF_WORKER_LOG_DP(DEBUG, "Timestamp check failed.\n");
		lf_statistics_worker_counter_inc(worker_context->statistics,
				outdated_timestamp);
	} else {
		LF_WORKER_LOG_DP(DEBUG, "Timestamp check passed.\n");
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
check_duplicate(struct lf_worker_context *worker_context, const uint8_t *mac,
		uint64_t ns_now)
{
#if LF_WORKER_OMIT_DUPLICATE_CHECK
	return 0;
#endif

	int res;

	res = lf_duplicate_filter_apply(worker_context->duplicate_filter, mac,
			ns_now);
	if (likely(res != 0)) {
		LF_WORKER_LOG_DP(DEBUG, "Duplicate check failed.\n");
		lf_statistics_worker_counter_inc(worker_context->statistics, duplicate);
	} else {
		LF_WORKER_LOG_DP(DEBUG, "Duplicate check passed.\n");
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
	res = check_ratelimit(worker_context, pkt_data->src_as,
			pkt_data->drkey_protocol, pkt_data->pkt_len, ns_now, &rl_pkt_ctx);
	if (unlikely(res > 0)) {
		return LF_CHECK_AS_RATELIMITED;
	} else if (unlikely(res < 0)) {
		return LF_CHECK_SYSTEM_RATELIMITED;
	}

	/*
	 * MAC Check
	 */
	u_int64_t drkey_epoch_start_ns;
	res = get_drkey(worker_context, pkt_data->src_as, &pkt_data->src_addr,
			&pkt_data->dst_addr, pkt_data->drkey_protocol, ns_now,
			pkt_data->grace_period, &drkey_epoch_start_ns, &drkey);
	if (unlikely(res != 0)) {
		return LF_CHECK_NO_KEY;
	}
	res = check_mac(worker_context, &drkey, pkt_data->mac, pkt_data->auth_data);
	if (unlikely(res != 0)) {
		return LF_CHECK_INVALID_MAC;
	}

	/*
	 * Timestamp Check
	 */
	uint64_t calculated_packet_timestamp_ns =
			drkey_epoch_start_ns + pkt_data->timestamp;
	res = check_timestamp(worker_context, calculated_packet_timestamp_ns,
			ns_now);
	if (likely(res != 0)) {
		return LF_CHECK_OUTDATED_TIMESTAMP;
	}

	/*
	 * Duplicate Check and Update
	 * Check that the packet is not a duplicate and update the bloom filter
	 * structure.
	 */
	res = check_duplicate(worker_context, pkt_data->mac, ns_now);
	if (likely(res != 0)) {
		return LF_CHECK_DUPLICATE;
	}

	/*
	 * Rate Limit Update
	 * Consider the packet to be forwarded and update the rate limiter state.
	 */
	consume_ratelimit(pkt_data->pkt_len, &rl_pkt_ctx);

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

#if LF_WORKER_OMIT_RATELIMIT_CHECK
	return LF_CHECK_BE;
#endif /* !LF_WORKER_OMIT_RATELIMIT_CHECK */

	return res = lf_ratelimiter_worker_apply_best_effort(
				   &worker_context->ratelimiter, pkt_len, ns_now);
	if (likely(res > 0)) {
		LF_WORKER_LOG_DP(DEBUG,
				"Best-effort rate limit filter check failed (res=%d).\n", res);
		lf_statistics_worker_counter_inc(worker_context->statistics,
				ratelimit_be);
		return LF_CHECK_BE_RATELIMITED;
	} else if (res < 0) {
		LF_WORKER_LOG_DP(DEBUG,
				"System rate limit filter check failed (res=%d).\n", res);
		lf_statistics_worker_counter_inc(worker_context->statistics,
				ratelimit_system);
		return LF_CHECK_SYSTEM_RATELIMITED;
	}
	return LF_CHECK_BE;
}
