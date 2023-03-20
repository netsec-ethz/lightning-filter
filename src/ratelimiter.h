/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#ifndef LF_RATELIMITER_H
#define LF_RATELIMITER_H

#include <inttypes.h>
#include <stdatomic.h>

#include <rte_hash.h>
#include <rte_rcu_qsbr.h>
#include <rte_spinlock.h>

#include "config.h"
#include "lf.h"
#include "lib/ratelimiter/token_bucket.h"

/**
 * This module provides the rate limiting functionalities.
 */

struct lf_ratelimiter_worker {
	struct rte_hash *dict;

	struct lf_token_bucket_ratelimit *buckets;

	struct lf_token_bucket_ratelimit overall;
	struct lf_token_bucket_ratelimit auth_peers;
	struct lf_token_bucket_ratelimit best_effort;
};

struct lf_ratelimiter_data {
	uint64_t packet_rate;
	uint64_t packet_burst;
	uint64_t byte_rate;
	uint64_t byte_burst;
};

struct lf_ratelimiter {
	struct lf_ratelimiter_worker *workers[LF_MAX_WORKER];
	uint16_t nb_workers;

	struct rte_hash *dict;
	/* max number of entries */
	uint32_t size;

	struct lf_ratelimiter_data overall;
	struct lf_ratelimiter_data auth_peers;
	struct lf_ratelimiter_data best_effort;

	/* synchronize management */
	rte_spinlock_t management_lock;
	/* Workers' Quiescent State Variable */
	struct rte_rcu_qsbr *qsv;
};

struct lf_ratelimiter_key {
	uint64_t as;
	uint16_t drkey_protocol;
} __attribute__((__packed__));

struct lf_ratelimiter_pkt_ctx {
	/* either peer rate limit or auth peers rate limit */
	struct lf_token_bucket_ratelimit *peer_ratelimit;
	/* overall rate limit */
	struct lf_token_bucket_ratelimit *overall_ratelimit;
};

#define LF_RATELIMITER_RES_BYTES             (1 << 0)
#define LF_RATELIMITER_RES_PKTS              (1 << 1)
#define LF_RATELIMITER_RES_OVERALL_BYTES     (1 << 2)
#define LF_RATELIMITER_RES_OVERALL_PKTS      (1 << 3)
#define LF_RATELIMITER_RES_BEST_EFFORT_BYTES (1 << 4)
#define LF_RATELIMITER_RES_BEST_EFFORT_PKTS  (1 << 5)

/**
 * Get the rate limit context for a packet, which then can be used for the
 * function lf_ratelimiter_worker_check and lf_ratelimiter_worker_consume.
 * If no rate limit is defined for the specified AS and DRKey protocol, i.e.,
 * peer, the best-effort rate limit is used.
 *
 * @param pkt_ctx Returns the rate limit context for the packet.
 * @return Returns 0 on success.
 */
static inline int
lf_ratelimiter_worker_get_pkt_ctx(struct lf_ratelimiter_worker *rl, uint64_t as,
		uint16_t drkey_protocol, struct lf_ratelimiter_pkt_ctx *pkt_ctx)
{
	int key_id;

	const struct rte_hash *dict = rl->dict;
	const struct lf_ratelimiter_key as_key = {
		.as = as,
		.drkey_protocol = drkey_protocol,
	};

	/* per-AS rate limit */
	key_id = rte_hash_lookup(dict, &as_key);
	if (key_id < 0) {
		pkt_ctx->peer_ratelimit = &rl->auth_peers;
	} else {
		pkt_ctx->peer_ratelimit = &rl->buckets[key_id];
	}

	/* overall rate limit */
	pkt_ctx->overall_ratelimit = &rl->overall;
	return 0;
}

/**
 * @return Returns 0 if the packet would not exceed the rate limit. Otherwise a
 * positive number.
 */
static inline int
lf_ratelimiter_worker_check(struct lf_ratelimiter_pkt_ctx *pkt_ctx,
		uint32_t pkt_len, uint64_t ns_now)
{
	int res = 0;

	/* overall rate limit */
	if (lf_token_bucket_check(&pkt_ctx->overall_ratelimit->byte, pkt_len,
				ns_now) != 0) {
		res |= LF_RATELIMITER_RES_OVERALL_BYTES;
	}
	if (lf_token_bucket_check(&pkt_ctx->overall_ratelimit->packet, 1, ns_now) !=
			0) {
		res |= LF_RATELIMITER_RES_OVERALL_PKTS;
	}

	/* peer or best-effort rate limit */
	if (lf_token_bucket_check(&pkt_ctx->peer_ratelimit->byte, pkt_len,
				ns_now) != 0) {
		res |= LF_RATELIMITER_RES_BYTES;
	}
	if (lf_token_bucket_check(&pkt_ctx->peer_ratelimit->packet, 1, ns_now) !=
			0) {
		res |= LF_RATELIMITER_RES_PKTS;
	}

	return res;
}

static inline void
lf_ratelimiter_worker_consume(struct lf_ratelimiter_pkt_ctx *pkt_ctx,
		uint32_t pkt_len)
{
	(void)lf_token_bucket_consume(&pkt_ctx->overall_ratelimit->byte, pkt_len);
	(void)lf_token_bucket_consume(&pkt_ctx->overall_ratelimit->packet, 1);
	(void)lf_token_bucket_consume(&pkt_ctx->peer_ratelimit->byte, pkt_len);
	(void)lf_token_bucket_consume(&pkt_ctx->peer_ratelimit->packet, 1);
}

/**
 * Apply best-effort ratelimiting for a single packet.
 * @param pkt_len: Packet length.
 * @return 0 if packet can be forwarded.
 */
static inline int
lf_ratelimiter_worker_apply_best_effort(struct lf_ratelimiter_worker *rl,
		uint32_t pkt_len, uint64_t ns_now)
{
	int res = 0;
	/* overall rate limit */
	if (lf_token_bucket_check(&rl->overall.byte, pkt_len, ns_now) != 0) {
		res |= LF_RATELIMITER_RES_OVERALL_BYTES;
	}
	if (lf_token_bucket_check(&rl->overall.packet, 1, ns_now) != 0) {
		res |= LF_RATELIMITER_RES_OVERALL_PKTS;
	}

	/* best-effort rate limit */
	if (lf_token_bucket_check(&rl->best_effort.byte, pkt_len, ns_now) != 0) {
		res |= LF_RATELIMITER_RES_BYTES;
	}
	if (lf_token_bucket_check(&rl->best_effort.packet, 1, ns_now) != 0) {
		res |= LF_RATELIMITER_RES_PKTS;
	}

	if (res != 0) {
		return res;
	}

	/* subtract tokens from bucket */
	(void)lf_token_bucket_consume(&rl->overall.byte, pkt_len);
	(void)lf_token_bucket_consume(&rl->overall.packet, 1);
	(void)lf_token_bucket_consume(&rl->best_effort.byte, pkt_len);
	(void)lf_token_bucket_consume(&rl->best_effort.packet, 1);

	return 0;
}

/**
 * Apply rate limiting for a single packet, i.e., check if enough tokens are
 * available and consume them.
 *
 * @param as: Packet's source AS (network order).
 * @param pkt_len: Packet length.
 * @return 0 if the rate limit is not exceeded. > 0 if the rate limits would be
 * exceeded. < 0 if an error occurred.
 */
static inline int
lf_ratelimiter_worker_apply(struct lf_ratelimiter_worker *rl, uint64_t as,
		uint16_t drkey_protocol, uint32_t pkt_len, uint64_t ns_now)
{
	int res;
	struct lf_ratelimiter_pkt_ctx pkt_ctx;

	res = lf_ratelimiter_worker_get_pkt_ctx(rl, as, drkey_protocol, &pkt_ctx);
	if (res != 0) {
		return -1;
	}

	res = lf_ratelimiter_worker_check(&pkt_ctx, pkt_len, ns_now);
	if (res != 0) {
		return res;
	}

	/*
	 * Subtract tokens from buckets
	 */
	lf_ratelimiter_worker_consume(&pkt_ctx, pkt_len);

	return 0;
}

/**
 * Replaces current config with new config.
 * @param config: new config
 * @return 0 on success, otherwise, -1.
 */
int
lf_ratelimiter_apply_config(struct lf_ratelimiter *rl,
		struct lf_config *config);

/**
 * Frees the content of the rate limiter struct (not itself).
 * This includes also the workers' structs. Hence, all the workers have to
 * terminate beforehand.
 *
 * @param rl Rate limiter struct to be closed
 */
void
lf_ratelimiter_close(struct lf_ratelimiter *rl);

/**
 * Initialize ratelimiter structures.
 *
 * @param workers: Initializes nb_workers ratelimiter workers contexts.
 */
int
lf_ratelimiter_init(struct lf_ratelimiter *rl,
		uint16_t worker_lcores[LF_MAX_WORKER], uint16_t nb_workers,
		uint32_t initial_size, struct rte_rcu_qsbr *qsv,
		struct lf_ratelimiter_worker *workers[LF_MAX_WORKER]);

/**
 * Register ratelimiter IPC commands for the provided context.
 */
int
lf_ratelimiter_register_ipc(struct lf_ratelimiter *rl);

#endif /* LF_ratelimiter_H */