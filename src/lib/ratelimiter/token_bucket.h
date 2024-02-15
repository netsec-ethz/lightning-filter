/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#ifndef LF_TOKEN_BUCKET_H
#define LF_TOKEN_BUCKET_H

#include <inttypes.h>
#include <stdatomic.h>

#include "../math/util.h"
#include "../time/time.h"

struct lf_token_bucket {
	_Atomic(uint64_t) rate;
	_Atomic(uint64_t) burst;

	uint64_t tokens;
	struct lf_timestamp last_fill; /* Unix epoch (nanoseconds) */
};

/**
 * Initiate the token bucket structure.
 * @param token_bucket The structure to be initiated.
 * @param rate Token rate in token/s
 * @param burst Maximum size of burst token
 */
static inline void
lf_token_bucket_init(struct lf_token_bucket *token_bucket, uint64_t rate,
		uint64_t burst)
{
	token_bucket->rate = rate;
	token_bucket->burst = burst;
	token_bucket->tokens = 0;
	lf_timestamp_init_zero(&token_bucket->last_fill);
}

/**
 * Set the rate and burst size of the token bucket.
 * IMPORTANT: To set the rate limit to 0, the rate and burst size must be set to
 * 0! Otherwise, tokens in the bucket are not removed.
 *
 * @param token_bucket
 * @param rate
 * @param burst
 */
static inline void
lf_token_bucket_set(struct lf_token_bucket *token_bucket, uint64_t rate,
		uint64_t burst)
{
	atomic_store_explicit(&token_bucket->rate, rate, memory_order_relaxed);
	atomic_store_explicit(&token_bucket->burst, burst, memory_order_relaxed);
}

static inline int
lf_token_bucket_check(struct lf_token_bucket *token_bucket, uint64_t tokens,
		struct lf_timestamp *t_now)
{
	uint64_t rate =
			atomic_load_explicit(&token_bucket->rate, memory_order_relaxed);
	uint64_t burst =
			atomic_load_explicit(&token_bucket->burst, memory_order_relaxed);


	if (token_bucket->tokens > burst) {
		/*
		 * The number of tokens is bigger than allowed.
		 * This can happen when decreasing the burst size.
		 */
		token_bucket->tokens = burst;
	}

	if (lf_timestamp_greater(t_now, &token_bucket->last_fill)) {
		struct lf_timestamp elapsed =
				lf_timestamp_sub(t_now, &token_bucket->last_fill);
		uint64_t elapsed_ns = elapsed.s * LF_TIME_NS_IN_S + elapsed.ns;
		uint64_t tokens_new = token_bucket->tokens + (elapsed_ns * rate) / 1000;

		/* check if new tokens could have been added */
		if (tokens_new != token_bucket->tokens) {
			token_bucket->tokens = MIN(tokens_new, burst);
			lf_timestamp_copy(&token_bucket->last_fill, t_now);
		}
	}

	if (token_bucket->tokens < tokens) {
		return -1;
	}
	return 0;
}

static inline int
lf_token_bucket_consume(struct lf_token_bucket *token_bucket, uint64_t tokens)
{
	if (token_bucket->tokens < tokens) {
		return -1;
	} else {
		token_bucket->tokens -= tokens;
		return 0;
	}
}


struct lf_token_bucket_ratelimit {
	struct lf_token_bucket packet;
	struct lf_token_bucket byte;
};

/**
 * @param packets_token_rate (packets per second)
 * @param packets_burst_size (max packets at once)
 * @param bytes_token_rate (bytes per second)
 * @param bytes_burst_size (max bytes at once)
 * @return int
 */
static inline int
lf_token_bucket_ratelimit_init(struct lf_token_bucket_ratelimit *rl,
		int64_t packets_token_rate, int64_t packets_burst_size,
		int64_t bytes_token_rate, int64_t bytes_burst_size)
{
	lf_token_bucket_init(&rl->packet, packets_token_rate, packets_burst_size);
	lf_token_bucket_init(&rl->byte, bytes_token_rate, bytes_burst_size);
	return 0;
}

/**
 * Set the rate and burst size.
 * IMPORTANT: To set the rate limit to 0, the rate and burst size must be set to
 * 0! Otherwise, tokens in the bucket are not removed.
 *
 * @param packets_token_rate (packets per second)
 * @param packets_burst_size (max packets at once)
 * @param bytes_token_rate (bytes per second)
 * @param bytes_burst_size (max bytes at once)
 * @return int
 */
static inline int
lf_token_bucket_ratelimit_set(struct lf_token_bucket_ratelimit *rl,
		int64_t packets_token_rate, int64_t packets_burst_size,
		int64_t bytes_token_rate, int64_t bytes_burst_size)
{
	lf_token_bucket_set(&rl->packet, packets_token_rate, packets_burst_size);
	lf_token_bucket_set(&rl->byte, bytes_token_rate, bytes_burst_size);
	return 0;
}

static inline int
lf_token_bucket_ratelimit_apply(struct lf_token_bucket_ratelimit *rl,
		int64_t packets, int64_t bytes, struct lf_timestamp *t_now)
{
	int res;
	res = lf_token_bucket_check(&rl->packet, packets, t_now);
	if (res < 0) {
		return -1;
	}
	res = lf_token_bucket_check(&rl->byte, bytes, t_now);
	if (res < 0) {
		return -2;
	}

	(void)lf_token_bucket_consume(&rl->packet, packets);
	(void)lf_token_bucket_consume(&rl->byte, bytes);

	return 0;
}

#endif /* LF_TOKEN_BUCKET_H */
