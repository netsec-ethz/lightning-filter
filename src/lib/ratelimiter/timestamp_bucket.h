/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#ifndef LF_TIMESTAMP_BUCKET_H
#define LF_TIMESTAMP_BUCKET_H

#include <stdatomic.h>
#include <stdint.h>

/**
 * Ratelimiter struct for the timestamp based token algorithm.
 *
 *
 */
struct lf_tsb {
	int64_t time;

	/**
	 * Time required to obtain new token.
	 * 0 if no rate limit is applied.
	 * -1 if the rate limit is 0.
	 */
	int64_t time_per_token;
	int64_t burst_time;
};

static inline int
lf_tsb_init(struct lf_tsb *bucket, int64_t time_per_token, int64_t burst_size)
{
	if (time_per_token < -1 || burst_size < 0) {
		return -1;
	}

	bucket->time = INT64_MIN;
	bucket->time_per_token = time_per_token;
	bucket->burst_time = burst_size * time_per_token;
	return 0;
}

static inline int
lf_tsb_set(struct lf_tsb *bucket, int64_t time_per_token, int64_t burst_size)
{
	if (time_per_token < -1 || burst_size < 0) {
		return -1;
	}
	bucket->time_per_token = time_per_token;
	bucket->burst_time = burst_size * time_per_token;
	return 0;
}

static inline int
lf_tsb_check(const struct lf_tsb *bucket, int64_t tokens, int64_t time_now)
{
	/* rate limit is 0 */
	if (bucket->time_per_token == -1) {
		return -1;
	}

	/* no rate limit */
	if (bucket->time_per_token == 0) {
		return 0;
	}

	if (tokens <= 0) {
		return 0;
	}

	const int64_t time_per_token = bucket->time_per_token;
	const int64_t burst_time = bucket->burst_time;

	/* the time required to collect the requested amount of tokens */
	const int64_t time_needed = tokens * time_per_token;

	const int64_t time_min = time_now - burst_time;

	/* time = max(time_min, bucket->time) */
	int64_t time = bucket->time;
	if (time_min > time) {
		time = time_min;
	}

	if (time + time_needed > time_now) {
		/* not enough tokens */
		return -1;
	}

	return time_needed;
}

static inline int
lf_tsb_consume(struct lf_tsb *bucket, const int64_t time_needed,
		int64_t time_now)
{
	const int64_t burst_time = bucket->burst_time;
	const int64_t time_min = time_now - burst_time;

	/* time = max(time_min, bucket->time) */
	int64_t time = bucket->time;
	if (time_min > time) {
		time = time_min;
	}

	bucket->time = time + time_needed;

	/*
	 * Inform that the limit has been succeeded.
	 */
	if (bucket->time > time_now) {
		return 1;
	}

	return 0;
}

static inline int
lf_tsb_apply(struct lf_tsb *bucket, const int64_t tokens, int64_t time_now)
{
	int64_t time_needed;
	time_needed = lf_tsb_check(bucket, tokens, time_now);
	if (time_needed < 0) {
		return -1;
	}
	return lf_tsb_consume(bucket, time_needed, time_now);
}


/********************************************************
 *
 * A lock-free implementation of the token bucket using atomics.
 * (fstreun) ATTENTION!
 * If the bucket's time is far in the past, it first has to be set to the
 * time_now - burst_time before adding time_needed. If two threads are
 * performing this operation in one atomic operation, the addition might
 * overshoot way too much.
 *
 ********************************************************/

struct lf_tsb_shared {
	_Atomic(int64_t) time; /* some time unit */

	_Atomic(int64_t) time_per_token; /* tokens per time unit */
	_Atomic(int64_t) burst_time;     /* time unit */
};

static inline int
lf_tsb_shared_init(struct lf_tsb_shared *bucket, int64_t time_per_token,
		int64_t burst_size)
{
	if (time_per_token < -1 || burst_size < 0) {
		return -1;
	}

	atomic_store(&bucket->time, INT64_MIN);

	atomic_store(&bucket->time_per_token, time_per_token);
	atomic_store(&bucket->burst_time, burst_size * time_per_token);

	return 0;
}

static inline int
lf_tsb_shared_set(struct lf_tsb_shared *bucket, int64_t time_per_token,
		int64_t burst_size)
{
	if (time_per_token < -1 || burst_size < 0) {
		return -1;
	}

	atomic_store_explicit(&bucket->time_per_token, time_per_token,
			memory_order_relaxed);
	atomic_store_explicit(&bucket->burst_time, burst_size * time_per_token,
			memory_order_relaxed);

	return 0;
}

static inline int
lf_tsb_shared_check(const struct lf_tsb_shared *bucket, const int64_t tokens,
		int64_t time_now)
{
	const int64_t time_per_token =
			atomic_load_explicit(&bucket->time_per_token, memory_order_relaxed);

	const int64_t burst_time =
			atomic_load_explicit(&bucket->burst_time, memory_order_relaxed);

	/* rate limit is 0 */
	if (time_per_token == -1) {
		return -1;
	}

	/* no rate limit */
	if (time_per_token == 0) {
		return 0;
	}

	if (tokens <= 0) {
		return 0;
	}

	/* the time required to collect the requested amount of tokens */
	const int64_t time_needed = tokens * time_per_token;

	const int64_t time_min = time_now - burst_time;

	/* time = max(time_min, bucket->time) */
	int64_t time = atomic_load_explicit(&bucket->time, memory_order_relaxed);
	if (time_min > time) {
		time = time_min;
	}

	if (time + time_needed > time_now) {
		/* not enough tockens */
		return -1;
	}

	return time_needed;
}

static inline int
lf_tsb_shared_consume(struct lf_tsb_shared *bucket, const int64_t time_needed,
		int64_t time_now)
{
	const int64_t burst_time =
			atomic_load_explicit(&bucket->burst_time, memory_order_relaxed);
	const int64_t time_min = time_now - burst_time;

	/* time = max(time_min, bucket->time) */
	int64_t time = atomic_load_explicit(&bucket->time, memory_order_relaxed);
	if (time_min > time) {
		time = time_min;
	}

	int64_t actual_time = atomic_fetch_add_explicit(&bucket->time,
			time + time_needed, memory_order_relaxed);


	/*
	 * Inform that the limit has been succeeded.
	 */
	if (actual_time + time_needed > time_now) {
		return 1;
	}

	return 0;
}

static inline int
lf_tsb_shared_apply(struct lf_tsb_shared *bucket, const int64_t tokens,
		int64_t time_now)
{
	int64_t time_needed;
	time_needed = lf_tsb_shared_check(bucket, tokens, time_now);
	if (time_needed < 0) {
		return -1;
	}
	/*
	 * We accept a race condition here!
	 * The bucket->time value might has changed between the previous if clause
	 * and the following addition.
	 * Therefore, bucket->time + time_needed can become bigger than time_now,
	 * i.e., be in the future. If this happens, there are two possible
	 * reactions.
	 * 1. Accept it and allow that the burst rate has been exceeded temporarily.
	 * 2. Decline it and loose some tokens.
	 */
	return lf_tsb_shared_consume(bucket, time_needed, time_now);
}

#endif /* LF_TIMESTAMP_BUCKET_H */