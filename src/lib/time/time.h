/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#ifndef LF_TIME_H
#define LF_TIME_H

#include <assert.h>
#include <inttypes.h>
#include <math.h>
#include <rte_branch_prediction.h>
#include <rte_cycles.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>

#include "../math/sat_op.h"

#define LF_TIME_WORKER_UPDATE_INTERVAL 0.1 /* Seconds */

static const uint64_t LF_TIME_NS_IN_S =
		(uint64_t)1e9; /* nanoseconds in seconds */
static const uint64_t LF_TIME_NS_IN_MS =
		(uint64_t)1e6; /* nanoseconds in milliseconds */

struct lf_timestamp {
	uint64_t s;
	uint32_t ns;
};

struct lf_time_worker {
	/* current cached time value */
	struct lf_timestamp t_now_cache;
	/* counter for unique time value */
	uint32_t counter;

	uint64_t last_update_tsc;
	uint64_t update_interval_tsc;
};

static inline void
lf_timestamp_init_zero(struct lf_timestamp *a)
{
	a->ns = 0;
	a->s = 0;
}

static inline void
lf_timestamp_init_s(struct lf_timestamp *a, uint64_t seconds)
{
	a->ns = 0;
	a->s = seconds;
}

static inline void
lf_timestamp_init_ns(struct lf_timestamp *a, uint64_t nanoseconds)
{
	a->ns = nanoseconds % LF_TIME_NS_IN_S;
	a->s = nanoseconds / LF_TIME_NS_IN_S;
}

static inline void
lf_timestamp_copy(struct lf_timestamp *dst, struct lf_timestamp *src)
{
	dst->ns = src->ns;
	dst->s = src->s;
}

static inline bool
lf_timestamp_equal(const struct lf_timestamp *a, const struct lf_timestamp *b)
{
	return (a->s == b->s) && (a->ns == b->ns);
}

static inline bool
lf_timestamp_less(const struct lf_timestamp *a, const struct lf_timestamp *b)
{
	return (a->s < b->s) || ((a->s == b->s) && (a->ns < b->ns));
}

static inline bool
lf_timestamp_greater(const struct lf_timestamp *a, const struct lf_timestamp *b)
{
	return (a->s > b->s) || ((a->s == b->s) && (a->ns > b->ns));
}

static inline struct lf_timestamp
lf_timestamp_add(const struct lf_timestamp *a, const struct lf_timestamp *b)
{
	struct lf_timestamp res;
	res.ns = (a->ns + b->ns) % LF_TIME_NS_IN_S;
	uint8_t ns_overflow = res.ns < (a->ns + b->ns) ? 1 : 0;
	res.s = a->s + b->s + ns_overflow;
	return res;
}

static inline struct lf_timestamp
lf_timestamp_sub(const struct lf_timestamp *a, const struct lf_timestamp *b)
{
	assert(!lf_timestamp_less(a, b));

	struct lf_timestamp res;
	res.ns = (LF_TIME_NS_IN_S + a->ns - b->ns) % LF_TIME_NS_IN_S;
	uint8_t ns_overflow = a->ns < b->ns ? 1 : 0;
	res.s = a->s - b->s - ns_overflow;
	return res;
}

static inline void
lf_timestamp_inc_ns(struct lf_timestamp *a, uint64_t nanoseconds)
{
	a->ns = (a->ns + nanoseconds) % LF_TIME_NS_IN_S;
	a->s = a->s + nanoseconds / LF_TIME_NS_IN_S;
}

static inline int
lf_time_get(struct lf_timestamp *t_now)
{
	int res;
	struct timespec spec;

	/* TODO: should use a monotonic time, such as TAI64NA */
	res = clock_gettime(CLOCK_REALTIME, &spec);
	if (res != 0) {
		return -1;
	}

	t_now->s = spec.tv_sec;
	t_now->ns = spec.tv_nsec;

	return 0;
}


static inline int
lf_time_worker_get(struct lf_time_worker *ctx, struct lf_timestamp *t_now)
{
	t_now->s = ctx->t_now_cache.s;
	t_now->ns = ctx->t_now_cache.ns;
	return 0;
}

/**
 * Sets a unique timestamp using a counter, which is added to the cached
 * nanosecond timestamp.
 */
static inline int
lf_time_worker_get_unique(struct lf_time_worker *ctx,
		struct lf_timestamp *t_now)
{
	t_now->s = ctx->t_now_cache.s +
	           ((ctx->t_now_cache.ns + ctx->counter) / LF_TIME_NS_IN_S);
	t_now->ns = (ctx->t_now_cache.ns + ctx->counter) % LF_TIME_NS_IN_S;

	ctx->counter += 1;
	return 0;
}

/**
 * Get counter value, which is unique for the currently provided timestamp.
 * This function call also increases the counter.
 */
static inline unsigned int
lf_time_worker_get_unique_counter(struct lf_time_worker *ctx)
{
	return ctx->counter++;
}

/**
 * Update the cached timestamp if required.
 * If the cached timestamp is updated, also the counter for the unique timestamp
 * is reseted and set to 0.
 * @param ctx
 * The worker's time context.
 * @return 0 on success. -1 if time could not be updated. 1 if time has been
 * updated but the counter has become to large and uniqueness of the timestamp
 * cannot be guaranteed anymore.
 */
static inline int
lf_time_worker_update(struct lf_time_worker *ctx)
{
	int res = 0;
	uint64_t current_tsc;
	struct lf_timestamp t_now;

#if LF_WORKER_OMIT_TIME_UPDATE
	return 0;
#endif

	current_tsc = rte_rdtsc();
	if (unlikely(current_tsc - ctx->last_update_tsc >=
				 ctx->update_interval_tsc)) {

		res = lf_time_get(&t_now);
		if (unlikely(res != 0)) {
			return -1;
		}
		/* check if uniqueness is guaranteed and set res accordingly */
		if (unlikely(sat_sub_u64(
							 ((t_now.s - ctx->t_now_cache.s) * LF_TIME_NS_IN_S +
									 t_now.ns),
							 ctx->t_now_cache.ns) <= ctx->counter)) {
			res = 1;
		}

		ctx->t_now_cache.s = t_now.s;
		ctx->t_now_cache.ns = t_now.ns;
		ctx->counter = 0;
		ctx->last_update_tsc = current_tsc;

		/* potentially the clock speed has changed */
		ctx->update_interval_tsc = (uint64_t)((double)rte_get_timer_hz() *
											  LF_TIME_WORKER_UPDATE_INTERVAL);
	}

	return res;
}

static inline void
lf_time_worker_init(struct lf_time_worker *ctx)
{
	(void)lf_time_get(&ctx->t_now_cache);
	ctx->last_update_tsc = rte_rdtsc();
	ctx->update_interval_tsc = (uint64_t)((double)rte_get_timer_hz() *
										  LF_TIME_WORKER_UPDATE_INTERVAL);
	ctx->counter = 0;
}

#endif /* LF_TIME_H */