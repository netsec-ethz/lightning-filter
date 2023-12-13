/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#ifndef LF_TIME_H
#define LF_TIME_H

#include <inttypes.h>
#include <math.h>
#include <stdlib.h>
#include <time.h>

#include "../math/sat_op.h"

#define LF_TIME_WORKER_UPDATE_INTERVAL 0.1 /* Seconds */

static const uint64_t LF_TIME_NS_IN_S =
		(uint64_t)1e9; /* nanoseconds in seconds */
static const uint64_t LF_TIME_NS_IN_MS =
		(uint64_t)1e6; /* nanoseconds in milliseconds */

struct lf_time_worker {
	/* current cached time value */
	uint64_t ns_now_cache;
	/* counter for unique time value */
	uint32_t counter;

	uint64_t last_update_tsc;
	uint64_t update_interval_tsc;
};

static inline int
lf_time_get(uint64_t *ns_now)
{
	int res;
	uint64_t ns;
	uint64_t s;
	struct timespec spec;

	/* TODO: should use a monotonic time, such as TAI64NA */
	res = clock_gettime(CLOCK_REALTIME, &spec);
	if (res != 0) {
		return -1;
	}

	s = spec.tv_sec;
	ns = spec.tv_nsec;

	*ns_now = s * LF_TIME_NS_IN_S + ns;

	return 0;
}


static inline int
lf_time_worker_get(struct lf_time_worker *ctx, uint64_t *ns_now)
{
	*ns_now = ctx->ns_now_cache;
	return 0;
}

/**
 * Sets a unique timestamp using a counter, which is added to the cached
 * nanosecond timestamp.
 */
static inline int
lf_time_worker_get_unique(struct lf_time_worker *ctx, uint64_t *ns_now)
{
	*ns_now = ctx->ns_now_cache + ctx->counter;
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
	uint64_t current_ns;

#if LF_WORKER_OMIT_TIME_UPDATE
	return 0;
#endif

	current_tsc = rte_rdtsc();
	if (unlikely(current_tsc - ctx->last_update_tsc >=
				 ctx->update_interval_tsc)) {

		res = lf_time_get(&current_ns);
		if (unlikely(res != 0)) {
			return -1;
		}
		/* check if uniqueness is guaranteed and set res accordingly */
		if (unlikely(sat_sub_u64(current_ns, ctx->ns_now_cache) <=
					 ctx->counter)) {
			res = 1;
		}

		ctx->ns_now_cache = current_ns;
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
	(void)lf_time_get(&ctx->ns_now_cache);
	ctx->last_update_tsc = rte_rdtsc();
	ctx->update_interval_tsc = (uint64_t)((double)rte_get_timer_hz() *
										  LF_TIME_WORKER_UPDATE_INTERVAL);
	ctx->counter = 0;
}

#endif /* LF_TIME_H */