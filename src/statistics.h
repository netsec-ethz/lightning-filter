/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#ifndef LF_STATISTICS_H
#define LF_STATISTICS_H

#include <inttypes.h>
#include <stdatomic.h>

#include <rte_rcu_qsbr.h>
#include <rte_spinlock.h>

#include "lf.h"
#include "lib/telemetry/counters.h"

/**
 * This statistics module provides an interface for workers to collect metrics.
 * Furthermore, it collects and aggregates the metrics, and exposes them through
 * the DPDK telemetry interface.
 */

/**
 * Declaration of the worker counter with all its fields.
 */
#define LF_STATISTICS_WORKER_COUNTER(M) \
	/* traffic */                       \
	M(uint64_t, rx_pkts)                \
	M(uint64_t, rx_bytes)               \
	M(uint64_t, tx_pkts)                \
	M(uint64_t, tx_bytes)               \
	M(uint64_t, drop_pkts)              \
	M(uint64_t, drop_bytes)             \
	M(uint64_t, besteffort_pkts)        \
	M(uint64_t, besteffort_bytes)       \
                                        \
	/* burst size */                    \
	M(uint64_t, rx_burst_1_5)           \
	M(uint64_t, rx_burst_6_10)          \
	M(uint64_t, rx_burst_11_15)         \
	M(uint64_t, rx_burst_16_20)         \
	M(uint64_t, rx_burst_21_25)         \
	M(uint64_t, rx_burst_26_30)         \
	M(uint64_t, rx_burst_31_)           \
                                        \
	/* direction and action */          \
	M(uint64_t, unknown_drop)           \
	M(uint64_t, unknown_forward)        \
	M(uint64_t, outbound_drop)          \
	M(uint64_t, outbound_forward)       \
	M(uint64_t, inbound_drop)           \
	M(uint64_t, inbound_forward)        \
                                        \
	/* inbound packet */                \
	M(uint64_t, error)                  \
	M(uint64_t, no_key)                 \
	M(uint64_t, invalid_mac)            \
	M(uint64_t, invalid_hash)           \
	M(uint64_t, outdated_timestamp)     \
	M(uint64_t, duplicate)              \
	M(uint64_t, ratelimit_as)           \
	M(uint64_t, ratelimit_system)       \
	M(uint64_t, ratelimit_be)           \
	M(uint64_t, valid)                  \
                                        \
	/* outbound packet */               \
	M(uint64_t, outbound_error)         \
	M(uint64_t, outbound_no_key)

struct lf_statistics_worker {
	LF_STATISTICS_WORKER_COUNTER(LF_TELEMETRY_FIELD_DECL)
} __rte_cache_aligned;

struct lf_statistics {
	struct lf_statistics_worker *worker[LF_MAX_WORKER];
	uint16_t nb_workers;
};

#define lf_statistics_worker_counter_add(statistics_worker, field, val) \
	statistics_worker->field += val

#define lf_statistics_worker_counter_inc(statistics_worker, field) \
	lf_statistics_worker_counter_add(statistics_worker, field, 1)

inline static void
lf_statistics_worker_add_burst(struct lf_statistics_worker *statistics_worker,
		unsigned int burst_size)
{
	if (burst_size <= 5) {
		lf_statistics_worker_counter_inc(statistics_worker, rx_burst_1_5);
	} else if (burst_size <= 10) {
		lf_statistics_worker_counter_inc(statistics_worker, rx_burst_6_10);
	} else if (burst_size <= 15) {
		lf_statistics_worker_counter_inc(statistics_worker, rx_burst_11_15);
	} else if (burst_size <= 20) {
		lf_statistics_worker_counter_inc(statistics_worker, rx_burst_16_20);
	} else if (burst_size <= 25) {
		lf_statistics_worker_counter_inc(statistics_worker, rx_burst_21_25);
	} else if (burst_size <= 30) {
		lf_statistics_worker_counter_inc(statistics_worker, rx_burst_26_30);
	} else {
		lf_statistics_worker_counter_inc(statistics_worker, rx_burst_31_);
	}
}

/**
 * Frees the content of the statistics struct (not itself).
 * This includes also the workers' structs. Hence, all the workers have to
 * terminate beforehand.
 *
 * @param stats Statistics struct to be closed
 */
void
lf_statistics_close(struct lf_statistics *stats);

/**
 * Initialize statistics struct. This also includes the allocates and
 * initialization of the worker contexts. Calling this function, also registers
 * the telemetry commands.
 *
 * @param stats The statistics struct to be initialized.
 * @param worker_lcores The lcore assignment for the workers, which determines
 * the socket for which memory is allocated.
 * @param nb_workers Number of worker contexts to be created.
 * @return 0 if successful.
 */
int
lf_statistics_init(struct lf_statistics *stats,
		uint16_t worker_lcores[LF_MAX_WORKER], uint16_t nb_workers);

#endif /* LF_STATISTICS_H */