/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#include <inttypes.h>
#include <stdatomic.h>

#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_rcu_qsbr.h>
#include <rte_spinlock.h>
#include <rte_telemetry.h>

#include "lf.h"
#include "lib/log/log.h"
#include "lib/time/time.h"
#include "statistics.h"
#include "version.h"

/*
 * Synchronization and Atomic Operations:
 * Writing and reading the workers' statistics pointer is always performed
 * atomically with relaxed memory order. Synchronization is provided through the
 * worker's RCU mechanism (rcu_qsbr).
 * This is sufficient, because the manager only accesses a worker's statistics
 * after giving the worker another statistics pointer and wait for the worker to
 * pass through the quiescent state.
 */

/**
 * Log function for statistics services (not on the data path).
 * Format: "Statistics: log message here"
 */
#define LF_STATISTICS_LOG(level, ...) LF_LOG(level, "Statistics: " __VA_ARGS__)

struct lf_statistics *telemetry_ctx;

/**
 * Escapes special character in string to make it JSON compatible.
 * This function is incomplete and might not escape all characters.
 *
 * @param in string to escape (zero ending)
 * @param out resulting string (zero ending)
 * @param out_len size of out array.
 * @return number of characters written to out if successful. Otherwise, -1.
 */
static int
escape_json(const char *in, char *out, int out_len)
{
	int out_counter = 0;
	int in_counter = 0;

	while (out_counter < out_len) {
		switch (in[in_counter]) {
		case '\n':
			out[out_counter++] = '\\';
			if (out_counter >= out_len) {
				return -1;
			}
			out[out_counter++] = 'n';
			break;
		case '\\':
		case '"':
			out[out_counter++] = '\\';
			if (out_counter >= out_len) {
				return -1;
			}
			out[out_counter++] = in[in_counter];
			break;
		default:
			if (out_counter >= out_len) {
				return -1;
			}
			out[out_counter++] = in[in_counter];
		}

		if (in[in_counter] == '\0') {
			/* successfully copied everything up to '\0' */
			return out_counter;
		}

		in_counter++;
	}

	return -1;
}

/**
 * List of all worker counter names.
 */
const struct lf_telemetry_field_name worker_counter_strings[] = {
	LF_STATISTICS_WORKER_COUNTER(LF_TELEMETRY_FIELD_NAME)
};
#define WORKER_COUNTER_NUM \
	(sizeof(worker_counter_strings) / sizeof(struct lf_telemetry_field_name))

#define other_state(state) (((state) + 1) % 2)

void
add_worker_statistics(struct lf_statistics_worker_counter *res,
		struct lf_statistics_worker_counter *a,
		struct lf_statistics_worker_counter *b)
{
	LF_STATISTICS_WORKER_COUNTER(LF_TELEMETRY_FIELD_OP_ADD)
}

void
reset_worker_statistics(struct lf_statistics_worker_counter *counter)
{
	LF_STATISTICS_WORKER_COUNTER(LF_TELEMETRY_FIELD_RESET)
}

void
aggregate_worker_statistics(struct lf_statistics *stats)
{
	int res;
	int read_state;
	uint16_t worker_id;
	uint64_t ns_now;

	res = lf_time_get(&ns_now);

	/* check if aggregation should be performed, i.e., if the minimal time
	interval between aggregation has passed. */
	if (res != 0 ||
			ns_now <=
					stats->last_aggregate +
							(uint64_t)(LF_STATISTICS_MIN_AGGREGATION_INTERVAL *
									   (double)LF_TIME_NS_IN_S)) {
		return;
	}

	LF_STATISTICS_LOG(INFO, "Aggregate statistics\n");
	stats->last_aggregate = ns_now;

	/* switch state and the worker's statistics structures */
	read_state = stats->current_state;
	stats->current_state = other_state(stats->current_state);
	for (worker_id = 0; worker_id < stats->nb_workers; ++worker_id) {
		atomic_store_explicit(&stats->worker[worker_id]->active_counter,
				&stats->worker[worker_id]->counter[stats->current_state],
				memory_order_relaxed);
	}

	/*
	 * wait until all workers have entered quiescent state and ensure that no
	 * worker still references memory of the other state.
	 */
	rte_rcu_qsbr_synchronize(stats->qsv, RTE_QSBR_THRID_INVALID);

	for (worker_id = 0; worker_id < stats->nb_workers; ++worker_id) {
		/* update worker statistics */
		add_worker_statistics(&stats->aggregate_worker[worker_id],
				&stats->worker[worker_id]->counter[read_state],
				&stats->aggregate_worker[worker_id]);

		/* update global statistics */
		add_worker_statistics(&stats->aggregate_global,
				&stats->worker[worker_id]->counter[read_state],
				&stats->aggregate_global);

		/* reset worker counter */
		reset_worker_statistics(&stats->worker[worker_id]->counter[read_state]);
	}
}

static int
handle_worker_stats(const char *cmd __rte_unused, const char *params,
		struct rte_tel_data *d)
{
	size_t i;
	uint64_t *values;
	int worker_id;

	rte_tel_data_start_dict(d);

	if (params) {
		worker_id = atoi(params);
		if (worker_id < 0 || worker_id >= telemetry_ctx->nb_workers) {
			return -EINVAL;
		}
		rte_spinlock_lock(&telemetry_ctx->lock);
		aggregate_worker_statistics(telemetry_ctx);
		values = (uint64_t *)&telemetry_ctx->aggregate_worker[worker_id];
		for (i = 0; i < WORKER_COUNTER_NUM; i++) {
			rte_tel_data_add_dict_uint(d, worker_counter_strings[i].name,
					values[i]);
		}
		rte_spinlock_unlock(&telemetry_ctx->lock);
	} else {
		(void)rte_spinlock_lock(&telemetry_ctx->lock);
		aggregate_worker_statistics(telemetry_ctx);
		values = (uint64_t *)&telemetry_ctx->aggregate_global;
		for (i = 0; i < WORKER_COUNTER_NUM; i++) {
			rte_tel_data_add_dict_uint(d, worker_counter_strings[i].name,
					values[i]);
		}
		(void)rte_spinlock_unlock(&telemetry_ctx->lock);
	}

	return 0;
}

#define ESCAPED_STRING_LENGTH 1024

static int
handle_version(const char *cmd __rte_unused, const char *params,
		struct rte_tel_data *d)
{
	int res;
	char escaped_string[ESCAPED_STRING_LENGTH];

	rte_tel_data_start_dict(d);

	/*
	 * Always add the major version number as integer.
	 * Having at least one numeric value in the returned JSON allows Prometheus
	 * to fetch the value (and get the strings as labels).
	 */
	rte_tel_data_add_dict_int(d, "version major", LF_VERSION_MAJOR);

	if (params == NULL) {
		rte_tel_data_add_dict_string(d, "version", LF_VERSION);
		rte_tel_data_add_dict_string(d, "git", xstr(LF_VERSION_GIT));
		rte_tel_data_add_dict_string(d, "worker", xstr(LF_WORKER));
		rte_tel_data_add_dict_string(d, "drkey_fetcher",
				xstr(LF_DRKEY_FETCHER));
		rte_tel_data_add_dict_string(d, "cbc_mac", xstr(LF_CBCMAC));
		rte_tel_data_add_dict_int(d, "log_dp_level", LF_LOG_DP_LEVEL);
		return 0;
	} else if (strcmp(params, "all") == 0) {
		res = escape_json(LF_VERSION_ALL, escaped_string,
				ESCAPED_STRING_LENGTH);
		if (res > ESCAPED_STRING_LENGTH) {
			return -1;
		}
		rte_tel_data_add_dict_string(d, "all", escaped_string);
		return 0;
	}

	return -1;
}

void
lf_statistics_close(struct lf_statistics *stats)
{
	uint16_t worker_id;

	for (worker_id = 0; worker_id < stats->nb_workers; ++worker_id) {
		rte_free(stats->worker[worker_id]);
	}

	telemetry_ctx = NULL;
}

int
lf_statistics_init(struct lf_statistics *stats,
		uint16_t worker_lcores[LF_MAX_WORKER], uint16_t nb_workers,
		struct rte_rcu_qsbr *qsv)
{
	int res;
	uint16_t worker_id;

	LF_STATISTICS_LOG(DEBUG, "Init\n");

	stats->current_state = 0;
	stats->nb_workers = nb_workers;
	stats->qsv = qsv;
	stats->last_aggregate = 0;

	for (worker_id = 0; worker_id < nb_workers; ++worker_id) {
		stats->worker[worker_id] = rte_zmalloc_socket("lf_statistics_worker",
				sizeof(struct lf_statistics_worker), RTE_CACHE_LINE_SIZE,
				(int)rte_lcore_to_socket_id(worker_lcores[worker_id]));
		if (stats->worker[worker_id] == NULL) {
			LF_STATISTICS_LOG(ERR, "Fail to allocate memory for worker.\n");
			return -1;
		}

		reset_worker_statistics(&stats->worker[worker_id]->counter[0]);
		reset_worker_statistics(&stats->worker[worker_id]->counter[1]);
		reset_worker_statistics(&stats->aggregate_worker[worker_id]);

		stats->worker[worker_id]->active_counter =
				&stats->worker[worker_id]->counter[stats->current_state];
	}

	reset_worker_statistics(&stats->aggregate_global);

	rte_spinlock_init(&stats->lock);

	/*
	 * Setup telemetry
	 */
	telemetry_ctx = stats;

	/* register /version */
	res = rte_telemetry_register_cmd(LF_TELEMETRY_PREFIX "/version",
			handle_version,
			"Prints Version. Parameters: None for simple version or 'all' for "
			"extended version information");
	if (res != 0) {
		LF_STATISTICS_LOG(ERR, "Failed to register telemetry: %d\n", res);
	}

	/* register /worker/stats */
	res = rte_telemetry_register_cmd(LF_TELEMETRY_PREFIX "/worker/stats",
			handle_worker_stats,
			"Returns worker statistics. Parameters: None (aggregated over all "
			"workers) or worker ID");
	if (res != 0) {
		LF_STATISTICS_LOG(ERR, "Failed to register telemetry: %d\n", res);
	}

	return 0;
}