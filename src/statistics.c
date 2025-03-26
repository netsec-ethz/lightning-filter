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
 * Thread Safety:
 * Each worker has its own statistics counter and updates it independently.
 * The telemetry process can read the statistics counters at any time because
 * we assume that updates (to uint64_t) are atomic.
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

void
add_worker_statistics(struct lf_statistics_worker *res,
		struct lf_statistics_worker *a, struct lf_statistics_worker *b)
{
	LF_STATISTICS_WORKER_COUNTER(LF_TELEMETRY_FIELD_OP_ADD)
}

void
reset_worker_statistics(struct lf_statistics_worker *counter)
{
	LF_STATISTICS_WORKER_COUNTER(LF_TELEMETRY_FIELD_RESET)
}

void
counter_field_add_dict(struct rte_tel_data *d, struct lf_statistics_worker *c)
{
	LF_STATISTICS_WORKER_COUNTER(LF_TELEMETRY_FIELD_ADD_DICT)
}

static int
handle_worker_stats(const char *cmd __rte_unused, const char *params,
		struct rte_tel_data *d)
{
	int worker_id;
	struct lf_statistics_worker total_stats;
	memset(&total_stats, 0, sizeof(total_stats));

	rte_tel_data_start_dict(d);

	if (params) {
		worker_id = atoi(params);
		if (worker_id < 0 || worker_id >= telemetry_ctx->nb_workers) {
			return -EINVAL;
		}
		add_worker_statistics(&total_stats, &total_stats,
				telemetry_ctx->worker[worker_id]);
	} else {
		for (worker_id = 0; worker_id < telemetry_ctx->nb_workers;
				++worker_id) {
			add_worker_statistics(&total_stats, &total_stats,
					telemetry_ctx->worker[worker_id]);
		}
	}
	counter_field_add_dict(d, &total_stats);
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
		uint16_t worker_lcores[LF_MAX_WORKER], uint16_t nb_workers)
{
	int res;
	uint16_t worker_id;

	LF_STATISTICS_LOG(DEBUG, "Init\n");

	stats->nb_workers = nb_workers;

	for (worker_id = 0; worker_id < nb_workers; ++worker_id) {
		stats->worker[worker_id] = rte_zmalloc_socket("lf_statistics_worker",
				sizeof(struct lf_statistics_worker), RTE_CACHE_LINE_SIZE,
				(int)rte_lcore_to_socket_id(worker_lcores[worker_id]));
		if (stats->worker[worker_id] == NULL) {
			LF_STATISTICS_LOG(ERR, "Fail to allocate memory for worker.\n");
			return -1;
		}

		reset_worker_statistics(stats->worker[worker_id]);
	}

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