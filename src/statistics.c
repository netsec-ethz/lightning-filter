/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#include <inttypes.h>
#include <stdatomic.h>

#include <rte_cycles.h>
#include <rte_errno.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_rcu_qsbr.h>
#include <rte_spinlock.h>
#include <rte_telemetry.h>

#include "lf.h"
#include "lib/log/log.h"
#include "lib/time/time.h"
#include "lib/utils/parse.h"
#include "statistics.h"
#include "version.h"

/*
 * Thread Safety:
 * Each worker has its own statistics counter and updates it independently.
 * The telemetry process can read the statistics counters at any time because
 * we assume that updates (to uint64_t) are atomic.
 * Hash table updates are protected by the RCU QSBR mechanism and the management
 * lock, which ensures that no worker and the telemetry process accesses freed
 * memory.
 */

/**
 * Log function for statistics services (not on the data path).
 * Format: "Statistics: log message here"
 */
#define LF_STATISTICS_LOG(level, ...) LF_LOG(level, "Statistics: " __VA_ARGS__)

#define LF_STATISTICS_IA_DICT_INIT_SIZE 1024

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
telemetry_add_dict_worker_statistics(struct rte_tel_data *d,
		struct lf_statistics_worker_counter *c)
{
	LF_STATISTICS_WORKER_COUNTER(LF_TELEMETRY_FIELD_ADD_DICT)
}

void
add_ia_statistics(struct lf_statistics_ia_counter *res,
		struct lf_statistics_ia_counter *a, struct lf_statistics_ia_counter *b)
{
	LF_STATISTICS_IA_COUNTER(LF_TELEMETRY_FIELD_OP_ADD)
}

void
telemetry_add_dict_ia_statistics(struct rte_tel_data *d,
		struct lf_statistics_ia_counter *c)
{
	LF_STATISTICS_IA_COUNTER(LF_TELEMETRY_FIELD_ADD_DICT)
}

static int
handle_ia_stats_list(const char *cmd __rte_unused,
		const char *params __rte_unused, struct rte_tel_data *d)
{
	rte_spinlock_lock(&telemetry_ctx->management_lock);

	rte_tel_data_start_array(d, RTE_TEL_STRING_VAL);

	for (int worker_id = 0; worker_id < telemetry_ctx->nb_workers;
			worker_id++) {
		struct lf_statistics_ia_key *key;
		struct lf_statistics_ia_counter *data;
		struct rte_hash *dict = telemetry_ctx->worker[worker_id]->ia_dict;
		for (uint32_t iterator = 0; rte_hash_iterate(dict, (const void **)&key,
											(void **)&data, &iterator) >= 0;) {
			char out[1028];
			sprintf(out, PRIISDAS ", %d",
					PRIISDAS_VAL(rte_be_to_cpu_64(key->ia)),
					rte_be_to_cpu_16(key->drkey_protocol));
			rte_tel_data_add_array_string(d, out);
		}
		/*
		 * We assume that all workers have the same keys in their dictionary.
		 * So we can break the loop here.
		 */
		break;
	}
	rte_spinlock_unlock(&telemetry_ctx->management_lock);
	return 0;
}

/** TODO
 * params:
 * - Null: aggregated over all ISD ASes and DRKey protocols
 * - "<ISD AS>,<DRKey protocol>": statistics for a specific ISD AS and DRKey
 * - "?,?": statistics for non-tracked ISD-ASes and DRKey protocols
 * protocol
 */
static int
handle_ia_stats(const char *cmd __rte_unused, const char *p,
		struct rte_tel_data *d)
{
	int res, err = 0;
	char params[200];
	char *tokens[2];
	uint64_t isd_as;
	uint64_t drkey_protocol;
	int worker_id;
	struct lf_statistics_ia_counter total_stats;
	memset(&total_stats, 0, sizeof(total_stats));

	rte_spinlock_lock(&telemetry_ctx->management_lock);
	rte_tel_data_start_dict(d);
	if (p == NULL) {
		for (worker_id = 0; worker_id < telemetry_ctx->nb_workers;
				worker_id++) {
			struct lf_statistics_ia_key *key;
			struct lf_statistics_ia_counter *data;
			struct rte_hash *dict = telemetry_ctx->worker[worker_id]->ia_dict;
			for (uint32_t iterator = 0;
					rte_hash_iterate(dict, (const void **)&key, (void **)&data,
							&iterator) >= 0;) {
				add_ia_statistics(&total_stats, &total_stats, data);
			}
		}
	} else {
		strcpy(params, p);
		tokens[0] = strtok(params, ",");
		if (tokens[0] == NULL) {
			LF_STATISTICS_LOG(ERR, "unexpected parameter 0 (must contain "
								   "ISD-AS and DRKey protocol number)\n");
			err = -1;
			goto error;
		}
		tokens[1] = strtok(NULL, ",");
		if (tokens[1] == NULL) {
			LF_STATISTICS_LOG(ERR, "unexpected parameter 1 (must contain "
								   "ISD-AS and DRKey protocol number)\n");
			err = -1;
			goto error;
		}
		if (strtok(NULL, ",") != NULL) {
			LF_STATISTICS_LOG(ERR, "unexpected parameter 2 (must contain "
								   "ISD-AS and DRKey protocol number)\n");
			err = -1;
			goto error;
		}
		if (strcmp(tokens[0], "?") == 0 && strcmp(tokens[1], "?") == 0) {
			for (worker_id = 0; worker_id < telemetry_ctx->nb_workers;
					worker_id++) {
				add_ia_statistics(&total_stats, &total_stats,
						&telemetry_ctx->worker[worker_id]->untracked_ia);
			}
		} else {
			res = lf_parse_isd_as(tokens[0], &isd_as);
			if (res != 0) {
				LF_STATISTICS_LOG(ERR,
						"unexpected parameter (failed to parse ISD-AS)\n");
				err = -1;
				goto error;
			}
			res = lf_parse_unum(tokens[1], &drkey_protocol);
			if (res != 0 || drkey_protocol > UINT16_MAX) {
				LF_STATISTICS_LOG(ERR, "unexpected parameter (failed to parse "
									   "DRKey protocol number)\n");
				err = -1;
				goto error;
			}
			for (worker_id = 0; worker_id < telemetry_ctx->nb_workers;
					worker_id++) {
				struct lf_statistics_ia_key key = {
					.ia = rte_cpu_to_be_64(isd_as),
					.drkey_protocol =
							rte_cpu_to_be_16((uint16_t)drkey_protocol),
				};
				struct lf_statistics_ia_counter *data;
				res = rte_hash_lookup_data(
						telemetry_ctx->worker[worker_id]->ia_dict, &key,
						(void **)&data);
				if (res < 0) {
					LF_STATISTICS_LOG(ERR,
							"unexpected parameter (not found <ISD-AS>,<DRKey "
							"Protocol>: " PRIISDAS ",%d)\n",
							PRIISDAS_VAL(isd_as), drkey_protocol);
					err = -1;
					goto error;
				}
				add_ia_statistics(&total_stats, &total_stats, data);
			}
		}
	}
	telemetry_add_dict_ia_statistics(d, &total_stats);

error:
	rte_spinlock_unlock(&telemetry_ctx->management_lock);
	return err;
}

static int
handle_worker_stats(const char *cmd __rte_unused, const char *params,
		struct rte_tel_data *d)
{
	int worker_id;
	struct lf_statistics_worker_counter total_stats;
	memset(&total_stats, 0, sizeof(total_stats));

	rte_tel_data_start_dict(d);

	if (params) {
		worker_id = atoi(params);
		if (worker_id < 0 || worker_id >= telemetry_ctx->nb_workers) {
			return -EINVAL;
		}
		add_worker_statistics(&total_stats, &total_stats,
				&telemetry_ctx->worker[worker_id]->counter);
	} else {
		for (worker_id = 0; worker_id < telemetry_ctx->nb_workers;
				++worker_id) {
			add_worker_statistics(&total_stats, &total_stats,
					&telemetry_ctx->worker[worker_id]->counter);
		}
	}
	telemetry_add_dict_worker_statistics(d, &total_stats);
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

static struct lf_statistics_ia_counter *
dictionary_data_new()
{
	return rte_zmalloc(NULL, sizeof(struct lf_statistics_ia_counter), 0);
}

void
dictionary_data_free(void *p, void *key_data)
{
	assert(p == NULL);
	(void)p;
	rte_free(key_data);
}

static struct rte_hash *
dictionary_new(uint32_t size, uint16_t lcore_id, struct rte_rcu_qsbr *qsv)
{
	struct rte_hash *dic;
	struct rte_hash_parameters params = { 0 };
	/* rte_hash table name */
	char name[RTE_HASH_NAMESIZE];
	/* counter to ensure unique rte_hash table name */
	static int counter = 0;

	/* DPDK hash table entry must be at least 8 (undocumented) */
	if (size < 8) {
		LF_STATISTICS_LOG(ERR,
				"Hash creation failed because size is smaller than 8\n");
		return NULL;
	}

	snprintf(name, sizeof(name), "lf_s_d%d\n", counter);
	counter += 1;

	params.name = name;
	/* DPDK hash table entry must be at least 8 (undocumented) */
	params.entries = size;
	/* size of key struct */
	params.key_len = sizeof(struct lf_statistics_ia_key);
	/* hash function */
	params.hash_func = rte_jhash;
	params.hash_func_init_val = 0;
	/* socket ID for particular worker */
	params.socket_id = (int)rte_lcore_to_socket_id(lcore_id);
	/* ensure that insertion always succeeds */
	params.extra_flag = RTE_HASH_EXTRA_FLAGS_EXT_TABLE;
	/* Lock Free Read Write
	 * This is required because the dictionary entries might be changed while a
	 * worker accesses them
	 */
	params.extra_flag |= RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF;

	dic = rte_hash_create(&params);

	if (dic == NULL) {
		LF_STATISTICS_LOG(ERR, "Hash creation failed with: %d\n", errno);
		return NULL;
	}

	struct rte_hash_rcu_config rcu_conf = {
		.mode = RTE_HASH_QSBR_MODE_DQ,
		.free_key_data_func = dictionary_data_free,
		.v = qsv,
	};

	if (rte_hash_rcu_qsbr_add(dic, &rcu_conf) != 0) {
		LF_STATISTICS_LOG(ERR, "Fail to configure RCU for dictionary (%s)\n",
				rte_strerror(rte_errno));
		rte_hash_free(dic);
		return NULL;
	}

	/* (fstreun) Why is it not strictly smaller?
	 * key_id starts at 0 and should go up to size - 1!
	 */
	assert(rte_hash_max_key_id(dic) >= 0 &&
			(uint32_t)rte_hash_max_key_id(dic) <= size);

	LF_STATISTICS_LOG(DEBUG, "Created hash table (size = %d).\n", size);

	return dic;
}

static void
dictionary_free(struct rte_hash *dict)
{
	uint32_t iterator;
	struct lf_statistics_ia_key *key_ptr;
	struct lf_statistics_ia_counter *data;
	for (iterator = 0; rte_hash_iterate(dict, (void *)&key_ptr, (void **)&data,
							   &iterator) >= 0;) {
		rte_free(data);
	}
	rte_hash_free(dict);
}

static int
dictionary_update(struct rte_hash *dict, const struct lf_config *config)
{
	int err = 0, res = 0;
	int key_id;
	uint32_t iterator;
	bool is_in_list;
	struct lf_statistics_ia_key *key_ptr;
	struct lf_statistics_ia_counter *dictionary_data;
	struct lf_config_peer *peer;

	/* remove dictionary entries which are not in the config */
	for (iterator = 0; (key_id = rte_hash_iterate(dict, (void *)&key_ptr,
								(void **)&dictionary_data, &iterator)) >= 0;) {
		is_in_list = false;
		for (peer = config->peers; peer != NULL; peer = peer->next) {
			if (peer->isd_as == key_ptr->ia &&
					peer->drkey_protocol == key_ptr->drkey_protocol) {
				is_in_list = true;
				break;
			}
		}

		if (!is_in_list) {
			LF_STATISTICS_LOG(DEBUG,
					"Remove entry for AS " PRIISDAS " DRKey protocol %u\n",
					PRIISDAS_VAL(rte_be_to_cpu_64(key_ptr->ia)),
					key_ptr->drkey_protocol);
			(void)rte_hash_del_key(dict, key_ptr);
		}
	}

	/* add dictionary entries according to the config */
	for (peer = config->peers; peer != NULL; peer = peer->next) {
		struct lf_statistics_ia_key key;
		key.ia = peer->isd_as;
		key.drkey_protocol = peer->drkey_protocol;
		key_id = rte_hash_lookup_data(dict, &key, (void **)&dictionary_data);

		if (key_id < 0) {
			/* entry does not exist yet */
			LF_STATISTICS_LOG(DEBUG,
					"Add statistics for IA " PRIISDAS
					" and DRKey protocol %u. \n",
					PRIISDAS_VAL(rte_be_to_cpu_64(key.ia)),
					rte_be_to_cpu_16(key.drkey_protocol));

			dictionary_data = dictionary_data_new();
			if (dictionary_data == NULL) {
				LF_STATISTICS_LOG(ERR, "Fail to allocate memory for dictionary "
									   "entry.\n");
				return key_id;
			}
			res = rte_hash_add_key_data(dict, &key, (void *)dictionary_data);
			if (res != 0) {
				LF_STATISTICS_LOG(ERR, "Fail to add dictionary entry.\n");
				rte_free(dictionary_data);
				err = res;
			}
		}
	}
	return err;
}

int
lf_statistics_apply_config(struct lf_statistics *stats,
		const struct lf_config *config)
{
	int err = 0;
	int res;
	uint16_t worker_id;

	rte_spinlock_lock(&stats->management_lock);

	for (worker_id = 0; worker_id < stats->nb_workers; worker_id++) {
		res = dictionary_update(stats->worker[worker_id]->ia_dict, config);
		if (res != 0) {
			err = res;
		}
	}

	rte_spinlock_unlock(&stats->management_lock);
	return err;
}

void
lf_statistics_close(struct lf_statistics *stats)
{
	rte_spinlock_lock(&stats->management_lock);
	telemetry_ctx = NULL;

	for (uint16_t worker_id = 0; worker_id < stats->nb_workers; ++worker_id) {
		dictionary_free(stats->worker[worker_id]->ia_dict);
		stats->worker[worker_id]->ia_dict = NULL;
		rte_free(stats->worker[worker_id]);
		stats->worker[worker_id] = NULL;
	}
	rte_spinlock_unlock(&stats->management_lock);
}

int
lf_statistics_init(struct lf_statistics *stats,
		uint16_t worker_lcores[LF_MAX_WORKER], uint16_t nb_workers,
		struct rte_rcu_qsbr *qsv)
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
		reset_worker_statistics(&stats->worker[worker_id]->counter);
		stats->worker[worker_id]->ia_dict = dictionary_new(
				LF_STATISTICS_IA_DICT_INIT_SIZE, worker_lcores[worker_id], qsv);
		if (stats->worker[worker_id]->ia_dict == NULL) {
			LF_STATISTICS_LOG(ERR, "Fail to configure dictionary.\n");
			return -1;
		}
	}

	rte_spinlock_init(&stats->management_lock);

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

	/* register /ia/stats */
	res = rte_telemetry_register_cmd(LF_TELEMETRY_PREFIX "/ia/stats",
			handle_ia_stats, "Returns ISD AS statistics.\n");
	if (res != 0) {
		LF_STATISTICS_LOG(ERR, "Failed to register telemetry: %d\n", res);
	}

	/* register /ia/stats/list */
	res = rte_telemetry_register_cmd(LF_TELEMETRY_PREFIX "/ia/stats/list",
			handle_ia_stats_list,
			"Returns a list of ISD AS and DRKey protocol numbers that are "
			"being tracked.\n"
			"The output can be used as parameters for IA stats.");
	if (res != 0) {
		LF_STATISTICS_LOG(ERR, "Failed to register telemetry: %d\n", res);
	}

	return 0;
}
