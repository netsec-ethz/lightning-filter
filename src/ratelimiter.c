/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdatomic.h>
#include <stdlib.h>

#include <rte_branch_prediction.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_malloc.h>

#include "config.h"
#include "lf.h"
#include "lib/ipc/ipc.h"
#include "lib/log/log.h"
#include "lib/math/sat_op.h"
#include "lib/math/util.h"
#include "lib/ratelimiter/token_bucket.h"
#include "lib/utils/parse.h"
#include "ratelimiter.h"

/*
 * Synchronization and Atomic Operations:
 * There are multiple memory locations shared between workers and managers; the
 * dictionary and the buckets.
 *
 * For the key dictionary, the rte_hash is used, which provides a lock-free RW
 * implementation. This is sufficient, since entries are rarely added or
 * removed. Since only the manager accesses the data stored in the dictionary,
 * it can be freed without synchronizing with the workers.
 *
 * Updates to a worker's bucket, i.e., changing a bucket's rate and burst, is
 * always performed atomically with relaxed memory order.
 *
 * The manager lock ensures that updates to the dictionary and the workers'
 * buckets cannot interleave.
 */

/**
 * Log function for ratelimiter service (not on data path).
 * Format: "Ratelimiter: log message here"
 */
#define LF_RATELIMITER_LOG(level, ...) \
	LF_LOG(level, "Ratelimiter: " __VA_ARGS__)

static inline void
dictionary_data_set(struct lf_ratelimiter_data *dict_data, uint64_t byte_rate,
		uint64_t byte_burst, uint64_t packet_rate, uint64_t packet_burst)
{
	dict_data->byte_rate = byte_rate;
	dict_data->byte_burst = byte_burst;
	dict_data->packet_rate = packet_rate;
	dict_data->packet_burst = packet_burst;
}

static int
dictionary_set(struct rte_hash *dict,
		const struct lf_ratelimiter_key *dictionary_key, uint64_t byte_rate,
		uint64_t byte_burst, uint64_t packet_rate, uint64_t packet_burst)
{
	int res, key_id;
	struct lf_ratelimiter_data *dictionary_data;

	key_id = rte_hash_lookup_data(dict, dictionary_key,
			(void **)&dictionary_data);

	if (key_id < 0) {
		/* entry does not exist yet */
		dictionary_data =
				rte_zmalloc(NULL, sizeof(struct lf_ratelimiter_data), 0);
		if (dictionary_data == NULL) {
			LF_RATELIMITER_LOG(ERR, "Fail to allocate memory for dictionary "
									"entry.\n");
			return key_id;
		}
		res = rte_hash_add_key_data(dict, dictionary_key,
				(void *)dictionary_data);
		if (res != 0) {
			LF_RATELIMITER_LOG(ERR, "Fail to add dictionary entry.\n");
			rte_free(dictionary_data);
			return res;
		}
		key_id = rte_hash_lookup(dict, dictionary_key);
		assert(key_id >= 0);
	}
	dictionary_data_set(dictionary_data, byte_rate, byte_burst, packet_rate,
			packet_burst);

	LF_RATELIMITER_LOG(DEBUG,
			"Set ratelimit for AS " PRIISDAS
			" and DRKey protocol %u: byte rate = %" PRIu64
			" , packet rate = %" PRIu64 " (key_id = %d).\n",
			PRIISDAS_VAL(rte_be_to_cpu_64(dictionary_key->as)),
			rte_be_to_cpu_16(dictionary_key->drkey_protocol), byte_rate,
			packet_rate, key_id);
	return key_id;
}

static struct rte_hash *
dictionary_new(uint32_t size)
{
	struct rte_hash *dic;
	struct rte_hash_parameters params = { 0 };
	/* rte_hash table name */
	char name[RTE_HASH_NAMESIZE];
	/* counter to ensure unique rte_hash table name */
	static int counter = 0;

	/* DPDK hash table entry must be at least 8 (undocumented) */
	if (size < 8) {
		LF_RATELIMITER_LOG(ERR,
				"Hash creation failed because size is smaller than 8\n");
		return NULL;
	}

	snprintf(name, sizeof(name), "lf_rl_dict_%d\n", counter);
	counter += 1;

	params.name = name;
	/* DPDK hash table entry must be at least 8 (undocumented) */
	params.entries = size;
	/* AS + drkey_protocol */
	params.key_len = sizeof(struct lf_ratelimiter_key);
	/* hash function */
	params.hash_func = rte_jhash;
	params.hash_func_init_val = 0;
	/* TODO: (fstreun) potentially use multiple hash tables for different
	 * NUMA sockets */
	params.socket_id = (int)rte_socket_id();
	/* ensure that insertion always succeeds */
	params.extra_flag = RTE_HASH_EXTRA_FLAGS_EXT_TABLE;
	/* Lock Free Read Write */
	params.extra_flag |= RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF;

	dic = rte_hash_create(&params);

	if (dic == NULL) {
		LF_RATELIMITER_LOG(ERR, "Hash creation failed with: %d\n", errno);
		rte_hash_free(dic);
		return NULL;
	}

	/* (fstreun) Why is it not strictly smaller?
	 * key_id starts at 0 and should go up to size - 1!
	 */
	assert(rte_hash_max_key_id(dic) >= 0 &&
			(uint32_t)rte_hash_max_key_id(dic) <= size);

	LF_RATELIMITER_LOG(DEBUG, "Created hash table (size = %d).\n", size);

	return dic;
}

static void
dictionary_free(struct rte_hash *dict)
{
	uint32_t iterator;
	struct lf_ratelimiter_dictionary_key *key_ptr;
	struct lf_ratelimiter_dictionary_data *data;

	for (iterator = 0; rte_hash_iterate(dict, (void *)&key_ptr, (void **)&data,
							   &iterator) >= 0;) {
		rte_free(data);
	}
	rte_hash_free(dict);
}

/**
 * Set AS rate limit. Requires the management lock!
 */
static int
set_as_limit(struct lf_ratelimiter *rl, uint64_t isd_as,
		uint16_t drkey_protocol, uint64_t byte_rate, uint64_t byte_burst,
		uint64_t packet_rate, uint64_t packet_burst)
{
	int key_id;
	struct lf_ratelimiter_key dictionary_key;
	int worker_id;

	dictionary_key.as = isd_as;
	dictionary_key.drkey_protocol = drkey_protocol;
	key_id = dictionary_set(rl->dict, &dictionary_key, byte_rate, byte_burst,
			packet_rate, packet_burst);
	if (key_id < 0) {
		/* potentially there is no space in the dictionary */
		return -1;
	}
	for (worker_id = 0; worker_id < rl->nb_workers; ++worker_id) {
		lf_token_bucket_set(&rl->workers[worker_id]->buckets[key_id].byte,
				byte_rate / rl->nb_workers, byte_burst / rl->nb_workers);
		lf_token_bucket_set(&rl->workers[worker_id]->buckets[key_id].packet,
				packet_rate / rl->nb_workers, packet_burst / rl->nb_workers);
	}
	if (rl->nb_workers > 0) {
		LF_RATELIMITER_LOG(DEBUG,
				"Per-worker rate limit: byte rate = %" PRIu64
				" , packet rate = %" PRIu64 ".\n",
				byte_rate / rl->nb_workers, packet_rate / rl->nb_workers);
	}

	return 0;
}

/**
 * Set overall rate limit. Requires the managements lock!
 */
static int
set_overall_limit(struct lf_ratelimiter *rl, uint64_t byte_rate,
		uint64_t byte_burst, uint64_t packet_rate, uint64_t packet_burst)
{
	int worker_id;
	LF_RATELIMITER_LOG(DEBUG,
			"Set overall ratelimit (byte_rate: %ld, "
			"packet_rate: %ld\n",
			byte_rate, packet_rate);
	dictionary_data_set(&rl->overall, byte_rate, byte_burst, packet_rate,
			packet_burst);
	for (worker_id = 0; worker_id < rl->nb_workers; ++worker_id) {
		lf_token_bucket_set(&rl->workers[worker_id]->overall.byte,
				byte_rate / rl->nb_workers, byte_burst / rl->nb_workers);
		lf_token_bucket_set(&rl->workers[worker_id]->overall.packet,
				packet_rate / rl->nb_workers, packet_burst / rl->nb_workers);
	}

	return 0;
}

/**
 * Set auth peers rate limit. Requires the managements lock!
 */
static int
set_auth_peers_limit(struct lf_ratelimiter *rl, uint64_t byte_rate,
		uint64_t byte_burst, uint64_t packet_rate, uint64_t packet_burst)
{
	int worker_id;
	LF_RATELIMITER_LOG(DEBUG,
			"Set auth peers rate limit (byte_rate: %ld, "
			"packet_rate: %ld\n",
			byte_rate, packet_rate);
	dictionary_data_set(&rl->auth_peers, byte_rate, byte_burst, packet_rate,
			packet_burst);
	for (worker_id = 0; worker_id < rl->nb_workers; ++worker_id) {
		lf_token_bucket_set(&rl->workers[worker_id]->auth_peers.byte,
				byte_rate / rl->nb_workers, byte_burst / rl->nb_workers);
		lf_token_bucket_set(&rl->workers[worker_id]->auth_peers.packet,
				packet_rate / rl->nb_workers, packet_burst / rl->nb_workers);
	}

	return 0;
}

/**
 * Set best-effort rate limit. Requires the managements lock!
 */
static int
set_besteffort_limit(struct lf_ratelimiter *rl, uint64_t byte_rate,
		uint64_t byte_burst, uint64_t packet_rate, uint64_t packet_burst)
{
	int worker_id;
	LF_RATELIMITER_LOG(DEBUG,
			"Set best-effort ratelimit (byte_rate: %ld, "
			"packet_rate: %ld\n",
			byte_rate, packet_rate);
	dictionary_data_set(&rl->best_effort, byte_rate, byte_burst, packet_rate,
			packet_burst);
	for (worker_id = 0; worker_id < rl->nb_workers; ++worker_id) {
		lf_token_bucket_set(&rl->workers[worker_id]->best_effort.byte,
				byte_rate / rl->nb_workers, byte_burst / rl->nb_workers);
		lf_token_bucket_set(&rl->workers[worker_id]->best_effort.packet,
				packet_rate / rl->nb_workers, packet_burst / rl->nb_workers);
	}

	return 0;
}

void
synchronize_worker(struct lf_ratelimiter *rl)
{
	rte_rcu_qsbr_synchronize(rl->qsv, RTE_QSBR_THRID_INVALID);
}

int
lf_ratelimiter_apply_config(struct lf_ratelimiter *rl, struct lf_config *config)
{
	int err = 0;
	int key_id;
	uint32_t ratelimit_counter;
	uint32_t iterator;
	bool is_in_list;
	struct lf_ratelimiter_key *key_ptr;
	struct lf_ratelimiter_data *dictionary_data;
	struct lf_config_peer *peer;
	int worker_id;

	rte_spinlock_lock(&rl->management_lock);
	LF_RATELIMITER_LOG(NOTICE, "Apply config...\n");

	/*
	 * Check that the number of peers with rate limits does not exceed the table
	 * size
	 */
	ratelimit_counter = 0;
	for (peer = config->peers; peer != NULL; peer = peer->next) {
		if (peer->ratelimit_option) {
			ratelimit_counter++;
		}
	}
	if (ratelimit_counter > rl->size) {
		LF_RATELIMITER_LOG(WARNING,
				"Number of peers with rate limits (%u) is bigger than "
				"dictionary size (%d)!\n",
				ratelimit_counter, rl->size);
		err = -1;
		goto exit;
	}

	/* remove dictionary entries which are not anymore in config */
	for (iterator = 0; (key_id = rte_hash_iterate(rl->dict, (void *)&key_ptr,
								(void **)&dictionary_data, &iterator)) >= 0;) {
		is_in_list = false;
		for (peer = config->peers; peer != NULL; peer = peer->next) {
			if (peer->isd_as == key_ptr->as &&
					peer->drkey_protocol == key_ptr->drkey_protocol) {
				is_in_list = true;
				break;
			}
		}

		if (!is_in_list) {

			LF_RATELIMITER_LOG(DEBUG,
					"Remove entry for AS " PRIISDAS " DRKey protocol %u\n",
					PRIISDAS_VAL(rte_be_to_cpu_64(key_ptr->as)),
					key_ptr->drkey_protocol);
			(void)rte_hash_del_key(rl->dict, key_ptr);
			rte_free(dictionary_data);

			for (worker_id = 0; worker_id < rl->nb_workers; ++worker_id) {
				lf_token_bucket_set(
						&rl->workers[worker_id]->buckets[key_id].byte, 0, 0);
				lf_token_bucket_set(
						&rl->workers[worker_id]->buckets[key_id].packet, 0, 0);
			}
		}
	}

	/*
	 * Wait for all workers to observe the removal of entries.
	 * This is required to be performed between removing and adding entries.
	 * Otherwise the worker might apply wrong rate limits!
	 * When removing AS A from the hash table and add AS B, the worker's token
	 * bucket might not have update due to the relaxed memory order. Hence, a
	 * worker looking up AS B in the dictionary would receive the key_id which
	 * points to the token bucket corresponding to AS A.
	 */
	synchronize_worker(rl);

	/* set (or add) dictionary entries according to config */
	for (peer = config->peers; peer != NULL; peer = peer->next) {
		err = set_as_limit(rl, peer->isd_as, peer->drkey_protocol,
				peer->ratelimit.byte_rate, peer->ratelimit.byte_burst,
				peer->ratelimit.packet_rate, peer->ratelimit.packet_burst);
		if (err != 0) {
			goto exit;
		}
	}

	/* set overall rate limit */
	(void)set_overall_limit(rl, config->ratelimit.byte_rate,
			config->ratelimit.byte_burst, config->ratelimit.packet_rate,
			config->ratelimit.packet_burst);

	/* set best effort traffic rate limits */
	(void)set_auth_peers_limit(rl, config->auth_peers.ratelimit.byte_rate,
			config->auth_peers.ratelimit.byte_burst,
			config->auth_peers.ratelimit.packet_rate,
			config->auth_peers.ratelimit.packet_burst);

	/* set best effort traffic rate limits */
	(void)set_besteffort_limit(rl, config->best_effort.ratelimit.byte_rate,
			config->best_effort.ratelimit.byte_burst,
			config->best_effort.ratelimit.packet_rate,
			config->best_effort.ratelimit.packet_burst);

	synchronize_worker(rl);

exit:
	rte_spinlock_unlock(&rl->management_lock);
	if (err != 0) {
		LF_RATELIMITER_LOG(NOTICE, "Config apply failed\n");
		return -1;
	}

	LF_RATELIMITER_LOG(NOTICE, "Config applied successfully\n");
	return 0;
}

void
lf_ratelimiter_close(struct lf_ratelimiter *rl)
{
	size_t i;

	rte_hash_free(rl->dict);

	for (i = 0; i < rl->nb_workers; i++) {
		rte_free(rl->workers[i]);
	}

	dictionary_free(rl->dict);
}

int
lf_ratelimiter_init(struct lf_ratelimiter *rl,
		uint16_t worker_lcores[LF_MAX_WORKER], uint16_t nb_workers,
		uint32_t initial_size, struct rte_rcu_qsbr *qsv,
		struct lf_ratelimiter_worker *workers[LF_MAX_WORKER])
{
	size_t i;

	LF_RATELIMITER_LOG(DEBUG, "Init\n");

	assert(nb_workers <= sizeof(rl->workers) / sizeof(rl->workers[0]));

	rl->qsv = qsv;
	rl->nb_workers = nb_workers;

	/* dictionary requires a size of at least 8 (magic number) */
	// NOLINTBEGIN(readability-magic-numbers)
	if (initial_size < 8) {
		initial_size = 8;
	}
	// NOLINTEND(readability-magic-numbers)

	rl->size = initial_size;
	rl->dict = dictionary_new(initial_size);
	if (rl->dict == NULL) {
		return -1;
	}

	rte_spinlock_init(&rl->management_lock);

	/* init overall rate limit */
	dictionary_data_set(&rl->overall, 0, 0, 0, 0);
	/* init auth peers rate limit */
	dictionary_data_set(&rl->auth_peers, 0, 0, 0, 0);
	/* init best-effort rate limit */
	dictionary_data_set(&rl->best_effort, 0, 0, 0, 0);

	for (i = 0; i < nb_workers; ++i) {
		workers[i]->dict = rl->dict;

		/* init workers' buckets */
		workers[i]->buckets = rte_calloc_socket(NULL, initial_size,
				sizeof(*workers[i]->buckets), RTE_CACHE_LINE_SIZE,
				(int)rte_lcore_to_socket_id(worker_lcores[i]));
		if (workers[i]->buckets == NULL) {
			LF_RATELIMITER_LOG(ERR,
					"Fail to allocate memory for worker dictionary data.\n");
		}

		/* update worker's context */
		rl->workers[i] = workers[i];
	}

	return 0;
}

/*
 * Ratelimiter IPC Functionalities
 */

/* Ratelimiter context used when IPC commands are processed. */
static struct lf_ratelimiter *rl_ctx;

static int
ipc_ratelimit_set(const char *cmd __rte_unused, const char *p, char *out_buf,
		size_t buf_len)
{
	int res;
	int i;
	char params[200];
	char *tokens[6];
	uint64_t isd_as;
	uint64_t parsed_num;
	uint16_t drkey_proto;
	uint64_t byte_rate, byte_burst, pkt_rate, pkt_burst;

	if (p == NULL) {
		return -1;
	}

	strcpy(params, p);

	tokens[0] = strtok(params, ",");
	if (tokens[0] == NULL) {
		return -1;
	}
	for (i = 1; i < 6; ++i) {
		tokens[i] = strtok(NULL, ",");
		if (tokens[i] == NULL) {
			return -1;
		}
	}
	if (strtok(NULL, ",") != NULL) {
		return -1;
	}

	/* parse the provided rate limits */
	res = lf_parse_unum(tokens[2], &byte_rate);
	if (res != 0) {
		return -1;
	}
	res = lf_parse_unum(tokens[3], &byte_burst);
	if (res != 0) {
		return -1;
	}
	res = lf_parse_unum(tokens[4], &pkt_rate);
	if (res != 0) {
		return -1;
	}
	res = lf_parse_unum(tokens[5], &pkt_burst);
	if (res != 0) {
		return -1;
	}

	/*
	 * First two parameters differentiate between setting rate limit for
	 * - specific AS and DRKey protocol
	 * - all traffic
	 * - auth peers
	 * - best-effort traffic
	 */
	if (strcmp(tokens[0], "-") == 0 && strcmp(tokens[1], "-") == 0) {
		/* overall rate limit */
		rte_spinlock_lock(&rl_ctx->management_lock);
		res = set_overall_limit(rl_ctx, byte_rate, byte_burst, pkt_rate,
				pkt_burst);
		rte_spinlock_unlock(&rl_ctx->management_lock);
		if (res != 0) {
			return -1;
		}
		return snprintf(out_buf, buf_len,
				"successfully set rate limit for all traffic");
	} else if (strcmp(tokens[0], "*") == 0 && strcmp(tokens[1], "*") == 0) {
		/* auth peers rate limit */
		rte_spinlock_lock(&rl_ctx->management_lock);
		res = set_auth_peers_limit(rl_ctx, byte_rate, byte_burst, pkt_rate,
				pkt_burst);
		rte_spinlock_unlock(&rl_ctx->management_lock);
		if (res != 0) {
			return -1;
		}
		return snprintf(out_buf, buf_len,
				"successfully set rate limit for auth peers");
	} else if (strcmp(tokens[0], "?") == 0 && strcmp(tokens[1], "?") == 0) {
		/* best-effort rate limit */
		rte_spinlock_lock(&rl_ctx->management_lock);
		res = set_besteffort_limit(rl_ctx, byte_rate, byte_burst, pkt_rate,
				pkt_burst);
		rte_spinlock_unlock(&rl_ctx->management_lock);
		if (res != 0) {
			return -1;
		}
		return snprintf(out_buf, buf_len,
				"successfully set rate limit for best-effort traffic");
	} else {
		/* peer rate limit */
		res = lf_parse_isd_as(tokens[0], &isd_as);
		if (res != 0) {
			return -1;
		}
		isd_as = rte_cpu_to_be_64(isd_as);

		res = lf_parse_unum(tokens[1], &parsed_num);
		if (res != 0 || parsed_num > UINT16_MAX) {
			return -1;
		}
		drkey_proto = rte_cpu_to_be_16((uint16_t)parsed_num);

		rte_spinlock_lock(&rl_ctx->management_lock);
		res = set_as_limit(rl_ctx, isd_as, drkey_proto, byte_rate, byte_burst,
				pkt_rate, pkt_burst);
		rte_spinlock_unlock(&rl_ctx->management_lock);
		if (res != 0) {
			return -1;
		}
		return snprintf(out_buf, buf_len,
				"successfully set rate limit for AS and DRKey protocol");
	}
}

int
lf_ratelimiter_register_ipc(struct lf_ratelimiter *rl)
{
	int res;
	rl_ctx = rl;
	/*
	 * parameter:
	 */
	res = lf_ipc_register_cmd("/ratelimiter/set", ipc_ratelimit_set,
			"Set rate limit.\n"
			"Please note that the set value is not persistent "
			"and will be overridden when updating the configuration.\n"
			"parameter (peer): <AS>,<DRKey-Proto>,<rate>\n"
			"parameter (overall): -,-,<rate>\n"
			"parameter (auth peers): *,*,<rate>\n"
			"parameter (best-effort): ?,?,<rate>\n"
			"rate: <byte_rate>,<byte_burst>,<pkt_rate>,<pkt_burst>");
	if (res != 0) {
		return -1;
	}

	return 0;
}

#undef inc_mod2