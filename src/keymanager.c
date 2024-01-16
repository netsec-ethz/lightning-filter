/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#include <inttypes.h>

#include <rte_branch_prediction.h>
#include <rte_byteorder.h>
#include <rte_cycles.h>
#include <rte_jhash.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_spinlock.h>
#include <rte_telemetry.h>

#include "config.h"
#include "drkey_fetcher.h"
#include "keyfetcher.h"
#include "keymanager.h"
#include "lib/crypto/crypto.h"
#include "lib/ipc/ipc.h"
#include "lib/log/log.h"
#include "lib/telemetry/counters.h"
#include "lib/time/time.h"

/*
 * Synchronization and Atomic Operations:
 * For the key dictionary, the rte_hash is used, which provides a lock-free RW
 * implementation. This is sufficient, since key updates only happen rarely.
 * After updating (or removing) a key, the old memory is freed after all workers
 * pass through the quiescent state. This ensures, that no worker still accesses
 * the memory.
 * The manager lock ensures that updates to the dictionary cannot interleave.
 */

/**
 * Log function for key manager service (not on data path).
 * Format: "Keymanager: log message here"
 */
#define LF_KEYMANAGER_LOG(level, ...) LF_LOG(level, "Keymanager: " __VA_ARGS__)

struct linked_list {
	void *data;
	void *next;
};

static void
linked_list_push(struct linked_list **head_ref, void *data)
{
	struct linked_list *new = rte_malloc(NULL, sizeof(struct linked_list), 0);
	new->data = data;
	new->next = *head_ref;
	*head_ref = new;
}

static void
linked_list_free(struct linked_list *ll)
{
	struct linked_list *next;
	while (ll != NULL) {
		rte_free(ll->data);
		next = ll->next;
		rte_free(ll);
		ll = next;
	}
}

/**
 * Wait for all workers to be in the quiescent state.
 */
inline static void
synchronize_worker(struct lf_keymanager *km)
{
	(void)rte_rcu_qsbr_synchronize(km->qsv, RTE_QSBR_THRID_INVALID);
}


void
lf_keymanager_service_update(struct lf_keymanager *km)
{
	int res;
	int err = 0;
	struct lf_keymanager_dictionary_key *key_ptr;
	uint32_t iterator;
	struct lf_keymanager_dictionary_data *data, *new_data;
	uint64_t ns_now;

	/* memory to be freed later */
	struct linked_list *free_list = NULL;

	if (lf_time_get(&ns_now) != 0) {
		LF_KEYMANAGER_LOG(ERR, "Fail to get current time\n");
		return;
	}

	/* Check if inbound keys are required to be updated */
	(void)rte_spinlock_lock(&km->management_lock);
	for (iterator = 0; rte_hash_iterate(km->dict, (void *)&key_ptr,
							   (void **)&data, &iterator) >= 0;) {
		if (ns_now + LF_DRKEY_PREFETCHING_PERIOD >=
				data->inbound_key.validity_not_after) {
			/*
			 * create new node and copy everything from old node
			 */
			new_data = rte_malloc(NULL,
					sizeof(struct lf_keymanager_dictionary_data), 0);
			if (new_data == NULL) {
				LF_KEYMANAGER_LOG(ERR,
						"Fail to allocate memory for key update\n");
				err = -1;
				goto exit;
			}
			(void)rte_memcpy(new_data, data,
					sizeof(struct lf_keymanager_dictionary_data));

			res = lf_keyfetcher_fetch_as_as_key(km->fetcher, key_ptr->as,
					km->src_as, key_ptr->drkey_protocol, ns_now,
					&new_data->inbound_key);
			if (res < 0) {
				rte_free(new_data);
				err = -1;
				goto exit;
			}

			/* keep key as old key */
			(void)rte_memcpy(&new_data->old_inbound_key, &data->inbound_key,
					sizeof(struct lf_keymanager_key_container));

			/* add new node to dictionary */
			res = rte_hash_add_key_data(km->dict, key_ptr, (void *)new_data);
			if (res != 0) {
				LF_KEYMANAGER_LOG(ERR,
						"Fail to add inbound key to dictionary (err = %d)\n",
						res);
				rte_free(new_data);
				err = -1;
				goto exit;
			}
			/* free old dictionary data later */
			(void)linked_list_push(&free_list, data);
		}
	}

	/* Check if outbound keys are required to be updated */
	for (iterator = 0; rte_hash_iterate(km->dict, (void *)&key_ptr,
							   (void **)&data, &iterator) >= 0;) {
		if (ns_now + LF_DRKEY_PREFETCHING_PERIOD >=
				data->outbound_key.validity_not_after) {
			/*
			 * create new node and copy everything from old node
			 */
			new_data = rte_malloc(NULL,
					sizeof(struct lf_keymanager_dictionary_data), 0);
			if (new_data == NULL) {
				LF_KEYMANAGER_LOG(ERR,
						"Fail to allocate memory for key update\n");
				err = -1;
				goto exit;
			}
			(void)rte_memcpy(new_data, data,
					sizeof(struct lf_keymanager_dictionary_data));

			res = lf_keyfetcher_fetch_as_as_key(km->fetcher, km->src_as,
					key_ptr->as, key_ptr->drkey_protocol, ns_now,
					&new_data->outbound_key);
			if (res < 0) {
				rte_free(new_data);
				err = -1;
				goto exit;
			}

			/* keep key as old key */
			(void)rte_memcpy(&new_data->old_outbound_key, &data->outbound_key,
					sizeof(struct lf_keymanager_key_container));

			/* add new node to dictionary */
			res = rte_hash_add_key_data(km->dict, key_ptr, (void *)new_data);
			if (res != 0) {
				LF_KEYMANAGER_LOG(ERR,
						"Fail to add outbound key to dictionary (err = %d)\n",
						res);
				rte_free(new_data);
				err = -1;
				goto exit;
			}
			/* free old dictionary data later */
			(void)linked_list_push(&free_list, data);
		}
	}
exit:
	if (free_list != NULL) {
		/* free old data after no worker accesses it anymore */
		synchronize_worker(km);
		linked_list_free(free_list);
	}
	if (err != 0) {
		LF_KEYMANAGER_LOG(ERR, "Error occurred during update (err = %d)\n",
				err);
	}
	(void)rte_spinlock_unlock(&km->management_lock);
}

int
lf_keymanager_service_launch(struct lf_keymanager *km)
{
	uint64_t current_tsc, last_rotation_tsc, period_tsc;

	/* measure time using the time stamp counter */
	last_rotation_tsc = rte_rdtsc();
	period_tsc =
			(uint64_t)((double)rte_get_timer_hz() * LF_KEYMANAGER_INTERVAL);

	while (!lf_force_quit) {
		current_tsc = rte_rdtsc();
		if (current_tsc - last_rotation_tsc >= period_tsc) {
			(void)lf_keymanager_service_update(km);
			last_rotation_tsc = current_tsc;

			/* potentially the clock speed has changed */
			period_tsc = (uint64_t)((double)rte_get_timer_hz() *
									LF_KEYMANAGER_INTERVAL);
		}
	}

	return 0;
}

/**
 * @param size of table. Must be at least 8.
 * @return struct rte_hash*
 */
static struct rte_hash *
key_dictionary_init(uint32_t size)
{
	struct rte_hash *dic;
	struct rte_hash_parameters params = { 0 };
	/* rte_hash table name */
	char name[RTE_HASH_NAMESIZE];
	/* counter to ensure unique rte_hash table name */
	static int counter = 0;

	LF_KEYMANAGER_LOG(DEBUG, "Init\n");

	/* DPDK hash table entry must be at least 8 (undocumented) */
	if (size < 8) {
		LF_KEYMANAGER_LOG(ERR,
				"Hash creation failed because size is smaller than 8\n");
		return NULL;
	}

	(void)snprintf(name, sizeof(name), "key_dictionary_%d\n", counter);
	counter += 1;

	params.name = name;
	/* DPDK hash table entry must be at least 8 (undocumented) */
	params.entries = size;
	/* AS + drkey_protocol */
	params.key_len = sizeof(struct lf_keymanager_dictionary_key);
	/* hash function */
	params.hash_func = rte_jhash;
	params.hash_func_init_val = 0;
	/* TODO: (fstreun) potentially use multiple hash tables for different
	 * sockets */
	params.socket_id = (int)rte_socket_id();
	/* ensure that insertion always succeeds */
	params.extra_flag = RTE_HASH_EXTRA_FLAGS_EXT_TABLE;
	/* Lock Free Read Write */
	params.extra_flag |= RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF;

	dic = rte_hash_create(&params);

	if (dic == NULL) {
		LF_KEYMANAGER_LOG(ERR, "Hash creation failed with: %d\n", errno);
		rte_hash_free(dic);
		return NULL;
	}

	LF_KEYMANAGER_LOG(DEBUG, "Created hash table (size = %d)\n", size);

	return dic;
}

/**
 * Free all keys stored in the dictionary and the dictionary itself.
 */
static void
key_dictionary_free(struct rte_hash *dict)
{
	uint32_t iterator;
	struct lf_keymanager_dictionary_key *key_ptr;
	struct lf_keymanager_dictionary_data *data;

	for (iterator = 0; rte_hash_iterate(dict, (void *)&key_ptr, (void **)&data,
							   &iterator) >= 0;) {
		rte_free(data);
	}
	rte_hash_free(dict);
}

int
lf_keymanager_apply_config(struct lf_keymanager *km,
		const struct lf_config *config)
{
	int res, err = 0, key_id;
	uint32_t iterator;
	bool is_in_list;
	struct lf_keymanager_dictionary_key key, *key_ptr;
	struct lf_keymanager_dictionary_data *dictionary_data;
	struct lf_config_peer *peer;
	uint64_t ns_now;

	/* memory to be freed later */
	struct linked_list *free_list = NULL;

	rte_spinlock_lock(&km->management_lock);
	LF_KEYMANAGER_LOG(NOTICE, "Apply config...\n");

	lf_keyfetcher_apply_config(km->fetcher, config);

	/*
	 * Update general keymanager configurations
	 */
	km->src_as = config->isd_as;
	memcpy(km->drkey_service_addr, config->drkey_service_addr,
			sizeof km->drkey_service_addr);

	res = lf_time_get(&ns_now);
	if (res != 0) {
		LF_KEYMANAGER_LOG(ERR, "Cannot get current time\n");
		err = -1;
		goto exit_unlock;
	}

	/*
	 * Update key dictionary
	 */
	if (config->nb_peers > km->size) {
		/* Note that also the system limits are stored in the dictionary */
		LF_KEYMANAGER_LOG(WARNING,
				"Number of peers (%u) is bigger than dictionary size (%d)!",
				config->nb_peers, km->size);
		err = -1;
		goto exit_unlock;
	}

	/* remove dictionary entries which are not anymore in config */
	for (iterator = 0; rte_hash_iterate(km->dict, (void *)&key_ptr,
							   (void **)&dictionary_data, &iterator) >= 0;) {
		is_in_list = false;
		for (peer = config->peers; peer != NULL; peer = peer->next) {
			if (peer->isd_as == key_ptr->as &&
					peer->drkey_protocol == key_ptr->drkey_protocol) {
				is_in_list = true;
				break;
			}
		}
		if (!is_in_list) {
			LF_KEYMANAGER_LOG(DEBUG,
					"Remove entry for AS " PRIISDAS " DRKey protocol %u\n",
					PRIISDAS_VAL(rte_be_to_cpu_64(key_ptr->as)),
					rte_be_to_cpu_16(key_ptr->drkey_protocol));
			(void)rte_hash_del_key(km->dict, key_ptr);
			/* free data later */
			(void)linked_list_push(&free_list, dictionary_data);
		}
	}

	for (peer = config->peers; peer != NULL; peer = peer->next) {
		key.as = peer->isd_as;
		key.drkey_protocol = peer->drkey_protocol;

		key_id = rte_hash_lookup(km->dict, &key);
		if (key_id >= 0) {
			/* key is already in table */
			continue;
		}

		/* create new dictionary entry for key */
		dictionary_data = rte_malloc(NULL,
				sizeof(struct lf_keymanager_dictionary_data), 0);
		if (dictionary_data == NULL) {
			LF_KEYMANAGER_LOG(ERR, "Fail to allocate memory for key\n");
			err = 1;
			break;
		}

		res = lf_keyfetcher_fetch_as_as_key(km->fetcher, key.as, config->isd_as,
				key.drkey_protocol, ns_now, &dictionary_data->inbound_key);
		if (res < 0) {
			dictionary_data->inbound_key.validity_not_after = 0;
		}

		res = lf_keyfetcher_fetch_as_as_key(km->fetcher, config->isd_as, key.as,
				key.drkey_protocol, ns_now, &dictionary_data->outbound_key);
		if (res < 0) {
			dictionary_data->outbound_key.validity_not_after = 0;
		}

		dictionary_data->old_inbound_key.validity_not_after = 0;
		dictionary_data->old_outbound_key.validity_not_after = 0;

		res = rte_hash_add_key_data(km->dict, &key, (void *)dictionary_data);
		if (res != 0) {
			LF_KEYMANAGER_LOG(ERR, "Add key failed with %d!\n", key_id);
			rte_free(dictionary_data);
			err = 1;
			break;
		}
	}

	if (err != 0) {
		goto exit_unlock;
	}

exit_unlock:
	if (free_list != NULL) {
		/* free old data after no worker accesses it anymore */
		synchronize_worker(km);
		linked_list_free(free_list);
	}

	(void)rte_spinlock_unlock(&km->management_lock);

	if (err == 0) {
		LF_KEYMANAGER_LOG(NOTICE, "Config applied successfully\n");
		return 0;
	} else {
		LF_KEYMANAGER_LOG(NOTICE, "Config apply failed\n");
		return -1;
	}
}

static void
reset_statistics(struct lf_keymanager_statistics *counter)
{
	LF_KEYMANAGER_STATISTICS(LF_TELEMETRY_FIELD_RESET)
}

int
lf_keymanager_close(struct lf_keymanager *km)
{
	uint16_t worker_id;

	key_dictionary_free(km->dict);
	km->dict = NULL;
	lf_crypto_drkey_ctx_close(&km->drkey_ctx);
	for (worker_id = 0; worker_id < km->nb_workers; worker_id++) {
		km->workers[worker_id].dict = NULL;
		lf_crypto_drkey_ctx_close(&km->workers[worker_id].drkey_ctx);
	}
	lf_keyfetcher_close(km->fetcher);
	km->fetcher = NULL;
	return 0;
}

int
lf_keymanager_init(struct lf_keymanager *km, uint16_t nb_workers,
		uint32_t initial_size, struct rte_rcu_qsbr *qsv)
{
	int res;
	size_t i;

	km->qsv = qsv;
	km->nb_workers = nb_workers;

	rte_spinlock_init(&km->management_lock);

	/* dictionary requires a size of at least 8 (magic number) */
	// NOLINTBEGIN(readability-magic-numbers)
	if (initial_size < 8) {
		initial_size = 8;
	}
	// NOLINTEND(readability-magic-numbers)
	km->size = initial_size;

	km->dict = key_dictionary_init(initial_size);
	if (km->dict == NULL) {
		return -1;
	}

	km->src_as = 0;
	memset(km->drkey_service_addr, 0, sizeof km->drkey_service_addr);

	res = lf_crypto_drkey_ctx_init(&km->drkey_ctx);
	if (res != 0) {
		/* TODO: (fstreun) error handling*/
		return -1;
	}

	for (i = 0; i < nb_workers; ++i) {
		km->workers[i].dict = km->dict;
		res = lf_crypto_drkey_ctx_init(&km->workers[i].drkey_ctx);
		if (res != 0) {
			/* TODO: (fstreun) error handling*/
			return -1;
		}
	}

	reset_statistics(&km->statistics);

	struct lf_keyfetcher *fetcher;
	fetcher = malloc(sizeof(struct lf_keyfetcher));
	if (fetcher == NULL) {
		return -1;
	}
	fetcher->dict = key_dictionary_init(initial_size);
	lf_keyfetcher_init(fetcher, initial_size);
	km->fetcher = fetcher;

	return 0;
}

/*
 * Keymanager IPC Functionalities
 */

/* Keymanager context used when IPC commands are processed. */
static struct lf_keymanager *ipc_ctx;

int
lf_keymanager_register_ipc(struct lf_keymanager *km)
{
	ipc_ctx = km;

	/* TODO: add command to add/remove peer */

	return 0;
}

/*
 * Keymanager Telemetry Functionalities
 */

/* Keymanager context used when IPC commands are processed. */
static struct lf_keymanager *tel_ctx;

const struct lf_telemetry_field_name lf_keymanager_statistics_strings[] = {
	LF_KEYMANAGER_STATISTICS(LF_TELEMETRY_FIELD_NAME)
};

#define LF_KEYMANAGER_STATISTICS_NUM            \
	(sizeof(lf_keymanager_statistics_strings) / \
			sizeof(struct lf_telemetry_field_name))

static int
handle_dict_stats(const char *cmd __rte_unused, const char *params __rte_unused,
		struct rte_tel_data *d)
{
	rte_tel_data_start_dict(d);

	rte_spinlock_lock(&tel_ctx->management_lock);
	rte_tel_data_add_dict_uint(d, "entries", rte_hash_count(tel_ctx->dict));
	rte_tel_data_add_dict_uint(d, "entries_max",
			rte_hash_max_key_id(tel_ctx->dict));

	rte_spinlock_lock(&tel_ctx->management_lock);

	return 0;
}

static int
handle_stats(const char *cmd __rte_unused, const char *params __rte_unused,
		struct rte_tel_data *d)
{
	size_t i;
	uint64_t *values;

	rte_tel_data_start_dict(d);
	values = (uint64_t *)&tel_ctx->statistics;
	for (i = 0; i < LF_KEYMANAGER_STATISTICS_NUM; i++) {
		rte_tel_data_add_dict_uint(d, lf_keymanager_statistics_strings[i].name,
				values[i]);
	}

	return 0;
}

int
lf_keymanager_register_telemetry(struct lf_keymanager *km)
{
	int res;
	tel_ctx = km;

	res = rte_telemetry_register_cmd(LF_TELEMETRY_PREFIX "/keymanager/stats",
			handle_stats, "Returns key manager statistics.");
	if (res != 0) {
		return -1;
	}

	res = rte_telemetry_register_cmd(LF_TELEMETRY_PREFIX "/keymanager/dict",
			handle_dict_stats, "Returns key manager dictionary statistics.");
	if (res != 0) {
		return -1;
	}

	return 0;
}