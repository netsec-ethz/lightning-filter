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

/**
 * Fetch AS-AS key (Level 1).
 * Increments statistics counter accordingly; increment fetch_success on success
 * and fetch_fail otherwise.
 *
 * @param drkey_service_addr: address of drkey service, such as the SCION
 * control service, e.g., 10.248.7.1:31008
 * @param src_ia: slow side of the DRKey (network byte order)
 * @param dst_ia: fast side of the DRKey (network byte order)
 * @param drkey_protocol: (network byte order)
 * @param ns_valid: Unix timestamp in nanoseconds, at which the requested key
 * must be valid.
 * @param key: pointer to key container struct to store result in.
 * @return 0 on success, otherwise, < 0.
 */
static int
fetch_as_as_key(struct lf_keymanager *km, const char drkey_service_addr[48],
		uint64_t src_ia, uint64_t dst_ia, uint16_t drkey_protocol,
		uint64_t ns_valid, struct lf_keymanager_key_container *key)
{
	int res;
	uint64_t ms_valid;
	int64_t validity_not_before_ms, validity_not_after_ms;
	uint8_t drkey_buf[LF_CRYPTO_DRKEY_SIZE];

	ms_valid = ns_valid / LF_TIME_NS_IN_MS;

	assert(ms_valid <= INT64_MAX);
	res = lf_drkey_fetcher_as_as_key(drkey_service_addr,
			rte_be_to_cpu_64(src_ia), rte_be_to_cpu_64(dst_ia),
			rte_be_to_cpu_16(drkey_protocol), (int64_t)ms_valid,
			&validity_not_before_ms, &validity_not_after_ms, drkey_buf);
	lf_log_drkey_value(drkey_buf, "AS-AS Key fetched");

	if (res != 0) {
		km->statistics.fetch_fail++;

		LF_KEYMANAGER_LOG(ERR,
				"Fetching AS AS Key failed with %d: drkey_service_addr "
				"%s, src_as" PRIISDAS ", dst_as " PRIISDAS
				", drkey_protocol %u, ms_valid %" PRIu64 "\n",
				res, drkey_service_addr, PRIISDAS_VAL(rte_be_to_cpu_64(src_ia)),
				PRIISDAS_VAL(rte_be_to_cpu_64(dst_ia)),
				rte_be_to_cpu_16(drkey_protocol), ms_valid);
		return -1;
	}

	km->statistics.fetch_successful++;
	LF_KEYMANAGER_LOG(INFO,
			"Fetched AS AS Key: drkey_service_addr "
			"%s, src_as " PRIISDAS ", dst_as " PRIISDAS
			", drkey_protocol %u, ms_valid %" PRIu64
			", validity_not_before_ms %" PRIu64
			", validity_not_after_ms %" PRIu64 "\n",
			drkey_service_addr, PRIISDAS_VAL(rte_be_to_cpu_64(src_ia)),
			PRIISDAS_VAL(rte_be_to_cpu_64(dst_ia)),
			rte_be_to_cpu_16(drkey_protocol), ms_valid, validity_not_before_ms,
			validity_not_after_ms);

	/* set values in returned key structure */
	key->validity_not_after =
			(uint64_t)validity_not_after_ms * LF_TIME_NS_IN_MS;
	key->validity_not_before =
			(uint64_t)validity_not_before_ms * LF_TIME_NS_IN_MS;
	lf_crypto_drkey_from_buf(&km->drkey_ctx, drkey_buf, &key->key);

	return 0;
}

/**
 * Set AS-AS key (Level 1).
 *
 * @param configured_drkey: drkey that is configured in the config
 * @param src_ia: slow side of the DRKey (network byte order)
 * @param dst_ia: fast side of the DRKey (network byte order)
 * @param drkey_protocol: (network byte order)
 * @param ns_valid: Unix timestamp in nanoseconds, at which the requested key
 * must be valid.
 * @param key: pointer to key container struct to store result in.
 * @return 0 on success, otherwise, < 0.
 */
static int
set_configured_as_as_key(struct lf_keymanager *km,
		uint8_t configured_drkey[LF_CRYPTO_DRKEY_SIZE], uint64_t src_ia,
		uint64_t dst_ia, uint16_t drkey_protocol, uint64_t ns_valid,
		struct lf_keymanager_key_container *key)
{
	uint64_t ms_valid;

	// TODO set some reasonable values for preconfigured keys
	int64_t validity_not_before_ms = 0;
	int64_t validity_not_after_ms = UINT64_MAX / 10000000;

	ms_valid = ns_valid / LF_TIME_NS_IN_MS;

	assert(ms_valid <= INT64_MAX);
	lf_log_drkey_value(configured_drkey, "AS-AS Key set from config");

	LF_KEYMANAGER_LOG(INFO,
			"Set AS AS Key: src_as " PRIISDAS ", dst_as " PRIISDAS
			", drkey_protocol %u, ms_valid %" PRIu64
			", validity_not_before_ms %" PRIu64
			", validity_not_after_ms %" PRIu64 "\n",
			PRIISDAS_VAL(rte_be_to_cpu_64(src_ia)),
			PRIISDAS_VAL(rte_be_to_cpu_64(dst_ia)),
			rte_be_to_cpu_16(drkey_protocol), ms_valid, validity_not_before_ms,
			validity_not_after_ms);

	/* set values in returned key structure */
	key->validity_not_after =
			(uint64_t)validity_not_after_ms * LF_TIME_NS_IN_MS;
	key->validity_not_before =
			(uint64_t)validity_not_before_ms * LF_TIME_NS_IN_MS;
	lf_crypto_drkey_from_buf(&km->drkey_ctx, configured_drkey, &key->key);

	return 0;
}

void
lf_keymanager_service_update(struct lf_keymanager *km)
{
	int res, key_id;
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

	// TODO: Change update behavior when using preconfigured keys
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

			key_id = fetch_as_as_key(km, km->drkey_service_addr, key_ptr->as,
					km->src_as, key_ptr->drkey_protocol,
					ns_now + LF_DRKEY_PREFETCHING_PERIOD,
					&new_data->inbound_key);
			if (key_id < 0) {
				(void)rte_free(new_data);
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
						"Fail to add inbound key to dictionary (err = "
						"%d)\n",
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

			key_id = fetch_as_as_key(km, km->drkey_service_addr, km->src_as,
					key_ptr->as, key_ptr->drkey_protocol,
					ns_now + LF_DRKEY_PREFETCHING_PERIOD,
					&new_data->outbound_key);
			if (key_id < 0) {
				(void)rte_free(new_data);
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
						"Fail to add outbound key to dictionary (err = "
						"%d)\n",
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
		(void)synchronize_worker(km);
		(void)linked_list_free(free_list);
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
		(void)rte_hash_free(dic);
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
		(void)rte_free(data);
	}
	(void)rte_hash_free(dict);
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

		if (&peer->drkey_level_1 != NULL) {
			res = set_configured_as_as_key(km, (&peer->drkey_level_1)->inbound,
					key.as, config->isd_as, key.drkey_protocol, ns_now,
					&dictionary_data->inbound_key);
		} else {
			/*
			 * Fetch keys from the new drkey service.
			 * If this does not succeed, initialize them as not valid, i.e., set
			 * validity_not_after to 0.
			 */
			res = fetch_as_as_key(km, config->drkey_service_addr, key.as,
					config->isd_as, key.drkey_protocol, ns_now,
					&dictionary_data->inbound_key);
		}
		if (res < 0) {
			dictionary_data->inbound_key.validity_not_after = 0;
		}
		dictionary_data->old_inbound_key.validity_not_after = 0;

		if (&peer->drkey_level_1 != NULL) {
			res = set_configured_as_as_key(km, (&peer->drkey_level_1)->outbound,
					key.as, config->isd_as, key.drkey_protocol, ns_now,
					&dictionary_data->outbound_key);
		} else {
			res = fetch_as_as_key(km, config->drkey_service_addr,
					config->isd_as, key.as, key.drkey_protocol, ns_now,
					&dictionary_data->outbound_key);
		}
		if (res < 0) {
			dictionary_data->outbound_key.validity_not_after = 0;
		}
		dictionary_data->old_outbound_key.validity_not_after = 0;

		res = rte_hash_add_key_data(km->dict, &key, (void *)dictionary_data);
		if (res != 0) {
			LF_KEYMANAGER_LOG(ERR, "Add key failed with %d!\n", key_id);
			(void)rte_free(dictionary_data);
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
		(void)synchronize_worker(km);
		(void)linked_list_free(free_list);
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

	return 0;
}

/*
 * Keymanager IPC Functionalities
 */

/* Keymanager context used when IPC commands are processed. */
static struct lf_keymanager *ipc_ctx;

static int
ipc_config_load(const char *cmd __rte_unused, const char *p, char *out_buf,
		size_t buf_len)
{
	int res;
	struct lf_config *config;

	LF_KEYMANAGER_LOG(INFO, "Load config from %s ...\n", p);
	config = lf_config_new_from_file(p);
	if (config == NULL) {
		LF_LOG(ERR, "Config parser failed\n");
		return -1;
	}

	res = lf_keymanager_apply_config(ipc_ctx, config);
	lf_config_free(config);

	if (res != 0) {
		return -1;
	}

	return snprintf(out_buf, buf_len, "successfully applied config");
}

int
lf_keymanager_register_ipc(struct lf_keymanager *km)
{
	int res;
	ipc_ctx = km;

	res = lf_ipc_register_cmd("/keymanager/config", ipc_config_load,
			"Load key manager config file. "
			"parameter: <config file>");
	if (res != 0) {
		return -1;
	}

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
	rte_tel_data_add_dict_u64(d, "entries", rte_hash_count(tel_ctx->dict));
	rte_tel_data_add_dict_u64(d, "entries_max",
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
		rte_tel_data_add_dict_u64(d, lf_keymanager_statistics_strings[i].name,
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