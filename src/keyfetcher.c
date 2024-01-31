/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#include <inttypes.h>

#include <rte_byteorder.h>
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
#include "lib/log/log.h"
#include "lib/time/time.h"

/**
 * Log function for key fetcher service (not on data path).
 * Format: "Keyfetcher: log message here"
 */
#define LF_KEYFETCHER_LOG(level, ...) LF_LOG(level, "Keyfetcher: " __VA_ARGS__)

/* 16 byte buffer with zero value. */
static const uint8_t zero_secret_value[16] = { 0 };

/**
 * Derives a short term AS-AS key from the shared secret.
 * The derivation is done using AES-CBC MAC keyed with the shared secret and the
 * input:
 *
 * (type | ISD_AS1 | ISD_AS2 | start timestamp)
 *
 * "type" is the 1 byte fixed constant 0.
 * "ISD_AS1" is the ISD_AS number (8 byte) in network byte order of the fast
 * side AS.
 * "ISD_AS2" is the ISD_AS number (8 byte) in network byte order of the slow
 * side AS.
 * "start timestamp" is the timestamp in ns (8 byte) of the start time of the
 * validity period for the resulting key. This can be synchronized between peers
 * since the initial start time is configured by both and consequent start times
 * can be calculated by configured time + k * VALIDITY_PERIOD for some k such
 * that the key is currently valid.
 *
 * @param drkey_ctx DRKey cipher context.
 * @param secret_node configured shared secret values.
 * @param src_ia DRKey slow side (CPU endian).
 * @param dst_ia DRKey fast side (CPU endian).
 * @param drkey_protocol (network byte order).
 * @param ns_valid time in nanoseconds for which the key should be valid.
 * @param key Returning AS-AS key.
 */
static int
lf_keyfetcher_derive_shared_key(struct lf_crypto_drkey_ctx *drkey_ctx,
		struct lf_keyfetcher_sv_dictionary_data *secret_node, uint64_t src_ia,
		uint64_t dst_ia, uint16_t drkey_protocol, uint64_t ns_valid,
		struct lf_keymanager_key_container *key)
{
	struct lf_keyfetcher_sv_container *secret = NULL;
	uint64_t ms_valid;
	ms_valid = ns_valid / LF_TIME_NS_IN_MS;

	// Find the correct shared secret to be used for current timestamp.
	for (int i = 0; i < LF_CONFIG_SV_MAX; i++) {
		if (memcmp(secret_node->secret_values[i].key.key, zero_secret_value,
					sizeof secret_node->secret_values[i].key.key) == 0) {
			continue;
		}
		if (secret_node->secret_values[i].validity_not_before <= ns_valid) {
			if (secret == NULL) {
				secret = &secret_node->secret_values[i];
			} else if (secret_node->secret_values[i].validity_not_before >=
					   secret->validity_not_before) {
				secret = &secret_node->secret_values[i];
			}
		}
	}
	if (secret == NULL) {
		LF_KEYFETCHER_LOG(ERR,
				"Could not find shared secret for: src_as " PRIISDAS
				", dst_as " PRIISDAS ", drkey_protocol %u, ms_valid %" PRIu64
				"\n",
				PRIISDAS_VAL(rte_be_to_cpu_64(src_ia)),
				PRIISDAS_VAL(rte_be_to_cpu_64(dst_ia)),
				rte_be_to_cpu_16(drkey_protocol), ms_valid);
		return -1;
	}

	uint64_t validity_not_before_ns =
			secret->validity_not_before +
			(int)((ns_valid - secret->validity_not_before) /
					LF_DRKEY_VALIDITY_PERIOD_NS) *
					LF_DRKEY_VALIDITY_PERIOD_NS;
	uint64_t validity_not_before_ns_be =
			rte_cpu_to_be_64(validity_not_before_ns);
	uint64_t validity_not_after_ns =
			validity_not_before_ns + LF_DRKEY_VALIDITY_PERIOD_NS - 1;

	uint8_t buf[2 * LF_CRYPTO_CBC_BLOCK_SIZE] = { 0 };
	buf[0] = LF_DRKEY_DERIVATION_TYPE_AS_AS;
	memcpy(buf + 1, &dst_ia, 8);
	memcpy(buf + 9, &src_ia, 8);
	memcpy(buf + 17, &validity_not_before_ns_be, 8);

	lf_crypto_drkey_derivation_step(drkey_ctx, &secret->key, buf, sizeof buf,
			&key->key);

	LF_KEYFETCHER_LOG(INFO,
			"Derived shared AS AS Key: src_as " PRIISDAS ", dst_as " PRIISDAS
			", drkey_protocol %u, ms_valid %" PRIu64
			", validity_not_before_ms %" PRIu64
			", validity_not_after_ms %" PRIu64 "\n",
			PRIISDAS_VAL(rte_be_to_cpu_64(src_ia)),
			PRIISDAS_VAL(rte_be_to_cpu_64(dst_ia)),
			rte_be_to_cpu_16(drkey_protocol), ms_valid,
			(validity_not_before_ns / LF_TIME_NS_IN_MS),
			(validity_not_after_ns / LF_TIME_NS_IN_MS));

	/* set values in returned key structure */
	key->validity_not_before = validity_not_before_ns;
	key->validity_not_after = validity_not_after_ns;

	return 0;
}

// should only be called when keymanager management lock is hold
int
lf_keyfetcher_fetch_as_as_key(struct lf_keyfetcher *kf, uint64_t src_ia,
		uint64_t dst_ia, uint16_t drkey_protocol, uint64_t ns_valid,
		struct lf_keymanager_key_container *key)
{
	int key_id, res;
	struct lf_keyfetcher_dictionary_key dict_key;
	struct lf_keyfetcher_sv_dictionary_data *shared_secret_node;

	// check if there is entry in cache
	dict_key.as = src_ia == kf->src_ia ? dst_ia : src_ia;
	dict_key.drkey_protocol = drkey_protocol;
	key_id = rte_hash_lookup_data(kf->dict, &dict_key,
			(void **)&shared_secret_node);
	if (key_id >= 0) {
		res = lf_keyfetcher_derive_shared_key(&kf->drkey_ctx,
				shared_secret_node, src_ia, dst_ia, drkey_protocol, ns_valid,
				key);
	} else {
		LF_KEYFETCHER_LOG(ERR,
				"Fail to look up shared secret: src_as " PRIISDAS
				", dst_as " PRIISDAS ", drkey_protocol %u\n",
				PRIISDAS_VAL(rte_be_to_cpu_64(src_ia)),
				PRIISDAS_VAL(rte_be_to_cpu_64(dst_ia)),
				rte_be_to_cpu_16(drkey_protocol));
		res = -1;
	}
	return res;
}

// should only be called when keymanager management lock is hold
int
lf_keyfetcher_fetch_host_as_key(struct lf_keyfetcher *kf, uint64_t src_ia,
		uint64_t dst_ia, const struct lf_host_addr *fast_side_host,
		uint16_t drkey_protocol, uint64_t ns_valid,
		struct lf_keymanager_key_container *key)
{
	int key_id, res;
	struct lf_keyfetcher_dictionary_key dict_key;
	struct lf_keyfetcher_sv_dictionary_data *shared_secret_node;
	struct lf_keymanager_key_container as_as_key;
	uint64_t ms_valid;
	int64_t validity_not_before_ms, validity_not_after_ms;
	uint8_t drkey_buf[LF_CRYPTO_DRKEY_SIZE];

	// check if there is entry in cache
	dict_key.as = src_ia;
	dict_key.drkey_protocol = drkey_protocol;
	key_id = rte_hash_lookup_data(kf->dict, &dict_key,
			(void **)&shared_secret_node);
	if (key_id >= 0) {
		res = lf_keyfetcher_derive_shared_key(&kf->drkey_ctx,
				shared_secret_node, src_ia, dst_ia, drkey_protocol, ns_valid,
				&as_as_key);
		if (res < 0) {
			return res;
		}
		lf_drkey_derive_host_as_from_as_as(&kf->drkey_ctx, &as_as_key.key,
				fast_side_host, drkey_protocol, &key->key);
		key->validity_not_before = as_as_key.validity_not_before;
		key->validity_not_after = as_as_key.validity_not_after;
	} else {
		// fetch from control service
		ms_valid = ns_valid / LF_TIME_NS_IN_MS;

		// TODO: implement address parsing correctly. IPv6 addresses do not fit
		// in uint64_t...
		res = lf_drkey_fetcher_host_as_key(kf->drkey_service_addr,
				rte_be_to_cpu_64(src_ia), rte_be_to_cpu_64(dst_ia),
				rte_be_to_cpu_64(*(uint64_t *)(fast_side_host->addr)),
				rte_be_to_cpu_16(drkey_protocol), (int64_t)ms_valid,
				&validity_not_before_ms, &validity_not_after_ms, drkey_buf);
		if (res < 0) {
			return res;
		}
		key->validity_not_after =
				(uint64_t)validity_not_after_ms * LF_TIME_NS_IN_MS;
		key->validity_not_before =
				(uint64_t)validity_not_before_ms * LF_TIME_NS_IN_MS;
		lf_crypto_drkey_from_buf(&kf->drkey_ctx, drkey_buf, &key->key);
	}

	return res;
}

// should only be called when keymanager management lock is hold
int
lf_keyfetcher_fetch_host_host_key(struct lf_keyfetcher *kf, uint64_t src_ia,
		uint64_t dst_ia, const struct lf_host_addr *fast_side_host,
		const struct lf_host_addr *slow_side_host, uint16_t drkey_protocol,
		uint64_t ns_valid, struct lf_keymanager_key_container *key)
{
	int key_id, res;
	struct lf_keyfetcher_dictionary_key dict_key;
	struct lf_keyfetcher_sv_dictionary_data *shared_secret_node;
	struct lf_keymanager_key_container as_as_key;
	uint64_t ms_valid;
	int64_t validity_not_before_ms, validity_not_after_ms;
	uint8_t drkey_buf[LF_CRYPTO_DRKEY_SIZE];

	// check if there is entry in cache
	dict_key.as = src_ia;
	dict_key.drkey_protocol = drkey_protocol;
	key_id = rte_hash_lookup_data(kf->dict, &dict_key,
			(void **)&shared_secret_node);
	if (key_id >= 0) {
		res = lf_keyfetcher_derive_shared_key(&kf->drkey_ctx,
				shared_secret_node, src_ia, dst_ia, drkey_protocol, ns_valid,
				&as_as_key);
		if (res < 0) {
			return res;
		}
		lf_drkey_derive_host_host_from_as_as(&kf->drkey_ctx, &as_as_key.key,
				fast_side_host, slow_side_host, drkey_protocol, &key->key);
		key->validity_not_before = as_as_key.validity_not_before;
		key->validity_not_after = as_as_key.validity_not_after;
	} else {
		// fetch from control service
		ms_valid = ns_valid / LF_TIME_NS_IN_MS;

		// TODO: implement address parsing correctly. IPv6 addresses do not fit
		// in uint64_t...
		res = lf_drkey_fetcher_host_host_key(kf->drkey_service_addr,
				rte_be_to_cpu_64(src_ia), rte_be_to_cpu_64(dst_ia),
				rte_be_to_cpu_64(*(uint64_t *)(fast_side_host->addr)),
				rte_be_to_cpu_64(*(uint64_t *)(slow_side_host->addr)),
				rte_be_to_cpu_16(drkey_protocol), (int64_t)ms_valid,
				&validity_not_before_ms, &validity_not_after_ms, drkey_buf);
		if (res < 0) {
			return res;
		}
		key->validity_not_after =
				(uint64_t)validity_not_after_ms * LF_TIME_NS_IN_MS;
		key->validity_not_before =
				(uint64_t)validity_not_before_ms * LF_TIME_NS_IN_MS;
		lf_crypto_drkey_from_buf(&kf->drkey_ctx, drkey_buf, &key->key);
	}

	return res;
}

// should only be called when keymanager management lock is hold
int
lf_keyfetcher_apply_config(struct lf_keyfetcher *kf,
		const struct lf_config *config)
{
	int res, err = 0, key_id;
	uint32_t iterator;
	bool is_in_list;
	struct lf_keyfetcher_dictionary_key key, *key_ptr;
	struct lf_keyfetcher_sv_dictionary_data *shared_secret_data;
	struct lf_config_peer *peer;

	LF_KEYFETCHER_LOG(NOTICE, "Apply config!\n");

	memcpy(kf->drkey_service_addr, config->drkey_service_addr,
			sizeof kf->drkey_service_addr);

	kf->src_ia = config->isd_as;

	for (iterator = 0; rte_hash_iterate(kf->dict, (void *)&key_ptr,
							   (void **)&shared_secret_data, &iterator) >= 0;) {
		is_in_list = false;
		for (peer = config->peers; peer != NULL; peer = peer->next) {
			if (peer->isd_as == key_ptr->as &&
					peer->drkey_protocol == key_ptr->drkey_protocol) {
				is_in_list = true;
				break;
			}
		}
		if (!is_in_list) {
			// Remove SV since peer is no longer configured.
			LF_KEYFETCHER_LOG(DEBUG,
					"Remove SV entry for AS " PRIISDAS " DRKey protocol %u\n",
					PRIISDAS_VAL(rte_be_to_cpu_64(key_ptr->as)),
					rte_be_to_cpu_16(key_ptr->drkey_protocol));
			rte_hash_del_key(kf->dict, key_ptr);
			// can be removed here since manager lock is beeing held
			rte_free(shared_secret_data);
		}
	}

	for (peer = config->peers; peer != NULL; peer = peer->next) {
		key.as = peer->isd_as;
		key.drkey_protocol = peer->drkey_protocol;

		// update secret values that were already in dict
		key_id = rte_hash_lookup_data(kf->dict, &key,
				(void **)&shared_secret_data);
		if (key_id >= 0) {
			if (peer->shared_secrets_configured_option) {
				for (int i = 0; i < LF_CONFIG_SV_MAX; i++) {
					shared_secret_data->secret_values[i].validity_not_before =
							peer->shared_secrets[i].not_before;
					lf_crypto_drkey_from_buf(&kf->drkey_ctx,
							peer->shared_secrets[i].sv,
							&shared_secret_data->secret_values[i].key);
				}
			} else {
				// Peer still exists but has no longer secret values defined.
				LF_KEYFETCHER_LOG(DEBUG,
						"Peer has no longer SVs defined. Remove SV entry for "
						"AS " PRIISDAS " DRKey protocol %u\n",
						PRIISDAS_VAL(rte_be_to_cpu_64(key.as)),
						rte_be_to_cpu_16(key.drkey_protocol));
				rte_hash_del_key(kf->dict, &key);
				// can be removed here since manager lock is beeing held
				rte_free(shared_secret_data);
			}
			continue;
		}

		if (peer->shared_secrets_configured_option) {
			// create entry of secret value for new hash table
			shared_secret_data =
					(struct lf_keyfetcher_sv_dictionary_data *)rte_zmalloc(NULL,
							sizeof(struct lf_keyfetcher_sv_dictionary_data), 0);
			if (shared_secret_data == NULL) {
				LF_KEYFETCHER_LOG(ERR, "Failed to allocate memory for key\n");
				err = 1;
				break;
			}

			// populate secret data and add to dict
			for (int i = 0; i < LF_CONFIG_SV_MAX; i++) {
				shared_secret_data->secret_values[i].validity_not_before =
						peer->shared_secrets[i].not_before;
				lf_crypto_drkey_from_buf(&kf->drkey_ctx,
						peer->shared_secrets[i].sv,
						&shared_secret_data->secret_values[i].key);
			}

			res = rte_hash_add_key_data(kf->dict, &key,
					(void *)shared_secret_data);
			if (res != 0) {
				LF_KEYFETCHER_LOG(ERR, "Add key failed with %d!\n", key_id);
				rte_free(shared_secret_data);
				err = 1;
				break;
			}
		}
	}
	if (err == 0) {
		return 0;
	} else {
		LF_KEYFETCHER_LOG(ERR, "Failed to set config");
		return -1;
	}
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

	LF_KEYFETCHER_LOG(DEBUG, "Init\n");

	/* DPDK hash table entry must be at least 8 (undocumented) */
	if (size < 8) {
		LF_KEYFETCHER_LOG(ERR,
				"Hash creation failed because size is smaller than 8\n");
		return NULL;
	}

	(void)snprintf(name, sizeof(name), "keyfetcher_dict_%d\n", counter);
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
		LF_KEYFETCHER_LOG(ERR, "Hash creation failed with: %d\n", errno);
		rte_hash_free(dic);
		return NULL;
	}

	LF_KEYFETCHER_LOG(DEBUG, "Created hash table (size = %d)\n", size);

	return dic;
}

/**
 * Free all keys stored in the dictionary and the dictionary itself.
 */
static void
lf_keyfetcher_dictionary_free(struct rte_hash *dict)
{
	uint32_t iterator;
	struct lf_keyfetcher_dictionary_key *key_ptr;
	struct lf_keyfetcher_sv_dictionary_data *data;

	for (iterator = 0; rte_hash_iterate(dict, (void *)&key_ptr, (void **)&data,
							   &iterator) >= 0;) {
		rte_free(data);
	}
	rte_hash_free(dict);
}

// should only be called when keymanager management lock is hold
int
lf_keyfetcher_close(struct lf_keyfetcher *kf)
{
	lf_keyfetcher_dictionary_free(kf->dict);
	kf->dict = NULL;
	lf_crypto_drkey_ctx_close(&kf->drkey_ctx);
	return 0;
}

int
lf_keyfetcher_init(struct lf_keyfetcher *kf, uint32_t initial_size)
{
	int res;

	/* dictionary requires a size of at least 8 (magic number) */
	// NOLINTBEGIN(readability-magic-numbers)
	if (initial_size < 8) {
		initial_size = 8;
	}
	// NOLINTEND(readability-magic-numbers)
	kf->size = initial_size;
	kf->dict = key_dictionary_init(initial_size);
	if (kf->dict == NULL) {
		return -1;
	}

	memset(kf->drkey_service_addr, 0, sizeof kf->drkey_service_addr);

	res = lf_crypto_drkey_ctx_init(&kf->drkey_ctx);
	if (res != 0) {
		/* TODO: error handling*/
		return -1;
	}

	return 0;
}
