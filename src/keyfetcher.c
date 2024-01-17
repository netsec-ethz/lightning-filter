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

static int
lf_keyfetcher_derive_shared_key(struct lf_crypto_drkey_ctx *drkey_ctx,
		struct lf_keyfetcher_sv_dictionary_data *secret_node, uint64_t src_ia,
		uint64_t dst_ia, uint16_t drkey_protocol, uint64_t ns_valid,
		struct lf_keymanager_key_container *key)
{
	struct lf_keyfetcher_sv_container *secret = NULL;

	// Find the correct shared secret to be used for current timestamp.
	for (int i = 0; i < LF_CONFIG_SV_MAX; i++) {
		if (secret_node->secret_values[i].validity_not_before == 0) {
			break;
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
		return -1;
	}

	uint64_t ms_valid;
	ms_valid = ns_valid / LF_TIME_NS_IN_MS;
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

	lf_crypto_drkey_derivation_step(drkey_ctx, &secret->key, buf,
			2 * LF_CRYPTO_CBC_BLOCK_SIZE, &key->key);

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


int
lf_keyfetcher_fetch_as_as_key(struct lf_keyfetcher *fetcher, uint64_t src_ia,
		uint64_t dst_ia, uint16_t drkey_protocol, uint64_t ns_valid,
		struct lf_keymanager_key_container *key)
{
	int key_id, res;
	struct lf_keyfetcher_dictionary_key dict_key;
	struct lf_keyfetcher_sv_dictionary_data *shared_secret_node;

	// check if there is entry in cache
	if (src_ia == fetcher->src_ia) {
		dict_key.as = dst_ia;
	} else {
		dict_key.as = src_ia;
	}
	dict_key.drkey_protocol = drkey_protocol;
	key_id = rte_hash_lookup_data(fetcher->dict, &dict_key,
			(void **)&shared_secret_node);
	if (key_id >= 0) {
		// derive next key locally
		res = lf_keyfetcher_derive_shared_key(&fetcher->drkey_ctx,
				shared_secret_node, src_ia, dst_ia, drkey_protocol, ns_valid,
				key);
	} else {
		// fetch from control service
		// for AS-AS keys there is no fetching from control service available.
		LF_KEYFETCHER_LOG(ERR, "FETCH ASAS from DRKEY %d!\n", key_id);

		res = -1;
	}
	return res;
}

int
lf_keyfetcher_fetch_host_as_key(struct lf_keyfetcher *fetcher, uint64_t src_ia,
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
	key_id = rte_hash_lookup_data(fetcher->dict, &dict_key,
			(void **)&shared_secret_node);
	if (key_id >= 0) {
		// derive next key locally
		res = lf_keyfetcher_derive_shared_key(&fetcher->drkey_ctx,
				shared_secret_node, src_ia, dst_ia, drkey_protocol, ns_valid,
				&as_as_key);
		if (res < 0) {
			return res;
		}
		lf_drkey_derive_host_as_from_as_as(&fetcher->drkey_ctx, &as_as_key.key,
				fast_side_host, drkey_protocol, &key->key);
		key->validity_not_before = as_as_key.validity_not_before;
		key->validity_not_after = as_as_key.validity_not_after;
	} else {
		// fetch from control service
		ms_valid = ns_valid / LF_TIME_NS_IN_MS;

		// TODO: implement address parsing correctly. IPv6 addresses do not fit
		// in uint64_t...
		res = lf_drkey_fetcher_host_as_key(fetcher->drkey_service_addr,
				rte_be_to_cpu_64(src_ia), rte_be_to_cpu_64(dst_ia),
				rte_be_to_cpu_64(*(uint64_t *)(fast_side_host->addr)),
				rte_be_to_cpu_16(drkey_protocol), (int64_t)ms_valid,
				&validity_not_before_ms, &validity_not_after_ms, drkey_buf);
		key->validity_not_after =
				(uint64_t)validity_not_after_ms * LF_TIME_NS_IN_MS;
		key->validity_not_before =
				(uint64_t)validity_not_before_ms * LF_TIME_NS_IN_MS;
		lf_crypto_drkey_from_buf(&fetcher->drkey_ctx, drkey_buf, &key->key);
	}

	return res;
}


int
lf_keyfetcher_fetch_host_host_key(struct lf_keyfetcher *fetcher,
		uint64_t src_ia, uint64_t dst_ia,
		const struct lf_host_addr *fast_side_host,
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
	key_id = rte_hash_lookup_data(fetcher->dict, &dict_key,
			(void **)&shared_secret_node);
	if (key_id >= 0) {
		// derive next key locally
		res = lf_keyfetcher_derive_shared_key(&fetcher->drkey_ctx,
				shared_secret_node, src_ia, dst_ia, drkey_protocol, ns_valid,
				&as_as_key);
		if (res < 0) {
			return res;
		}
		lf_drkey_derive_host_host_from_as_as(&fetcher->drkey_ctx,
				&as_as_key.key, fast_side_host, slow_side_host, drkey_protocol,
				&key->key);
		key->validity_not_before = as_as_key.validity_not_before;
		key->validity_not_after = as_as_key.validity_not_after;
	} else {
		// fetch from control service
		ms_valid = ns_valid / LF_TIME_NS_IN_MS;

		// TODO: implement address parsing correctly. IPv6 addresses do not fit
		// in uint64_t...
		res = lf_drkey_fetcher_host_host_key(fetcher->drkey_service_addr,
				rte_be_to_cpu_64(src_ia), rte_be_to_cpu_64(dst_ia),
				rte_be_to_cpu_64(*(uint64_t *)(fast_side_host->addr)),
				rte_be_to_cpu_64(*(uint64_t *)(slow_side_host->addr)),
				rte_be_to_cpu_16(drkey_protocol), (int64_t)ms_valid,
				&validity_not_before_ms, &validity_not_after_ms, drkey_buf);
		key->validity_not_after =
				(uint64_t)validity_not_after_ms * LF_TIME_NS_IN_MS;
		key->validity_not_before =
				(uint64_t)validity_not_before_ms * LF_TIME_NS_IN_MS;
		lf_crypto_drkey_from_buf(&fetcher->drkey_ctx, drkey_buf, &key->key);
	}

	return res;
}

// should only be called when keymanager management lock is hold
int
lf_keyfetcher_apply_config(struct lf_keyfetcher *fetcher,
		const struct lf_config *config)
{
	LF_KEYFETCHER_LOG(ERR, "Apply config!\n");

	int res, err = 0, key_id;
	uint32_t iterator;
	bool is_in_list;
	struct lf_keyfetcher_dictionary_key key, *key_ptr;
	struct lf_keyfetcher_sv_dictionary_data *shared_secret_data;
	struct lf_config_peer *peer;

	memcpy(fetcher->drkey_service_addr, config->drkey_service_addr,
			sizeof fetcher->drkey_service_addr);

	fetcher->src_ia = config->isd_as;

	for (iterator = 0; rte_hash_iterate(fetcher->dict, (void *)&key_ptr,
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
			LF_KEYFETCHER_LOG(DEBUG,
					"Remove SV entry for AS " PRIISDAS " DRKey protocol %u\n",
					PRIISDAS_VAL(rte_be_to_cpu_64(key_ptr->as)),
					rte_be_to_cpu_16(key_ptr->drkey_protocol));
			(void)rte_hash_del_key(fetcher->dict, key_ptr);
			// can be removed here since manager lock is beeing held
			(void)rte_free(shared_secret_data);
		}
	}

	for (peer = config->peers; peer != NULL; peer = peer->next) {
		key.as = peer->isd_as;
		key.drkey_protocol = peer->drkey_protocol;

		// update secret values that were already in dict
		key_id = rte_hash_lookup_data(fetcher->dict, &key,
				(void **)&shared_secret_data);
		if (key_id >= 0) {
			if (peer->shared_secret_configured_option) {
				for (int i = 0; i < LF_CONFIG_SV_MAX; i++) {
					shared_secret_data->secret_values[i].validity_not_before =
							peer->shared_secrets[i].not_before;
					lf_crypto_drkey_from_buf(&fetcher->drkey_ctx,
							peer->shared_secrets[i].sv,
							&shared_secret_data->secret_values[i].key);
				}
			}
			continue;
		}

		if (peer->shared_secret_configured_option) {
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
				if (peer->shared_secrets[i].not_before == 0) {
					break;
				}
				shared_secret_data->secret_values[i].validity_not_before =
						peer->shared_secrets[i].not_before;
				lf_crypto_drkey_from_buf(&fetcher->drkey_ctx,
						peer->shared_secrets[i].sv,
						&shared_secret_data->secret_values[i].key);
			}

			res = rte_hash_add_key_data(fetcher->dict, &key,
					(void *)shared_secret_data);
			if (res != 0) {
				LF_KEYFETCHER_LOG(ERR, "Add key failed with %d!\n", key_id);
				(void)rte_free(shared_secret_data);
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
		(void)rte_free(data);
	}
	(void)rte_hash_free(dict);
}

int
lf_keyfetcher_close(struct lf_keyfetcher *fetcher)
{
	lf_keyfetcher_dictionary_free(fetcher->dict);
	fetcher->dict = NULL;
	lf_crypto_drkey_ctx_close(&fetcher->drkey_ctx);
	return 0;
}

int
lf_keyfetcher_init(struct lf_keyfetcher *fetcher, uint32_t initial_size)
{
	int res;

	/* dictionary requires a size of at least 8 (magic number) */
	// NOLINTBEGIN(readability-magic-numbers)
	if (initial_size < 8) {
		initial_size = 8;
	}
	// NOLINTEND(readability-magic-numbers)
	fetcher->size = initial_size;

	memset(fetcher->drkey_service_addr, 0, sizeof fetcher->drkey_service_addr);

	res = lf_crypto_drkey_ctx_init(&fetcher->drkey_ctx);
	if (res != 0) {
		/* TODO: error handling*/
		return -1;
	}

	return 0;
}
