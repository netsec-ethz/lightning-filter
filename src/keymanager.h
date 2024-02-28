/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#ifndef LF_KEYMANAGER_H
#define LF_KEYMANAGER_H

#include <inttypes.h>
#include <stdatomic.h>
#include <stdbool.h>

#include <rte_byteorder.h>
#include <rte_hash.h>
#include <rte_memcpy.h>
#include <rte_spinlock.h>

#include "config.h"
#include "drkey.h"
#include "keyfetcher.h"
#include "lf.h"
#include "lib/crypto/crypto.h"
#include "lib/telemetry/counters.h"
#include "lib/time/time.h"

#include "lib/log/log.h"

/**
 * The key manager manages the storage, caching and fetching of the required
 * DRKeys. It provides an interface for workers to query host-to-host keys
 * efficiently.
 *
 * For the fetching, it uses the keyfetcher.
 */

#define LF_KEYMANAGER_INTERVAL 0.5 /* seconds */

struct lf_keymanager_worker {
	struct rte_hash *dict;
	struct lf_crypto_drkey_ctx drkey_ctx;
};

struct lf_keymanager_dictionary_data {
	/* newest keys */
	struct lf_keymanager_key_container outbound_key;
	struct lf_keymanager_key_container inbound_key;
	/* previous keys */
	struct lf_keymanager_key_container old_inbound_key;
	struct lf_keymanager_key_container old_outbound_key;
};

struct lf_keymanager_dictionary_key {
	uint64_t as;             /* network byte order */
	uint16_t drkey_protocol; /* network byte order */
} __attribute__((__packed__));


#define LF_KEYMANAGER_STATISTICS(M) \
	M(uint64_t, fetch_successful)   \
	M(uint64_t, fetch_fail)

struct lf_keymanager_statistics {
	LF_KEYMANAGER_STATISTICS(LF_TELEMETRY_FIELD_DECL)
};

struct lf_keymanager {
	struct lf_keymanager_worker workers[LF_MAX_WORKER];
	uint16_t nb_workers;

	/* AS-AS DRKey dictionary */
	struct rte_hash *dict;
	/* max number of entries */
	uint32_t size;

	uint64_t src_as;

	struct lf_keyfetcher *fetcher;

	char drkey_service_addr[48];

	/* crypto DRKey context */
	struct lf_crypto_drkey_ctx drkey_ctx;

	/* synchronize management */
	rte_spinlock_t management_lock;
	/* Workers' Quiescent State Variable */
	struct rte_rcu_qsbr *qsv;

	/* statistics counters */
	struct lf_keymanager_statistics statistics;
};

/**
 * Check if DRKey is valid at the requested time.
 *
 * @param drkey: DRKey to be checked.
 * @param ns_now: Unix timestamp in nanoseconds, at which the requested key
 * must be valid.
 * @return Returns 0 if the requested time is within the DRKey's epoch. Returns
 * 1 if the DRKey is valid only due to the grace period.
 */
static inline int
lf_keymanager_check_drkey_validity(struct lf_keymanager_key_container *drkey,
		uint64_t ns_now)
{
	if (likely(ns_now >= drkey->validity_not_before &&
				ns_now < drkey->validity_not_after)) {
		return 0;
	}

	if (likely(ns_now >= drkey->validity_not_before &&
				ns_now < drkey->validity_not_after + LF_DRKEY_GRACE_PERIOD)) {
		return 1;
	}

	return -1;
}

/**
 * Obtain inbound DRKey.
 *
 * @param peer_as: Packet's source AS (network byte order).
 * @param peer_addr: Packet's source address (network byte order).
 * @param backend_addr: Packet's destination address (network byte
 * order).
 * @param drkey_protocol: (network byte order).
 * @param ns_now: Unix timestamp in nanoseconds, at which the requested key
 * must be valid.
 * @param ns_rel_time: Relative timestamp in nanoseconds to uniquely identify
 * the epoch for the key that should be used.
 * @param drkey: Memory to write DRKey to.
 * @return 0 if success. Otherwise, < 0.
 */
static inline int
lf_keymanager_worker_inbound_get_drkey(struct lf_keymanager_worker *kmw,
		uint64_t peer_as, const struct lf_host_addr *peer_addr,
		const struct lf_host_addr *backend_addr, uint16_t drkey_protocol,
		uint64_t ns_now, uint64_t ns_rel_time, uint64_t *ns_drkey_epoch_start,
		struct lf_crypto_drkey *drkey)
{
	int res;
	int key_id;
	struct lf_keymanager_dictionary_data *dict_node;
	struct lf_keymanager_dictionary_key key = {
		.as = peer_as,
		.drkey_protocol = drkey_protocol,
	};

	/* find AS-AS key */
	key_id = rte_hash_lookup_data(kmw->dict, &key, (void **)&dict_node);
	if (unlikely(key_id < 0)) {
		return -1;
	}

	/* NOTE: Different from the SCION documentation we only check for two
	 * possible DRKeys here instead of the proposed three (i-1, i, i+1). This is
	 * mainly done to save memory. It works since new DRKeys (i+1) are fetched
	 * before they are valid and after the old keys (i-1) grace period is over.
	 * Therefore the two stored keys are the only ones that make sense at any
	 * given moment. Further information can be found in the LF documentation.
	 */

	/* Check if the start time of the new key with offset ns_rel_time is whithin
	 * the acceptance window around ns_now. */
	if ((dict_node->inbound_key.validity_not_before + ns_rel_time <
				ns_now + LF_DRKEY_ACCEPTANCE_WINDOW_SIZE_NS) &&
			(dict_node->inbound_key.validity_not_before + ns_rel_time >=
					ns_now - LF_DRKEY_ACCEPTANCE_WINDOW_SIZE_NS)) {
		/* A key with offet ns_rel_time could still be within the acceptance
		 * window but not be valid anymore. Therefore the validity has to be
		 * checked explicitly. */
		res = lf_keymanager_check_drkey_validity(&dict_node->inbound_key,
				ns_now);
		if (res < 0) {
			return -3;
		}
		lf_drkey_derive_host_host_from_as_as(&kmw->drkey_ctx,
				&dict_node->inbound_key.key, backend_addr, peer_addr,
				drkey_protocol, drkey);
		*ns_drkey_epoch_start = dict_node->inbound_key.validity_not_before;
		return 0;
	}

	/* Check if the start time of the old key with offset ns_rel_time is whithin
	 * the acceptance window around ns_now. */
	if ((dict_node->old_inbound_key.validity_not_before + ns_rel_time <
				ns_now + LF_DRKEY_ACCEPTANCE_WINDOW_SIZE_NS) &&
			(dict_node->old_inbound_key.validity_not_before + ns_rel_time >=
					ns_now - LF_DRKEY_ACCEPTANCE_WINDOW_SIZE_NS)) {
		/* A key with offet ns_rel_time could still be within the acceptance
		 * window but not be valid anymore. Therefore the validity has to be
		 * checked explicitly. */
		res = lf_keymanager_check_drkey_validity(&dict_node->old_inbound_key,
				ns_now);
		if (res < 0) {
			return -4;
		}
		lf_drkey_derive_host_host_from_as_as(&kmw->drkey_ctx,
				&dict_node->old_inbound_key.key, backend_addr, peer_addr,
				drkey_protocol, drkey);
		*ns_drkey_epoch_start = dict_node->old_inbound_key.validity_not_before;
		return 0;
	}

	return -2;
}

/**
 * Obtain an outbound DRKey that is valid (including grace period) at the
 * requested time. If two valid DRKeys are available, which is possible due to
 * the grace period, the newer key is returned which is not in the grace period.
 *
 * @param peer_as: Packet's destination AS (network byte order).
 * @param peer_addr: Packet's destination address (network byte order).
 * @param backend_addr: Packet's source address (network byte order).
 * @param drkey_protocol: (network byte order).
 * @param ns_now: Unix timestamp in nanoseconds, at which the requested key
 * must be valid.
 * @param drkey: Memory to write DRKey to.
 * @return Returns 0 if a DRKey has been found which is valid for the requested
 * time. Returns 1 if a DRKey has been found that is in the grace period.
 * Otherwise, a negative number is returned
 */
static inline int
lf_keymanager_worker_outbound_get_drkey(struct lf_keymanager_worker *kmw,
		uint64_t peer_as, const struct lf_host_addr *peer_addr,
		const struct lf_host_addr *backend_addr, uint16_t drkey_protocol,
		uint64_t ns_now, uint64_t *ns_drkey_epoch_start,
		struct lf_crypto_drkey *drkey)
{
	int res;
	int key_id;
	struct lf_keymanager_dictionary_data *dict_node;
	struct lf_keymanager_dictionary_key key = {
		.as = peer_as,
		.drkey_protocol = drkey_protocol,
	};

	/* find AS-AS key */
	key_id = rte_hash_lookup_data(kmw->dict, &key, (void **)&dict_node);
	if (unlikely(key_id < 0)) {
		return -1;
	}

	/* Check if the new key is valid. */
	res = lf_keymanager_check_drkey_validity(&dict_node->outbound_key, ns_now);
	if (likely(res == 0 || res == 1)) {
		lf_drkey_derive_host_host_from_as_as(&kmw->drkey_ctx,
				&dict_node->outbound_key.key, peer_addr, backend_addr,
				drkey_protocol, drkey);
		*ns_drkey_epoch_start = dict_node->outbound_key.validity_not_before;
		return res;
	}

	/* Check if the old key is valid */
	res = lf_keymanager_check_drkey_validity(&dict_node->old_outbound_key,
			ns_now);
	if (likely(res == 0 || res == 1)) {
		lf_drkey_derive_host_host_from_as_as(&kmw->drkey_ctx,
				&dict_node->old_outbound_key.key, peer_addr, backend_addr,
				drkey_protocol, drkey);
		*ns_drkey_epoch_start = dict_node->old_outbound_key.validity_not_before;
		return res;
	}

	return -2;
}

/**
 * Launch function for keymanager service.
 */
int
lf_keymanager_service_launch(struct lf_keymanager *km);

/**
 * Replaces current config with new config.
 * @param config: new config
 * @return 0 on success, otherwise, -1.
 */
int
lf_keymanager_apply_config(struct lf_keymanager *km,
		const struct lf_config *config);

/**
 * Frees the content of the keymanager struct (not itself).
 * This includes also the workers' structs. Hence, all the workers have to
 * terminate beforehand.
 */
int
lf_keymanager_close(struct lf_keymanager *km);

/**
 * @param qsv workers' QS variable for the RCU synchronization. The QS variable
 * can be shared with other services, i.e., other processes call check on it,
 * because the keymanager service calls it rarely and can also wait.
 */
int
lf_keymanager_init(struct lf_keymanager *km, uint16_t nb_workers,
		uint32_t initial_size, struct rte_rcu_qsbr *qsv);


/**
 * Register keymanager IPC commands for the provided context.
 */
int
lf_keymanager_register_ipc(struct lf_keymanager *km);


/**
 * Register keymanager telemetry commands for the provided context.
 */
int
lf_keymanager_register_telemetry(struct lf_keymanager *km);

#endif /* LF_KEYMANAGER_H */