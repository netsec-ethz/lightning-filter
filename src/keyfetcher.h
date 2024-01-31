/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#ifndef LF_KEYFETCHER_H
#define LF_KEYFETCHER_H

#include <inttypes.h>

#include <rte_jhash.h>

#include "config.h"
#include "drkey.h"
#include "drkey_fetcher.h"
#include "lib/crypto/crypto.h"
#include "lib/log/log.h"

/**
 * The keyfetcher fetches the requested DRKeys.
 * It either fetches the keys from the control service or derives them for peers
 * that have shared secret values configured. The configured shared values are
 * stored in the keyfetcher.
 *
 * The keyfetcher does not implement additional caching.
 *
 * The CS fetching depends on a DRKey fetcher module, which depends on the
 * deployment setup.
 */

struct lf_keyfetcher_sv_container {
	uint64_t validity_not_before; /* Unix timestamp (nanoseconds) */
	struct lf_crypto_drkey key;
};

struct lf_keyfetcher_sv_dictionary_data {
	struct lf_keyfetcher_sv_container secret_values[LF_CONFIG_SV_MAX];
};

struct lf_keyfetcher_dictionary_key {
	uint64_t as;             /* network byte order */
	uint16_t drkey_protocol; /* network byte order */
} __attribute__((__packed__));


struct lf_keyfetcher {
	/* SV dictionary */
	struct rte_hash *dict;
	/* max number of entries */
	uint32_t size;

	uint64_t src_ia;

	char drkey_service_addr[48];

	/* crypto DRKey context */
	struct lf_crypto_drkey_ctx drkey_ctx;
};

int
lf_keyfetcher_fetch_as_as_key(struct lf_keyfetcher *kf, uint64_t src_ia,
		uint64_t dst_ia, uint16_t drkey_protocol, uint64_t ns_valid,
		struct lf_keymanager_key_container *key);

int
lf_keyfetcher_fetch_host_as_key(struct lf_keyfetcher *kf, uint64_t src_ia,
		uint64_t dst_ia, const struct lf_host_addr *fast_side_host,
		uint16_t drkey_protocol, uint64_t ns_valid,
		struct lf_keymanager_key_container *key);

int
lf_keyfetcher_fetch_host_host_key(struct lf_keyfetcher *kf, uint64_t src_ia,
		uint64_t dst_ia, const struct lf_host_addr *fast_side_host,
		const struct lf_host_addr *slow_side_host, uint16_t drkey_protocol,
		uint64_t ns_valid, struct lf_keymanager_key_container *key);

// should only be called when keymanager management lock is hold
int
lf_keyfetcher_apply_config(struct lf_keyfetcher *kf,
		const struct lf_config *config);

int
lf_keyfetcher_close(struct lf_keyfetcher *kf);

int
lf_keyfetcher_init(struct lf_keyfetcher *kf, uint32_t initial_size);

#endif /* LF_KEYFETCHER_H */