/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#ifndef LF_DRKEY_H
#define LF_DRKEY_H

#include <inttypes.h>
#include <stdbool.h>

#include "lf.h"
#include "lib/crypto/crypto.h"
#include "lib/time/time.h"

/*
 * A DRKey is valid during a certain epoch defined by a starting and ending
 * point in time. During the transition between an old key and a new key, both
 * keys are valid. This transition period is defined by the
 * LF_DRKEY_GRACE_PERIOD, which extends the ending point of the old key by a
 * certain amount of time.
 */
#define LF_DRKEY_GRACE_PERIOD       (2 * LF_TIME_NS_IN_S) /* in nanoseconds */
#define LF_DRKEY_PREFETCHING_PERIOD (1 * LF_TIME_NS_IN_S) /* in nanoseconds */

/*
 * DRKey derivation types.
 */
#define LF_DRKEY_DERIVATION_TYPE_AS_AS     0
#define LF_DRKEY_DERIVATION_TYPE_AS_HOST   1
#define LF_DRKEY_DERIVATION_TYPE_HOST_AS   2
#define LF_DRKEY_DERIVATION_TYPE_HOST_HOST 3

/*
 * DRKey validity period used for shared, configured keys.
 */
#define LF_DRKEY_VALIDITY_PERIOD_NS \
	(3 * 24 * 3600 * LF_TIME_NS_IN_S) /* in nanoseconds */

/*
 * IPv6 prefix for embedded IPv4 address
 */
static const uint8_t IPV4_MAPPED_IPV6_PREFIX[12] = { 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF };

/**
 * The key container wraps all information required to use a key.
 * A DRKeys validity is usually defined in seconds. Because the workers operate
 * with nanosecond timestamps, the validity timestamps are also stored in
 * nanoseconds to avoid any conversion.
 */
struct lf_keymanager_key_container {
	uint64_t validity_not_before; /* Unix timestamp (nanoseconds) */
	uint64_t validity_not_after;  /* Unix timestamp (nanoseconds) */
	struct lf_crypto_drkey key;
};

/**
 * Derive HOST-AS DRKey from AS-AS DRKey.
 *
 * @param drkey_ctx DRKey cipher context.
 * @param drkey_as_as AS-AS DRKey.
 * @param fast_side_host Fast side host address.
 * @param drkey_protocol (network byte order).
 * @param drkey_ha Returning HOST-AS DRKey.
 */
static inline void
lf_drkey_derive_host_as_from_as_as(struct lf_crypto_drkey_ctx *drkey_ctx,
		const struct lf_crypto_drkey *drkey_as_as,
		const struct lf_host_addr *fast_side_host,
		const uint16_t drkey_protocol, struct lf_crypto_drkey *drkey_ha)
{
	assert(LF_HOST_ADDR_LENGTH(fast_side_host) <= LF_CRYPTO_CBC_BLOCK_SIZE);

	uint8_t addr_type_len = (uint8_t)(fast_side_host->type_length);
	uint8_t *addr = (uint8_t *)(fast_side_host->addr);
	uint8_t addr_len = LF_HOST_ADDR_LENGTH(fast_side_host);

	// IPv4 mapped to IPv6
	if (addr_type_len == 3 && memcmp(addr, IPV4_MAPPED_IPV6_PREFIX,
									  sizeof IPV4_MAPPED_IPV6_PREFIX) == 0) {
		addr += 12;
		addr_len = 4;
		addr_type_len = 0;
	}

	int buf_len = (addr_len == 4) ? LF_CRYPTO_CBC_BLOCK_SIZE
	                              : 2 * LF_CRYPTO_CBC_BLOCK_SIZE;
	uint8_t buf[2 * LF_CRYPTO_CBC_BLOCK_SIZE] = { 0 };
	buf[0] = LF_DRKEY_DERIVATION_TYPE_HOST_AS;
	memcpy(buf + 1, &drkey_protocol, 2);
	buf[3] = addr_type_len;
	memcpy(buf + 4, addr, addr_len);

	lf_crypto_drkey_derivation_step(drkey_ctx, drkey_as_as, buf, buf_len,
			drkey_ha);
}

/**
 * Derive HOST-HOST DRKey from HOST-AS DRKey.
 *
 * @param drkey_ctx DRKey cipher context.
 * @param drkey_host_as HOST-AS DRKey.
 * @param slow_side_host Slow side host address.
 * @param drkey_hh Returning HOST-HOST DRKey.
 */
static inline void
lf_drkey_derive_host_host_from_host_as(struct lf_crypto_drkey_ctx *drkey_ctx,
		const struct lf_crypto_drkey *drkey_host_as,
		const struct lf_host_addr *slow_side_host,
		struct lf_crypto_drkey *drkey_hh)
{
	assert(LF_HOST_ADDR_LENGTH(slow_side_host) <= LF_CRYPTO_CBC_BLOCK_SIZE);

	uint8_t addr_type_len = (uint8_t)(slow_side_host->type_length);
	uint8_t *addr = (uint8_t *)(slow_side_host->addr);
	uint8_t addr_len = LF_HOST_ADDR_LENGTH(slow_side_host);

	// IPv4 mapped to IPv6
	if (addr_type_len == 3 && memcmp(addr, IPV4_MAPPED_IPV6_PREFIX,
									  sizeof IPV4_MAPPED_IPV6_PREFIX) == 0) {
		addr += 12;
		addr_len = 4;
		addr_type_len = 0;
	}

	int buf_len = (addr_len == 4) ? LF_CRYPTO_CBC_BLOCK_SIZE
	                              : 2 * LF_CRYPTO_CBC_BLOCK_SIZE;
	uint8_t buf[2 * LF_CRYPTO_CBC_BLOCK_SIZE] = { 0 };
	buf[0] = LF_DRKEY_DERIVATION_TYPE_HOST_HOST;
	buf[1] = addr_type_len;
	memcpy(buf + 2, addr, addr_len);

	lf_crypto_drkey_derivation_step(drkey_ctx, drkey_host_as, buf, buf_len,
			drkey_hh);
}

/**
 * Derive HOST-HOST DRKey from AS-AS DRKey.
 *
 * @param drkey_ctx DRKey cipher context.
 * @param drkey_as_as AS-AS DRKey.
 * @param fast_side_host Fast side host address.
 * @param slow_side_host Slow side host address.
 * @param drkey_protocol (network byte order).
 * @param drkey_hh Returning HOST-HOST DRKey.
 */
static inline void
lf_drkey_derive_host_host_from_as_as(struct lf_crypto_drkey_ctx *drkey_ctx,
		const struct lf_crypto_drkey *drkey_as_as,
		const struct lf_host_addr *fast_side_host,
		const struct lf_host_addr *slow_side_host,
		const uint16_t drkey_protocol, struct lf_crypto_drkey *drkey_hh)
{
	struct lf_crypto_drkey drkey_ha;
	lf_drkey_derive_host_as_from_as_as(drkey_ctx, drkey_as_as, fast_side_host,
			drkey_protocol, &drkey_ha);
	lf_drkey_derive_host_host_from_host_as(drkey_ctx, &drkey_ha, slow_side_host,
			drkey_hh);
}

#endif // LF_DRKEY_H