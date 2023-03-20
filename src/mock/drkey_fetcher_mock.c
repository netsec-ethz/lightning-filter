/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#include <stdint.h>
#include <string.h>

#include "../drkey_fetcher.h"
#include "../lib/crypto/crypto.h"

#define DRKEY_SIZE      16
#define VALIDITY_PERIOD 10000 /* 10 seconds */

int
lf_drkey_fetcher_as_as_key(const char drkey_service_addr[48], uint64_t src_ia,
		uint64_t dst_ia, uint16_t drkey_protocol, int64_t val_time_ms,
		int64_t *validity_not_before, int64_t *validity_not_after, void *key)
{
	int res;
	struct lf_crypto_drkey_ctx drkey_ctx;
	struct lf_crypto_drkey sv_drkey;

	(void)drkey_service_addr;
	/*
	 * Validity period starts and stops at multiples of VALIDITY_PERIOD and has
	 * a duration of VALIDITY_PERIOD. I.e., the n-th validity period is
	 * [n*VALIDITY_PERIOD,(n+1)*VALIDITY_PERIOD].
	 * With this approach, the DRKey epochs are deterministic, as long as
	 * VALIDITY_PERIOD is defined.
	 */
	*validity_not_before = (val_time_ms / VALIDITY_PERIOD) * VALIDITY_PERIOD;
	*validity_not_after =
			(val_time_ms / VALIDITY_PERIOD) * VALIDITY_PERIOD + VALIDITY_PERIOD;

	/* The DRKey's secret value (SV) has the drkey_protocol identifier (cpu
	 * endian) as its first two bytes and zeros for the following bytes */
	uint8_t sv[DRKEY_SIZE] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	memcpy(sv, &drkey_protocol, sizeof(drkey_protocol));
	uint8_t buf[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	memcpy(buf, &src_ia, sizeof src_ia);
	memcpy(buf + 8, &dst_ia, sizeof dst_ia);

	res = lf_crypto_drkey_ctx_init(&drkey_ctx);
	if (res != 0) {
		return -1;
	}

	lf_crypto_drkey_from_buf(&drkey_ctx, sv, &sv_drkey);
	lf_crypto_drkey_cbcmac(&drkey_ctx, &sv_drkey, buf, 16, key);

	lf_crypto_drkey_ctx_close(&drkey_ctx);
	return 0;
}