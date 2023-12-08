/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#include <stdint.h>
#include <string.h>

#include "../drkey_fetcher.h"
#include "../lib/crypto/crypto.h"

#define DRKEY_SIZE      16
#define VALIDITY_PERIOD 10000 /* 10 seconds */

// TODO remove this warning supression once implemented.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

int
lf_drkey_fetcher_host_as_key(const char drkey_service_addr[48], uint64_t src_ia,
		uint64_t dst_ia, uint64_t src_addr, uint16_t drkey_protocol,
		int64_t val_time_ms, int64_t *validity_not_before,
		int64_t *validity_not_after, void *key)
{
	return -1;
}

int
lf_drkey_fetcher_host_host_key(const char drkey_service_addr[48],
		uint64_t src_ia, uint64_t dst_ia, uint64_t src_addr, uint64_t dst_addr,
		uint16_t drkey_protocol, int64_t val_time_ms,
		int64_t *validity_not_before, int64_t *validity_not_after, void *key)
{
	return -1;
}

#pragma GCC diagnostic pop
