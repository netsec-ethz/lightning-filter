/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#ifndef LF_DRKEY_FETCHER_H
#define LF_DRKEY_FETCHER_H

#include <stdint.h>

/**
 * This file contains the DRKey fetcher interface that is expected by the key
 * manager.
 * Depending on the deployment, a different key fetcher can might be used as
 * long as it implements this interface.
 */

/**
 * Fetch a AS to AS (level 1) DRKey from a DRKey service.
 *
 * @param drkey_service_addr Service address ("IP:Port")
 * @param src_ia DRKey slow side (CPU endian)
 * @param dst_ia DRKey fast side (CPU endian)
 * @param drkey_protocol DRKey protocol (CPU endian)
 * @param val_time_ms Time at which the requested key should be valid
 * (millisecond UNIX timestamp)
 * @param validity_not_before Return DRKey epoch start (millisecond UNIX
 * timestamp)
 * @param validity_not_after Return DRKey epoch end (millisecond UNIX timestamp)
 * @param key Return requested DRKey as byte array of size 16.
 * @return 0 on success.
 */
int
lf_drkey_fetcher_as_as_key(const char drkey_service_addr[48], uint64_t src_ia,
		uint64_t dst_ia, uint16_t drkey_protocol, int64_t val_time_ms,
		int64_t *validity_not_before, int64_t *validity_not_after, void *key);


#endif /* LF_DRKEY_FETCHER_H */