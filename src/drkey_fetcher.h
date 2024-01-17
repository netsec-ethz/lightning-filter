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

// TODO (abojarski) use correct types for src_addr and dst_addr to accommodate
// enough space for IPV6 addresses.

/**
 * Fetch a host-AS (level 2) DRKey from a DRKey service.
 *
 * @param drkey_service_addr Service address ("IP:Port")
 * @param src_ia DRKey slow side (CPU endian)
 * @param dst_ia DRKey fast side (CPU endian)
 * @param src_addr DRKey slow side (CPU endian)
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
lf_drkey_fetcher_host_as_key(const char drkey_service_addr[48], uint64_t src_ia,
		uint64_t dst_ia, uint64_t src_addr, uint16_t drkey_protocol,
		int64_t val_time_ms, int64_t *validity_not_before,
		int64_t *validity_not_after, void *key);

/**
 * Fetch a host-host (level 3) DRKey from a DRKey service.
 *
 * @param drkey_service_addr Service address ("IP:Port")
 * @param src_ia DRKey slow side (CPU endian)
 * @param dst_ia DRKey fast side (CPU endian)
 * @param src_addr DRKey slow side (CPU endian)
 * @param dst_addr DRKey fast side (CPU endian)
 * @param drkey_protocol DRKey protocol (CPU endian)
 * @param val_time_ms Time at which the requested key should be valid
 * (millisecond UNIX timestamp)
 * @param validity_not_before Return DRKey epoch start (millisecond UNIX
 * timestamp)
 * @param validity_not_after Return DRKey epoch end (millisecond UNIX
 * timestamp)
 * @param key Return requested DRKey as byte array of size 16.
 * @return 0 on success.
 */
int
lf_drkey_fetcher_host_host_key(const char drkey_service_addr[48],
		uint64_t src_ia, uint64_t dst_ia, uint64_t src_addr, uint64_t dst_addr,
		uint16_t drkey_protocol, int64_t val_time_ms,
		int64_t *validity_not_before, int64_t *validity_not_after, void *key);


#endif /* LF_DRKEY_FETCHER_H */