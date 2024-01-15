/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#include <stdint.h>

#include "drkey_fetcher.h"
#include "lib/scion_drkey/drkey.h"

int
lf_drkey_fetcher_host_as_key(const char drkey_service_addr[48], uint64_t src_ia,
		uint64_t dst_ia, uint64_t src_addr, uint16_t drkey_protocol,
		int64_t val_time_ms, int64_t *validity_not_before,
		int64_t *validity_not_after, void *key)
{
/*
 * Cast the const char* drkey_service_addr to a non-constant char*!
 * This is done because Cgo does not know the principle of const variable.
 * However, the GetASASKey function does not change the address string,
 * therefore, this cast is legal (and disabling the compiler warnings is
 * acceptable)!
 */
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
#endif
	char *non_const_addr = (char *)drkey_service_addr;
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

	return (int)GetHostASKey(non_const_addr, src_ia, dst_ia, src_addr,
			drkey_protocol, val_time_ms, (GoInt64 *)validity_not_before,
			(GoInt64 *)validity_not_after, key);
}

int
lf_drkey_fetcher_host_host_key(const char drkey_service_addr[48],
		uint64_t src_ia, uint64_t dst_ia, uint64_t src_addr, uint64_t dst_addr,
		uint16_t drkey_protocol, int64_t val_time_ms,
		int64_t *validity_not_before, int64_t *validity_not_after, void *key)
{
/*
 * Cast the const char* drkey_service_addr to a non-constant char*!
 * This is done because Cgo does not know the principle of const variable.
 * However, the GetASASKey function does not change the address string,
 * therefore, this cast is legal (and disabling the compiler warnings is
 * acceptable)!
 */
#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
#endif
	char *non_const_addr = (char *)drkey_service_addr;
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

	return (int)GetHostHostKey(non_const_addr, src_ia, dst_ia, src_addr,
			dst_addr, drkey_protocol, val_time_ms,
			(GoInt64 *)validity_not_before, (GoInt64 *)validity_not_after, key);
}