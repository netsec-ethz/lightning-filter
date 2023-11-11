/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#ifndef LF_JSON_UTIL_H
#define LF_JSON_UTIL_H

#include <arpa/inet.h>
#include <assert.h>
#include <inttypes.h>

#include <rte_byteorder.h>

#include "../utils/parse.h"
#include "json.h"

static inline int
lf_json_parse_double(const json_value *json_val, double *val)
{
	if (json_val == NULL) {
		return -1;
	}
	if (json_val->type != json_double) {
		return -1;
	}

	*val = json_val->u.dbl;
	return 0;
}

static inline int
lf_json_parse_string(const json_value *json_val, char *dst, size_t n)
{
	if (json_val->type != json_string) {
		return -1;
	}

	if (json_val->u.string.length > n) {
		return -1;
	}

	(void)strcpy(dst, json_val->u.string.ptr);
	return 0;
}

static inline int
lf_json_parse_uint16(const json_value *json_val, uint16_t *dst)
{
	int64_t drkey_protocol;

	if (json_val->type != json_integer) {
		return -1;
	}

	drkey_protocol = json_val->u.integer;
	if (drkey_protocol < 0 || drkey_protocol > UINT16_MAX) {
		return -1;
	}
	*dst = (uint16_t)drkey_protocol;
	return 0;
}

static inline int
lf_json_parse_uint64(json_value *json_val, uint64_t *val)
{
	if (json_val == NULL) {
		return -1;
	}
	if (json_val->type != json_integer) {
		return -1;
	}

	*val = (uint64_t)json_val->u.integer;
	;
	return 0;
}

static inline int
lf_json_parse_bool(json_value *json_val, bool *val)
{
	if (json_val == NULL) {
		return -1;
	}
	if (json_val->type != json_boolean) {
		return -1;
	}

	*val = (bool)json_val->u.boolean;
	return 0;
}

/**
 * Parse ethernet address string.
 * @param val result ethernet address (newtork byte order).
 */
static inline int
lf_json_parse_ether(const json_value *json_val, uint8_t val[6])
{
	char *addrstr;
	size_t i = 0, j = 0, k = 0;

	if (json_val->type != json_string) {
		return -1;
	}

	addrstr = json_val->u.string.ptr;

	do {
		if (k != 0) {
			assert(i <= json_val->u.string.length);
			if (addrstr[i] != ':') {
				return -1;
			}
			i++;
		}
		val[k] = 0;
		j = i;
		do {
			assert(j <= json_val->u.string.length);
			if (('0' <= addrstr[j]) && (int)(addrstr[j] <= '9')) {
				val[k] = (val[k] << 4) | (addrstr[j] - '0');
			} else if (('a' <= addrstr[j]) && (addrstr[j] <= 'f')) {
				val[k] = (val[k] << 4) | (int)(addrstr[j] - 'a' + 10);
			} else {
				return -1;
			}
			j++;
		} while (j - i != 2);
		i += 2;
		k++;
	} while (k != 6);
	assert(i == json_val->u.string.length);
	assert(addrstr[i] == '\0');

	return 0;
}

/**
 * Parse IPv4 address string.
 * @param val result IP address (newtork byte order).
 */
static inline int
lf_json_parse_ipv4(const json_value *json_val, uint32_t *val)
{
	int res;
	if (json_val->type != json_string) {
		return -1;
	}
	assert(sizeof *val == sizeof(struct in_addr));

	res = inet_pton(AF_INET, json_val->u.string.ptr, val);
	if (res != 1) {
		return -1;
	}

	return 0;
}

static inline int
lf_json_parse_ipv6(const json_value *json_val, uint8_t val[16])
{
	int res;
	if (json_val->type != json_string) {
		return -1;
	}
	assert(16 == sizeof(struct in6_addr));

	res = inet_pton(AF_INET6, json_val->u.string.ptr, val);
	if (res != 1) {
		return -1;
	}

	return 0;
}

/**
 * Parse UDP/TCP port number.
 * @param val result port number (newtork byte order).
 */
static inline int
lf_json_parse_port(const json_value *json_val, uint16_t *dst)
{
	int res;
	res = lf_json_parse_uint16(json_val, dst);
	if (res != 0) {
		return res;
	}
	*dst = rte_cpu_to_be_16(*dst);
	return 0;
}

/**
 * Parse ISD AS contained in json_val and set val.
 * The json_val should be a json_string of a format equivalent to
 * "65535-ffff:ffff:ffff" or "65535-5466125".
 * @param val result ISD AS number (newtork byte order).
 */
static inline int
lf_json_parse_isd_as_be(json_value *json_val, uint64_t *val)
{
	int res;
	char iastr[sizeof "65535-ffff:ffff:ffff"];

	if (json_val == NULL) {
		return -1;
	}
	if (json_val->type != json_string) {
		return -1;
	}

	if (json_val->u.string.length > sizeof iastr) {
		return -1;
	}
	(void)strncpy(iastr, json_val->u.string.ptr, sizeof(iastr) - 1);

	res = lf_parse_isd_as(iastr, val);
	if (res != 0) {
		return -1;
	}
	*val = rte_cpu_to_be_64(*val);

	return 0;
}


/**
 * Parse DRKey string.
 * @param val result 16 byte DRKey (newtork byte order).
 */
static inline int
lf_json_parse_drkey(const json_value *json_val, uint8_t val[16])
{
	char *addrstr;

	if (json_val->type != json_string) {
		return -1;
	}

	addrstr = json_val->u.string.ptr;

	for (uint8_t i = 0; i < 16; i++) {
		val[i] = 0;
		for (uint8_t j = 2 * i; j < 2 * i + 2; j++) {
			assert(j <= json_val->u.string.length);
			if (('0' <= addrstr[j]) && (int)(addrstr[j] <= '9')) {
				val[i] = (val[i] << 4) | (addrstr[j] - '0');
			} else if (('a' <= addrstr[j]) && (addrstr[j] <= 'f')) {
				val[i] = (val[i] << 4) | (int)(addrstr[j] - 'a' + 10);
			} else {
				return -1;
			}
		}
	}
	assert(32 == json_val->u.string.length);
	assert(addrstr[32] == '\0');

	return 0;
}

#endif /* LF_JSON_UTIL_H */