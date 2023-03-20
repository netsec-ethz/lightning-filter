/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#ifndef LF_UTILS_PARSE_H
#define LF_UTILS_PARSE_H

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>

static inline int
lf_parse_unum(const char *str, uint64_t *val)
{
	errno = 0;
	*val = strtoull(str, NULL, 10);
	if (errno != 0) {
		return -1;
	}
	return 0;
}

static inline int32_t
lf_parse_as_part(const char *str, size_t length)
{
	int32_t as_num_part;
	size_t i;
	if ((length == 0) || (length > 4)) {
		as_num_part = -1;
	} else {
		as_num_part = 0;
		i = 0;
		do {
			if (('0' <= str[i]) && (str[i] <= '9')) {
				as_num_part = (as_num_part << 4) | (int)(str[i] - '0');
			} else if (('A' <= str[i]) && (str[i] <= 'F')) {
				as_num_part = (as_num_part << 4) | (int)(str[i] - 'A' + 10);
			} else if (('a' <= str[i]) && (str[i] <= 'f')) {
				as_num_part = (as_num_part << 4) | (int)(str[i] - 'a' + 10);
			} else {
				as_num_part = -1;
			}
			i++;
		} while ((as_num_part >= 0) && (i != length));
	}
	return as_num_part;
}

static inline int64_t
lf_parse_as_bgp(const char *str, size_t length)
{
	int64_t as_num;
	size_t i;
	int x;
	if (length == 0) {
		as_num = -1;
	} else {
		as_num = 0;
		i = 0;
		do {
			if (('0' <= str[i]) && (str[i] <= '9')) {
				x = (int)(str[i] - '0');
				if (as_num <= (4294967295 - x) / 10) {
					as_num = 10 * as_num + x;
				} else {
					as_num = -1;
				}
			} else {
				as_num = -1;
			}
			i++;
		} while ((as_num >= 0) && (i != length));
	}
	return as_num;
}

/**
 * Parse AS address string.
 * If successfully, returns positive number (max 48 bits).
 * Otherwise, returns -1.
 */
static inline int64_t
lf_parse_as(const char *str)
{
	uint64_t as;
	int32_t as_part;
	int64_t as_bgp;
	size_t i = 0, j = 0;

	while ((str[j] != '\0') && (str[j] != ':')) {
		j++;
	}
	if (str[j] == '\0') {
		as_bgp = lf_parse_as_bgp(&str[0], j);
		if (as_bgp < 0) {
			return -1;
		}
		as = (uint64_t)as_bgp;
	} else {
		as = 0;
		as_part = lf_parse_as_part(&str[i], j - i);
		if (as_part < 0) {
			return -1;
		}
		as |= (uint64_t)as_part << 32;
		j++;
		i = j;
		while ((str[j] != '\0') && (str[j] != ':')) {
			j++;
		}
		if (str[j] == '\0') {
			return -1;
		}
		as_part = lf_parse_as_part(&str[i], j - i);
		if (as_part < 0) {
			return -1;
		}
		as |= (uint64_t)as_part << 16;
		j++;
		i = j;
		while (str[j] != '\0') {
			j++;
		}
		as_part = lf_parse_as_part(&str[i], j - i);
		if (as_part < 0) {
			return -1;
		}
		as |= (uint64_t)as_part;
	}

	/* AS number does not exceed INT64_MAX */
	return (int64_t)as;
}

/**
 * Parse ISD address string.
 * If successfully, returns positive number (max 16 bits).
 * Otherwise, returns -1.
 */
static inline int32_t
lf_parse_isd(const char *str, size_t length)
{
	int32_t isd_num;
	size_t i;
	int x;
	if (length == 0) {
		isd_num = -1;
	} else {
		isd_num = 0;
		i = 0;
		do {
			if (('0' <= str[i]) && (str[i] <= '9')) {
				x = (int)(str[i] - '0');
				if (isd_num <= (65535 - x) / 10) {
					isd_num = 10 * isd_num + x;
				} else {
					isd_num = -1;
				}
			} else {
				isd_num = -1;
			}
			i++;
		} while ((isd_num >= 0) && (i != length));
	}
	return isd_num;
}

/**
 * Parse an ISD AS number string.
 *
 * @param iastr
 * @param length: length of the string
 * @param val: parsed ISD AS number (cpu byte order)
 * @return int 0 on success, -1 for invalid ISD, -2 for invalid AS.
 */
static inline int
lf_parse_isd_as(const char *iastr, uint64_t *val)
{
	int32_t isd;
	int64_t as;
	size_t j = 0;

	/* find deliminator '-' between ISD and AS */
	while ((iastr[j] != '\0') && (iastr[j] != '-')) {
		j++;
	}
	if (iastr[j] == '\0') {
		return -1;
	}

	/* parse ISD part */
	isd = lf_parse_isd(&iastr[0], j);
	if (isd < 0) {
		return -1;
	}

	/* skip deliminator '-' */
	j++;

	/* parse AS part */
	as = lf_parse_as(&iastr[j]);
	if (as < 0) {
		return -2;
	}

	/* combine ISD and AS */
	*val = ((uint64_t)isd << 48) | (uint64_t)as;
	return 0;
}

#endif /* LF_UTILS_PARSE_H */