/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

/*
 * Saturating Operations for Integers
 * Use these operations to avoid overflows.
 */

#ifndef LF_MATH_SAT_OP_H
#define LF_MATH_SAT_OP_H

#include <stdint.h>

static inline uint64_t
sat_add_u64(uint64_t x, uint64_t y)
{
	return x + y >= x ? x + y : UINT64_MAX;
}

static inline uint64_t
sat_sub_u64(uint64_t x, uint64_t y)
{
	return x - y <= x ? x - y : 0;
}

static inline int64_t
sat_add_64(int64_t x, int64_t y)
{
	return x + y >= x ? x + y : INT64_MAX;
}

static inline uint64_t
sat_sub_64(int64_t x, int64_t y)
{
	return x - y <= x ? x - y : 0;
}

#endif /* LF_MATH_SAT_OP_H */