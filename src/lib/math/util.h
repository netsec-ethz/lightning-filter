/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

/*
 * Saturating Operations for Integers
 * Use these operations to avoid overflows.
 */

#ifndef LF_MATH_UTIL_H
#define LF_MATH_UTIL_H


#ifndef MIN
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

#ifndef MAX
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#endif

#define inc_mod2(val) (((val) + 1) % 2)

#endif /* LF_MATH_UTIL_H */