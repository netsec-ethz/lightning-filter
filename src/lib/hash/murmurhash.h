/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#ifndef LF_MURMURHASH_H
#define LF_MURMURHASH_H

#include <inttypes.h>

#define LF_MURMURHASH_KEY_SIZE 16

uint32_t
lf_murmurhash(const uint8_t key[LF_MURMURHASH_KEY_SIZE], unsigned int seed);

#endif /* LF_MURMURHASH_H */