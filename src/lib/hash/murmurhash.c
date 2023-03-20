/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#include <stdint.h>
#include <stdlib.h>

#include "murmurhash.h"

// NOLINTBEGIN(readability-magic-numbers)

//-----------------------------------------------------------------------------
// MurmurHash3 was written by Austin Appleby, and is placed in the public
// domain. The author hereby disclaims copyright to this source code.
//
// https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp
//-----------------------------------------------------------------------------

static inline uint32_t
rotl32(uint32_t x, int8_t r)
{
	return (x << r) | (x >> (32 - r));
}

//-----------------------------------------------------------------------------
// Block read - if your platform needs to do endian-swapping or can only
// handle aligned reads, do the conversion here
static inline uint32_t
getblock32(const uint32_t *p, int i)
{
	return p[i];
}

//-----------------------------------------------------------------------------
// Finalization mix - force all bits of a hash block to avalanche
static inline uint32_t
fmix32(uint32_t h)
{
	h ^= h >> 16;
	h *= 0x85ebca6b;
	h ^= h >> 13;
	h *= 0xc2b2ae35;
	h ^= h >> 16;

	return h;
}

static inline void
MurmurHash3_x86_32(const void *key, int len, uint32_t seed, void *out)
{
	const uint8_t *data = (const uint8_t *)key;
	const int nblocks = len / 4;

	uint32_t h1 = seed;

	const uint32_t c1 = 0xcc9e2d51;
	const uint32_t c2 = 0x1b873593;

	//----------
	// body

/*
 * Clang issues the following warning:
 * 	error: cast from 'const uint8_t *' (aka 'const unsigned char *') to 'const
 *  uint32_t *' (aka 'const unsigned int *') increases required alignment from 1
 *	to 4 [-Werror,-Wcast-align]
 *
 * This warning is ignored as we assume to operate on a x86 architecture.
 * On a x86 architecture, an unaligned access should only introduce a time
 * penalty and not undefined behaviour.
 */
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-align"
#endif
	const uint32_t *blocks = (const uint32_t *)(data + nblocks * 4);
#ifdef __clang
#pragma clang diagnostic pop
#endif

	for (int i = -nblocks; i; i++) {
		uint32_t k1 = getblock32(blocks, i);

		k1 *= c1;
		k1 = rotl32(k1, 15);
		k1 *= c2;

		h1 ^= k1;
		h1 = rotl32(h1, 13);
		h1 = h1 * 5 + 0xe6546b64;
	}

	//----------
	// tail

	const uint8_t *tail = (const uint8_t *)(data + nblocks * 4);

	uint32_t k1 = 0;

	switch (len & 3) {
	case 3:
		k1 ^= tail[2] << 16;
		/* FALLTHRU */
	case 2:
		k1 ^= tail[1] << 8;
		/* FALLTHRU */
	case 1:
		k1 ^= tail[0];
		k1 *= c1;
		k1 = rotl32(k1, 15);
		k1 *= c2;
		h1 ^= k1;
	};

	//----------
	// finalization

	h1 ^= len;

	h1 = fmix32(h1);

	*(uint32_t *)out = h1;
}

// NOLINTEND(readability-magic-numbers)

uint32_t
lf_murmurhash(const uint8_t key[LF_MURMURHASH_KEY_SIZE],
		const unsigned int seed)
{
	uint32_t res;
	(void)MurmurHash3_x86_32(key, LF_MURMURHASH_KEY_SIZE, seed, &res);
	return res;
}