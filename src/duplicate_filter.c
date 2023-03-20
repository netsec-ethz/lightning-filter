/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#include <rte_branch_prediction.h>
#include <rte_lcore.h>
#include <rte_malloc.h>

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "duplicate_filter.h"
#include "lib/hash/murmurhash.h"
#include "lib/log/log.h"
#include "lib/math/sat_op.h"

/**
 * Log function for duplicate filter service (not on data path).
 * Format: "Duplicate Filter: log message here"
 */
#define LF_DUPLICATE_FILTER_LOG(level, ...) \
	LF_LOG(level, "Duplicate Filter: " __VA_ARGS__)

inline static int
check_bit_set_bit(uint8_t *bf_array, unsigned int bit, int set_bit)
{
	unsigned int byte = bit >> 3;
	unsigned int mask = 1 << (bit & 0x7); /* 1 << (bit % 8) */

	if (bf_array[byte] & mask) {
		/* hit */
		return 1;
	} else {
		/* no hit */
		if (set_bit) {
			bf_array[byte] |= mask;
		}
		return 0;
	}
}


inline static int
check_key_add_key(uint8_t *bf_arrays[], unsigned int nb_bf,
		unsigned int current_bf, uint32_t modulo_mask, unsigned int bf_hashes,
		unsigned int secret, const uint8_t key[16])
{
	unsigned int i, j;
	uint32_t hash_1, hash_2, a, b;
	uint32_t bit;
	unsigned int hit_counter;

	/*
	 * Calculate multiple hash values from two hashes using enhanced double
	 * hashing.
	 * hashes[i] = h1(x) + i*h2(x) + (i*i*i - i)/6
	 */

	hash_1 = lf_murmurhash(key, secret);
	hash_2 = lf_murmurhash(key, hash_1);

	hit_counter = 0;

	a = hash_1;
	b = hash_2;
	for (i = 0; i < bf_hashes; ++i) {
		/* a % (bf_size*8) == a & modulo_mask */
		bit = a & modulo_mask;
		a += b;
		b += i;

		if (check_bit_set_bit(bf_arrays[current_bf], bit, 1)) {
			hit_counter++;
		}
	}

	if (hit_counter == bf_hashes) {
		/* collision detected */
		return 1;
	}

	for (j = 0; j < nb_bf - 1; ++j) {
		if (j == current_bf) {
			continue;
		}

		hit_counter = 0;

		a = hash_1;
		b = hash_2;
		for (i = 0; i < bf_hashes; ++i) {
			/* a % (bf_size*8) == a & modulo_mask */
			bit = a & modulo_mask;
			a += b;
			b += i;

			if (check_bit_set_bit(bf_arrays[j], bit, 0)) {
				hit_counter++;
			} else {
				break; /* potentially early break */
			}
		}

		if (hit_counter == bf_hashes) {
			/* collision detected */
			return 1; /* potentially early return */
		}
	}

	return 0;
}

int
lf_duplicate_filter_apply(struct lf_duplicate_filter_worker *df,
		const uint8_t key[16], uint64_t ns_now)
{
	/* periodically rotate bloom filter */
	if (unlikely(sat_sub_u64(ns_now, df->bf_period) > df->last_rotation)) {
		df->current_bf = (df->current_bf + 1U) % df->nb_bf;
		(void)memset(df->bf_arrays[df->current_bf], 0, df->bf_size);

		df->last_rotation = ns_now;
	}

	return check_key_add_key(df->bf_arrays, df->nb_bf, df->current_bf,
			df->modulo_mask, df->bf_hashes, df->secret, key);
}

struct lf_duplicate_filter_worker *
lf_duplicate_filter_worker_new(uint16_t socket, unsigned int nb_bf,
		unsigned int bf_period, unsigned int bf_hashes, unsigned int bf_size,
		unsigned int hash_secret)
{
	int res;
	unsigned int i;
	unsigned int nb_bits;
	size_t struct_size;
	struct lf_duplicate_filter_worker *df_worker;

	/* check that 8*bf_size is power of 2 and at least 8. */
	nb_bits = 8 * bf_size;
	if (!((nb_bits & (nb_bits - 1)) == 0 && nb_bits >= 8)) {
		LF_DUPLICATE_FILTER_LOG(ERR,
				"8*bf_size must be a power of 2 and at least 8.\n");
		return NULL;
	}

	/*
	 * The struct size is dynamic and consists of the size of the struct without
	 * the dynamically sized array plus a pointer for each bloom filter.
	 */
	struct_size = sizeof(struct lf_duplicate_filter_worker) +
	              nb_bf * sizeof(uint8_t *);

	df_worker =
			rte_zmalloc_socket(NULL, struct_size, RTE_CACHE_LINE_SIZE, socket);
	if (df_worker == NULL) {
		LF_DUPLICATE_FILTER_LOG(ERR, "Unable to allocate %d bytes\n",
				sizeof(struct lf_duplicate_filter_worker));
		return NULL;
	}

	/* assign all arrays */
	res = 0;
	for (i = 0; i < nb_bf; ++i) {
		df_worker->bf_arrays[i] =
				rte_zmalloc_socket(NULL, bf_size, RTE_CACHE_LINE_SIZE, socket);

		if (df_worker->bf_arrays[i] == NULL) {
			LF_DUPLICATE_FILTER_LOG(ERR,
					"Unable to allocate %d bytes for bloom filter\n", bf_size);
			res = -1;
			break;
		}
	}

	/* check if an error occurred, i.e., it the loop was terminated early */
	if (res != 0) {
		/* free allocated memory */
		for (i = 0; i < nb_bf; ++i) {
			/* check if bloom filter has already been allocated */
			if (df_worker->bf_arrays[i] == NULL) {
				break;
			}
			rte_free(df_worker->bf_arrays[i]);
		}
		rte_free(df_worker);
		return NULL;
	}

	/* x % (bf_size*8) == x & modulo_mask */
	df_worker->modulo_mask = nb_bits - 1;
	df_worker->last_rotation = 0;
	df_worker->bf_period = bf_period;
	df_worker->current_bf = 0;
	df_worker->bf_size = bf_size;
	df_worker->bf_hashes = bf_hashes;
	df_worker->secret = hash_secret;
	df_worker->nb_bf = nb_bf;

	return df_worker;
}

void
lf_duplicate_filter_worker_free(struct lf_duplicate_filter_worker *df)
{
	rte_free(df);
}

int
lf_duplicate_filter_init(struct lf_duplicate_filter *df,
		uint16_t worker_lcores[LF_MAX_WORKER], uint16_t nb_workers,
		unsigned int nb_bf, unsigned int bf_period, unsigned int bf_hashes,
		unsigned int bf_size, unsigned int hash_secret)
{
	int res;
	int worker_id;
	unsigned int nb_bits;

	LF_DUPLICATE_FILTER_LOG(DEBUG, "Init\n");

	/* check that 8*bf_size is power of 2 and at least 8. */
	nb_bits = 8 * bf_size;
	if (!((nb_bits & (nb_bits - 1)) == 0 && nb_bits >= 8)) {
		LF_DUPLICATE_FILTER_LOG(ERR,
				"8*bf_size must be a power of 2 and at least 8.\n");
		return -1;
	}

	res = 0;
	for (worker_id = 0; worker_id < nb_workers; ++worker_id) {
		df->workers[worker_id] = lf_duplicate_filter_worker_new(
				rte_lcore_to_socket_id(worker_lcores[worker_id]), nb_bf,
				bf_period, bf_hashes, bf_size, hash_secret);
		if (df->workers[worker_id] == NULL) {
			res = -1;
			break;
		}
	}

	if (res != 0) {
		/* free allocated duplicate filter of workers */
		for (worker_id = worker_id - 1; worker_id >= 0; --worker_id) {
			lf_duplicate_filter_worker_free(df->workers[worker_id]);
			df->workers[worker_id] = NULL;
		}
	}

	df->nb_workers = nb_workers;

	return res;
}

void
lf_duplicate_filter_close(struct lf_duplicate_filter *df)
{
	uint16_t worker_id;

	for (worker_id = 0; worker_id < df->nb_workers; ++worker_id) {
		lf_duplicate_filter_worker_free(df->workers[worker_id]);
		df->workers[worker_id] = NULL;
	}
}