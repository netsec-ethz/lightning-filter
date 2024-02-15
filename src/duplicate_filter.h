/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#ifndef LF_DUPLICATE_FILTER_H
#define LF_DUPLICATE_FILTER_H

#include <inttypes.h>

#include "lf.h"
#include "lib/time/time.h"

/**
 * This module provides the (MAC) duplicate filtering functionalities.
 */

/**
 * The worker's duplicate filter struct, containing the worker's rotating bloom
 * filters.
 */
struct lf_duplicate_filter_worker {
	struct lf_timestamp last_rotation;
	struct lf_timestamp bf_period;

	/* Bloom Filter Variables */
	unsigned int bf_hashes;
	unsigned int bf_size;
	unsigned int secret;
	unsigned int current_bf;
	unsigned int nb_bf;

	/*
	 * It is required that bf_size*8 is a power of 2.
	 * This enables an efficient modulo computation simply using a mask:
	 * x % (bf_size*8) == x & modulo_mask
	 */
	uint32_t modulo_mask;

	/* all bloom filters. */
	uint8_t *bf_arrays[]; /* dynamically sized */
};

struct lf_duplicate_filter {
	struct lf_duplicate_filter_worker *workers[LF_MAX_WORKER];
	uint16_t nb_workers;
};

/**
 * Applies duplicate detection.
 * @return 0 if no duplication has been identified.
 * Otherwise, a duplicate is suspected.
 */
int
lf_duplicate_filter_apply(struct lf_duplicate_filter_worker *df,
		const uint8_t key[16], struct lf_timestamp *t_now);

/**
 * Create new duplicate filter worker context and initialize it.
 * See lf_duplicate_filter_init for the description of the parameters.
 * @return new duplicate filter worker context
 */
struct lf_duplicate_filter_worker *
lf_duplicate_filter_worker_new(uint16_t socket, unsigned int nb_bf,
		unsigned int bf_period, unsigned int bf_hashes, unsigned int bf_size,
		unsigned int hash_secret);

void
lf_duplicate_filter_worker_free(struct lf_duplicate_filter_worker *df);

/**
 * Initializes the duplicate filter struct. This also includes the allocation
 * and initialization of the worker contexts.
 * @param df: Duplicate filter struct to be initialized.
 * @param worker_lcores: The lcore assignment for the workers, which determines
 * the socket for which memory is allocated.
 * @param nb_workers: Number of worker contexts to be created.
 * @param nb_bf: Number of Bloom filters to use.
 * @param bf_period: Period between Bloom filter rotation in nanoseconds.
 * @param bf_hashes: Number of hash values used for the Bloom filters.
 * @param bf_size: Size of each Bloom filter bit array in bytes.
 * The size in bits (8*bf_size) must be a power of 2, at least 8,
 * and fit into a 32 bit unsigned integer.
 * @param hash_secret: Random secret used to make the hash unpredictable.
 * @returns 0 if successful.
 */
int
lf_duplicate_filter_init(struct lf_duplicate_filter *df,
		uint16_t worker_lcores[LF_MAX_WORKER], uint16_t nb_workers,
		unsigned int nb_bf, unsigned int bf_period, unsigned int bf_hashes,
		unsigned int bf_size, unsigned int hash_secret);

/**
 * De-initialize the duplicate filter struct and free all memory allocated for
 * it, i.e., the worker contexts.
 * @param df: Duplicate filter struct to be de-initialized.
 */
void
lf_duplicate_filter_close(struct lf_duplicate_filter *df);

#endif /* LF_DUPLICATE_FILTER_H */