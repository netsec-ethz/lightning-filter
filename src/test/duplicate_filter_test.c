/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#include <arpa/inet.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <rte_eal.h>

#include "../duplicate_filter.h"

/**
 * Create a duplicate filter worker context, perform some simple duplicate tests
 * on it, and free context.
 *
 * @return number of errors.
 */
int
duplicate_filter_worker()
{
	int res;
	int error_count;
	struct lf_duplicate_filter_worker *df;

	uint64_t ns_now = 0;
	unsigned int bf_period = 1000;
	unsigned int bf_hashes = 4;
	unsigned int bf_bytes = 4;
	unsigned int secret = 0;

	df = lf_duplicate_filter_worker_new(0, 4, bf_period, bf_hashes, bf_bytes,
			secret);
	if (df == NULL) {
		printf("FAILED: init");
		return 1;
	}

	const uint8_t in1[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		'a', 'b', 'c', 'd', 'e', 'f' };
	const uint8_t in2[16] = { '1', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		'a', 'b', 'c', 'd', 'e', 'f' };

	error_count = 0;
	res = lf_duplicate_filter_apply(df, in1, 0);
	if (res != 0) {
		printf("Failed: in1\n");
		error_count++;
	}


	res = lf_duplicate_filter_apply(df, in2, 0);
	if (res != 0) {
		printf("Failed: in2\n");
		error_count++;
	}

	res = lf_duplicate_filter_apply(df, in2, 0);
	if (res == 0) {
		printf("Failed: second in2\n");
		error_count++;
	}

	/* check that during rotations in2 is still being detected as duplicate. */
	for (unsigned int i = 0; i < df->nb_bf + 1; ++i) {
		ns_now = ns_now + bf_period + 1;
		res = lf_duplicate_filter_apply(df, in2, ns_now);
		if (res == 0) {
			printf("Failed: in2 at %" PRId64 "\n", ns_now);
			error_count++;
		}
	}

	/* after performing more than LF_DUPLICATE_FILTER_BLOOMFILTERS rotations,
	 * in1 should not be detected as duplicate. */
	res = lf_duplicate_filter_apply(df, in1, ns_now);
	if (res != 0) {
		printf("Failed: second in1\n");
		error_count++;
	}


	lf_duplicate_filter_worker_free(df);

	return error_count;
}


int
main(int argc, char *argv[])
{
	int res = rte_eal_init(argc, argv);
	if (res < 0) {
		return -1;
	}
	int error_counter = 0;

	error_counter += duplicate_filter_worker();

	if (error_counter > 0) {
		printf("Error Count: %d\n", error_counter);
		return 1;
	}

	printf("All tests passed!\n");
	return 0;
}