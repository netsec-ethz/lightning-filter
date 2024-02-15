/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#include <stdio.h>

#include "../token_bucket.h"

int
test_lf_token_bucket_ratelimit()
{
	int res;
	int error_counter = 0;
	struct lf_token_bucket_ratelimit ratelimit;
	struct lf_timestamp t_now;
	lf_timestamp_init_zero(&t_now);

	lf_token_bucket_ratelimit_init(&ratelimit, 0, 0, 0, 0);

	res = lf_token_bucket_ratelimit_apply(&ratelimit, 1, 1, &t_now);
	if (res == 0) {
		printf("Error: 1 tb check failed\n");
		error_counter++;
	}

	lf_timestamp_inc_ns(&t_now, 1000);
	res = lf_token_bucket_ratelimit_apply(&ratelimit, 1, 1, &t_now);
	if (res == 0) {
		printf("Error: 2 tb check failed\n");
		error_counter++;
	}

	lf_token_bucket_ratelimit_set(&ratelimit, 1000, 1000, 1000, 1000);

	res = lf_token_bucket_ratelimit_apply(&ratelimit, 1, 1, &t_now);
	/*
	 * This test fails (and that is ok)!
	 * The token bucket has not been refilled since ms = 0.
	 * Because t_now = 1000, the buckets are refilled with 1000 tokens.
	 *
	 * Allowing this traffic does not exceed the rate nor the burst size!
	 */
	/*
	if (res == 0) {
	    printf("Error: 3 tb check failed\n");
	    error_counter++;
	}
	*/

	lf_timestamp_inc_ns(&t_now, 1000);
	res = lf_token_bucket_ratelimit_apply(&ratelimit, 999, 999, &t_now);
	if (res != 0) {
		printf("Error: 4 tb check failed\n");
		error_counter++;
	}

	res = lf_token_bucket_ratelimit_apply(&ratelimit, 999, 999, &t_now);
	if (res == 0) {
		printf("Error: 5 tb check failed\n");
		error_counter++;
	}

	return error_counter;
}

int
main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	int error_counter = 0;

	error_counter += test_lf_token_bucket_ratelimit();

	if (error_counter > 0) {
		printf("Error Count: %d\n", error_counter);
		return 1;
	}

	printf("All tests passed!\n");
	return 0;
}