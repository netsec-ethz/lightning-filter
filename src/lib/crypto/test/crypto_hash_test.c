/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#include "../crypto.h"

uint8_t payload_1[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };
uint8_t payload_2[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };

int
test()
{
	int res;
	uint8_t hash_1[20];
	uint8_t hash_2[20];
	struct lf_crypto_hash_ctx hash_ctx;

	res = lf_crypto_hash_ctx_init(&hash_ctx);
	if (res != 0) {
		printf("Error while initializing crypto hash context.");
		return 1;
	}

	lf_crypto_hash_update(&hash_ctx, payload_1, sizeof payload_1);
	lf_crypto_hash_update(&hash_ctx, payload_2, sizeof payload_2);
	lf_crypto_hash_final(&hash_ctx, hash_1);

	lf_crypto_hash_update(&hash_ctx, payload_1, sizeof payload_1);
	lf_crypto_hash_update(&hash_ctx, payload_2, sizeof payload_2);
	lf_crypto_hash_final(&hash_ctx, hash_2);

	res = lf_crypto_hash_cmp(hash_1, hash_2);
	if (res != 0) {
		printf("Applying twice the hash function results in different "
			   "hashes.\n");
		return 1;
	}

	return 0;
}

int
main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	int error_counter = 0;

	error_counter += test();

	if (error_counter > 0) {
		printf("Error Count: %d\n", error_counter);
		return 1;
	}

	printf("All tests passed!\n");

	return error_counter;
}