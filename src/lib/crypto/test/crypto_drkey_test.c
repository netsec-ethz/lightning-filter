/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#include "../crypto.h"


const static uint8_t drkey_zero_buf[LF_CRYPTO_DRKEY_SIZE] = { 0 };
const static uint8_t drkey_one_buf[LF_CRYPTO_DRKEY_SIZE] = { 1 };

const static uint8_t mac_data_zero[LF_CRYPTO_MAC_DATA_SIZE] = { 0 };
const static uint8_t mac_data_one[LF_CRYPTO_MAC_DATA_SIZE] = { 1 };

int
test_same_key_different_data()
{
	int res;
	struct lf_crypto_drkey_ctx drkey_ctx;
	struct lf_crypto_drkey drkey_zero1;
	struct lf_crypto_drkey drkey_zero2;
	uint8_t mac_with_data_zero[LF_CRYPTO_MAC_SIZE];

	res = lf_crypto_drkey_ctx_init(&drkey_ctx);
	if (res != 0) {
		printf("Error: initializing crypto drkey context.");
		return 1;
	}

	lf_crypto_drkey_from_buf(&drkey_ctx, drkey_zero_buf, &drkey_zero1);
	lf_crypto_drkey_from_buf(&drkey_ctx, drkey_zero_buf, &drkey_zero2);

	lf_crypto_drkey_compute_mac(&drkey_ctx, &drkey_zero1, mac_data_zero,
			mac_with_data_zero);

	res = lf_crypto_drkey_check_mac(&drkey_ctx, &drkey_zero2, mac_data_one,
			mac_with_data_zero);
	if (res == 0) {
		printf("Error: drkey check expected !=0 got %d.\n", res);
		return 1;
	}

	lf_crypto_drkey_ctx_close(&drkey_ctx);

	return 0;
}

int
test_different_key_same_data()
{
	int res;
	struct lf_crypto_drkey_ctx drkey_ctx;
	struct lf_crypto_drkey drkey_zero;
	struct lf_crypto_drkey drkey_one;
	uint8_t mac_with_drkey_zero[LF_CRYPTO_MAC_SIZE];

	res = lf_crypto_drkey_ctx_init(&drkey_ctx);
	if (res != 0) {
		printf("Error: initializing crypto drkey context.");
		return 1;
	}

	lf_crypto_drkey_from_buf(&drkey_ctx, drkey_zero_buf, &drkey_zero);
	lf_crypto_drkey_from_buf(&drkey_ctx, drkey_one_buf, &drkey_one);

	lf_crypto_drkey_compute_mac(&drkey_ctx, &drkey_zero, mac_data_zero,
			mac_with_drkey_zero);

	res = lf_crypto_drkey_check_mac(&drkey_ctx, &drkey_one, mac_data_zero,
			mac_with_drkey_zero);
	if (res == 0) {
		printf("Error: drkey check expected !=0 got %d.\n", res);
		return 1;
	}

	lf_crypto_drkey_ctx_close(&drkey_ctx);

	return 0;
}

int
test_same_key_same_data()
{
	int res;
	struct lf_crypto_drkey_ctx drkey_ctx;
	struct lf_crypto_drkey drkey_zero1;
	struct lf_crypto_drkey drkey_zero2;
	uint8_t mac[LF_CRYPTO_MAC_SIZE];

	res = lf_crypto_drkey_ctx_init(&drkey_ctx);
	if (res != 0) {
		printf("Error: initializing crypto drkey context.");
		return 1;
	}

	lf_crypto_drkey_from_buf(&drkey_ctx, drkey_zero_buf, &drkey_zero1);
	lf_crypto_drkey_from_buf(&drkey_ctx, drkey_zero_buf, &drkey_zero2);

	lf_crypto_drkey_compute_mac(&drkey_ctx, &drkey_zero1, mac_data_zero, mac);

	res = lf_crypto_drkey_check_mac(&drkey_ctx, &drkey_zero2, mac_data_zero,
			mac);
	if (res != 0) {
		printf("Error: drkey check expected 0 got %d.\n", res);
		return 1;
	}

	lf_crypto_drkey_ctx_close(&drkey_ctx);

	return 0;
}

int
main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	int res;
	int error_counter = 0;

	res = test_same_key_same_data();
	if (res != 0) {
		printf("Error: test_same_key_same_data (%d)\n", res);
	}
	error_counter += res;

	res = test_same_key_different_data();
	if (res != 0) {
		printf("Error: test_same_key_different_data (%d)\n", res);
	}
	error_counter += res;

	res = test_different_key_same_data();
	if (res != 0) {
		printf("Error: test_same_key_different_data (%d)\n", res);
	}
	error_counter += res;

	if (error_counter > 0) {
		printf("Error Count: %d\n", error_counter);
		return 1;
	}

	printf("All tests passed!\n");

	return error_counter;
}