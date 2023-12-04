/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../crypto.h"

#define LF_DRKEY_SIZE    16
#define LF_MAC_SIZE      16
#define LF_MAC_DATA_SIZE 32

int
main(int argc, char *argv[])
{
	if (argc < 3 || argc > 3) {
		printf("Wrong number of arguments supplied.\n Call like ./cbcmactest "
			   "key(16B hex) input(hex)\n");
		return 0;
	}

	// parse key
	uint8_t key_buf[16];
	struct lf_crypto_drkey drkey;
	unsigned int tmp; // to hold byte values

	for (int i = 0; i < 16; i++) {
		tmp = 0;
		if (sscanf(argv[1], "%2x", &tmp) != 1) {
			printf("Byte %d: Illegal byte value '%s' in input\n", i + 1,
					argv[2]);
			break;
		}
		key_buf[i] = (char)tmp;
		argv[1] += 2;
	}

	// parse input string (note: our cbcmac only works for full blocks, thus
	// multiples of 16 bytes)
	int len = strlen(argv[2]);
	int numBytes = (len / 2); // length of input

	if (numBytes % 16 != 0) {
		printf("input is not a multiple of 16 bytes.");
		return 0;
	}

	unsigned char *input = calloc(numBytes, sizeof(unsigned char));

	if (input == 0) {
		printf("Cannot allocate memory");
	}

	for (int i = 0; i < numBytes; i++) {
		tmp = 0;
		if (sscanf(argv[2], "%2x", &tmp) != 1) {
			printf("Byte %d: Illegal byte value '%s'\n", i + 1, argv[2]);
			break;
		}
		input[i] = (char)tmp;
		argv[2] += 2;
	}

	struct lf_crypto_drkey_ctx ctx;
	uint8_t mac[16];

	lf_crypto_drkey_ctx_init(&ctx);
	lf_crypto_drkey_from_buf(&ctx, key_buf, &drkey);
	lf_crypto_drkey_compute_mac(&ctx, &drkey, input, mac);
	lf_crypto_drkey_ctx_close(&ctx);

	// print cbcmac
	for (int j = 0; j < 16; j++) {
		printf("%02X", mac[j]);
	}

	free(input);
}