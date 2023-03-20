/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../libdrkey.h"

#define PRIISDAS "%u-%x:%x:%x"
#define PRIISDAS_VAL(isd_as)                                                  \
	(uint16_t)((isd_as) >> 48 & 0XFFFF), (uint16_t)((isd_as) >> 32 & 0XFFFF), \
			(uint16_t)((isd_as) >> 16 & 0XFFFF),                              \
			(uint16_t)((isd_as) >> 0 & 0XFFFF)

struct drkey {
	int64_t validity_not_before;
	int64_t validity_not_after;
	unsigned char key[16];
};

char DAEMON_ADDR[48] = "127.0.0.11:31000";
const uint64_t SRC_IA = 0x0001ff0000000111; // 1-ff00:0:111
const uint64_t DST_IA = 0x0001ff0000000110; // 1-ff00:0:110
const uint16_t DRKEY_PROTOCOL = 3;

int
fetch_as_as_key(char drkey_service_addr[48], uint64_t slow_ia, uint64_t fast_ia,
		uint16_t drkey_protocol, int64_t val_time_ms)
{
	int res;
	struct drkey dk;
	memset(&dk, 0, sizeof dk);

	printf("Fetch AS AS Key: drkey_service_addr "
		   "%s, src_as " PRIISDAS ", dst_as " PRIISDAS
		   ", drkey_protocol %u, val_time_ms %" PRId64 "\n",
			drkey_service_addr, PRIISDAS_VAL(slow_ia), PRIISDAS_VAL(fast_ia),
			drkey_protocol, val_time_ms);


	printf("Call GetASASKey(...)\n");
	res = GetASASKey(drkey_service_addr, slow_ia, fast_ia, drkey_protocol,
			val_time_ms, (GoInt64 *)&dk.validity_not_before,
			(GoInt64 *)&dk.validity_not_after, dk.key);

	if (res != 0) {
		printf("GetASASKey failed with %d.\n", res);
		return -1;
	}

	printf("DRKey = ");
	for (size_t i = 0; i < sizeof dk.key; ++i) {
		printf("%02x", dk.key[i]);
	}
	printf(", epoch = [");
	struct tm *gmt;
	gmt = gmtime((time_t *)&dk.validity_not_before);
	if (gmt != NULL) {
		printf("%04d-%02d-%02d'T'%02d:%02d:%02d'Z'", 1900 + gmt->tm_year,
				1 + gmt->tm_mon, gmt->tm_mday, gmt->tm_hour, gmt->tm_min,
				gmt->tm_sec);
	}
	printf(", ");
	gmt = gmtime((time_t *)&dk.validity_not_after);
	if (gmt != NULL) {
		printf("%04d-%02d-%02d'T'%02d:%02d:%02d'Z'", 1900 + gmt->tm_year,
				1 + gmt->tm_mon, gmt->tm_mday, gmt->tm_hour, gmt->tm_min,
				gmt->tm_sec);
	}
	printf("]\n");

	return 0;
}

int
test(char *key_server_addr, uint64_t slow_ia, uint64_t fast_ia,
		uint16_t drkey_protocol)
{
	int res;
	time_t s;
	struct timespec spec;

	res = clock_gettime(CLOCK_REALTIME, &spec);
	if (res != 0) {
		printf("Syscal clock_gettime failed.\n");
		return -1;
	}

	s = spec.tv_sec * 1000;

	res = fetch_as_as_key(key_server_addr, slow_ia, fast_ia, drkey_protocol, s);

	return 0;
}

void
print_usage()
{
	printf("Usage: \n"
		   "./drkey_test <key_server_addr> <src_ia> <dst_ia> "
		   "<drkey_protocol>\n");
}

int
main(int argc, char *argv[])
{
	int res;
	char server_addr[48];
	uint64_t slow_ia;
	uint64_t fast_ia;
	uint16_t drkey_protocol;

	if (argc < 5 || argc > 5) {
		printf("Wrong number of arguments supplied.\n");
		return 0;
	}

	size_t length = strlen(argv[1]) + 1;
	if (length > sizeof server_addr) {
		printf("The first argument (key_server_addr) is too long!\n");
	}
	memcpy(server_addr, argv[1], length);

	printf("Arguments: %s %s %s\n", argv[2], argv[3], argv[4]);

	slow_ia = strtoull(argv[2], NULL, 0);
	fast_ia = strtoull(argv[3], NULL, 0);
	drkey_protocol = strtoull(argv[4], NULL, 0);

	res = test(server_addr, slow_ia, fast_ia, drkey_protocol);

	return res;
}