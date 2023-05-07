/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#ifndef LF_H
#define LF_H

#include <stdbool.h>

/* defined in main.c */
extern volatile bool lf_force_quit;

/* lcore assignments */
extern uint16_t lf_nb_workers;
extern uint16_t lf_worker_lcores[RTE_MAX_LCORE];
extern uint16_t lf_keymanager_lcore;
extern uint16_t lf_distributor_lcores[RTE_MAX_LCORE];
extern uint16_t lf_nb_distributors;

#define LF_TELEMETRY_PREFIX "/lf"

#define LF_MAX_PKT_BURST 32
#define LF_MAX_WORKER    128

enum lf_forwarding_direction {
	LF_FORWARDING_DIRECTION_BOTH,
	LF_FORWARDING_DIRECTION_OUTBOUND,
	LF_FORWARDING_DIRECTION_INBOUND
};
static const char *const lf_forwarding_direction_str[] = {
	[LF_FORWARDING_DIRECTION_BOTH] = "both",
	[LF_FORWARDING_DIRECTION_OUTBOUND] = "outbound",
	[LF_FORWARDING_DIRECTION_INBOUND] = "inbound",
};

/**
 * Struct to represent the different types of host addresses.
 * The encoding follows the format of the SCION host addresses.
 */
struct lf_host_addr {
	/* Type/Length encoding */
	unsigned int type_length: 4;

	/* Pointer to address in network byte order */
	void *addr;
};

#define LF_HOST_ADDR_LENGTH(addr) ((((addr)->type_length & 0x3) + 1) * 4)
#define LF_HOST_ADDR_TL_IPV4      0x0 // 0b0000
#define LF_HOST_ADDR_TL_IPV6      0x3 // 0b0011

/*
 * Default Values
 */
#define LF_DRKEY_PROTOCOL 0

/* LF over IP options */
#define LF_DEFAULT_UDP_PORT 49149

#endif /* LF_H */
