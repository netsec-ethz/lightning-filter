/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#ifndef LF_H
#define LF_H

#include <stdbool.h>

#include <rte_mbuf.h>
#include <rte_mbuf_dyn.h>

/* defined in main.c */
extern volatile bool lf_force_quit;

/* lcore assignments */
extern uint16_t lf_nb_workers;
extern uint16_t lf_keymanager_lcore;

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

/*
 * During the processing of each packet, we derive the action that should be
 * performed with the packet.
 */
#define LF_PKT_ACTION_UNKNOWN        0
#define LF_PKT_ACTION_DROP           0
#define LF_PKT_ACTION_FORWARD        1
#define LF_PKT_ACTION_FORWARD_MIRROR 2

/* We store the LF packet action information in a mbuf dynfield. */
#define LF_PKT_ACTION_DYNFIELD_NAME "lf_pkt_action_dynfield"
typedef uint32_t lf_pkt_action_t;
extern int lf_pkt_action_dynfield_offset;

/**
 * Helper function to optain a pointer to the pkt action dynfield in the mbuf.
 */
static inline lf_pkt_action_t *
lf_pkt_action(struct rte_mbuf *mbuf)
{
	/* (fstreun) No idea how to avoid this clang tidy performance warning. */
	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	return RTE_MBUF_DYNFIELD(mbuf, lf_pkt_action_dynfield_offset,
			lf_pkt_action_t *);
}

#endif /* LF_H */
