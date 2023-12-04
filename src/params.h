/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#ifndef LF_PARAMS_H
#define LF_PARAMS_H

#include <inttypes.h>
#include <limits.h>

#include <rte_config.h>

#include "lf.h"

/**
 * Parameters are expected in the usual DPDK format:
 * (<EAL Parameters> -- <Application Parameters>)
 *
 * This module parses the application parameters and returns a parameter struct.
 * Parameters that are not provided are set to a default in the struct.
 */

/**
 * Application parameters are divided according to the modules they are used
 * for.
 */
struct lf_params {

	/*
	 * Config Manager
	 */
	char config_file[PATH_MAX];

	/*
	 * Setup
	 */
	uint32_t portmask;                   /* enabled ports */
	uint32_t rx_portmask;                /* enabled rx ports */
	uint32_t tx_portmask;                /* enabled tx ports */
	uint32_t promiscuous;                /* promiscuous ports */
	uint16_t dst_port[RTE_MAX_ETHPORTS]; /* rx, tx port pair */
	enum lf_forwarding_direction
			forwarding_direction[RTE_MAX_ETHPORTS]; /* rx packet direction */
	unsigned int mtu;                               /* tx MTU */
	bool disable_mirrors; /* disable mirrors for all ports */

	/*
	 * Timestamp Filter
	 */
	unsigned int tf_threshold; /* threshold in milliseconds */

	/*
	 * Duplicate Filter
	 */
	unsigned int bf_nb;
	unsigned int bf_period; /* rotation period in milliseconds */
	unsigned int bf_hashes;
	unsigned int bf_bytes;

	/*
	 * Rate Limiter
	 */
	unsigned int rl_size;

	/*
	 * Keymanager
	 */
	unsigned int km_size;
};

int
lf_params_parse(int argc, char **argv, struct lf_params *params);

#endif /* LF_PARAMETERS_H */