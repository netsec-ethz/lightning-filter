/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#ifndef LF_SETUP_H
#define LF_SETUP_H

#include <rte_config.h>

#include "lf.h"
#include "params.h"

/**
 * The setup module is responsible to prepare the ports.
 * This includes the configuration of memory pools, ports, queues, hardware
 * offloading, etc.
 */

/**
 * Struct for a port/queue transmit pair.
 */
struct lf_setup_port_queue_pair {
	uint16_t rx_queue_id;
	uint16_t tx_queue_id;
	struct rte_eth_dev_tx_buffer *tx_buffer;
};

#define LF_SETUP_INVALID_ID (uint16_t) ~0

/**
 * The setup function is responsible to prepare the memory pools, ports and
 * rx/tx queues. After running this function, the active ports are started.
 * @param workers Array defining for which workers queues have to be setup.
 * @param params LF parameters.
 * @param port_queues Return the initiated queues for each worker for each port.
 * @param mirror_ctx Return the initiated mirror context, which is initiated for
 * all ports.
 * @return 0 on success.
 */
int
lf_setup_ports(bool workers[RTE_MAX_LCORE], const struct lf_params *params,
		struct lf_setup_port_queue_pair port_queues[RTE_MAX_LCORE]
												   [RTE_MAX_ETHPORTS],
		struct lf_mirror *mirror_ctx);

/**
 * Terminates, i.e., stops, all ports which have been started according to the
 * given parameters.
 * This function should be called before exiting the DPDK application, such that
 * ports are properly reset.
 *
 * @param portmask Port mask indicating the ports to be stoped.
 * @param mirror_ctx Mirror context, which is also gonna be closed.
 * @return 0 on success.
 */
int
lf_setup_terminate(uint32_t portmask, struct lf_mirror *mirror_ctx);

#endif /* LF_SETUP_H */
