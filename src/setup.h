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
struct lf_setup_port_queue {
	uint16_t rx_port_id;
	uint8_t rx_queue_id;
	uint16_t tx_port_id;
	uint8_t tx_queue_id;

	enum lf_forwarding_direction forwarding_direction;
};

/**
 * Control traffic (ct) queues for each port and the port ID of the vdev, to
 * which the control traffic is forwarded.
 */
struct lf_setup_ct_port_queue {
	uint32_t portmask;
	uint8_t rx_queue_id[RTE_MAX_ETHPORTS];
	uint8_t tx_queue_id[RTE_MAX_ETHPORTS];
	uint16_t vport_id[RTE_MAX_ETHPORTS];
};

/**
 * The setup function is responsible to prepare the memory pools, ports and
 * rx/tx queues. After running this function, the active ports are started.
 * @param nb_port_queues Number of queue pairs to be initiated.
 * @param lcores Maping between the queue pairs and lcores that handle the
 * queues. E.g., the lcores of the workers, which are responsible to handle the
 * queue pairs. If the queue pairs are located on another socket than the
 * handler, which is identified by the given, a warning is issued.
 * @param params LF parameters.
 * @param port_queues Return the initiated queue pairs.
 * @param ct_port_queue If not NULL, returns the control traffic port queues and
 * the control traffic filter is setup. of each enabled port.
 * @return 0 on success.
 */
int
lf_setup_ports(uint16_t nb_port_queues, const uint16_t lcores[LF_MAX_WORKER],
		const struct lf_params *params,
		struct lf_setup_port_queue port_queues[LF_MAX_WORKER],
		struct lf_setup_ct_port_queue *ct_port_queue);

/**
 * Terminates, i.e., stops, all ports which have been started according to the
 * given parameters.
 * This function should be called before exiting the DPDK application, such that
 * ports are properly reset.
 *
 * @param portmask Port mask indicating the ports to be stoped.
 * @return 0 on success.
 */
int
lf_setup_terminate(uint32_t portmask);

#endif /* LF_SETUP_H */
