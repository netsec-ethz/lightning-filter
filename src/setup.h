/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#ifndef LF_SETUP_H
#define LF_SETUP_H

#include <rte_config.h>

#include "lf.h"
#include "params.h"
#include "distributor.h"

/**
 * The setup module is responsible to prepare the ports.
 * This includes the configuration of memory pools, ports, queues, hardware
 * offloading, etc.
 */

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
 * The setup function is responsible to prepare the DPDK environment.
 * This includes the configuration of memory pools, ports, queue pairs. Queue
 * pairs consist of on rx and one tx queue. After running this function, the
 * active ports are started.
 * @param nb_queues Number of queue pairs to be initiated.
 * @param worker_lcores Maping between the queue pairs and lcores of the
 * worker handling the queue. E.g., the lcores of the workers, which are
 * responsible to handle the queue pairs. If the queue pairs are located on
 * another socket than the handler, which is identified by the given, a warning
 * is issued.
 * @param portmask Mask indicating enabled ports.
 * @param dst_port For each rx ports the corresponding tx port. The value
 * RTE_MAX_ETHPORTS is used if rx port is not used.
 * @param forwading_direction For each rx port the corresponding packet
 * direction (inbound, outbound, or both).
 * @param port_queues Return the initiated queue pairs.
 * @param ct_port_queues If not NULL, returns the control traffic port queues
 * and the control traffic filter is setup. of each enabled port.
 * @return 0 on success.
 */
int
lf_setup_ports(uint16_t nb_workers,
		const uint16_t worker_lcores[LF_MAX_WORKER],
		const struct lf_params *params,
		struct lf_distributor_port_queue *port_queues[LF_MAX_WORKER],
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