/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#ifndef LF_DISTRIBUTOR_H
#define LF_DISTRIBUTOR_H

#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_reorder.h>

#include "lf.h"
#include "setup.h"

/**
 * The distributor offers the possibility to distribute received packets on a
 * port/queue among multiple workers. This ensures that not a flow can be
 * targeted with a flooding attack by overwhelming a single worker, as it is
 * possible when just using RSS. After the worker processes a packet, it is
 * returned to the distributor, which then performs the packet action
 * (drop/forward). Furthermore, a lightweight packet order mechanism is provided
 * that can be enabled to preserve packet order.
 */

#define LF_MAX_DISTRIBUTOR LF_MAX_WORKER

#define LF_DISTRIBUTOR_ACTION_FWD  0
#define LF_DISTRIBUTOR_ACTION_DROP 1
typedef uint32_t lf_distributor_action_t;
extern int lf_distributor_action_dynfield_offset;

static inline lf_distributor_action_t *
lf_distributor_action(struct rte_mbuf *mbuf)
{
	/* (fstreun) No idea how to avoid this clang tidy performance warning. */
	// NOLINTNEXTLINE(performance-no-int-to-ptr)
	return RTE_MBUF_DYNFIELD(mbuf, lf_distributor_action_dynfield_offset,
			lf_distributor_action_t *);
}

struct lf_distributor_context {
	/* Identifier */
	uint16_t id;

	/* Lcore on which the distributer is running on */
	uint16_t lcore_id;

	/* The ports/queues to receive and send packets to */
	struct lf_setup_port_queue queue;

	/* number of workers to which packets are distributed */
	uint16_t nb_workers;
	/* One buffer per worker to transfer packets between this distributor and
	 * worker */
	struct rte_ring *worker_rx_rings[LF_MAX_WORKER];
	struct rte_ring *worker_tx_rings[LF_MAX_WORKER];

#if LF_DISTRIBUTOR_REORDER
	struct rte_reorder_buffer *reorder_buffer;
#endif /* LF_DISTRIBUTOR_REORDER */
};

struct lf_distributor_worker {
	struct rte_ring *rx_ring;
	struct rte_ring *tx_ring;

	enum lf_forwarding_direction forwarding_direction;
};

/**
 * Initialize the distributor contexts according the given application
 * parameters (params). This includes the contexts of the distributors itself
 * and the workers.
 *
 * @param lf_params Application parameters.
 * @param distributor_lcores Lcore map for the distributors.
 * @param nb_distributors Number of distributors.
 * @param worker_lcores Lcore map of the workers.
 * @param nb_workers Number of workers.
 * @param distributor_contexts Initialized distributor contexts.
 * @param worker Initialized worker contexts.
 * @return int 0 on success.
 */
int
lf_distributor_init(struct lf_params *params,
		uint16_t distributor_lcores[LF_MAX_DISTRIBUTOR],
		uint16_t nb_distributors, uint16_t worker_lcores[LF_MAX_WORKER],
		uint16_t nb_workers,
		struct lf_distributor_context distributor_contexts[LF_MAX_DISTRIBUTOR],
		struct lf_distributor_worker *worker[LF_MAX_WORKER]);

/**
 * Distributor running function. Expected to be called with
 * rte_eal_remote_launch(...).
 *
 * @param distributor_context Initialized context of the distributor.
 * @return int 0 on successful exit.
 */
int
lf_distributor_run(struct lf_distributor_context *distributor_context);

#endif /* LF_DISTRIBUTOR_H */