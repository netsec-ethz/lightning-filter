/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#include <stdint.h>

#include <rte_malloc.h>
#include <rte_reorder.h>
#include <rte_ring.h>

#include "distributor.h"
#include "lib/log/log.h"
#include "lib/math/util.h"
#include "lib/utils/packet.h"
#include "worker.h"

#define LF_DISTRIBUTOR_RING_SIZE 512
#define REORDER_BUFFER_SIZE      512

#define LF_DISTRIBUTOR_MAX_PKT_BURST LF_MAX_PKT_BURST

#define LF_DISTRIBUTOR_ACTION_DYNFIELD_NAME "lf_distributor_action_dynfield"
int lf_distributor_action_dynfield_offset = -1;

static int
register_dynfield()
{
	static const struct rte_mbuf_dynfield distributor_action_dynfield_desc = {
		.name = LF_DISTRIBUTOR_ACTION_DYNFIELD_NAME,
		.size = sizeof(lf_distributor_action_t),
		.align = __alignof__(lf_distributor_action_t),
	};
	lf_distributor_action_dynfield_offset =
			rte_mbuf_dynfield_register(&distributor_action_dynfield_desc);
	if (lf_distributor_action_dynfield_offset < 0) {
		LF_DISTRIBUTOR_LOG(ERR, "Failed to register mbuf dynfield field (%d)\n",
				rte_errno);
		return -1;
	}
	return 0;
}

static struct rte_eth_dev_tx_buffer *
new_tx_buffer(uint16_t socket)
{
	struct rte_eth_dev_tx_buffer *tx_buffer;

	/* Initialize TX buffers */
	tx_buffer = rte_zmalloc_socket("tx_buffer",
			RTE_ETH_TX_BUFFER_SIZE(LF_MAX_PKT_BURST), 0, socket);
	if (tx_buffer == NULL) {
		LF_DISTRIBUTOR_LOG(ERR, "Cannot allocate tx buffer\n");
		return NULL;
	}

	rte_eth_tx_buffer_init(tx_buffer, LF_MAX_PKT_BURST);
	return tx_buffer;
}

static void
free_tx_buffer(struct rte_eth_dev_tx_buffer *tx_buffer)
{
	rte_free(tx_buffer);
}

int
lf_distributor_init(struct lf_distributor *distributor,
		struct lf_setup_port_queue *port_queues, uint16_t nb_port_queues,
		struct lf_distributor_worker *workers[LF_MAX_WORKER])
{
	int res;
	int i;
	uint16_t dist_id, worker_id, worker_counter;
	uint16_t socket_id;
	uint16_t nb_workers_per_distributor;
	struct rte_ring *rx_ring, *tx_ring;
	struct rte_eth_dev_tx_buffer *tx_buffer;
	char ring_name[RTE_RING_NAMESIZE];
	char reorder_buffer_name[32];

	res = register_dynfield();
	if (res != 0) {
		return -1;
	}

	/* init distributor struct */
	distributor->nb_workers = lf_nb_workers;
	distributor->nb_distributors = lf_nb_distributors;
	for (i = 0; i < lf_nb_workers; i++) {
		distributor->workers[i] = workers[i];
	}

	/* assign port queues either to distributors or workers */
	if (LF_DISTRIBUTOR) {
		assert(nb_port_queues == lf_nb_distributors);
		for (i = 0; i < lf_nb_distributors; i++) {
			tx_buffer =
					new_tx_buffer(rte_lcore_to_socket_id(lf_worker_lcores[i]));
			if (tx_buffer == NULL) {
				return -1;
			}
			distributor->distributor_contexts[i].queue =
					(struct lf_distributor_rx_tx_port){
						.rx_port_id = port_queues[i].rx_port_id,
						.rx_queue_id = port_queues[i].rx_queue_id,
						.tx_port_id = port_queues[i].tx_port_id,
						.tx_queue_id = port_queues[i].tx_queue_id,
						.tx_buffer = tx_buffer,
					};
		}
	} else {
		assert(nb_port_queues == lf_nb_workers);
		for (i = 0; i < lf_nb_workers; i++) {
			tx_buffer =
					new_tx_buffer(rte_lcore_to_socket_id(lf_worker_lcores[i]));
			if (tx_buffer == NULL) {
				return -1;
			}
			workers[i]->rx_tx.port = (struct lf_distributor_rx_tx_port){
				.rx_port_id = port_queues[i].rx_port_id,
				.rx_queue_id = port_queues[i].rx_queue_id,
				.tx_port_id = port_queues[i].tx_port_id,
				.tx_queue_id = port_queues[i].tx_queue_id,
				.tx_buffer = tx_buffer,
			};
		}
	}

	if (!LF_DISTRIBUTOR) {
		return 0;
	}

	if (lf_nb_workers % lf_nb_distributors != 0) {
		LF_DISTRIBUTOR_LOG(ERR,
				"Invalid parameters: number of workers (%u) can not be divided "
				"evenly among distributors (%u)\n",
				lf_nb_workers, lf_nb_distributors);
		return -1;
	}
	nb_workers_per_distributor = lf_nb_workers / lf_nb_distributors;

	worker_id = 0;
	for (dist_id = 0; dist_id < lf_nb_distributors; ++dist_id) {
		distributor->distributor_contexts[dist_id].id = dist_id;
		distributor->distributor_contexts[dist_id].nb_workers =
				nb_workers_per_distributor;
		socket_id = rte_lcore_to_socket_id(lf_distributor_lcores[dist_id]);

		for (worker_counter = 0; worker_counter < nb_workers_per_distributor;
				++worker_counter) {

			/* warn if worker is on another lcore than distributer */
			if (socket_id !=
					rte_lcore_to_socket_id(lf_worker_lcores[worker_id])) {
				LF_DISTRIBUTOR_LOG(WARNING,
						"Worker and distributor on different sockets: worker "
						"%d on socket %d (locre %d), distributor %d on socket "
						"%d (lcore %d)\n",
						worker_id,
						rte_lcore_to_socket_id(lf_worker_lcores[worker_id]),
						lf_worker_lcores[worker_id], dist_id, socket_id,
						lf_distributor_lcores[dist_id]);
			}

			(void)snprintf(ring_name, sizeof(ring_name), "dist_%u_w_%u_rx",
					dist_id, worker_id);

			rx_ring = rte_ring_create(ring_name, LF_DISTRIBUTOR_RING_SIZE,
					socket_id, RING_F_SC_DEQ | RING_F_SP_ENQ);
			if (rx_ring == NULL) {
				LF_DISTRIBUTOR_LOG(ERR, "RX ring creation failed with %d\n",
						errno);
				return -1;
			}

			(void)snprintf(ring_name, sizeof(ring_name), "dist_%u_w_%u_tx",
					dist_id, worker_id);
			tx_ring = rte_ring_create(ring_name, LF_DISTRIBUTOR_RING_SIZE,
					socket_id, RING_F_SC_DEQ | RING_F_SP_ENQ);
			if (tx_ring == NULL) {
				LF_DISTRIBUTOR_LOG(ERR, "TX ring creation failed with %d\n",
						rte_errno);
				return -1;
			}

			distributor->distributor_contexts[dist_id]
					.worker_rx_rings[worker_counter] = rx_ring;
			distributor->distributor_contexts[dist_id]
					.worker_tx_rings[worker_counter] = tx_ring;

			distributor->workers[worker_id]->rx_tx.ring.rx_ring = rx_ring;
			distributor->workers[worker_id]->rx_tx.ring.tx_ring = tx_ring;

			worker_id += 1;
		}

		if (LF_DISTRIBUTOR_REORDER) {
			(void)snprintf(reorder_buffer_name, sizeof(reorder_buffer_name),
					"dist_%u_ro", dist_id);
			distributor->distributor_contexts[dist_id].reorder_buffer =
					rte_reorder_create(reorder_buffer_name, rte_socket_id(),
							REORDER_BUFFER_SIZE);
			if (distributor->distributor_contexts[dist_id].reorder_buffer ==
					NULL) {
				LF_DISTRIBUTOR_LOG(ERR, "Reorder buffer creation failed  %d\n",
						rte_errno);
				return -1;
			}
		}
	}

	return 0;
}

void
lf_distributor_close(struct lf_distributor *distributor)
{
	int i, j;

	if (LF_DISTRIBUTOR) {
		for (i = 0; i < distributor->nb_distributors; i++) {
			free_tx_buffer(
					distributor->distributor_contexts[i].queue.tx_buffer);
		}
		for (j = 0; j < distributor->distributor_contexts[i].nb_workers; j++)
			rte_ring_free(
					distributor->distributor_contexts[i].worker_rx_rings[j]);
		rte_ring_free(distributor->distributor_contexts[i].worker_tx_rings[j]);
		if (LF_DISTRIBUTOR_REORDER) {
			rte_reorder_free(
					distributor->distributor_contexts[i].reorder_buffer);
		}
	} else {
		for (i = 0; i < distributor->nb_workers; i++) {
			free_tx_buffer(distributor->workers[i]->rx_tx.port.tx_buffer);
		}
	}
}

void
lf_distributor_main_loop(struct lf_distributor_context *distributor_context)
{
	int i;
	uint16_t nb_rx, nb_fwd, nb_dist;

	/* packet buffers */
	struct rte_mbuf *rx_pkts[LF_MAX_PKT_BURST];
	struct rte_mbuf *tx_pkts[2 * LF_MAX_PKT_BURST];

	const int nb_workers = distributor_context->nb_workers;
	int worker_rx_counter = 0;
	int worker_rx_counter_init = 0;
	int worker_tx_counter = 0;
	int worker_tx_counter_init = 0;
	struct rte_ring **worker_rx_rings = distributor_context->worker_rx_rings;
	struct rte_ring **worker_tx_rings = distributor_context->worker_tx_rings;

	int res;
	uint32_t seqn = 0;
	struct rte_reorder_buffer *reorder_buffer =
			distributor_context->reorder_buffer;


	while (likely(!lf_force_quit)) {
		nb_rx = lf_distributor_rx_port(&distributor_context->queue, rx_pkts);

		if (LF_DISTRIBUTOR_REORDER) {
			/* mark sequence number */
			for (i = 0; i < nb_rx; i++) {
				/* (fstreun) No idea how to avoid this clang tidy performance
				 * warning. */
				// NOLINTNEXTLINE(performance-no-int-to-ptr)
				*RTE_MBUF_DYNFIELD(rx_pkts[i], rte_reorder_seqn_dynfield_offset,
						rte_reorder_seqn_t *) = seqn++;
			}
		}

		/*
		 * Distribute packets among multiple workers.
		 * The loop tries to enqueues packets at most once per worker, hence, it
		 * terminates.
		 * The following has to hold otherwise there are always drops
		 * under high traffic: LF_DISTRIBUTOR_MAX_PKT_BURST * nb_workers <=
		 * LF_MAX_PKT_BURST
		 */
		worker_rx_counter_init = worker_rx_counter;
		nb_dist = 0;
		while (nb_dist < nb_rx) {
			nb_dist += rte_ring_enqueue_burst(
					worker_rx_rings[worker_rx_counter],
					(void **)(&rx_pkts[nb_dist]),
					MIN(nb_rx - nb_dist, LF_DISTRIBUTOR_MAX_PKT_BURST), NULL);
			worker_rx_counter += 1;
			if (worker_rx_counter == nb_workers) {
				worker_rx_counter = 0;
			}

			/* abort loop early if all queues have been checked. */
			if (worker_rx_counter_init == worker_rx_counter) {
				break;
			}
		}

		/*
		 * Drop packets that cannot be forwarded to workers
		 */
		if (nb_dist < nb_rx) {
			rte_pktmbuf_free_bulk(&rx_pkts[nb_dist], nb_rx - nb_dist);
			LF_DISTRIBUTOR_LOG_DP(DEBUG, "Failed to distribute %u packets\n",
					nb_rx - nb_dist);
		}

		/*
		 * Collect all processed packets.
		 * Get as much packets as possible (up to LF_MAX_PKT_BURST) from each
		 * worker with one dequeue call.
		 * If at least LF_MAX_PKT_BURST packets are collected, forward them.
		 * Note that at most 2*LF_MAX_PKT_BURST-1 packets can be added to the
		 * tx_pkts buffer before exiting the loop. The loop tries to dequeue
		 * packets at most once per worker, hence, it terminates.
		 */
		worker_tx_counter_init = worker_tx_counter;
		nb_fwd = 0;
		while (nb_fwd < LF_MAX_PKT_BURST) {
			nb_fwd += rte_ring_dequeue_burst(worker_tx_rings[worker_tx_counter],
					(void **)(&tx_pkts[nb_fwd]), LF_MAX_PKT_BURST, NULL);

			worker_tx_counter += 1;
			if (worker_tx_counter == nb_workers) {
				worker_tx_counter = 0;
			}

			/* abort loop early if all queues have been checked. */
			if (worker_tx_counter_init == worker_tx_counter) {
				break;
			}
		}

		if (LF_DISTRIBUTOR_REORDER) {
			/* Add forward packets first to the reorder buffer */
			for (i = 0; i < nb_fwd; ++i) {
				res = rte_reorder_insert(reorder_buffer, tx_pkts[i]);

				if (unlikely(res == -1)) {
					LF_DISTRIBUTOR_LOG_DP(DEBUG,
							"Cannot insert packet into reorder buffer. "
							"Directly enqueuing it to TX\n");
					lf_distributor_tx_port(&distributor_context->queue,
							&tx_pkts[i], 1);
				}
			}

			/* then get the available ordered packets */
			nb_fwd = rte_reorder_drain(reorder_buffer, tx_pkts,
					2 * LF_MAX_PKT_BURST);
		}

		lf_distributor_tx_port(&distributor_context->queue, tx_pkts, nb_fwd);
	}
}

int
lf_distributor_run(struct lf_distributor_context *distributor_context)
{
	LF_DISTRIBUTOR_LOG_DP(INFO, "run\n");
	lf_distributor_main_loop(distributor_context);
	LF_DISTRIBUTOR_LOG_DP(INFO, "terminate\n");
	return 0;
}
