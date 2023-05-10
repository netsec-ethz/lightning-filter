/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#ifndef LF_DISTRIBUTOR_H
#define LF_DISTRIBUTOR_H

#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_reorder.h>

#include "lf.h"
#include "lib/log/log.h"
#include "setup.h"

/**
 * The distributor module is responsible for getting received packets from the
 * ports to the workers and vice versa for transmitting packets.
 *
 * Furthermore, the distributor offers the possibility to distribute received
 * packets on a port among multiple workers. This ensures that not a flow can be
 * targeted with a flooding attack by overwhelming a single worker, as it is
 * possible when just using RSS. After the worker processes a packet, it is
 * returned to the distributor, which then performs the packet action
 * (drop/forward). Additionally, a lightweight packet order mechanism is
 * provided that can be enabled to preserve packet order.
 */

/**
 * Log function for distributor.
 * The lcore ID is added to each message. Format with lcore ID 1:
 * Distributor [1]: log message here
 */
#define LF_DISTRIBUTOR_LOG(level, ...)                                      \
	LF_LOG(level, RTE_FMT("Distributor [%d]: " RTE_FMT_HEAD(__VA_ARGS__, ), \
						  rte_lcore_id(), RTE_FMT_TAIL(__VA_ARGS__, )))

#define LF_DISTRIBUTOR_LOG_DP(level, ...)                                      \
	LF_LOG_DP(level, RTE_FMT("Distributor [%d]: " RTE_FMT_HEAD(__VA_ARGS__, ), \
							 rte_lcore_id(), RTE_FMT_TAIL(__VA_ARGS__, )))

#define LF_MAX_DISTRIBUTOR LF_MAX_WORKER

#define LF_DISTRIBUTOR_ACTION_UNKNOWN 0
#define LF_DISTRIBUTOR_ACTION_DROP    0
#define LF_DISTRIBUTOR_ACTION_FORWARD 1

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

struct lf_distributor_rx_tx_ring {
	struct rte_ring *rx_ring;
	struct rte_ring *tx_ring;
};

struct lf_distributor_rx_tx_port {
	uint16_t rx_port_id;
	uint8_t rx_queue_id;
	uint16_t tx_port_id;
	uint8_t tx_queue_id;

	struct rte_eth_dev_tx_buffer *tx_buffer;
};

struct lf_distributor_context {
	/* Identifier */
	uint16_t id;

	/* Lcore on which the distributer is running on */
	uint16_t lcore_id;

	/* The ports/queues to receive and send packets to */
	struct lf_distributor_rx_tx_port queue;

	/* number of workers to which packets are distributed */
	uint16_t nb_workers;

	/* One buffer per worker to transfer packets between this distributor and
	 * worker */
	struct rte_ring *worker_rx_rings[LF_MAX_WORKER];
	struct rte_ring *worker_tx_rings[LF_MAX_WORKER];

	/* The reorder buffer is initialized if LF_DISTRIBUTOR_REORDER is set to
	 * true. */
	struct rte_reorder_buffer *reorder_buffer;
};

struct lf_distributor_worker {
	union {
		struct lf_distributor_rx_tx_ring ring;
		struct lf_distributor_rx_tx_port port;
	} rx_tx;
};

struct lf_distributor {
	struct lf_distributor_worker *workers[LF_MAX_WORKER];
	uint16_t nb_workers;

	struct lf_distributor_context distributor_contexts[LF_MAX_DISTRIBUTOR];
	uint16_t nb_distributors;
};

inline static int
lf_distributor_tx_port(struct lf_distributor_rx_tx_port *queue,
		struct rte_mbuf *pkts[LF_MAX_PKT_BURST], int nb_pkts)
{
	int i;
	struct rte_ether_hdr *ether_hdr;
	uint16_t nb_fwd = 0;
	uint16_t nb_drop = 0;

	/* Add forward packets to transmit buffer or drop them */
	for (i = 0; i < nb_pkts; ++i) {
		if (*lf_distributor_action(pkts[i]) == LF_DISTRIBUTOR_ACTION_FORWARD) {
			nb_fwd++;
			ether_hdr =
					rte_pktmbuf_mtod_offset(pkts[i], struct rte_ether_hdr *, 0);
			(void)rte_eth_macaddr_get(queue->tx_port_id, &ether_hdr->src_addr);

			rte_eth_tx_buffer(queue->tx_port_id, queue->tx_queue_id,
					queue->tx_buffer, pkts[i]);
		} else {
			nb_drop++;
			rte_pktmbuf_free(pkts[i]);
		}
	}

	if (nb_fwd > 0) {
		rte_eth_tx_buffer_flush(queue->tx_port_id, queue->tx_queue_id,
				queue->tx_buffer);
	}

	/* TODO: add statistics for dropped and forwarded pkts/bytes */
	if ((nb_fwd > 0) | (nb_drop > 0)) {
		LF_DISTRIBUTOR_LOG_DP(DEBUG,
				"%u packets forwarded , (port %u, queue %u)\n", nb_fwd,
				queue->rx_port_id, queue->rx_queue_id);
		LF_DISTRIBUTOR_LOG_DP(DEBUG, "%u packets dropped (port %u, queue %u)\n",
				nb_drop, queue->rx_port_id, queue->rx_queue_id);
	}

	return nb_fwd;
}

inline static int
lf_distributor_rx_port(struct lf_distributor_rx_tx_port *queue,
		struct rte_mbuf *rx_pkts[LF_MAX_PKT_BURST])
{
	uint16_t nb_rx;

	nb_rx = rte_eth_rx_burst(queue->rx_port_id, queue->rx_queue_id, rx_pkts,
			LF_MAX_PKT_BURST);
	if (nb_rx > 0) {
		LF_DISTRIBUTOR_LOG_DP(DEBUG,
				"%u packets received (port %u, queue %u)\n", nb_rx,
				queue->rx_port_id, queue->rx_queue_id);
	}

	return nb_rx;
}

inline static int
lf_distributor_worker_rx(struct lf_distributor_worker *worker_context,
		struct rte_mbuf *rx_pkts[LF_MAX_PKT_BURST])
{
	int nb_pkts;
	if (LF_DISTRIBUTOR) {
		nb_pkts = rte_ring_dequeue_burst(worker_context->rx_tx.ring.rx_ring,
				(void **)rx_pkts, LF_MAX_PKT_BURST, NULL);
	} else {
		nb_pkts = lf_distributor_rx_port(&worker_context->rx_tx.port, rx_pkts);
	}
	return nb_pkts;
}

inline static int
lf_distributor_worker_tx(struct lf_distributor_worker *worker_context,
		struct rte_mbuf *rx_pkts[LF_MAX_PKT_BURST], int nb_pkts)
{
	if (LF_DISTRIBUTOR) {
		int nb_tx = 0;
		do {
			nb_tx += rte_ring_enqueue_burst(worker_context->rx_tx.ring.tx_ring,
					(void **)rx_pkts + nb_tx, nb_pkts - nb_tx, NULL);
		} while (unlikely(nb_tx < nb_pkts));
	} else {
		(void)lf_distributor_tx_port(&worker_context->rx_tx.port, rx_pkts,
				nb_pkts);
	}

	return 0;
}

/**
 * Initialize the distributor context. This includes the contexts of the
 * distributors itself and the workers.
 *
 * @param lf_distributor The distributor context to be initialized.
 * @param port_queues List of port/queues to receive packets from and sent
 * packets out.
 * @param nb_port_queues Lenght of port_queues list.
 * @param workers List of pointers to worker contexts to be initialized.
 * @return int 0 on success.
 */
int
lf_distributor_init(struct lf_distributor *lf_distributor,
		struct lf_setup_port_queue *port_queues, uint16_t nb_port_queues,
		struct lf_distributor_worker *workers[LF_MAX_WORKER]);

/**
 * Frees the content of the lf_distributor struct (not itself).
 * This includes the distributors' and workers' structs. Hence, all the workers
 * have to terminate beforehand.
 */
void
lf_distributor_close(struct lf_distributor *distributor);

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
