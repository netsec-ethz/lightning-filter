/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#ifndef LF_MIRROR_H
#define LF_MIRROR_H

#include <inttypes.h>

#include <rte_mbuf.h>
#include <rte_ring.h>

struct lf_mirror_worker {
	struct rte_ring *rx_ring;
	struct rte_ring *tx_ring;
};

struct lf_mirror {
	uint32_t portmask;
	uint16_t mirrors[RTE_MAX_ETHPORTS];
	struct rte_ring *rx_ring[RTE_MAX_LCORE];
	struct rte_ring *tx_ring[RTE_MAX_LCORE];
};

int
lf_mirror_init(struct lf_mirror *mirror_ctx, uint32_t port_mask);


void
lf_mirror_close(struct lf_mirror *mirror_ctx);

int
lf_mirror_worker_init(struct lf_mirror *mirror_ctx,
		struct lf_mirror_worker *mirror_worker, uint16_t lcore_id);

/**
 * Forward received packets to the mirror.
 */
static inline int
lf_mirror_worker_rx(struct lf_mirror_worker *mirror_ctx,
		struct rte_mbuf *pkts[], uint16_t nb_pkts)
{
	uint16_t nb_fwd;

	nb_fwd = rte_ring_enqueue_burst(mirror_ctx->rx_ring, (void **)pkts, nb_pkts,
			NULL);
	if (nb_pkts - nb_fwd > 0) {
		rte_pktmbuf_free_bulk(&pkts[nb_fwd], nb_pkts - nb_fwd);
	}
	return 0;
}

/**
 * Get packets from the mirror.
 */
static inline int
lf_mirror_worker_tx(struct lf_mirror_worker *mirror_ctx,
		struct rte_mbuf *pkts[], int n)
{
	return rte_ring_dequeue_bulk(mirror_ctx->tx_ring, (void **)pkts, n, NULL);
}

#endif /* LF_MIRROR_H */
