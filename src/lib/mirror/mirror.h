/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#ifndef LF_MIRROR_H
#define LF_MIRROR_H

#include <inttypes.h>

#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ring.h>

struct lf_mirror;

struct lf_mirror_worker {
	uint16_t queue;
	struct lf_mirror *ctx;
};

struct lf_mirror {
	uint32_t portmask;
	/* Map from each port to their mirror */
	uint16_t mirrors[RTE_MAX_ETHPORTS];
	/* Map from each mirror to their port */
	uint16_t mirror_to_port[RTE_MAX_ETHPORTS];

	struct lf_mirror_worker workers[RTE_MAX_LCORE];
};

typedef struct rte_mempool *(*lf_mirror_mbuf_pool_get)(int);

int
lf_mirror_init(struct lf_mirror *mirror_ctx, uint32_t port_mask,
		bool lcores[RTE_MAX_LCORE], lf_mirror_mbuf_pool_get get_pool);

void
lf_mirror_close(struct lf_mirror *mirror_ctx);

int
lf_mirror_main_loop(struct lf_mirror *mirror_ctx);

int
lf_mirror_worker_init(struct lf_mirror *mirror_ctx,
		struct lf_mirror_worker *mirror_worker, uint16_t lcore_id);

/**
 * Forward received packets to the mirror.
 */
static inline int
lf_mirror_worker_tx(struct lf_mirror_worker *mirror_ctx, uint16_t port_id,
		struct rte_mbuf *pkts[], uint16_t nb_pkts)
{
	uint16_t mirror_id = mirror_ctx->ctx->mirrors[port_id];
	return rte_eth_tx_burst(mirror_id, mirror_ctx->queue, pkts, nb_pkts);
}

/**
 * Get packets from the mirror.
 */
static inline int
lf_mirror_worker_rx(struct lf_mirror_worker *mirror_ctx, uint16_t port_id,
		struct rte_mbuf *pkts[], uint16_t n)
{
	uint16_t mirror_id = mirror_ctx->ctx->mirrors[port_id];
	return rte_eth_rx_burst(mirror_id, mirror_ctx->queue, pkts, n);
}

#endif /* LF_MIRROR_H */
