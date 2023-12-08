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

#include "../log/log.h"

struct lf_mirror;

struct lf_mirror_worker {
	uint16_t queue[RTE_MAX_ETHPORTS];
	struct lf_mirror *ctx;
};

struct lf_mirror {
	/* Map from each port to their mirror */
	uint16_t mirrors[RTE_MAX_ETHPORTS];
	/* Map from each mirror to their port */
	uint16_t mirror_to_port[RTE_MAX_ETHPORTS];

	struct lf_mirror_worker workers[RTE_MAX_LCORE];
};


int
lf_mirror_init(struct lf_mirror *mirror_ctx);

void
lf_mirror_close(struct lf_mirror *mirror_ctx);

int
lf_mirror_add_port(struct lf_mirror *mirror_ctx, uint16_t port_id,
		bool lcore[RTE_MAX_LCORE]);

int
lf_mirror_main_loop(struct lf_mirror *mirror_ctx);

/**
 * Forward received packets to the mirror of a ethernet port.
 * @param port_id: Port ID of ethernet port.
 */
static inline int
lf_mirror_worker_tx(struct lf_mirror_worker *mirror_ctx, uint16_t port_id,
		struct rte_mbuf *pkts[], uint16_t nb_pkts)
{
	uint16_t mirror_id = mirror_ctx->ctx->mirrors[port_id];
	if (mirror_id == RTE_MAX_ETHPORTS) {
		LF_LOG_DP(ERR, "Mirror for port %u does not exist\n", port_id);
		return 0;
	}
	return rte_eth_tx_burst(mirror_id, mirror_ctx->queue[port_id], pkts,
			nb_pkts);
}

/**
 * Get packets from the mirror of a ethernet port.
 * @param port_id: Port ID of ethernet port.
 */
static inline int
lf_mirror_worker_rx(struct lf_mirror_worker *mirror_ctx, uint16_t port_id,
		struct rte_mbuf *pkts[], uint16_t n)
{
	uint16_t mirror_id = mirror_ctx->ctx->mirrors[port_id];
	if (mirror_id == RTE_MAX_QUEUES_PER_PORT) {
		LF_LOG_DP(ERR, "Mirror for port %u does not exist\n", port_id);
		return 0;
	}
	return rte_eth_rx_burst(mirror_id, mirror_ctx->queue[port_id], pkts, n);
}

/**
 * Check if a mirror exists for a ethernet port.
 * @param port_id: Port ID of ethernet port.
 */
static inline bool
lf_mirror_exists(struct lf_mirror *mirror_ctx, uint16_t port_id)
{
	return mirror_ctx->mirrors[port_id] != RTE_MAX_ETHPORTS;
}

#endif /* LF_MIRROR_H */
