
#include <rte_dev.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_lcore.h>

#include "../../lf.h"
#include "../log/log.h"
#include "mirror.h"

/*
 * Configurable number of RX/TX ring descriptors
 */
static uint16_t nb_rxd = 1024;
//static uint16_t nb_txd = 1024;
#define LF_MIRROR_RING_SIZE 64
#define LF_MIRROR_MAX_BURST 32

int
create_mirror(uint16_t port_id)
{
	int res;
	uint16_t mirror_id;
	char portname[32];
	char portargs[256];
	struct rte_ether_addr addr = { 0 };

	/* use MAC address of physical port */
	rte_eth_macaddr_get(port_id, &addr);

	/* set the name and arguments */
	snprintf(portname, sizeof(portname), "mirror_%u", port_id);
	snprintf(portargs, sizeof(portargs),
			"path=/dev/"
			"vhost-net,queues=1,queue_size=%u,iface=%s,"
			"mac=" RTE_ETHER_ADDR_PRT_FMT,
			nb_rxd, portname, RTE_ETHER_ADDR_BYTES(&addr));

	res = rte_eal_hotplug_add("vdev", portname, portargs);
	if (res < 0) {
		LF_LOG(ERR, "Cannot create mirror for port %u\n", port_id);
		return -1;
	}
	res = rte_eth_dev_get_port_by_name(portname, &mirror_id);
	if (res != 0) {
		LF_LOG(ERR, "Cannot get mirror port id %s\n", portname);
		return -2;
	}

	return (int) mirror_id;
}

int
init_mirrors(struct lf_mirror *mirror_ctx, uint32_t portmask)
{
	int res;
	uint16_t port_id;


	RTE_ETH_FOREACH_DEV(port_id) {
		mirror_ctx->mirrors[port_id] = 0;

		/* skip ports that are not enabled */
		if ((portmask & (1 << port_id)) == 0) {
			continue;
		}

		res = create_mirror(port_id);
		if (res < 0) {
			LF_LOG(ERR, "Failed to create mirror");
			return -1;
		}
		mirror_ctx->mirrors[port_id] = res;
	}

	return 0;
}

void
close_mirror(struct lf_mirror *mirror_ctx)
{
	int res;
	uint16_t port_id;
	char portname[32];

	for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
		if (mirror_ctx->mirrors[port_id] == 0) {
			continue;
		}

		res = rte_eth_dev_get_name_by_port(mirror_ctx->mirrors[port_id], portname);
		if (res != 0) {
			continue;
		}

		res = rte_eal_hotplug_remove("vdev", portname);
		if (res != 0) {
			continue;
		}
	}
}

int
init_worker_rings(struct lf_mirror *mirror_ctx)
{
	uint16_t lcore_id, socket_id;
	char ring_name[RTE_RING_NAMESIZE];

	RTE_LCORE_FOREACH(lcore_id) {
		socket_id = rte_lcore_to_socket_id(lcore_id);
		(void)snprintf(ring_name, sizeof(ring_name), "mirror_%u", lcore_id);
		mirror_ctx->rx_ring[lcore_id] = rte_ring_create(ring_name,
				LF_MIRROR_RING_SIZE, socket_id, RING_F_SC_DEQ | RING_F_SP_ENQ);
		if (mirror_ctx->rx_ring[lcore_id] == NULL) {
			return -1;
		}
	}

	return 0;
}

void
close_worker_rings(struct lf_mirror *mirror_ctx)
{
	uint16_t lcore_id;

	for (lcore_id = 0; lcore_id < LF_MAX_WORKER; lcore_id++) {
		if (mirror_ctx->rx_ring[lcore_id] == NULL) {
			continue;
		}

		rte_ring_free(mirror_ctx->rx_ring[lcore_id]);
	}
}

int
lf_mirror_init(struct lf_mirror *mirror_ctx, uint32_t portmask)
{
	int res;

	(void)memset(mirror_ctx, 0, sizeof *mirror_ctx);

	mirror_ctx->portmask = portmask;

	res = init_mirrors(mirror_ctx, portmask);
	if (res != 0) {
		lf_mirror_close(mirror_ctx);
		return -1;
	}

	res = init_worker_rings(mirror_ctx);
	if (res != 0) {
		lf_mirror_close(mirror_ctx);
		return -1;
	}

	return 0;
}

void
lf_mirror_close(struct lf_mirror *mirror_ctx)
{
	mirror_ctx->portmask = 0;
	close_mirror(mirror_ctx);
	close_worker_rings(mirror_ctx);
}


static void
forward_tx_pkts(struct lf_mirror *mirror_ctx)
{
	uint16_t port_id;
	uint16_t mirror_id;
	uint16_t nb_pkts, nb_fwd;
	struct rte_mbuf *pkts[LF_MAX_PKT_BURST];

	RTE_ETH_FOREACH_DEV(port_id) {
		/* skip ports that are not enabled */
		if ((mirror_ctx->portmask & (1 << port_id)) == 0) {
			continue;
		}

		mirror_id = mirror_ctx->mirrors[port_id];
		if (mirror_id == 0) {
			continue;
		}

		nb_pkts = rte_eth_rx_burst(mirror_id, /*queue_id*/ 0, pkts,
				LF_MAX_PKT_BURST);

		/* Replace the mirror's port ID with the ID of the actual port */
		for (int i = 0; i < nb_pkts; i++) {
			pkts[i]->port = port_id;
		}

		/* XXX: Packets that are received on the mirror interface are always forwarded to the worker
		 * with lcore ID 1. We assume that this lcore always exists and always has access to all
		 * interfaces. However, this assumption might not always be true and this behavior must be
		 * adjusted, e.g., by keeping a list of workers that can forward packets to the ports. */
		nb_fwd = rte_ring_enqueue_burst(mirror_ctx->rx_ring[1], (void **)pkts, nb_pkts, NULL);
		if (nb_pkts - nb_fwd > 0) {
			rte_pktmbuf_free_bulk(&pkts[nb_fwd], nb_pkts - nb_fwd);
		}
	}
}

static void
forward_pkts_to_mirror(struct lf_mirror *mirror_ctx,
		struct rte_mbuf *rx_pkts[], uint16_t nb_rx)
{
	int i;
	uint16_t mirror_id;
	uint16_t nb_fwd;
	struct rte_mbuf *pkt;

	for (i = 0; i < nb_rx; i++) {
		pkt = rx_pkts[i];
		mirror_id = mirror_ctx->mirrors[pkt->port];
		nb_fwd = rte_eth_tx_burst(mirror_id, /*queue_id*/ 0, &rx_pkts[i], 1);
		if (nb_fwd != 1) {
			rte_pktmbuf_free(rx_pkts[i]);
		}
	}
}

static void
forward_rx_pkts(struct lf_mirror *mirror_ctx)
{
	uint16_t lcore_id;
	struct rte_ring *rx_ring;
	uint16_t nb_rx;
	struct rte_mbuf *rx_pkts[LF_MIRROR_MAX_BURST];

	RTE_LCORE_FOREACH(lcore_id) {
		rx_ring = mirror_ctx->rx_ring[lcore_id];
		nb_rx = rte_ring_dequeue_burst(rx_ring, (void **)(rx_pkts),
				LF_MIRROR_MAX_BURST, NULL);
		forward_pkts_to_mirror(mirror_ctx, rx_pkts, nb_rx);
	}
}

int
lf_mirror_main_loop(struct lf_mirror *mirror_ctx)
{
	while (likely(!lf_force_quit)) {
		forward_rx_pkts(mirror_ctx);
		forward_tx_pkts(mirror_ctx);
	}

	return 0;
}


int
lf_mirror_worker_init(struct lf_mirror *mirror_ctx,
		struct lf_mirror_worker *mirror_worker, uint16_t lcore_id)
{
	mirror_worker->rx_ring = mirror_ctx->rx_ring[lcore_id];
	if (mirror_worker->rx_ring == NULL) {
		return -1;
	}
	mirror_worker->tx_ring = mirror_ctx->tx_ring[lcore_id];
	if (mirror_worker->tx_ring == NULL) {
		return -1;
	}

	return 0;
}
