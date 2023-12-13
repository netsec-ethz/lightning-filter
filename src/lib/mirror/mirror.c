
#include <rte_dev.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_lcore.h>

#include "../../lf.h"
#include "../log/log.h"
#include "mirror.h"


#define MAX_NB_SOCKETS 8

/* mbuf pools used for the mirrors */
static struct rte_mempool *pktmbuf_pool[MAX_NB_SOCKETS];
static uint32_t pktmbuf_pool_size = 1024;

/*
 * Number of RX/TX ring descriptors
 */
static uint16_t nb_rxd = 512;
static uint16_t nb_txd = 512;

static const struct rte_eth_conf mirror_port_conf = {
	.rxmode = {
		/* TODO: make mtu configurable on the mirror. */
		.mtu = 1500,
	},
	.txmode = {
		.mq_mode = RTE_ETH_MQ_TX_NONE,
#if LF_OFFLOAD_CKSUM
		.offloads = RTE_ETH_TX_OFFLOAD_UDP_CKSUM |
				    RTE_ETH_TX_OFFLOAD_TCP_CKSUM,
#endif /* LF_OFFLOAD_CKSUM */
	},
};


static int
init_mbuf_pool(int32_t socket_id, uint32_t nb_mbuf,
		struct rte_mempool **mb_pool)
{
	char s[64];

	(void)snprintf(s, sizeof(s) - 1, "mbuf_pool_mirror_%u", socket_id);
	LF_LOG(INFO, "Creating mbuf pool '%s' on socket %u with %u mbufs\n", s,
			socket_id, nb_mbuf);
	*mb_pool = rte_pktmbuf_pool_create(s, nb_mbuf, 0, 0, 2048, socket_id);

	if (*mb_pool == NULL) {
		/* log error from rte_errno */
		LF_LOG(ERR, "Cannot create mbuf pool on socket %u: %s (%d)\n",
				socket_id, rte_strerror(rte_errno), rte_errno);
		return -1;
	} else {
		return 0;
	}
}

static struct rte_mempool *
get_mbuf_pool(int32_t socket_id)
{
	int res;
	if (socket_id > MAX_NB_SOCKETS) {
		LF_LOG(ERR, "Socket ID too large socket_id = %d)\n", socket_id);
		return NULL;
	}

	/* initialize pool if not yet done */
	if (pktmbuf_pool[socket_id] == NULL) {
		res = init_mbuf_pool(socket_id, pktmbuf_pool_size,
				&pktmbuf_pool[socket_id]);
		if (res != 0 || pktmbuf_pool[socket_id] == NULL) {
			LF_LOG(ERR, "Failed to init mbuf pool %d\n", socket_id);
			return NULL;
		}
	}

	return pktmbuf_pool[socket_id];
}

static int
configure_port(uint16_t port_id, uint16_t nb_queues,
		struct rte_mempool *mb_pool)
{
	int res;
	uint16_t rx_queue_id, tx_queue_id, socket_id;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_conf local_port_conf = mirror_port_conf;
	struct rte_eth_rxconf rxq_conf;
	struct rte_eth_txconf txq_conf;

	LF_LOG(INFO, "Configuring device port %u:\n", port_id);

	socket_id = rte_eth_dev_socket_id(port_id);

	res = rte_eth_dev_info_get(port_id, &dev_info);
	if (res != 0) {
		LF_LOG(ERR, "Could not retrive device (port %u) info: %s\n", port_id,
				strerror(-res));
		return -1;
	}


	/* check that number of queues are supported */
	if (nb_queues > dev_info.max_rx_queues) {
		LF_LOG(ERR, "Port %u required %u rx queues (max rx queue is %u)\n",
				port_id, nb_queues, dev_info.max_rx_queues);
		return -1;
	}

	if (nb_queues > dev_info.max_tx_queues) {
		LF_LOG(ERR, "Port %u required %u tx queues (max tx queue is %u)\n",
				port_id, nb_queues, dev_info.max_tx_queues);
		return -1;
	}

	LF_LOG(INFO,
			"Creating queues: nb_rx_queue=%d nb_tx_queue=%u (max_rx_queue: %d, "
			"mx_tx_queue: %d)...\n",
			nb_queues, nb_queues, dev_info.max_rx_queues,
			dev_info.max_tx_queues);

	/* Check that all required capabilities are supported */
	if ((local_port_conf.rxmode.offloads & dev_info.rx_offload_capa) !=
			local_port_conf.rxmode.offloads) {
		LF_LOG(ERR,
				"Port %u required RX offloads: 0x%" PRIx64
				", available RX offloads: 0x%" PRIx64 "\n",
				port_id, local_port_conf.rxmode.offloads,
				dev_info.rx_offload_capa);
		return -1;
	}

	if ((local_port_conf.txmode.offloads & dev_info.tx_offload_capa) !=
			local_port_conf.txmode.offloads) {
		LF_LOG(ERR,
				"Port %u required TX offloads: 0x%" PRIx64
				", available TX offloads: 0x%" PRIx64 "\n",
				port_id, local_port_conf.txmode.offloads,
				dev_info.tx_offload_capa);
		return -1;
	}

	local_port_conf.rx_adv_conf.rss_conf.rss_hf &=
			dev_info.flow_type_rss_offloads;
	if (local_port_conf.rx_adv_conf.rss_conf.rss_hf !=
			mirror_port_conf.rx_adv_conf.rss_conf.rss_hf) {
		LF_LOG(WARNING,
				"Port %u modified RSS hash function based on hardware support, "
				"requested:%#" PRIx64 " configured:%#" PRIx64 "\n",
				port_id, mirror_port_conf.rx_adv_conf.rss_conf.rss_hf,
				local_port_conf.rx_adv_conf.rss_conf.rss_hf);
		if (local_port_conf.rx_adv_conf.rss_conf.rss_hf == 0) {
			LF_LOG(WARNING, "Port %u does not use RSS!\n", port_id);
			local_port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;
		}
	}

	/* configure port */
	LF_LOG(INFO,
			"Port %u configuring rx_offloads=0x%" PRIx64
			", tx_offloads=0x%" PRIx64 "\n",
			port_id, local_port_conf.rxmode.offloads,
			local_port_conf.txmode.offloads);

	res = rte_eth_dev_configure(port_id, nb_queues, nb_queues,
			&local_port_conf);

	if (res < 0) {
		LF_LOG(ERR, "Cannot configure device: err=%d, port=%d\n", res, port_id);
		return -1;
	}

	res = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd, &nb_txd);
	if (res < 0) {
		LF_LOG(WARNING,
				"Cannot adjust number of descriptors: err=%d, port=%d\n", res,
				port_id);
	}

	/* init RX queues */
	for (rx_queue_id = 0; rx_queue_id < nb_queues; ++rx_queue_id) {
		LF_LOG(INFO, "Setup rxq=%d,socket_id=%d,mempool=%p\n", rx_queue_id,
				socket_id, mb_pool);

		rxq_conf = dev_info.default_rxconf;
		rxq_conf.offloads = local_port_conf.rxmode.offloads;
		res = rte_eth_rx_queue_setup(port_id, rx_queue_id, nb_rxd, socket_id,
				&rxq_conf, mb_pool);
		if (res < 0) {
			LF_LOG(ERR, "rte_eth_rx_queue_setup: err=%d, port=%d\n", res,
					port_id);
			return -1;
		}
	}

	/* init TX queues */
	for (tx_queue_id = 0; tx_queue_id < nb_queues; ++tx_queue_id) {
		LF_LOG(INFO, "Setup txq: tx_queue_id=%d, socket_id=%d\n", tx_queue_id,
				socket_id);

		txq_conf = dev_info.default_txconf;
		txq_conf.offloads = local_port_conf.txmode.offloads;
		res = rte_eth_tx_queue_setup(port_id, tx_queue_id, nb_txd, socket_id,
				&txq_conf);
		if (res < 0) {
			LF_LOG(ERR, "rte_eth_tx_queue_setup: err=%d, port=%d\n", res,
					port_id);
			return -1;
		}
	}

	return 0;
}

int
create_mirror(uint16_t port_id, uint16_t nb_queues)
{
	int res;
	uint16_t mirror_id;
	char portname[32];
	char portargs[256];
	struct rte_ether_addr addr = { 0 };

	/* use MAC address of physical port */
	rte_eth_macaddr_get(port_id, &addr);

	/* set the name and arguments */
	snprintf(portname, sizeof(portname), "virtio_user%u", port_id);
	snprintf(portargs, sizeof(portargs),
			"path=/dev/"
			"vhost-net,queues=%d,queue_size=%u,iface=%s,"
			"mac=" RTE_ETHER_ADDR_PRT_FMT,
			nb_queues, nb_rxd, portname, RTE_ETHER_ADDR_BYTES(&addr));

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

	return (int)mirror_id;
}

int
lf_mirror_add_port(struct lf_mirror *mirror_ctx, uint16_t port_id,
		bool lcores[RTE_MAX_LCORE])
{
	int res;
	int mirror_id;
	uint16_t lcore;
	uint16_t nb_queues = 0;
	struct rte_mempool *mb_pool;
	if (mirror_ctx->mirrors[port_id] != RTE_MAX_ETHPORTS) {
		LF_LOG(ERR, "Mirror for port %u already exists\n", port_id);
		return -1;
	}

	RTE_LCORE_FOREACH(lcore) {
		if (lcores[lcore] == false) {
			continue;
		}
		mirror_ctx->workers[lcore].queue[port_id] = nb_queues;
		nb_queues++;
	}

	if (nb_queues == 0) {
		LF_LOG(ERR, "No queues selected for port %u\n", port_id);
		return -1;
	}

	mirror_id = create_mirror(port_id, nb_queues);
	if (mirror_id < 0) {
		LF_LOG(ERR, "Failed to create mirror\n");
		return -1;
	}

	// Get memory pool from the port's socket.
	mb_pool = get_mbuf_pool(rte_eth_dev_socket_id(port_id));
	if (mb_pool == NULL) {
		LF_LOG(ERR, "Failed to get memory pool\n");
		return -1;
	}

	res = configure_port(mirror_id, nb_queues, mb_pool);
	if (res < 0) {
		LF_LOG(ERR, "Failed to init mirror\n");
		return -1;
	}

	mirror_ctx->mirrors[port_id] = mirror_id;
	mirror_ctx->mirror_to_port[mirror_id] = port_id;

	return 0;
}

int
init_mirrors(struct lf_mirror *mirror_ctx, uint32_t portmask,
		uint16_t nb_queues)
{
	int res;
	uint16_t port_id;

	/* Reset values */
	for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
		mirror_ctx->mirrors[port_id] = 0;
		mirror_ctx->mirror_to_port[port_id] = 0;
	}


	RTE_ETH_FOREACH_DEV(port_id) {
		/* skip ports that are not enabled */
		if ((portmask & (1 << port_id)) == 0) {
			continue;
		}

		res = create_mirror(port_id, nb_queues);
		if (res < 0) {
			LF_LOG(ERR, "Failed to create mirror\n");
			return -1;
		}
		configure_port(res, nb_queues, get_mbuf_pool(0));
		mirror_ctx->mirrors[port_id] = res;
		mirror_ctx->mirror_to_port[res] = port_id;
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
		if (mirror_ctx->mirrors[port_id] == RTE_MAX_ETHPORTS) {
			continue;
		}

		res = rte_eth_dev_get_name_by_port(mirror_ctx->mirrors[port_id],
				portname);
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
lf_mirror_init(struct lf_mirror *mirror_ctx)
{
	(void)memset(mirror_ctx, 0, sizeof *mirror_ctx);

	for (int j = 0; j < RTE_MAX_ETHPORTS; j++) {
		/* Set invalid mirror port number for all ports */
		mirror_ctx->mirrors[j] = RTE_MAX_ETHPORTS;
		/* Set invalid port number for all mirror ports */
		mirror_ctx->mirror_to_port[j] = RTE_MAX_ETHPORTS;
		for (int i = 0; i < RTE_MAX_LCORE; i++) {
			// Set invalid queue number for all queues.
			mirror_ctx->workers[i].queue[j] = RTE_MAX_QUEUES_PER_PORT;
		}
	}

	for (int i = 0; i < RTE_MAX_LCORE; i++) {
		mirror_ctx->workers[i].ctx = mirror_ctx;
	}

	return 0;
}

void
lf_mirror_close(struct lf_mirror *mirror_ctx)
{
	close_mirror(mirror_ctx);
}
