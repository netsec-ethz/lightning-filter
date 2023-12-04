/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_malloc.h>

#include "lf.h"
#include "lib/log/log.h"
#include "lib/mirror/mirror.h"
#include "lib/utils/packet.h"
#include "params.h"
#include "setup.h"
#include "worker.h"

#define MAX_NB_SOCKETS 8

#if LF_JUMBO_FRAME
/* allow max jumbo frame 9720 */
#define JUMBO_FRAME_MAX_SIZE 0x25F8
#endif

/*
 * Memory Constants
 */
#define LF_SETUP_MEMPOOL_CACHE_SIZE 256
#define LF_SETUP_METADATA_SIZE      0
#if LF_JUMBO_FRAME
#define LF_SETUP_BUF_SIZE JUMBO_FRAME_MAX_SIZE
#else
#define LF_SETUP_BUF_SIZE RTE_MBUF_DEFAULT_BUF_SIZE
#endif

/*
 * Port Constants
 */
#define LF_SETUP_MAX_QUEUE   32
#define LF_SETUP_MAX_RX_DESC 1024
#define LF_SETUP_MAX_TX_DESC 1024

struct port_queues_conf {
	uint16_t rx_sockets[LF_SETUP_MAX_QUEUE];
	struct rte_mempool *rx_mbuf_pool[LF_SETUP_MAX_QUEUE];
	uint16_t nb_rx_queue;
	uint16_t tx_sockets[LF_SETUP_MAX_QUEUE];
	uint16_t nb_tx_queue;
};

static const struct rte_eth_conf global_port_conf = {
	.rxmode = {
		.mq_mode = RTE_ETH_MQ_RX_RSS,
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL,
			.rss_hf = RTE_ETH_RSS_FRAG_IPV4
				| RTE_ETH_RSS_NONFRAG_IPV4_TCP
				| RTE_ETH_RSS_NONFRAG_IPV4_UDP
				| RTE_ETH_RSS_NONFRAG_IPV4_SCTP
				| RTE_ETH_RSS_NONFRAG_IPV4_OTHER
				| RTE_ETH_RSS_FRAG_IPV6
				| RTE_ETH_RSS_NONFRAG_IPV6_TCP
				| RTE_ETH_RSS_NONFRAG_IPV6_UDP
				| RTE_ETH_RSS_NONFRAG_IPV6_SCTP
				| RTE_ETH_RSS_NONFRAG_IPV6_OTHER
				| RTE_ETH_RSS_L2_PAYLOAD,
		},
	},
	.txmode = {
		.mq_mode = RTE_ETH_MQ_TX_NONE,
#if LF_OFFLOAD_CKSUM
		.offloads = RTE_ETH_TX_OFFLOAD_UDP_CKSUM |
				    RTE_ETH_TX_OFFLOAD_TCP_CKSUM,
#endif /* LF_OFFLOAD_CKSUM */
	},
};

static const struct port_queues_conf default_port_queues_conf = {
	.nb_rx_queue = 0,
	.nb_tx_queue = 0,
};

/*
 * This expression is used to calculate the number of mbufs needed
 * depending on user input, taking  into account memory for rx and
 * tx hardware rings, cache per lcore and mtable per port per lcore.
 * RTE_MAX is used to ensure that NB_MBUF never goes below a minimum
 * value of 8192
 */
unsigned int
calculate_nb_mbufs(uint16_t nb_lcores, uint16_t nports, uint16_t nb_rx_queue,
		uint16_t nb_rxd, uint16_t n_tx_queue, uint16_t nb_txd)
{
	return RTE_MAX((nports * nb_rx_queue * nb_rxd +
						   nports * nb_lcores * LF_MAX_PKT_BURST +
						   nports * n_tx_queue * nb_txd +
						   nb_lcores * LF_SETUP_MEMPOOL_CACHE_SIZE),
			(unsigned)8192);
}

static int
init_mbuf_pool(uint16_t port_id, int32_t socket_id, uint32_t nb_mbuf,
		struct rte_mempool **mb_pool)
{
	char s[64];

	(void)snprintf(s, sizeof(s) - 1, "mbuf_pool_%u_%u", port_id, socket_id);
	LF_LOG(INFO, "Creating mbuf pool '%s' on socket %u with %u mbufs\n", s,
			socket_id, nb_mbuf);
	*mb_pool = rte_pktmbuf_pool_create(s, nb_mbuf, LF_SETUP_MEMPOOL_CACHE_SIZE,
			LF_SETUP_METADATA_SIZE, LF_SETUP_BUF_SIZE, socket_id);

	if (*mb_pool == NULL) {
		/* log error from rte_errno */
		LF_LOG(ERR, "Cannot create mbuf pool on socket %u: %s (%d)\n",
				socket_id, rte_strerror(rte_errno), rte_errno);
		return -1;
	} else {
		return 0;
	}
}

static struct rte_mempool *pktmbuf_pool[RTE_MAX_ETHPORTS][MAX_NB_SOCKETS];
static struct rte_mempool *
get_mbuf_pool(uint16_t port_id, uint16_t socket_id, unsigned int nb_mbuf)
{
	int res;
	if (socket_id > MAX_NB_SOCKETS) {
		LF_LOG(ERR, "Socket ID too large socket_id = %d)\n", socket_id);
		return NULL;
	}

	/* initialize pool if not yet done */
	if (pktmbuf_pool[port_id][socket_id] == NULL) {
		res = init_mbuf_pool(port_id, socket_id, nb_mbuf,
				&pktmbuf_pool[port_id][socket_id]);
		if (res != 0 || pktmbuf_pool[port_id][socket_id] == NULL) {
			LF_LOG(ERR, "Failed to init mbuf pool %d\n", socket_id);
			return NULL;
		}
	}

	return pktmbuf_pool[port_id][socket_id];
}

static struct rte_eth_dev_tx_buffer *
new_tx_buffer(uint16_t socket)
{
	struct rte_eth_dev_tx_buffer *tx_buffer;

	/* Initialize TX buffers */
	tx_buffer = rte_zmalloc_socket("tx_buffer",
			RTE_ETH_TX_BUFFER_SIZE(LF_MAX_PKT_BURST), 0, socket);
	if (tx_buffer == NULL) {
		LF_LOG(ERR, "Cannot allocate tx buffer\n");
		return NULL;
	}

	rte_eth_tx_buffer_init(tx_buffer, LF_MAX_PKT_BURST);
	return tx_buffer;
}

/**
 * Initialize port identified by port_id.
 * Queues are configured according to the information provided in port_conf.
 * Besides the default port configuration, also specific port offloading
 * flags can be set (especially usefull when different kind of ports are used).
 * The return value is 0 if the port initialization succeeds, -1 otherwise.
 */
static int
port_init(uint16_t port_id, struct port_queues_conf *port_conf,
		uint64_t req_rx_offloads, uint64_t req_tx_offloads, uint32_t mtu)
{
	int res;
	uint16_t nb_tx_queue, nb_rx_queue;
	uint16_t rx_queue_id, tx_queue_id, socket_id;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_conf local_port_conf = global_port_conf;
	struct rte_eth_rxconf rxq_conf;
	struct rte_eth_txconf txq_conf;
	struct rte_mempool *mb_pool;

	uint16_t nb_rxd = LF_SETUP_MAX_RX_DESC;
	uint16_t nb_txd = LF_SETUP_MAX_TX_DESC;

	LF_LOG(INFO, "Configuring device port %u:\n", port_id);

	res = rte_eth_dev_info_get(port_id, &dev_info);
	if (res != 0) {
		LF_LOG(ERR, "Could not retrive device (port %u) info: %s\n", port_id,
				strerror(-res));
		return -1;
	}

	nb_rx_queue = port_conf->nb_rx_queue;
	nb_tx_queue = port_conf->nb_tx_queue;

	/* check that number of queues are supported */
	if (nb_rx_queue > dev_info.max_rx_queues) {
		LF_LOG(ERR, "Port %u required %u rx queues (max rx queue is %u)\n",
				port_id, nb_rx_queue, dev_info.max_rx_queues);
		return -1;
	}

	if (nb_tx_queue > dev_info.max_tx_queues) {
		LF_LOG(ERR, "Port %u required %u tx queues (max tx queue is %u)\n",
				port_id, nb_tx_queue, dev_info.max_tx_queues);
		return -1;
	}

	LF_LOG(INFO,
			"Creating queues: nb_rx_queue=%d nb_tx_queue=%u (max_rx_queue: %d, "
			"mx_tx_queue: %d)...\n",
			nb_rx_queue, nb_tx_queue, dev_info.max_rx_queues,
			dev_info.max_tx_queues);

	/* Add HW offloads to default, as requested */
	local_port_conf.rxmode.offloads |= req_rx_offloads;
	local_port_conf.txmode.offloads |= req_tx_offloads;

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
			global_port_conf.rx_adv_conf.rss_conf.rss_hf) {
		LF_LOG(WARNING,
				"Port %u modified RSS hash function based on hardware support, "
				"requested:%#" PRIx64 " configured:%#" PRIx64 "\n",
				port_id, global_port_conf.rx_adv_conf.rss_conf.rss_hf,
				local_port_conf.rx_adv_conf.rss_conf.rss_hf);
		if (local_port_conf.rx_adv_conf.rss_conf.rss_hf == 0) {
			LF_LOG(WARNING, "Port %u does not use RSS!\n", port_id);
			local_port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;
		}
	}

	/* set MTU */
	local_port_conf.rxmode.mtu = mtu;

	/* configure port */
	LF_LOG(INFO,
			"Port %u configuring rx_offloads=0x%" PRIx64
			", tx_offloads=0x%" PRIx64 "\n",
			port_id, local_port_conf.rxmode.offloads,
			local_port_conf.txmode.offloads);

	res = rte_eth_dev_configure(port_id, nb_rx_queue, nb_tx_queue,
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
	for (rx_queue_id = 0; rx_queue_id < nb_rx_queue; ++rx_queue_id) {
		socket_id = port_conf->rx_sockets[rx_queue_id];
		mb_pool = port_conf->rx_mbuf_pool[rx_queue_id];

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
	for (tx_queue_id = 0; tx_queue_id < nb_tx_queue; ++tx_queue_id) {
		socket_id = port_conf->tx_sockets[tx_queue_id];

		LF_LOG(INFO, "Setup txq=%d,%d\n", tx_queue_id, socket_id);

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

/**
 * The function replaces the experimental function rte_eth_link_speed_to_str().
 */
const char *
lf_rte_eth_link_speed_to_str(uint32_t link_speed)
{
	/* clang-format off */
	switch (link_speed) {
	case RTE_ETH_SPEED_NUM_NONE: return "None";
	case RTE_ETH_SPEED_NUM_10M:  return "10 Mbps";
	case RTE_ETH_SPEED_NUM_100M: return "100 Mbps";
	case RTE_ETH_SPEED_NUM_1G:   return "1 Gbps";
	case RTE_ETH_SPEED_NUM_2_5G: return "2.5 Gbps";
	case RTE_ETH_SPEED_NUM_5G:   return "5 Gbps";
	case RTE_ETH_SPEED_NUM_10G:  return "10 Gbps";
	case RTE_ETH_SPEED_NUM_20G:  return "20 Gbps";
	case RTE_ETH_SPEED_NUM_25G:  return "25 Gbps";
	case RTE_ETH_SPEED_NUM_40G:  return "40 Gbps";
	case RTE_ETH_SPEED_NUM_50G:  return "50 Gbps";
	case RTE_ETH_SPEED_NUM_56G:  return "56 Gbps";
	case RTE_ETH_SPEED_NUM_100G: return "100 Gbps";
	case RTE_ETH_SPEED_NUM_200G: return "200 Gbps";
	case RTE_ETH_SPEED_NUM_UNKNOWN: return "Unknown";
	default: return "Invalid";
	}
	/* clang-format on */
}

/**
 * The function replaces the experimental function rte_eth_link_to_str().
 */
static int
lf_rte_eth_link_to_str(char *str, size_t len,
		const struct rte_eth_link *eth_link)
{
	if (eth_link->link_status == RTE_ETH_LINK_DOWN) {
		return snprintf(str, len, "Link down");
	} else {
		return snprintf(str, len, "Link up at %s %s %s",
				lf_rte_eth_link_speed_to_str(eth_link->link_speed),
				(eth_link->link_duplex == RTE_ETH_LINK_FULL_DUPLEX) ? "FDX"
																	: "HDX",
				(eth_link->link_autoneg == RTE_ETH_LINK_AUTONEG) ? "Autoneg"
																 : "Fixed");
	}
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90  /* 9s (90 * 100ms) in total */
	int res;
	uint16_t port_id;
	uint8_t count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;
	char link_status_text[RTE_ETH_LINK_MAX_STR_LEN];

	LF_LOG(INFO, "Checking link status\n");
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		if (lf_force_quit) {
			return;
		}
		all_ports_up = 1;
		RTE_ETH_FOREACH_DEV(port_id) {
			if (lf_force_quit) {
				return;
			}
			if ((port_mask & (1 << port_id)) == 0) {
				continue;
			}
			(void)memset(&link, 0, sizeof(link));
			res = rte_eth_link_get_nowait(port_id, &link);
			if (res < 0) {
				all_ports_up = 0;
				if (print_flag == 1) {
					LF_LOG(WARNING, "Port %u link get failed: %s\n", port_id,
							rte_strerror(-res));
				}
				continue;
			}
			/* print link status if flag set */
			if (print_flag == 1) {
				(void)lf_rte_eth_link_to_str(link_status_text,
						sizeof(link_status_text) - 1, &link);
				LF_LOG(INFO, "Port %d %s\n", port_id, link_status_text);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == RTE_ETH_LINK_DOWN) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1) {
			break;
		}

		if (all_ports_up == 0) {
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			LF_LOG(INFO, "Finished checking link status\n");
		}
	}
}

int
lf_setup_ports(bool workers[RTE_MAX_LCORE], const struct lf_params *params,
		struct lf_setup_port_queue_pair port_queues[RTE_MAX_LCORE]
												   [RTE_MAX_ETHPORTS],
		struct lf_mirror *mirror_ctx)
{
	int res;
	uint16_t nb_workers, nb_ports;
	uint16_t lcore_id, socket_id, port_id;
	uint16_t queue_counter;
	struct port_queues_conf port_queues_conf[RTE_MAX_ETHPORTS];
	struct port_queues_conf *port_conf;

	const uint32_t portmask = params->portmask;
	unsigned int mtu = params->mtu;

	nb_workers = 0;
	RTE_LCORE_FOREACH(lcore_id) {
		if (workers[lcore_id]) {
			nb_workers++;
		}
	}

	if (nb_workers == 0) {
		LF_LOG(ERR, "Invalid parameters: number of workers is zero\n");
		return -1;
	}

	nb_ports = 0;
	RTE_ETH_FOREACH_DEV(port_id) {
		if ((portmask & (1 << port_id)) != 0) {
			nb_ports++;
		}
	}

	for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
		port_queues_conf[port_id] = default_port_queues_conf;
	}

	for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
		for (socket_id = 0; socket_id < MAX_NB_SOCKETS; ++socket_id) {
			pktmbuf_pool[port_id][socket_id] = NULL;
		}
	}

	unsigned int pool_nb_mbufs = calculate_nb_mbufs(nb_workers, nb_ports,
			nb_workers, LF_SETUP_MAX_RX_DESC, nb_workers, LF_SETUP_MAX_TX_DESC);

	/* initialize mirror context */
	res = lf_mirror_init(mirror_ctx);
	if (res != 0) {
		LF_LOG(ERR, "Failed to initialize mirror context\n");
		return -1;
	}

	/* set port configurations to default */
	RTE_ETH_FOREACH_DEV(port_id) {
		port_queues_conf[port_id] = default_port_queues_conf;
	}
	/* set port queue pairs to default */
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
			port_queues[lcore_id][port_id].rx_queue_id = LF_SETUP_INVALID_ID;
			port_queues[lcore_id][port_id].tx_queue_id = LF_SETUP_INVALID_ID;
			port_queues[lcore_id][port_id].tx_buffer = NULL;
		}
	}

	RTE_ETH_FOREACH_DEV(port_id) {
		/* skip ports that are not enabled */
		if ((portmask & (1 << port_id)) == 0) {
			continue;
		}

		port_conf = &port_queues_conf[port_id];
		port_conf->nb_rx_queue = nb_workers;
		port_conf->nb_tx_queue = nb_workers;

		if (!params->disable_mirrors) {
			/* add mirror for port */
			res = lf_mirror_add_port(mirror_ctx, port_id, workers);
			if (res != 0) {
				LF_LOG(ERR, "Failed to add mirror for port %d\n", port_id);
				return -1;
			}
		}

		/* Assign one rx queue to each worker. */
		queue_counter = 0;
		RTE_LCORE_FOREACH(lcore_id) {
			if (!workers[lcore_id]) {
				continue;
			}
			socket_id = rte_lcore_to_socket_id(lcore_id);

			/* check if worker runs on a different socket than the receiving
			 * port */
			if (socket_id != rte_eth_dev_socket_id(port_id)) {
				LF_LOG(WARNING,
						"Worker and port on different sockets: lcore_id %d on "
						"socket, port %d on socket %d\n",
						lcore_id, socket_id, port_id,
						rte_eth_dev_socket_id(port_id));
			}

			/* assign core's socket to queues and memory pool*/
			port_conf->rx_sockets[queue_counter] = socket_id;
			port_conf->tx_sockets[queue_counter] = socket_id;

			/* XXX: We do not use per port pools. Hence, we always use port_id
			 * 0. */
			port_conf->rx_mbuf_pool[queue_counter] =
					get_mbuf_pool(0, socket_id, pool_nb_mbufs);


			if (port_conf->rx_mbuf_pool[queue_counter] == NULL) {
				LF_LOG(ERR, "Failed to get mbuf pool for port %d\n", port_id);
				return -1;
			}

			/*
			 * set worker values
			 */
			port_queues[lcore_id][port_id].rx_queue_id = queue_counter;
			port_queues[lcore_id][port_id].tx_queue_id = queue_counter;
			port_queues[lcore_id][port_id].tx_buffer = new_tx_buffer(socket_id);
			/* TODO: error handling in case new_tx_buffer fails */

			queue_counter++;
		}

		assert(port_conf->nb_rx_queue == queue_counter);
		assert(port_conf->nb_tx_queue == queue_counter);
	}

	/* initialize ports */
	RTE_ETH_FOREACH_DEV(port_id) {
		/* skip ports that are not enabled */
		if ((portmask & (1 << port_id)) == 0) {
			continue;
		}
		res = port_init(port_id, &port_queues_conf[port_id], 0, 0, mtu);
		if (res != 0) {
			LF_LOG(ERR, "Port initialization failed\n");
			return -1;
		}

		/* enable promiscuous mode on port */
		if ((params->promiscuous & (1 << port_id)) == 0) {
			(void)rte_eth_promiscuous_enable(port_id);
		}
	}

	/* start ports */
	RTE_ETH_FOREACH_DEV(port_id) {
		/* skip ports that are not enabled */
		if (((portmask & (1 << port_id)) == 0)) {
			continue;
		}

		res = rte_eth_dev_start(port_id);
		if (res < 0) {
			LF_LOG(ERR, "rte_eth_dev_start: err=%d, port=%d\n", res, port_id);
			return -1;
		}

		/* start mirror of port if it exists */
		if (lf_mirror_exists(mirror_ctx, port_id)) {
			res = rte_eth_dev_start(mirror_ctx->mirrors[port_id]);
			if (res < 0) {
				LF_LOG(ERR,
						"rte_eth_dev_start of mirror: "
						"err=%d, port=%d, mirror=%d\n",
						res, port_id, mirror_ctx->mirrors[port_id]);
				return -1;
			}
		}
	}

	/* check link status of all enabled ports */
	check_all_ports_link_status(portmask);

	return 0;
}

int
lf_setup_terminate(uint32_t portmask, struct lf_mirror *mirror_ctx)
{
	int res;
	uint16_t port_id;

	RTE_ETH_FOREACH_DEV(port_id) {
		/* skip ports that are not enabled */
		if ((portmask & (1 << port_id)) == 0) {
			continue;
		}

		LF_LOG(INFO, "Closing port %d...\n", port_id);
		res = rte_eth_dev_stop(port_id);
		if (res != 0) {
			LF_LOG(ERR, "rte_eth_dev_stop: err=%d, port=%d\n", res, port_id);
		}
		(void)rte_eth_dev_close(port_id);
	}

	lf_mirror_close(mirror_ctx);

	/* TODO: free tx buffer */

	return 0;
}
