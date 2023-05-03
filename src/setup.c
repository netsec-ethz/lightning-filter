/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>

#include "lf.h"
#include "lib/log/log.h"
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

/*
 * Configurable number of RX/TX ring descriptors
 */
static uint16_t nb_rxd = LF_SETUP_MAX_RX_DESC;
static uint16_t nb_txd = LF_SETUP_MAX_TX_DESC;

static const struct rte_eth_conf global_port_conf = {
	.rxmode = {
		.split_hdr_size = 0,
		.mq_mode = RTE_ETH_MQ_RX_RSS,
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL,
			.rss_hf = ETH_RSS_FRAG_IPV4
				| ETH_RSS_NONFRAG_IPV4_TCP
				| ETH_RSS_NONFRAG_IPV4_UDP
				| ETH_RSS_NONFRAG_IPV4_SCTP
				| ETH_RSS_NONFRAG_IPV4_OTHER
				| ETH_RSS_FRAG_IPV6
				| ETH_RSS_NONFRAG_IPV6_TCP
				| ETH_RSS_NONFRAG_IPV6_UDP
				| ETH_RSS_NONFRAG_IPV6_SCTP
				| ETH_RSS_NONFRAG_IPV6_OTHER
				| ETH_RSS_L2_PAYLOAD,
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

static const struct lf_distributor_port_queue default_port_queue = {
	.rx_port_id = RTE_MAX_ETHPORTS,
	.rx_queue_id = LF_SETUP_MAX_QUEUE,
	.tx_port_id = RTE_MAX_ETHPORTS,
	.tx_queue_id = LF_SETUP_MAX_QUEUE,

	.forwarding_direction = LF_FORWARDING_DIRECTION_BOTH,
};

uint32_t
calculate_nb_mbufs(uint16_t nb_rx_ports, uint16_t nb_tx_ports,
		uint16_t nb_lcores, uint16_t nb_rxq, uint_fast16_t nb_txq)
{
	/* clang-format off */
	return RTE_MAX(nb_rx_ports * nb_rxq * LF_SETUP_MAX_RX_DESC +
			nb_rx_ports * nb_lcores * LF_MAX_PKT_BURST +
			nb_tx_ports * nb_txq * LF_SETUP_MAX_TX_DESC +
			nb_lcores * LF_SETUP_MEMPOOL_CACHE_SIZE,
			8192U);
	/* clang-format on */
}

int
pool_init(int32_t socket_id, uint32_t nb_mbuf, struct rte_mempool **mb_pool)
{
	char s[64];

	(void)snprintf(s, sizeof(s) - 1, "mbuf_pool_%u", socket_id);
	*mb_pool = rte_pktmbuf_pool_create(s, nb_mbuf, LF_SETUP_MEMPOOL_CACHE_SIZE,
			LF_SETUP_METADATA_SIZE, LF_SETUP_BUF_SIZE, socket_id);

	if (*mb_pool == NULL) {
		LF_LOG(ERR, "Cannot init mbuf pool on socket %u\n", socket_id);
		return -1;
	} else {
		LF_LOG(INFO, "Allocated mbuf pool on socket %u\n", socket_id);
		return 0;
	}
}

struct rte_mempool *pktmbuf_pool[MAX_NB_SOCKETS];
uint32_t pktmbuf_pool_size = 0;
struct rte_mempool *
get_mbuf_pool(int32_t socket_id)
{
	int res;
	if (socket_id > MAX_NB_SOCKETS) {
		LF_LOG(ERR, "Socket ID too large socket_id = %d)\n", socket_id);
		return NULL;
	}

	/* initialize pool if not yet done */
	if (pktmbuf_pool[socket_id] == NULL) {
		res = pool_init(socket_id, pktmbuf_pool_size, &pktmbuf_pool[socket_id]);
		if (res != 0 || pktmbuf_pool[socket_id] == NULL) {
			LF_LOG(ERR, "Failed to init mbuf pool %d\n", socket_id);
			return NULL;
		}
	}

	return pktmbuf_pool[socket_id];
}

/**
 * Set the provided flow rule if possible.
 *
 * @param port_id ID of port on which flow rule should be created.
 * @param attr Flow rule attribute.
 * @param pattern Flow rule pattern.
 * @param action Flow rule action.
 * @return int Returns 0 on success.
 */
int
set_flow_rule(uint16_t port_id, struct rte_flow_attr *attr,
		struct rte_flow_item pattern[], struct rte_flow_action action[])
{
	int res;
	struct rte_flow *flow;
	struct rte_flow_error error;
	res = rte_flow_validate(port_id, attr, pattern, action, &error);
	if (res != 0) {
		LF_LOG(ERR, "create_arp_flow error: %s\n", error.message);
		return -1;
	}

	flow = rte_flow_create(port_id, attr, pattern, action, &error);
	if (flow == NULL) {
		LF_LOG(ERR, "create_arp_flow error: %s\n", error.message);
		return -1;
	}
	return 0;
}

/**
 * Clears all flow rules on the port.
 *
 * @param port_id ID of port.
 * @return int Returns 0 if no error has occurred.
 */
int
clear_flow_rules(uint16_t port_id)
{
	int res;
	struct rte_flow_error error;
	res = rte_flow_flush(port_id, &error);
	if (res != 0) {
		LF_LOG(WARNING, "Error while flushing flow rules: %s\n", error.message);
		return -1;
	}
	return 0;
}

/**
 * Create the control traffic flow rules and apply them to the port.
 * The control traffic flow rule forwards the following packets to the control
 * traffic queue. ETH/ARP, ETH/LLDP, ETH/IPV6/ICMP
 *
 * @param port_id ID of the port.
 * @param queue_index Index of queue to forward control traffic to.
 * @return int
 */
int
set_ct_flow_rules(uint16_t port_id, uint16_t queue_index)
{
	/*
	 * Test with testpmd:
	 * IPv4 ARP:
	 *		flow validate 0 ingress pattern eth type is 0x0806 / end actions
	 *		queue index 0 / end
	 *
	 * IPv6 Neighbor Discovery:
	 * 		flow validate 0 ingress pattern eth / ipv6 proto is 58 / end actions
	 *		queue index 0 / end
	 */
	int res;
	struct rte_flow_attr attr;
	struct rte_flow_item pattern[3];
	struct rte_flow_action action[2];
	struct rte_flow_item_eth item_eth_mask = {};
	struct rte_flow_item_eth item_eth_spec = {};
	struct rte_flow_item_ipv6 item_ipv6_mask = {};
	struct rte_flow_item_ipv6 item_ipv6_spec = {};
	struct rte_flow_action_queue queue = { .index = queue_index };

	memset(&attr, 0, sizeof(struct rte_flow_attr));
	memset(action, 0, sizeof(action));
	memset(pattern, 0, sizeof(pattern));

	attr.ingress = 1;

	/* action: move packet to queue */
	action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
	action[0].conf = &queue;
	action[1].type = RTE_FLOW_ACTION_TYPE_END;

	/* pattern: ETH/ARP */
	LF_LOG(DEBUG, "Setup flow rule for port %d: ETH/ARP -> rx %d\n", port_id,
			queue);
	item_eth_spec.hdr.ether_type = RTE_BE16(RTE_ETHER_TYPE_ARP);
	item_eth_mask.hdr.ether_type = RTE_BE16(0xFFFF);
	pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[0].mask = &item_eth_mask;
	pattern[0].spec = &item_eth_spec;
	pattern[1].type = RTE_FLOW_ITEM_TYPE_END;
	res = set_flow_rule(port_id, &attr, pattern, action);
	if (res != 0) {
		return -1;
	}

	/* pattern: ETH/LLDP */
	LF_LOG(DEBUG, "Setup flow rule for port %d: ETH/LLDP -> rx %d\n", port_id,
			queue);
	item_eth_spec.hdr.ether_type = RTE_BE16(RTE_ETHER_TYPE_LLDP);
	res = set_flow_rule(port_id, &attr, pattern, action);
	if (res != 0) {
		return -1;
	}

	/* pattern: ETH/IPV6/ICMP */
	/* TODO: this will not allow IPV6 ICMP packets to pass through LF! */
	LF_LOG(DEBUG, "Setup flow rule for port %d: ETH/IPV6/ICMP -> rx %d\n",
			port_id, queue);
	item_ipv6_spec.hdr.proto = IP_PROTO_ID_ICMP6;
	item_ipv6_mask.hdr.proto = 0xFF;
	pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[0].mask = NULL;
	pattern[0].spec = NULL;
	pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV6;
	pattern[1].mask = &item_ipv6_mask;
	pattern[1].spec = &item_ipv6_spec;
	pattern[2].type = RTE_FLOW_ITEM_TYPE_END;
	res = set_flow_rule(port_id, &attr, pattern, action);
	if (res != 0) {
		return -1;
	}

	return 0;
}

/**
 * Create and initialize vdev for control traffic from a specific port.
 *
 * @param port_id ID of port.
 * @param vport_id Returns ID of vdev.
 * @return int Returns 0 on success.
 */
static int
setup_ct_vdev(uint16_t port_id, uint16_t *vport_id)
{
	int res;
	char portname[32];
	char portargs[256];
	struct rte_ether_addr addr = { 0 };

	/* get MAC address of physical port to use as MAC of virtio_user port */
	rte_eth_macaddr_get(port_id, &addr);

	/* set the name and arguments */
	snprintf(portname, sizeof(portname), "virtio_user%u", port_id);
	snprintf(portargs, sizeof(portargs),
			"path=/dev/"
			"vhost-net,queues=1,queue_size=%u,iface=%s,"
			"mac=" RTE_ETHER_ADDR_PRT_FMT,
			nb_rxd, portname, RTE_ETHER_ADDR_BYTES(&addr));

	res = rte_eal_hotplug_add("vdev", portname, portargs);
	if (res < 0) {
		LF_LOG(ERR, "Cannot create paired port for port %u\n", port_id);
		return -1;
	}
	res = rte_eth_dev_get_port_by_name(portname, vport_id);
	if (res != 0) {
		return -1;
	}

	return 0;
}

/**
 * Create RSS rule and apply it to port.
 * This RSS rule adopts the current RSS rule such that packets are distributed
 * only to a limited number of queues. More specifically, only the queues [0,
 * queue_num[ are considered.
 *
 * @param port_id ID of the port.
 * @param queue_num Number of queues.
 * @return int Return 0 on success.
 */
int
setup_rss_flow_rule(uint16_t port_id, uint16_t queue_num)
{
	int res;
	int i;
	struct rte_flow_attr attr;
	struct rte_flow_item pattern[3];
	struct rte_flow_action action[2];
	uint16_t queue[RTE_MAX_QUEUES_PER_PORT];
	uint8_t rss_key[64];
	struct rte_eth_rss_conf rss_conf = {
		.rss_key = rss_key,
		.rss_key_len = sizeof(rss_key),
	};
	struct rte_flow_action_rss action_rss;

	memset(&attr, 0, sizeof(struct rte_flow_attr));
	memset(action, 0, sizeof(action));
	memset(pattern, 0, sizeof(pattern));

	attr.ingress = 1;

	/*
	 * create the action sequence.
	 * apply RSS and distribute packets among queues [0, queue_num[
	 */
	res = rte_eth_dev_rss_hash_conf_get(port_id, &rss_conf);
	if (res != 0) {
		LF_LOG(ERR, "rte_eth_dev_rss_hash_conf_get: res=%d\n", res);
		return -1;
	}
	for (i = 0; i < queue_num; i++) {
		queue[i] = i;
	}
	action_rss = (struct rte_flow_action_rss){
		.types = rss_conf.rss_hf,
		.key_len = rss_conf.rss_key_len,
		.queue_num = queue_num,
		.key = rss_key,
		.queue = queue,
	};
	action[0].type = RTE_FLOW_ACTION_TYPE_RSS;
	action[0].conf = &action_rss;
	action[1].type = RTE_FLOW_ACTION_TYPE_END;

	/*
	 * create pattern sequence
	 */
	pattern[0].type = RTE_FLOW_ITEM_TYPE_END;
	res = set_flow_rule(port_id, &attr, pattern, action);
	if (res != 0) {
		return -1;
	}

	return 0;
}

/**
 * Initialize port identified by port_id.
 * Queues are configured according to the information provided in port_conf.
 * Besides the default port configuration, also specific port offloading
 * flags can be set (especially usefull when different kind of ports are used).
 * The return value is 0 if the port initialization succeeds, -1 otherwise.
 */
int
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
			local_port_conf.rxmode.mq_mode = ETH_MQ_RX_NONE;
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

		LF_LOG(INFO, "Setup rxq=%d,socket_id=%d,mempoo=%p\n", rx_queue_id,
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
			if (link.link_status == ETH_LINK_DOWN) {
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

static inline struct rte_eth_dev_tx_buffer *
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

int
lf_setup_ports(uint16_t nb_workers,
		const uint16_t worker_lcores[LF_MAX_WORKER],
		const struct lf_params *params,
		struct lf_distributor_port_queue *port_queues[LF_MAX_WORKER],
		struct lf_setup_ct_port_queue *ct_port_queue)
{
	int res;
	uint16_t worker_id, lcore_id, socket_id, port_id, tx_port_id;
	uint16_t nb_worker_per_port;
	uint16_t nb_rx_ports, nb_tx_ports;
	uint16_t nb_queues_per_port, queue_counter;
	uint16_t rx_queue, tx_queue;
	uint32_t rx_portmask, tx_portmask;
	struct port_queues_conf port_queues_conf[RTE_MAX_ETHPORTS];
	struct port_queues_conf *port_conf, *tx_port_conf;

	struct lf_distributor_port_queue *port_queue;

	const uint32_t portmask = params->portmask;
	const uint16_t *dst_port = params->dst_port;
	const enum lf_forwarding_direction *forwarding_direction =
			params->forwarding_direction;
	unsigned int mtu = params->mtu;

	/* create rx and tx portmasks */
	rx_portmask = 0;
	tx_portmask = 0;
	for (port_id = 0; port_id < RTE_MAX_ETHPORTS; ++port_id) {
		if (dst_port[port_id] == RTE_MAX_ETHPORTS) {
			continue;
		}

		rx_portmask |= (1 << port_id);
		tx_portmask |= (1 << dst_port[port_id]);
	}

	/* number of worker lcores */
	nb_rx_ports = __builtin_popcount(rx_portmask);
	nb_tx_ports = __builtin_popcount(tx_portmask);
	if (nb_rx_ports != nb_tx_ports) {
		LF_LOG(ERR, "Invalid parameters: number of rx ports must be equal to "
					"number tx ports\n");
		return -1;
	}

	if (nb_workers == 0) {
		LF_LOG(ERR, "Invalid parameters: number of workers is zero\n");
		return -1;
	}

	if (nb_workers % nb_rx_ports) {
		LF_LOG(ERR, "Invalid parameters: number of workers can not be "
					"divided evenly among receiving ports\n");
		return -1;
	}

	/* each port has the same number of queues */
	nb_worker_per_port = nb_workers / nb_rx_ports;
	nb_queues_per_port = nb_worker_per_port + (ct_port_queue ? 1 : 0);
	if (nb_queues_per_port > LF_SETUP_MAX_QUEUE) {
		LF_LOG(ERR,
				"Invalid parameters: number of queues per port is not "
				"supported. Requested = %d, Max = %d\n",
				nb_queues_per_port, LF_SETUP_MAX_QUEUE);
		return -1;
	}

	/*
	 * Initialize a memory pool for each socket on which a worker is running.
	 */
	LF_LOG(INFO, "Initialize memory pools\n");
	for (socket_id = 0; socket_id < MAX_NB_SOCKETS; ++socket_id) {
		pktmbuf_pool[socket_id] = NULL;
	}
	pktmbuf_pool_size = calculate_nb_mbufs(nb_rx_ports, nb_rx_ports, nb_workers,
			nb_queues_per_port, nb_queues_per_port);


	/*
	 * distribute lcores among ports
	 */

	/* set port configurations to default */
	for (port_id = 0; port_id < RTE_MAX_ETHPORTS; ++port_id) {
		port_queues_conf[port_id] = default_port_queues_conf;
	}
	/* set lcore configurations to default */
	for (worker_id = 0; worker_id < nb_workers; ++worker_id) {
		*port_queues[worker_id] = default_port_queue;
	}

	worker_id = 0;
	RTE_ETH_FOREACH_DEV(port_id) {
		/* skip ports that are not enabled */
		if ((portmask & (1 << port_id)) == 0) {
			continue;
		}

		/* skip ports that are not receiving ports */
		if ((rx_portmask & (1 << port_id)) == 0) {
			continue;
		}

		/* get tx port (tx_port_id) corresponding to the rx port (port_id) */
		tx_port_id = dst_port[port_id];
		if ((portmask & (1 << tx_port_id)) == 0 ||
				(tx_portmask & (1 << tx_port_id)) == 0) {
			LF_LOG(ERR, "TX port is not enabled.\n");
			return -1;
		}

		LF_LOG(INFO, "RX Port %d --> TX Port %d: %d queues, %s direction\n",
				port_id, tx_port_id, nb_worker_per_port,
				lf_forwarding_direction_str[forwarding_direction[port_id]]);

		port_conf = &port_queues_conf[port_id];
		tx_port_conf = &port_queues_conf[tx_port_id];

		/* Assign each rx queue to one worker. */
		for (queue_counter = 0; queue_counter < nb_worker_per_port;
				queue_counter++) {

			port_queue = port_queues[worker_id];

			lcore_id = worker_lcores[worker_id];

			socket_id = rte_lcore_to_socket_id(lcore_id);

			/* check if worker runs on a different socket than the receiving
			 * port */
			if (socket_id != rte_eth_dev_socket_id(port_id)) {
				LF_LOG(WARNING,
						"Worker and port on different sockets: worker %d on "
						"socket "
						"%d (lcore %d), port %d on socket %d\n",
						worker_id, socket_id, lcore_id, port_id,
						rte_eth_dev_socket_id(port_id));
			}

			LF_LOG(INFO, "worker %d (lcore %d): RX Queue %d --> TX Queue %d\n",
					worker_id, lcore_id, queue_counter, queue_counter);

			/* assign core's socket memory pool*/
			port_conf->rx_mbuf_pool[queue_counter] = get_mbuf_pool(socket_id);

			/* assign socket to rx queue and increase rx queue number */
			port_conf->rx_sockets[queue_counter] = socket_id;
			++port_conf->nb_rx_queue;

			/* assign socket for tx queue and increase tx queue number */
			tx_port_conf->tx_sockets[queue_counter] = socket_id;
			++tx_port_conf->nb_tx_queue;

			/*
			 * set worker values
			 */
			port_queue->rx_port_id = port_id;
			port_queue->rx_queue_id = queue_counter;
			port_queue->tx_port_id = tx_port_id;
			port_queue->tx_queue_id = queue_counter;
			port_queue->forwarding_direction = forwarding_direction[port_id];

			port_queue->tx_buffer = new_tx_buffer(rte_eth_dev_socket_id(tx_port_id));
			if (port_queue->tx_buffer == NULL) {
				LF_LOG(ERR, "Failed setting up tx port %u.\n", tx_port_id);
				return -1;
			}

			/* increase worker_id and lcore_id */
			++worker_id;
		}

		if (queue_counter != nb_worker_per_port) {
			LF_LOG(ERR, "Expected queue_counter to be %d but got %d!\n",
					nb_worker_per_port, queue_counter);
			return -1;
		}
	}

	/* all workers have been assigned a receiving port */
	assert(worker_id == nb_workers);

	if (ct_port_queue) {
		LF_LOG(DEBUG, "Initialize signal ports...\n");
		ct_port_queue->portmask = portmask;
		RTE_ETH_FOREACH_DEV(port_id) {
			/* skip ports that are not enabled */
			if ((portmask & (1 << port_id)) == 0) {
				continue;
			}
			rx_queue = port_queues_conf[port_id].nb_rx_queue;
			tx_queue = port_queues_conf[port_id].nb_tx_queue;

			ct_port_queue->rx_queue_id[port_id] = rx_queue;
			ct_port_queue->tx_queue_id[port_id] = tx_queue;

			/* assign the ports socket to the queue */
			/* TODO: ensure that mbuf for socket is allocated! */
			port_queues_conf[port_id].rx_sockets[rx_queue] =
					rte_eth_dev_socket_id(port_id);
			port_queues_conf[port_id].tx_sockets[tx_queue] =
					rte_eth_dev_socket_id(port_id);
			port_queues_conf[port_id].rx_mbuf_pool[rx_queue] =
					get_mbuf_pool(rte_eth_dev_socket_id(port_id));
			port_queues_conf[port_id].nb_rx_queue++;
			port_queues_conf[port_id].nb_tx_queue++;

			/* Setup and add vdev */
			res = setup_ct_vdev(port_id, &ct_port_queue->vport_id[port_id]);
			if (res != 0) {
				return -1;
			}

			port_queues_conf[ct_port_queue->vport_id[port_id]].nb_rx_queue = 1;
			port_queues_conf[ct_port_queue->vport_id[port_id]].nb_tx_queue = 1;
			port_queues_conf[ct_port_queue->vport_id[port_id]].rx_sockets[0] =
					0;
			port_queues_conf[ct_port_queue->vport_id[port_id]].rx_mbuf_pool[0] =
					get_mbuf_pool(0);

			res = port_init(ct_port_queue->vport_id[port_id],
					&port_queues_conf[ct_port_queue->vport_id[port_id]], 0, 0,
					mtu);
			if (res != 0) {
				LF_LOG(ERR, "Port initialization failed\n");
				return -1;
			}

			res = rte_eth_dev_start(ct_port_queue->vport_id[port_id]);
			if (res < 0) {
				LF_LOG(ERR, "rte_eth_dev_start: err=%d, port=%d\n", res,
						port_id);
				return -1;
			}
		}
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
	}

	/* start ports */
	RTE_ETH_FOREACH_DEV(port_id) {
		/* skip ports that are not enabled */
		if ((portmask & (1 << port_id)) == 0) {
			continue;
		}

		if (ct_port_queue) {

			(void)clear_flow_rules(port_id);
			res = setup_rss_flow_rule(port_id,
					ct_port_queue->rx_queue_id[port_id]);
			if (res != 0) {
				LF_LOG(INFO,
						"On port %d, failed to exclude the signal queue from "
						"RSS.\n",
						port_id, ct_port_queue->rx_queue_id[port_id]);
				return -1;
			}

			res = set_ct_flow_rules(port_id,
					ct_port_queue->rx_queue_id[port_id]);
			if (res != 0) {
				LF_LOG(INFO, "On port %d, failed to set the signal queue %d.\n",
						port_id, ct_port_queue->rx_queue_id[port_id]);
				return -1;
			} else {
				LF_LOG(INFO, "On port %d, the signal queue is %d.\n", port_id,
						ct_port_queue->rx_queue_id[port_id]);
			}
		}

		res = rte_eth_dev_start(port_id);
		if (res < 0) {
			LF_LOG(ERR, "rte_eth_dev_start: err=%d, port=%d\n", res, port_id);
			return -1;
		}

		/* enable promiscuous mode on port */
		if ((params->promiscuous & (1 << port_id)) == 0) {
			(void)rte_eth_promiscuous_enable(port_id);
		}
	}

	/* check link status of all enabled ports */
	check_all_ports_link_status(portmask);

	return 0;
}

int
lf_setup_terminate(uint32_t portmask)
{
	int res;
	uint16_t port_id;

	RTE_ETH_FOREACH_DEV(port_id) {
		/* skip ports that are not enabled */
		if ((portmask & (1 << port_id)) == 0) {
			continue;
		}

		(void)clear_flow_rules(port_id);

		LF_LOG(INFO, "Closing port %d...\n", port_id);
		res = rte_eth_dev_stop(port_id);
		if (res != 0) {
			LF_LOG(ERR, "rte_eth_dev_stop: err=%d, port=%d\n", res, port_id);
		}
		(void)rte_eth_dev_close(port_id);
	}

	return 0;
}