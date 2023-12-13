/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#include <stdint.h>

#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_mbuf_core.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include "config.h"
#include "configmanager.h"
#include "duplicate_filter.h"
#include "keymanager.h"
#include "lf.h"
#include "lib/crypto/crypto.h"
#include "lib/time/time.h"
#include "lib/utils/lf_ip.h"
#include "lib/utils/packet.h"
#include "ratelimiter.h"
#include "statistics.h"
#include "worker.h"

#if LF_IPV6
#error IPv6 support is not yet implemented!
#endif

#define LF_IP_PROTOCOL_ID 3

#ifndef LF_OFFLOAD_CKSUM
#define LF_OFFLOAD_CKSUM 0
#endif

/**
 * @param offset Offset to memory after ethernet, IP header, and UDP header.
 */
static enum lf_pkt_action
handle_inbound_pkt(struct lf_worker_context *worker_context, struct rte_mbuf *m,
		unsigned int offset, struct rte_ether_hdr *ether_hdr,
		struct rte_ipv4_hdr *ipv4_hdr, __rte_unused struct rte_udp_hdr *udp_hdr)
{
	int res;
	struct lf_pkt_data pkt_data;

	uint32_t dst_ip;
	struct lf_ip_hdr *lf_hdr;
	enum lf_check_state check_state;
	uint8_t exp_hash[20]; /* expected hash */
	uint16_t payload_len; /* payload (upper layer) length */

	offset = get_lf_hdr(m, offset, &lf_hdr);
	if (unlikely(offset == 0)) {
		return LF_PKT_INBOUND_DROP;
	}

	if (lf_hdr->rsv != 0) {
		LF_WORKER_LOG_DP(NOTICE, "Unexpected reserved values.\n");
		return LF_PKT_INBOUND_DROP;
	}

	/*
	 * Set host address structs.
	 * Additionally, check if the destination is using a different public
	 * address
	 */
	res = lf_configmanager_worker_get_ip_public(worker_context->config,
			&dst_ip);
	if (res != 0) {
		/* No public IP is provided: use the packets address. */
		dst_ip = ipv4_hdr->dst_addr;
	}

	/* Initialize packet data structure */
	pkt_data.src_as = lf_hdr->src_as;
	pkt_data.dst_as = 0; /* not used for inbound packets */

	pkt_data.dst_addr.addr = &dst_ip;
	pkt_data.dst_addr.type_length = LF_HOST_ADDR_TL_IPV4;
	pkt_data.src_addr.addr = &ipv4_hdr->src_addr;
	pkt_data.src_addr.type_length = LF_HOST_ADDR_TL_IPV4;

	pkt_data.timestamp = rte_be_to_cpu_64(lf_hdr->timestamp);
	pkt_data.drkey_protocol = lf_hdr->drkey_protocol;
	pkt_data.grace_period = lf_hdr->drkey_e;
	pkt_data.mac = lf_hdr->mac;
	pkt_data.auth_data = (uint8_t *)lf_hdr + 4;
	pkt_data.pkt_len = m->pkt_len - offset;

	/* Apply authenticated data struct and add payload length to it. */
	/* TODO: (fstreun) check that payload length fits into a uint16_t */
	payload_len = m->pkt_len - offset;
	lf_hdr->drkey_protocol = rte_cpu_to_be_16(payload_len);

	check_state = lf_worker_check_pkt(worker_context, &pkt_data);

	if (unlikely(check_state != LF_CHECK_VALID)) {
		/* TODO: (fstreun) for testing, all packets are checked as valid.
		 * However, under attack it is more likely that packets are declared
		 * invalid. */
		return LF_PKT_INBOUND_DROP;
	}

	/* check packet hash */
#if !(LF_WORKER_OMIT_HASH_CHECK)
	LF_WORKER_LOG_DP(DEBUG, "Check packet hash.\n");
	(void)lf_crypto_hash_update(&worker_context->crypto_hash_ctx,
			(uint8_t *)(lf_hdr + 1), payload_len);
	(void)lf_crypto_hash_final(&worker_context->crypto_hash_ctx, exp_hash);
	res = lf_crypto_hash_cmp(exp_hash, lf_hdr->hash);
	if (likely(res != 0)) {
		LF_WORKER_LOG_DP(DEBUG, "Packet hash check failed.\n");
		lf_statistics_worker_counter_inc(worker_context->statistics,
				invalid_hash);
#if !(LF_WORKER_IGNORE_HASH_CHECK)
		// LF_CHECK_VALID_MAC_BUT_INVALID_HASH;
		return LF_PKT_INBOUND_DROP;
#else
		res = 0;
#endif /* !(LF_WORKER_IGNORE_HASH_CHECK) */
	}
#else
	(void)exp_hash;
	(void)payload_len;
#endif /* !(LF_WORKER_OMIT_HASH_CHECK) */

#if !LF_WORKER_OMIT_DECAPSULATION
	/**
	 * Decapsulation: remove UDP and LF header
	 * Adjust used headers, i.e., void UDP and LF header and move ether and IP
	 * header.
	 * Subtract the removed headers from the offset.
	 */
	LF_WORKER_LOG_DP(DEBUG, "Decapsulate Packet\n");
	size_t encaps_hdr_len = lf_decapsulate_pkt(m, offset, ipv4_hdr, lf_hdr);
	if (unlikely(encaps_hdr_len % 2 != 0)) {
		/* unexpected error occurred */
		LF_WORKER_LOG_DP(ERR, "Ether header move ignores alignment of 2!\n");
		return LF_PKT_INBOUND_DROP;
	}
	ether_hdr = lf_ether_hdr_move(ether_hdr, encaps_hdr_len);
	ipv4_hdr = (struct rte_ipv4_hdr *)((uint8_t *)ipv4_hdr + encaps_hdr_len);

	/* void variables which cannot be used anymore after the decapsulation */
	(void)udp_hdr;
	(void)lf_hdr;
	(void)offset;
#endif /* !LF_WORKER_OMIT_DECAPSULATION */

	/*
	 * Apply inbound packet modifications, i.e., ethernet and IP address,
	 * and reset checksums.
	 */
	lf_worker_pkt_mod(m, ether_hdr, ipv4_hdr,
			lf_configmanager_worker_get_inbound_pkt_mod(
					worker_context->config));

	return LF_PKT_INBOUND_FORWARD;
}

/**
 * @param offset Offset to memory after the ethernet and IP header.
 * @return Size of the upd/lf header construct, which has been added.
 * - Negative number if an error occurred.
 */
static inline int
encapsulate_pkt(struct lf_worker_context *worker_context,
		const struct lf_config_peer *peer, struct rte_mbuf *m,
		unsigned int offset, struct rte_ipv4_hdr *ipv4_hdr)
{
	int res;
	uint16_t drkey_protocol;
	struct rte_udp_hdr *udp_hdr;
	struct lf_ip_hdr *lf_hdr;
	struct lf_host_addr src_addr;
	struct lf_host_addr dst_addr;
	uint32_t src_ip;
	uint64_t timestamp;
	struct lf_crypto_drkey drkey;
	int encaps_hdr_len;
	uint16_t udp_port;
	uint16_t payload_len;

	/* TODO: (fstreun) check that payload length fits into a uin16_t */
	payload_len = m->pkt_len - offset;

	encaps_hdr_len = lf_add_udp_lf_hdr(m, offset, ipv4_hdr,
			rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4), &udp_hdr, &lf_hdr);
	if (encaps_hdr_len < 0) {
		return -1;
	}
	offset = offset + encaps_hdr_len;
	/* move packet pointers to new position */
	ipv4_hdr = (struct rte_ipv4_hdr *)((uint8_t *)ipv4_hdr - encaps_hdr_len);

	drkey_protocol = lf_configmanager_worker_get_outbound_drkey_protocol(
			worker_context->config);

	/*
	 * Set host address structs.
	 * Additionally, check if the source is using a different public address
	 */
	res = lf_configmanager_worker_get_ip_public(worker_context->config,
			&src_ip);
	if (res != 0) {
		/* No public IP is provided: use the packets address. */
		src_ip = ipv4_hdr->src_addr;
	}
	src_addr = (struct lf_host_addr){
		.addr = &src_ip,
		.type_length = LF_HOST_ADDR_TL_IPV4,
	};
	dst_addr = (struct lf_host_addr){
		.addr = &ipv4_hdr->dst_addr,
		.type_length = LF_HOST_ADDR_TL_IPV4,
	};

	/*
	 * Set UDP and LF header fields.
	 */
	udp_port = lf_configmanager_worker_get_port(worker_context->config);
	udp_hdr->src_port = udp_port;
	udp_hdr->dst_port = udp_port;

	lf_hdr->src_as =
			lf_configmanager_worker_get_local_as(worker_context->config);
	lf_hdr->drkey_protocol = rte_cpu_to_be_16(payload_len);
	lf_hdr->rsv = 0;

	/* Calculate packet hash */
	lf_crypto_hash_update(&worker_context->crypto_hash_ctx,
			(uint8_t *)(lf_hdr + 1), m->pkt_len - offset);
	lf_crypto_hash_final(&worker_context->crypto_hash_ctx, lf_hdr->hash);

	/* Set timestamp */
	res = lf_time_worker_get_unique(&worker_context->time, &timestamp);
	if (unlikely(res != 0)) {
		LF_WORKER_LOG_DP(ERR, "Failed to get timestamp.\n");
		return -1;
	}
	lf_hdr->timestamp = rte_cpu_to_be_64(timestamp);

	/* Get drkey */
	res = lf_keymanager_worker_outbound_get_drkey(worker_context->key_manager,
			peer->isd_as, &dst_addr, &src_addr, drkey_protocol, timestamp,
			&drkey);
	if (unlikely(res < 0)) {
		LF_WORKER_LOG_DP(NOTICE,
				"Outbound DRKey not found for AS " PRIISDAS
				" and drkey_protocol %d (ns_now = %" PRIu64 ", res = %d)!\n",
				PRIISDAS_VAL(rte_be_to_cpu_64(peer->isd_as)),
				rte_be_to_cpu_16(drkey_protocol), timestamp, res);
		return -1;
	}

	LF_WORKER_LOG_DP(DEBUG,
			"DRKey [" PRIISDAS "]:" PRIIP " - [XX]:" PRIIP
			" and drkey_protocol %d (ns_now = %" PRIu64 ") is %x\n",
			PRIISDAS_VAL(rte_be_to_cpu_64(peer->isd_as)),
			PRIIP_VAL(*(uint32_t *)dst_addr.addr),
			PRIIP_VAL(*(uint32_t *)src_addr.addr),
			rte_be_to_cpu_16(drkey_protocol), timestamp, drkey.key[0]);

	/* Set DRKey epoch flag */
	lf_hdr->drkey_e = res;

	/* MAC */
	lf_crypto_drkey_compute_mac(&worker_context->crypto_drkey_ctx, &drkey,
			(uint8_t *)lf_hdr + 4, lf_hdr->mac);

	/* Overwrite payload length with DRKey protocol number */
	lf_hdr->drkey_protocol = drkey_protocol;

	return encaps_hdr_len;
}

/**
 * @param offset Offset to memory after ethernet and IP header.
 */
static enum lf_pkt_action
handle_outbound_pkt(struct lf_worker_context *worker_context,
		struct rte_mbuf *m, unsigned int offset,
		struct rte_ether_hdr *ether_hdr, struct rte_ipv4_hdr *ipv4_hdr)
{
	int encaps_hdr_len = 0;
	struct lf_config_peer *peer;

	/* get peer */
	peer = lf_configmanager_worker_get_peer_from_ip(worker_context->config,
			ipv4_hdr->dst_addr);
	if (unlikely(peer == NULL)) {
		LF_WORKER_LOG_DP(DEBUG, "No peer found.\n");
		return LF_PKT_OUTBOUND_DROP;
	}

	/**
	 * Encapsulation: add UDP and LF header
	 * Adjust used headers, i.e., move ether and IP header.
	 */
	encaps_hdr_len = encapsulate_pkt(worker_context, peer, m, offset, ipv4_hdr);
	if (unlikely(encaps_hdr_len < 0)) {
		LF_WORKER_LOG_DP(DEBUG, "Packet encapsulation failed.\n");
		return LF_PKT_OUTBOUND_DROP;
	}
	if (unlikely(encaps_hdr_len % 2 != 0)) {
		LF_WORKER_LOG_DP(ERR, "Ether header move ignores alignment of 2!\n");
		return LF_PKT_OUTBOUND_DROP;
	}
	ether_hdr = lf_ether_hdr_move(ether_hdr, -encaps_hdr_len);
	ipv4_hdr = (struct rte_ipv4_hdr *)((uint8_t *)ipv4_hdr - encaps_hdr_len);

	/*
	 * Apply outbound packet modifications, i.e., ethernet and IP address,
	 * and reset checksums.
	 */
	lf_worker_pkt_mod(m, ether_hdr, ipv4_hdr,
			lf_configmanager_worker_get_outbound_pkt_mod(
					worker_context->config));

	return LF_PKT_OUTBOUND_FORWARD;
}

static enum lf_pkt_action
handle_pkt(struct lf_worker_context *worker_context, struct rte_mbuf *m)
{
	unsigned int offset, offset_tmp;
	struct rte_ether_hdr *ether_hdr;
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_udp_hdr *udp_hdr;

	uint16_t lf_port = lf_configmanager_worker_get_port(worker_context->config);

	if (unlikely(m->data_len != m->pkt_len)) {
		LF_WORKER_LOG_DP(NOTICE,
				"Not yet implemented: buffer with multiple segments "
				"received.\n");
		return LF_PKT_UNKNOWN_DROP;
	}

	offset = 0;
	offset = lf_get_eth_hdr(m, offset, &ether_hdr);
	if (unlikely(offset == 0)) {
		return LF_PKT_UNKNOWN_DROP;
	}

	if (unlikely(ether_hdr->ether_type !=
				 rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))) {
		LF_WORKER_LOG_DP(NOTICE,
				"Unsupported packet type %#X: must be IPv4 (%#X).\n",
				rte_be_to_cpu_16(ether_hdr->ether_type), RTE_ETHER_TYPE_IPV4);
		return LF_PKT_UNKNOWN_DROP;
	}

	offset = lf_get_ip_hdr(m, offset, &ipv4_hdr);
	if (unlikely(offset == 0)) {
		return LF_PKT_UNKNOWN_DROP;
	}

	/*
	 * With the destination UDP port number, it is determined
	 * if the packet is a inbound or outbound packet.
	 */
	if (ipv4_hdr->next_proto_id == IP_PROTO_ID_UDP) {
		offset_tmp = lf_get_udp_hdr(m, offset, &udp_hdr);
		if (unlikely(offset_tmp == 0)) {
			return LF_PKT_UNKNOWN_DROP;
		}
		if (udp_hdr->dst_port == lf_port) {
			LF_WORKER_LOG_DP(DEBUG, "Inbound packet\n");
			return handle_inbound_pkt(worker_context, m, offset_tmp, ether_hdr,
					ipv4_hdr, udp_hdr);
		}
	}
	LF_WORKER_LOG_DP(DEBUG, "Outbound packet\n");
	return handle_outbound_pkt(worker_context, m, offset, ether_hdr, ipv4_hdr);
}

void
lf_worker_handle_pkt(struct lf_worker_context *worker_context,
		struct rte_mbuf **pkt_burst, uint16_t nb_pkts,
		enum lf_pkt_action *pkt_res)
{
	int i;

	for (i = 0; i < nb_pkts; i++) {
		if (pkt_res[i] != LF_PKT_UNKNOWN) {
			/* If packet action is already determined, do not process it */
			continue;
		}

		pkt_res[i] = handle_pkt(worker_context, pkt_burst[i]);
	}
}
