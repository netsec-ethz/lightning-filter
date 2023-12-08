/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#ifndef LF_WORKER_H
#define LF_WORKER_H

#include <inttypes.h>

#include <rte_common.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

#include "config.h"
#include "keymanager.h"
#include "lf.h"
#include "lib/crypto/crypto.h"
#include "lib/log/log.h"
#include "lib/mirror/mirror.h"
#include "lib/time/time.h"
#include "ratelimiter.h"

/**
 * The worker implements the LightningFilter pipeline and processes packets
 * (inbound as well as outbound).
 */

/**
 * Log function for LF worker.
 * The lcore ID is added to each message. Format with lcore ID 1:
 * Worker [1]: log message here
 */
#define LF_WORKER_LOG(level, ...)                                      \
	LF_LOG(level, RTE_FMT("Worker [%d]: " RTE_FMT_HEAD(__VA_ARGS__, ), \
						  rte_lcore_id(), RTE_FMT_TAIL(__VA_ARGS__, )))

#define LF_WORKER_LOG_DP(level, ...)                                      \
	LF_LOG_DP(level, RTE_FMT("Worker [%d]: " RTE_FMT_HEAD(__VA_ARGS__, ), \
							 rte_lcore_id(), RTE_FMT_TAIL(__VA_ARGS__, )))

struct lf_worker_context {
	uint16_t lcore_id;

	/* RX/TX ports and queues */
	/* TODO: remove from the lf worker context */
	uint16_t max_rx_tx_index, current_rx_tx_index;
	uint16_t rx_port_id[RTE_MAX_ETHPORTS];
	uint16_t rx_queue_id[RTE_MAX_ETHPORTS];
	uint16_t tx_port_id[RTE_MAX_ETHPORTS];
	uint16_t tx_queue_id[RTE_MAX_ETHPORTS];
	uint16_t tx_queue_id_by_port[RTE_MAX_ETHPORTS];
	struct rte_eth_dev_tx_buffer *tx_buffer[RTE_MAX_ETHPORTS];
	struct rte_eth_dev_tx_buffer *tx_buffer_by_port[RTE_MAX_ETHPORTS];

	/* Forwarding port pair */
	/* TODO: replace with a ip lookup struct for proper l3 forwarding */
	uint16_t port_pair[RTE_MAX_ETHPORTS];

	/* Timestamp threshold in nanoseconds */
	uint64_t timestamp_threshold;

	/*
	 * Worker contexts of the different modules
	 */
	struct lf_configmanager_worker *config;
	struct lf_keymanager_worker *key_manager;
	struct lf_duplicate_filter_worker *duplicate_filter;
	struct lf_ratelimiter_worker ratelimiter;
	struct lf_statistics_worker *statistics;
	struct lf_time_worker time;
	struct lf_crypto_hash_ctx crypto_hash_ctx;
	struct lf_crypto_drkey_ctx crypto_drkey_ctx;
	struct lf_mirror_worker *mirror_ctx;

	/* Quiescent State Variable */
	struct rte_rcu_qsbr *qsv;
	unsigned int qsv_id;
} __rte_cache_aligned;

/**
 * Summary of data contained in a packet that is required by LightningFilter.
 * This includes addresses, timestamp, DRKey protocol number, MAC, etc..
 */
struct lf_pkt_data {
	/* Peer/Source ISD AS number (network byte order). */
	uint64_t src_as;
	/* Destination ISD AS number (network byte order). */
	uint64_t dst_as;

	/* Peer/Source host address with length/type and pointer to
	 * address (network byte order). */
	struct lf_host_addr src_addr;
	/* Destination host address with length/type and pointer to
	 * address (network byte order). */
	struct lf_host_addr dst_addr;

	/* Packet timestamp: Unix epoch in nanoseconds  */
	uint64_t timestamp;

	/* DRKey Protocol number (network byte order). */
	uint16_t drkey_protocol;

	/* Indicator that the DRKey is only valid due to the grace
	 * period. */
	bool grace_period;

	/* LF_CRYPTO_MAC_SIZE bytes of MAC */
	uint8_t *mac;
	/* LF_CRYPTO_MAC_DATA_SIZE bytes of authenticated data, i.e., input for MAC
	 * calculation. */
	uint8_t *auth_data;

	/* Packet length for rate limiting. */
	uint32_t pkt_len;
};

/**
 * The action to be performed with the packet.
 */
enum lf_pkt_action {
	LF_PKT_UNKNOWN = 0,
	LF_PKT_UNKNOWN_DROP,
	LF_PKT_UNKNOWN_FORWARD,
	LF_PKT_OUTBOUND_DROP,
	LF_PKT_OUTBOUND_FORWARD,
	LF_PKT_INBOUND_DROP,
	LF_PKT_INBOUND_FORWARD,
};

/**
 * The packet check can provide following results.
 */
enum lf_check_state {
	LF_CHECK_ERROR,
	LF_CHECK_NO_HEADER,
	LF_CHECK_NO_KEY,
	LF_CHECK_INVALID_MAC,
	LF_CHECK_OUTDATED_TIMESTAMP,
	LF_CHECK_DUPLICATE,
	LF_CHECK_AS_RATELIMITED,
	LF_CHECK_SYSTEM_RATELIMITED,
	LF_CHECK_VALID_MAC_BUT_INVALID_HASH,
	LF_CHECK_VALID, /* Valid Packet */
	LF_CHECK_BE_RATELIMITED,
	LF_CHECK_BE, /* Best-Effort Packet */
};

/**
 * Reset all worker contexts for all lcores that run a worker. All fields but
 * the lcore_id field are set to 0. The lcore_id field is set approapriately.
 *
 * @param worker_lcores The lcore boolean map for workers, that indicates which
 * cores run a worker.
 * @param worker_contexts Array of worker contexts.
 * @return 0 on success.
 */
int
lf_worker_init(bool worker_lcores[RTE_MAX_LCORE],
		struct lf_worker_context worker_contexts[RTE_MAX_LCORE]);

/**
 * Launch function for the workers.
 * @param worker_context The worker context.
 * @return Returns 0.
 */
int
lf_worker_run(struct lf_worker_context *worker_context);

/**
 * Parse the packet and decide wether to forward it or to drop it.
 */
void
lf_worker_handle_pkt(struct lf_worker_context *worker_context,
		struct rte_mbuf **pkt_burst, uint16_t nb_pkts,
		enum lf_pkt_action *pkt_res);

/**
 * Check if packet can pass as a valid packet.
 * Therefore, this function verifies the MAC, checks the timestamp, applies
 * duplicate filtering, and rate limiting.
 *
 * @param pkt_data Struct containing packet data to perform the checks.
 * @return Result of the packet check
 */
enum lf_check_state
lf_worker_check_pkt(struct lf_worker_context *worker_context,
		const struct lf_pkt_data *pkt_data);

/**
 * Check if packet can pass as a best-effort packet.
 * Therefore, this function applies rate limiting.
 *
 * @return enum lf_check_state.
 */
enum lf_check_state
lf_worker_check_best_effort_pkt(struct lf_worker_context *worker_context,
		uint32_t pkt_len);

/**
 * This function modifies the packet (ethernet and IP header) according the
 * provided modifier and updates the checksum.
 *
 * @param ether_hdr Ethernet header to be modified. Can be NULL.
 * @param l3_hdr pointer to l3 header. If LF_IPV6, "struct rte_ipv6_hdr *",
 * otherwise, "struct rte_ipv4_hdr *".
 * @param pkt_mod The packet modification configuration.
 */
void
lf_worker_pkt_mod(struct rte_mbuf *m, struct rte_ether_hdr *ether_hdr,
		void *l3_hdr, const struct lf_config_pkt_mod *pkt_mod);

#endif /* LF_WORKER_H */
