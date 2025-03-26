/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#include <rte_common.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_udp.h>

#include "../lib/ratelimiter/token_bucket.h"
#include "../lib/scion/scion.h"
#include "../lib/utils/packet.h"
#include "../worker.h"
#include "plugins.h"

/*
 * WireGuard (WG) Ratelimiter:
 * Enforces rate limits for WG packets identified by the destination port
 * number. Different rate limits are applied for handshake packets (including
 * cookie response packet) and data packets.
 */

#define SCION_IP_GATEWAY_PORT 30056

enum lf_wgr_pkt_state {
	LF_WGR_FORWARD,
	LF_WGR_RATELIMITED,
	LF_WGR_ERROR,
};

#define LF_WGR_LOG(level, ...)                                      \
	LF_PLUGINS_LOG(level,                                           \
			RTE_FMT("WG Ratelimiter: " RTE_FMT_HEAD(__VA_ARGS__, ), \
					RTE_FMT_TAIL(__VA_ARGS__, )))

#define LF_WGR_LOG_DP(level, ...)                                   \
	LF_PLUGINS_LOG_DP(level,                                        \
			RTE_FMT("WG Ratelimiter: " RTE_FMT_HEAD(__VA_ARGS__, ), \
					RTE_FMT_TAIL(__VA_ARGS__, )))

struct wg_ratelimiter_worker {
	uint16_t wg_port;
	struct lf_token_bucket_ratelimit handshake_bucket;
	struct lf_token_bucket_ratelimit data_bucket;
};

struct wg_ratelimiter {
	uint16_t nb_workers;
	struct wg_ratelimiter_worker *workers[LF_MAX_WORKER];
};

struct wg_ratelimiter wg_ratelimiter;

struct wg_hdr {
	uint8_t type;
	uint8_t reserved;
} __attribute__((__packed__));

static inline unsigned int
get_wg_hdr(const struct lf_worker_context *worker_context,
		const struct rte_mbuf *m, unsigned int offset,
		struct wg_hdr **wg_hdr_ptr)
{
	if (unlikely(sizeof(struct wg_hdr) > m->data_len - offset)) {
		LF_WGR_LOG_DP(ALERT,
				"Not yet implemented: WG header exceeds first buffer "
				"segment.\n");
		return 0;
	}

	*wg_hdr_ptr = rte_pktmbuf_mtod_offset(m, struct wg_hdr *, offset);
	offset += sizeof(struct wg_hdr);

	return offset;
}

static enum lf_wgr_pkt_state
handle_wg_pkt(struct lf_worker_context *worker_context,
		struct wg_ratelimiter_worker *ctx, struct rte_mbuf *m,
		struct wg_hdr *wg_hdr)
{
	int res;

	int64_t ms_now;
	res = lf_time_worker_get(&worker_context->time, &ms_now);
	if (res != 0) {
		return LF_WGR_ERROR;
	}

	if (wg_hdr->type == 0x1 || wg_hdr->type == 0x2 || wg_hdr->type == 0x3) {
		/* The packet is a WG handshake packet */
		res = lf_token_bucket_ratelimit_apply(&ctx->handshake_bucket, 1,
				m->pkt_len, ms_now);
		LF_WGR_LOG_DP(DEBUG, "Handshake rate limit result %d\n", res);
		if (res != 0) {
			return LF_WGR_RATELIMITED;
		}
	} else if (wg_hdr->type == 0x4) {
		/* The packet is a WG data packet */
		res = lf_token_bucket_ratelimit_apply(&ctx->data_bucket, 1, m->pkt_len,
				ms_now);
		LF_WGR_LOG_DP(DEBUG, "Data rate limit result %d\n", res);
		if (res != 0) {
			return LF_WGR_RATELIMITED;
		}
	} else {
		/* unknown type */
		LF_WGR_LOG_DP(NOTICE, "Unknown WireGuard type %d\n", wg_hdr->type);
		return LF_WGR_ERROR;
	}

	return LF_WGR_FORWARD;
}

enum lf_pkt_action
lf_wg_ratelimiter_handle_pkt_post(struct lf_worker_context *worker_context,
		struct rte_mbuf *m, enum lf_pkt_action pkt_action)
{
	int res;
	struct wg_ratelimiter_worker *ctx =
			wg_ratelimiter.workers[worker_context->worker_id];

	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_udp_hdr *udp_hdr;
	struct wg_hdr *wg_hdr;

	unsigned int offset = 0;

	LF_WGR_LOG_DP(DEBUG, "Processing packet.\n");

	/* Only consider forwarded inbound packets */
	if (pkt_action != LF_PKT_INBOUND_FORWARD) {
		return pkt_action;
	}

	if (worker_context->pkt_processing == LF_PKT_PROCESSING_SCION) {
		res = scion_skip_gateway(SCION_IP_GATEWAY_PORT, m, &ipv4_hdr);
		if (res == 0) {
			LF_WGR_LOG_DP(DEBUG, "SCION packet is not a SIG frame.\n");
			return pkt_action;
		} else if (res < 0) {
			LF_WGR_LOG_DP(DEBUG, "Error parsing SCION packet.\n");
			return LF_PKT_INBOUND_DROP;
		}
		LF_WGR_LOG_DP(DEBUG, "SCION packet is a SIG frame.\n");
		offset = res;
	} else if (worker_context->pkt_processing == LF_PKT_PROCESSING_IP) {
		struct rte_ether_hdr *ether_hdr;
		offset = lf_get_eth_hdr(m, offset, &ether_hdr);
		if (offset == 0) {
			return LF_PKT_INBOUND_DROP;
		}

		offset = lf_get_ip_hdr(m, offset, &ipv4_hdr);
		if (unlikely(offset == 0)) {
			return LF_PKT_INBOUND_DROP;
		}
	} else {
		LF_WGR_LOG_DP(ERR, "Unknown packet processing type %d\n",
				worker_context->pkt_processing);
		return LF_PKT_UNKNOWN;
	}

	if (ipv4_hdr->next_proto_id != IPPROTO_UDP) {
		/* It's not a UDP packet */
		LF_WGR_LOG_DP(DEBUG,
				"Packet type is not UDP (%#X) but %#X (i.e., not a WG "
				"packet)\n",
				IPPROTO_UDP, ipv4_hdr->next_proto_id);
		return pkt_action;
	}

	offset = lf_get_udp_hdr(m, offset, &udp_hdr);
	if (offset == 0) {
		return LF_PKT_INBOUND_DROP;
	}

	if (udp_hdr->dst_port != ctx->wg_port) {
		LF_WGR_LOG_DP(DEBUG,
				"UDP port is no WG port (%u) but %u (i.e., not a WG packet)\n",
				rte_be_to_cpu_16(ctx->wg_port),
				rte_be_to_cpu_16(udp_hdr->dst_port));
		return pkt_action;
	}

	offset = get_wg_hdr(worker_context, m, offset, &wg_hdr);
	if (offset == 0) {
		return LF_PKT_INBOUND_DROP;
	}

	res = handle_wg_pkt(worker_context, ctx, m, wg_hdr);

	if (res == LF_WGR_FORWARD) {
		return pkt_action;
	} else if (res == LF_WGR_RATELIMITED) {
		return LF_PKT_INBOUND_DROP;
	} else {
		return LF_PKT_INBOUND_DROP;
	}
}

int
lf_wg_ratelimiter_apply_config(const struct lf_config *config)
{
	int res = 0;
	uint16_t worker_id;
	struct lf_config_ratelimit ratelimit;
	uint64_t packet_rate, packet_burst, byte_rate, byte_burst;
	struct wg_ratelimiter_worker *ctx;

	LF_WGR_LOG(NOTICE, "Apply config...\n");

	LF_WGR_LOG(DEBUG, "Set WG port to %u\n",
			rte_be_to_cpu_16(config->wg_ratelimiter.wg_port));
	for (worker_id = 0; worker_id < wg_ratelimiter.nb_workers; ++worker_id) {
		ctx = wg_ratelimiter.workers[worker_id];
		ctx->wg_port = config->wg_ratelimiter.wg_port;
	}

	/*
	 * Handshake Ratelimit
	 */
	ratelimit = config->wg_ratelimiter.handshake_ratelimit;
	LF_WGR_LOG(DEBUG,
			"Set handshake rate limit "
			"(byte_rate: %ld, byte_burst: %ld, "
			"packet_rate: %ld, packet_burst %ld)\n",
			ratelimit.byte_rate, ratelimit.byte_burst, ratelimit.packet_rate,
			ratelimit.packet_burst);

	/* per core */
	packet_rate = ratelimit.packet_rate / wg_ratelimiter.nb_workers;
	packet_burst = ratelimit.packet_burst / wg_ratelimiter.nb_workers;
	byte_rate = ratelimit.byte_rate / wg_ratelimiter.nb_workers;
	byte_burst = ratelimit.byte_burst / wg_ratelimiter.nb_workers;
	LF_WGR_LOG(DEBUG,
			"Set handshake rate limit per core "
			"(byte_rate: %ld, byte_burst: %ld, "
			"packet_rate: %ld, packet_burst %ld)\n",
			byte_rate, byte_burst, packet_rate, packet_burst);
	for (worker_id = 0; worker_id < wg_ratelimiter.nb_workers; ++worker_id) {
		ctx = wg_ratelimiter.workers[worker_id];
		res |= lf_token_bucket_ratelimit_set(&ctx->handshake_bucket,
				packet_rate, packet_burst, byte_rate, byte_burst);
	}

	/*
	 * Data Ratelimit
	 */
	ratelimit = config->wg_ratelimiter.data_ratelimit;
	LF_WGR_LOG(DEBUG,
			"Set data rate limit "
			"(byte_rate: %ld, byte_burst: %ld, "
			"packet_rate: %ld, packet_burst %ld)\n",
			ratelimit.byte_rate, ratelimit.byte_burst, ratelimit.packet_rate,
			ratelimit.packet_burst);

	/* per core */
	packet_rate = ratelimit.packet_rate / wg_ratelimiter.nb_workers;
	packet_burst = ratelimit.packet_burst / wg_ratelimiter.nb_workers;
	byte_rate = ratelimit.byte_rate / wg_ratelimiter.nb_workers;
	byte_burst = ratelimit.byte_burst / wg_ratelimiter.nb_workers;
	LF_WGR_LOG(DEBUG,
			"Set data rate limit per core "
			"(byte_rate: %ld, byte_burst: %ld, "
			"packet_rate: %ld, packet_burst %ld)\n",
			byte_rate, byte_burst, packet_rate, packet_burst);
	for (worker_id = 0; worker_id < wg_ratelimiter.nb_workers; ++worker_id) {
		ctx = wg_ratelimiter.workers[worker_id];
		res |= lf_token_bucket_ratelimit_set(&ctx->data_bucket, packet_rate,
				packet_burst, byte_rate, byte_burst);
	}

	if (res == 0) {
		LF_WGR_LOG(NOTICE, "Applied config successfully\n");
	}
	return res;
}

int
lf_wg_ratelimiter_init(struct lf_worker_context *workers, uint16_t nb_workers)
{
	uint16_t worker_id;
	wg_ratelimiter.nb_workers = nb_workers;

	for (worker_id = 0; worker_id < wg_ratelimiter.nb_workers; ++worker_id) {
		wg_ratelimiter.workers[worker_id] = rte_zmalloc_socket(NULL,
				sizeof(struct wg_ratelimiter_worker), RTE_CACHE_LINE_SIZE,
				rte_lcore_to_socket(workers[worker_id].lcore_id));

		lf_token_bucket_ratelimit_init(
				&wg_ratelimiter.workers[worker_id]->handshake_bucket, 0, 0, 0,
				0);
		lf_token_bucket_ratelimit_init(
				&wg_ratelimiter.workers[worker_id]->data_bucket, 0, 0, 0, 0);
	}

	return 0;
}
