/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#include <rte_net.h>

#include "../lib/ratelimiter/token_bucket.h"
#include "../lib/utils/packet.h"
#include "../worker.h"

#include "plugins.h"

#define IP_DST_ADDR      "10.248.1.1"
#define IP_DST_PKT_RATE  1 /* 1 pkt per ms */
#define IP_DST_BYTE_RATE 1 /* 1 byte per ms -> 1000 bytes per s */

#define LF_DSTR_LOG(level, ...)                                     \
	LF_PLUGINS_LOG(level,                                           \
			RTE_FMT("WG Ratelimiter: " RTE_FMT_HEAD(__VA_ARGS__, ), \
					RTE_FMT_TAIL(__VA_ARGS__, )))

#define LF_DSTR_LOG_DP(level, ...)                                  \
	LF_PLUGINS_LOG_DP(level,                                        \
			RTE_FMT("WG Ratelimiter: " RTE_FMT_HEAD(__VA_ARGS__, ), \
					RTE_FMT_TAIL(__VA_ARGS__, )))

struct dst_ratelimiter {
	uint16_t nb_workers;
	uint32_t dst_ip;
	struct lf_token_bucket_ratelimit buckets[LF_MAX_WORKER];
};

struct dst_ratelimiter dst_ratelimiter;

int
lf_dst_ratelimiter_init(uint16_t nb_workers)
{
	uint16_t worker_id;
	dst_ratelimiter.nb_workers = nb_workers;

	for (worker_id = 0; worker_id < dst_ratelimiter.nb_workers; ++worker_id) {
		lf_token_bucket_ratelimit_init(&dst_ratelimiter.buckets[worker_id], 0,
				0, 0, 0);
	}

	return 0;
}

int
lf_dst_ratelimiter_apply_config(const struct lf_config *config)
{
	int res = 0;
	uint16_t worker_id;
	struct lf_config_ratelimit ratelimit = config->dst_ratelimiter.ratelimit;

	/* per core */
	uint64_t packet_rate = ratelimit.packet_rate / dst_ratelimiter.nb_workers;
	uint64_t packet_burst = ratelimit.packet_burst / dst_ratelimiter.nb_workers;
	uint64_t byte_rate = ratelimit.byte_rate / dst_ratelimiter.nb_workers;
	uint64_t byte_burst = ratelimit.byte_burst / dst_ratelimiter.nb_workers;

	LF_DSTR_LOG(NOTICE, "Apply config...\n");

	dst_ratelimiter.dst_ip = config->dst_ratelimiter.dst_ip;

	LF_DSTR_LOG(DEBUG,
			"Add ratelimit for dst_ip %u (byte_rate: %ld, byte_burst: %ld,"
			"packet_rate: %ld, packet_burst %ld)\n",
			dst_ratelimiter.dst_ip, ratelimit.byte_rate, ratelimit.byte_burst,
			ratelimit.packet_rate, ratelimit.packet_burst);

	for (worker_id = 0; worker_id < dst_ratelimiter.nb_workers; ++worker_id) {
		res |= lf_token_bucket_ratelimit_set(
				&dst_ratelimiter.buckets[worker_id], packet_rate, packet_burst,
				byte_rate, byte_burst);
	}

	if (res == 0) {
		LF_DSTR_LOG(NOTICE, "Applied config successfully\n");
	}
	return res;
}

enum lf_pkt_action
lf_dst_ratelimiter_handle_pkt_post(struct lf_worker_context *worker_context,
		struct rte_mbuf *m, enum lf_pkt_action pkt_action)
{
	int res;
	struct rte_ether_hdr *ether_hdr;
	struct rte_ipv4_hdr *ipv4_hdr;
	unsigned int offset = 0;


	/* Only consider forwarded inbound packets */
	if (pkt_action != LF_PKT_INBOUND_FORWARD) {
		return pkt_action;
	}

	offset = lf_get_eth_hdr(worker_context, m, offset, &ether_hdr);
	if (offset == 0) {
		return pkt_action;
	}

	offset = lf_get_ip_hdr(worker_context, m, offset, &ipv4_hdr);
	if (offset == 0) {
		return pkt_action;
	}

	if (ipv4_hdr->dst_addr != dst_ratelimiter.dst_ip) {
		/* apply rate limit */
		return pkt_action;
	}


	struct lf_timestamp t_now;
	res = lf_time_worker_get(&worker_context->time, &t_now);
	if (res != 0) {
		return pkt_action;
	}

	res = lf_token_bucket_ratelimit_apply(
			&dst_ratelimiter.buckets[worker_context->worker_id], 1, m->pkt_len,
			&t_now);
	LF_DSTR_LOG_DP(DEBUG, "Ratelimit result %d\n", res);
	if (res != 0) {
		return LF_PKT_INBOUND_DROP;
	}

	return pkt_action;
}