/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#ifndef LF_PLUGINS_H
#define LF_PLUGINS_H

#include <rte_common.h>

#include "../lib/log/log.h"
#include "../worker.h"

/**
 * Log function for LF plugin.
 * The lcore ID is added to each message. Format with lcore ID 1:
 * Plugin [1]: log message here
 */
#define LF_PLUGINS_LOG(level, ...)                                     \
	LF_LOG(level, RTE_FMT("Plugin [%d]: " RTE_FMT_HEAD(__VA_ARGS__, ), \
						  rte_lcore_id(), RTE_FMT_TAIL(__VA_ARGS__, )))

#define LF_PLUGINS_LOG_DP(level, ...)                                     \
	LF_LOG_DP(level, RTE_FMT("Plugin [%d]: " RTE_FMT_HEAD(__VA_ARGS__, ), \
							 rte_lcore_id(), RTE_FMT_TAIL(__VA_ARGS__, )))

int
lf_dst_ratelimiter_init(uint16_t nb_workers);
int
lf_dst_ratelimiter_apply_config(const struct lf_config *config);
enum lf_pkt_action
lf_dst_ratelimiter_handle_pkt_post(struct lf_worker_context *worker_context,
		struct rte_mbuf *m, enum lf_pkt_action pkt_action);


int
lf_wg_ratelimiter_init(struct lf_worker_context *workers, uint16_t nb_workers);
int
lf_wg_ratelimiter_apply_config(const struct lf_config *config);
enum lf_pkt_action
lf_wg_ratelimiter_handle_pkt_post(struct lf_worker_context *worker_context,
		struct rte_mbuf *m, enum lf_pkt_action pkt_action);

/**
 * Initialize all enabled plugins.
 * TODO: (fstreun) make plugins NUMA aware (i.e., provide worker contexts).
 * @param nb_workers Number of workers.
 * @return 0 on success.
 */
int
lf_plugins_init(struct lf_worker_context *workers, uint16_t nb_workers);

/**
 * Apply configuration to all enabled plugins.
 * @param config New configuration to be applied.
 * @return int 0 on success.
 */
int
lf_plugins_apply_config(const struct lf_config *config);

static inline enum lf_pkt_action
lf_plugins_pre(struct lf_worker_context *worker_context, struct rte_mbuf *m,
		enum lf_pkt_action pkt_action)
{
	enum lf_pkt_action pkt_action_res = pkt_action;

	(void)worker_context;
	(void)m;
	return pkt_action_res;
}

/**
 * Post packet processing for enabled plugins.
 * This function is called after the core modules have processed the packet.
 * @param worker_context The worker's context.
 * @param m The processed packet.
 * @param pkt_action The packet action provided by the core modules.
 * @return The new packet action determined by the enabled plugins.
 */
static inline enum lf_pkt_action
lf_plugins_post(struct lf_worker_context *worker_context, struct rte_mbuf *m,
		enum lf_pkt_action pkt_action)
{
	enum lf_pkt_action pkt_action_res = pkt_action;

#if LF_PLUGIN_DST_RATELIMITER
	pkt_action_res = lf_dst_ratelimiter_handle_pkt_post(worker_context, m,
			pkt_action_res);
#endif

#if LF_PLUGIN_WG_RATELIMITER
	pkt_action_res = lf_wg_ratelimiter_handle_pkt_post(worker_context, m,
			pkt_action_res);
#endif

	(void)worker_context;
	(void)m;
	return pkt_action_res;
}

#endif /* LF_PLUGINS_H*/
