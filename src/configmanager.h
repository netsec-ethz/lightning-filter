/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#ifndef LF_CONFIGMANAGER_H
#define LF_CONFIGMANAGER_H

#include <inttypes.h>
#include <stdatomic.h>

#include <rte_rcu_qsbr.h>
#include <rte_spinlock.h>

#include "config.h"
#include "keymanager.h"
#include "lf.h"
#include "ratelimiter.h"

/**
 * The config manager provides access to the current configuration for the
 * different modules as well as workers.
 * It offers a IPC interface, allowing the configuration to be changed during
 * runtime.
 */

/**
 * The worker's config manager struct to access the current
 * configuration.
 */
struct lf_configmanager_worker {
	/* Atomic pointer to the current configuration, which can be change by the
	 * config manager */
	_Atomic(struct lf_config *) config;
};

struct lf_configmanager {
	struct lf_configmanager_worker workers[LF_MAX_WORKER];
	uint16_t nb_workers;

	/* Workers' Quiescent State Variable */
	struct rte_rcu_qsbr *qsv;

	/* Currently active configuration */
	struct lf_config *config;

	/* Lock to synchronize any manager actions, such as changing the current
	 * configuration */
	rte_spinlock_t manager_lock;

	/* Reference to other services which are notified on config change. */
	struct lf_keymanager *km;
	struct lf_ratelimiter *rl;
};

/**
 * Initiate the config manager structure and worker structures.
 */
int
lf_configmanager_init(struct lf_configmanager *cm, uint16_t nb_workers,
		struct rte_rcu_qsbr *qsv, struct lf_keymanager *km,
		struct lf_ratelimiter *rl);

/**
 * Load new config from json file.
 * If no config path is provided (i.e., config_path == NULL), the default config
 * is set.
 * @return Returns 0 on success.
 */
int
lf_configmanager_apply_config_file(struct lf_configmanager *cm,
		const char *config_path);

/**
 * Register configmanager IPC functionality.
 * This includes the command to update config globally to all modules, such as,
 * keymanager, ratelimiter, and plugins.
 * @return Returns 0 on success.
 */
int
lf_configmanager_register_ipc(struct lf_configmanager *cm);

/**
 * Get outbound DRKey protocol (network byte order).
 */
static inline uint16_t
lf_configmanager_worker_get_outbound_drkey_protocol(
		const struct lf_configmanager_worker *config_ctx)
{
	struct lf_config *config =
			atomic_load_explicit(&config_ctx->config, memory_order_relaxed);
	return config->drkey_protocol;
}

/**
 * Get peer using the ISD and AS number as identifier.
 * If no peer is found, NULL is returned.
 */
static inline struct lf_config_peer *
lf_configmanager_worker_get_peer_from_as(
		const struct lf_configmanager_worker *config_ctx, uint64_t isd_as)
{
	struct lf_config_peer *peer;
	struct lf_config *config =
			atomic_load_explicit(&config_ctx->config, memory_order_relaxed);

	peer = config->peers;
	while (peer != NULL) {
		if (peer->isd_as == isd_as) {
			return peer;
		}
		peer = peer->next;
	}
	return NULL;
}

/**
 * Get peer using the IP address (in network byte order) as identifier.
 * If no peer is found, NULL is returned.
 */
static inline struct lf_config_peer *
lf_configmanager_worker_get_peer_from_ip(
		const struct lf_configmanager_worker *config_ctx, uint32_t ip)
{
	struct lf_config_peer *peer;
	struct lf_config *config =
			atomic_load_explicit(&config_ctx->config, memory_order_relaxed);

	peer = config->peers;
	while (peer != NULL) {
		if (peer->ip == ip) {
			return peer;
		}
		peer = peer->next;
	}
	return NULL;
}

/**
 * Get local AS number.
 * @return AS number (network byte order)
 */
static inline uint64_t
lf_configmanager_worker_get_local_as(
		const struct lf_configmanager_worker *config_ctx)
{
	struct lf_config *config =
			atomic_load_explicit(&config_ctx->config, memory_order_relaxed);
	return config->isd_as;
}

/**
 * @return LF port number (network byte order)
 */
static inline uint16_t
lf_configmanager_worker_get_port(
		const struct lf_configmanager_worker *config_ctx)
{
	struct lf_config *config =
			atomic_load_explicit(&config_ctx->config, memory_order_relaxed);
	return config->port;
}

/**
 * @param ip_public Returns public IP if defined.
 * @return 0, if public IP is defined.
 */
static inline int
lf_configmanager_worker_get_ip_public(
		const struct lf_configmanager_worker *config_ctx, uint32_t *ip_public)
{
	struct lf_config *config =
			atomic_load_explicit(&config_ctx->config, memory_order_relaxed);
	if (config->option_ip_public) {
		*ip_public = config->ip_public;
		return 0;
	}
	return 1;
}

static inline struct lf_config_pkt_mod *
lf_configmanager_worker_get_outbound_pkt_mod(
		const struct lf_configmanager_worker *config_ctx)
{
	struct lf_config *config =
			atomic_load_explicit(&config_ctx->config, memory_order_relaxed);
	return &config->outbound_next_hop;
}

static inline struct lf_config_pkt_mod *
lf_configmanager_worker_get_inbound_pkt_mod(
		const struct lf_configmanager_worker *config_ctx)
{
	struct lf_config *config =
			atomic_load_explicit(&config_ctx->config, memory_order_relaxed);
	return &config->inbound_next_hop;
}

#endif /* LF_CONFIGMANAGER_H */