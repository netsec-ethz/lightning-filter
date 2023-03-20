/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#include <rte_rcu_qsbr.h>
#include <rte_spinlock.h>

#include "config.h"
#include "configmanager.h"
#include "keymanager.h"
#include "lib/ipc/ipc.h"
#include "lib/log/log.h"
#include "plugins/plugins.h"
#include "ratelimiter.h"


/*
 * Synchronization and Atomic Operations:
 * Writing and reading the workers' config pointer is always performed
 * atomically with relaxed memory order. Synchronization is provided
 * through the worker's RCU mechanism (rcu_qsbr). Therefore, after the manager
 * changed the workers' config pointer, the workers will observe the change at
 * least after passing through the quiescent state.
 */

/**
 * Log function for config manager (not on data path).
 * Format: "Config Manager: log message here"
 */
#define LF_CONFIGMANAGER_LOG(level, ...) \
	LF_LOG(level, "Config Manager: " __VA_ARGS__)

/**
 * Set the new configuration for the manager and all workers.
 * @return struct lf_config* Returns the old configuration struct, which can be
 * freed by the caller.
 */
struct lf_config *
set_config(struct lf_configmanager *cm, struct lf_config *new_config)
{
	size_t i;
	struct lf_config *old_config;
	old_config = cm->config;
	cm->config = new_config;

	rte_spinlock_lock(&cm->manager_lock);
	LF_CONFIGMANAGER_LOG(NOTICE, "Set config...\n");

	/* set config for workers */
	for (i = 0; i < cm->nb_workers; ++i) {
		atomic_store_explicit(&cm->workers[i].config, cm->config,
				memory_order_relaxed);
	}

	rte_rcu_qsbr_synchronize(cm->qsv, RTE_QSBR_THRID_INVALID);

	rte_spinlock_unlock(&cm->manager_lock);

	LF_CONFIGMANAGER_LOG(NOTICE, "Set config successfully\n");

	return old_config;
}

int
lf_configmanager_load_config(struct lf_configmanager *cm,
		const char *config_path)
{
	struct lf_config *config;

	LF_CONFIGMANAGER_LOG(INFO, "Load config from %s ...\n", config_path);
	config = lf_config_new_from_file(config_path);
	if (config == NULL) {
		LF_LOG(ERR, "CMD: Config parser failed\n");
		return -1;
	}

	config = set_config(cm, config);
	if (config != NULL) {
		lf_config_free(config);
	}

	return 0;
}

int
lf_configmanager_init(struct lf_configmanager *cm, uint16_t nb_workers,
		struct rte_rcu_qsbr *qsv)
{
	uint16_t worker_id;

	LF_CONFIGMANAGER_LOG(DEBUG, "Init\n");

	cm->config = lf_config_new();
	if (cm->config == NULL) {
		LF_CONFIGMANAGER_LOG(ERR, "Failed to load default config\n");
		return -1;
	}
	rte_spinlock_init(&cm->manager_lock);

	cm->nb_workers = nb_workers;
	cm->qsv = qsv;

	for (worker_id = 0; worker_id < cm->nb_workers; ++worker_id) {
		cm->workers[worker_id].config = cm->config;
	}

	return 0;
}

/*
 * Configmanager IPC Functionalities
 */

/* Global config manager context */
static struct lf_configmanager *cm_ctx = NULL;
static struct lf_ratelimiter *ipc_ratelimiter = NULL;
static struct lf_keymanager *ipc_keymanager = NULL;

int
ipc_global_config(const char *cmd __rte_unused, const char *p, char *out_buf,
		size_t buf_len)
{
	int res = 0;
	struct lf_config *config;

	LF_LOG(INFO, "Load config from %s ...\n", p);
	config = lf_config_new_from_file(p);
	if (config == NULL) {
		LF_LOG(ERR, "Config parser failed\n");
		return -1;
	}

	if (ipc_ratelimiter != NULL) {
		res = lf_ratelimiter_apply_config(ipc_ratelimiter, config);
	}
	if (ipc_keymanager != NULL) {
		res |= lf_keymanager_apply_config(ipc_keymanager, config);
	}
	res |= lf_plugins_apply_config(config);

	config = set_config(cm_ctx, config);
	if (config != NULL) {
		lf_config_free(config);
	}

	if (res != 0) {
		return -1;
	}

	return snprintf(out_buf, buf_len, "successfully applied config");
}

int
ipc_traffic_config(const char *cmd __rte_unused, const char *params,
		char *out_buf, size_t buf_len)
{
	if (params != NULL) {
		if (lf_configmanager_load_config(cm_ctx, params)) {
			return snprintf(out_buf, buf_len, "An error ocurred");
		}
		return snprintf(out_buf, buf_len, "Loaded config from %s.", params);
	} else {
		return snprintf(out_buf, buf_len, "File path is missing.");
	}
}

int
lf_configmanager_register_ipc(struct lf_configmanager *cm,
		struct lf_keymanager *km, struct lf_ratelimiter *rl)
{
	int res;

	res = lf_ipc_register_cmd("/traffic/config", ipc_traffic_config,
			"Load traffic config from file");
	res |= lf_ipc_register_cmd("/config", ipc_global_config,
			"Load global config, i.e., config for all modules, from file");
	if (res != 0) {
		LF_CONFIGMANAGER_LOG(ERR, "Failed to register IPC command\n");
		return -1;
	}

	/* set ipc contexts */
	cm_ctx = cm;
	ipc_ratelimiter = rl;
	ipc_keymanager = km;

	return 0;
}