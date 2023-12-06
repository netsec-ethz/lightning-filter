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

int
lf_configmanager_apply_config(struct lf_configmanager *cm,
		struct lf_config *new_config)
{
	int res = 0;
	struct lf_config *old_config;

	rte_spinlock_lock(&cm->manager_lock);
	LF_CONFIGMANAGER_LOG(NOTICE, "Set config...\n");

	/* replace stored config */
	old_config = cm->config;
	cm->config = new_config;

	/* update service's config */
	if (cm->rl != NULL) {
		res = lf_ratelimiter_apply_config(cm->rl, new_config);
	}
	if (cm->km != NULL) {
		res |= lf_keymanager_apply_config(cm->km, new_config);
	}
	res |= lf_plugins_apply_config(new_config);

	/* update worker's config */
	for (uint16_t i = 0; i < cm->nb_workers; ++i) {
		atomic_store_explicit(&cm->workers[i].config, cm->config,
				memory_order_relaxed);
	}
	rte_rcu_qsbr_synchronize(cm->qsv, RTE_QSBR_THRID_INVALID);

	/* free old config */
	if (old_config != NULL) {
		lf_config_free(old_config);
	}

	if (res == 0) {
		LF_CONFIGMANAGER_LOG(NOTICE, "Set config successfully\n");
	} else {
		LF_CONFIGMANAGER_LOG(ERR, "Failed applying config\n");
	}

	rte_spinlock_unlock(&cm->manager_lock);

	return res;
}

int
lf_configmanager_apply_config_file(struct lf_configmanager *cm,
		const char *config_path)
{
	struct lf_config *config;

	LF_CONFIGMANAGER_LOG(INFO, "Load config from %s ...\n", config_path);
	config = lf_config_new_from_file(config_path);
	if (config == NULL) {
		LF_LOG(ERR, "CMD: Config parser failed\n");
		return -1;
	}

	return lf_configmanager_apply_config(cm, config);
}

int
lf_configmanager_init(struct lf_configmanager *cm, uint16_t nb_workers,
		struct rte_rcu_qsbr *qsv, struct lf_keymanager *km,
		struct lf_ratelimiter *rl)
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

	cm->km = km;
	cm->rl = rl;

	return 0;
}

/*
 * Configmanager IPC Functionalities
 */

/* Global config manager context */
static struct lf_configmanager *cm_ctx = NULL;

int
ipc_global_config(const char *cmd __rte_unused, const char *p, char *out_buf,
		size_t buf_len)
{
	int res = 0;
	res = lf_configmanager_apply_config_file(cm_ctx, p);
	if (res != 0) {
		return snprintf(out_buf, buf_len, "An error ocurred");
	}
	return snprintf(out_buf, buf_len, "successfully applied config");
}

int
lf_configmanager_register_ipc(struct lf_configmanager *cm)
{
	int res = 0;

	res |= lf_ipc_register_cmd("/config", ipc_global_config,
			"Load global config, i.e., config for all modules, from file");
	if (res != 0) {
		LF_CONFIGMANAGER_LOG(ERR, "Failed to register IPC command\n");
		return -1;
	}

	/* set ipc contexts */
	cm_ctx = cm;

	return 0;
}