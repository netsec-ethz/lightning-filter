/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <rte_common.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_random.h>
#include <rte_rcu_qsbr.h>
#ifdef LF_PDUMP
#include <rte_pdump.h>
#endif

#include "config.h"
#include "configmanager.h"
#include "duplicate_filter.h"
#include "keymanager.h"
#include "lf.h"
#include "lib/ipc/ipc.h"
#include "lib/log/log.h"
#include "lib/mirror/mirror.h"
#include "lib/time/time.h"
#include "params.h"
#include "plugins/plugins.h"
#include "ratelimiter.h"
#include "setup.h"
#include "statistics.h"
#include "version.h"
#include "worker.h"

/**
 * This is the main application file.
 * It includes the setup of the EAL (DPDK) environment, the setup of the ports,
 * as well as the  initialization and management of all modules and all workers.
 */

/* lcore assignemnts */
uint16_t lf_nb_workers;
bool lf_worker_lcores[RTE_MAX_LCORE];
uint16_t lf_worker_lcore_map[RTE_MAX_LCORE];
uint16_t lf_keymanager_lcore;

/* module contextes */
static struct lf_worker_context worker_contexts[RTE_MAX_LCORE];
static struct lf_configmanager configmanager;
static struct lf_statistics statistics;
static struct lf_keymanager keymanager;
static struct lf_ratelimiter ratelimiter;
static struct lf_duplicate_filter duplicate_filter;
static struct lf_mirror mirror_ctx;

/**
 * Global force quit flag.
 */
volatile bool lf_force_quit = false;

/**
 * Signal handler to process Interupt and Termination signals.
 * @param signum Received signal number.
 */
static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		/*
		 * It is not safe to call rte_log in a signal handler!
		 * https://lore.kernel.org/all/20220711230448.557715-1-stephen@networkplumber.org/t/
		 */
		/*
		LF_LOG(NOTICE, "\n\nSignal %d received, preparing to exit...\n",
		        signum);
		*/
		lf_force_quit = true;
	}
}

int lf_logtype;
void
lf_log(uint32_t level, const char *format, ...)
{
	va_list args;
	va_start(args, format);
	(void)rte_vlog(level, lf_logtype, format, args);
	va_end(args);
}

void
lf_print(const char *format, ...)
{
	va_list args;
	va_start(args, format);
	(void)vprintf(format, args);
	va_end(args);
}

int lf_pkt_action_dynfield_offset = -1;
static int
register_dynfield()
{
	static const struct rte_mbuf_dynfield pkt_action_dynfield_desc = {
		.name = LF_PKT_ACTION_DYNFIELD_NAME,
		.size = sizeof(lf_pkt_action_t),
		.align = __alignof__(lf_pkt_action_t),
	};
	lf_pkt_action_dynfield_offset =
			rte_mbuf_dynfield_register(&pkt_action_dynfield_desc);
	if (lf_pkt_action_dynfield_offset < 0) {
		LF_LOG(ERR, "Failed to register mbuf dynfield field (%d)\n", rte_errno);
		return -1;
	}
	LF_LOG(DEBUG, "Registered mbuf dynfield field at offset %d\n",
			lf_pkt_action_dynfield_offset);
	return 0;
}

/**
 * Initialize the Worker RCU QS variable qsv.
 * @param nb_qs_vars Number of workers
 * @return 0 on success.
 */
static int
init_rcu_qs(uint16_t nb_qs_vars, struct rte_rcu_qsbr **qsv)
{
	size_t sz;
	LF_LOG(DEBUG, "Initialize RCU QS Variable (nb_qs_vars: %u)\n", nb_qs_vars);

	/* create RCU QSBR variable */
	sz = rte_rcu_qsbr_get_memsize(nb_qs_vars);
	*qsv = (struct rte_rcu_qsbr *)rte_zmalloc(NULL, sz, RTE_CACHE_LINE_SIZE);
	if (*qsv == NULL) {
		LF_LOG(ERR, "RCU QSBR alloc failed\n");
		return -1;
	}

	/* initialize QS variable for all workers */
	if (rte_rcu_qsbr_init(*qsv, nb_qs_vars) != 0) {
		LF_LOG(ERR, "RCU QSBR init failed\n");
		rte_free(*qsv);
		return -1;
	}
	return 0;
}

/**
 * Distribute the available lcores among manager threads, and workers.
 *
 * @return int 0 on success.
 */
int
assign_lcores(__rte_unused struct lf_params *params)
{
	uint16_t lcore_id, worker_counter;
	uint16_t nb_cores_required;

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		lf_worker_lcores[lcore_id] = false;
		lf_worker_lcore_map[lcore_id] = RTE_MAX_LCORE;
	}

	/* main lcore + key manager lcore + at least one worker lcore */
	nb_cores_required = 3;

	if (nb_cores_required > rte_lcore_count()) {
		LF_LOG(ERR, "Not enough lcores: detected %d but require at least %d\n",
				rte_lcore_count(), nb_cores_required);
		return -1;
	}

	/*
	 * Distribute lcores
	 */
	lf_keymanager_lcore = RTE_MAX_LCORE;

	worker_counter = 0;
	RTE_LCORE_FOREACH_WORKER(lcore_id) {

		/* first (non-main) lcore is assigned to the keymanager service */
		if (lf_keymanager_lcore == RTE_MAX_LCORE) {
			lf_keymanager_lcore = lcore_id;
			LF_LOG(DEBUG, "lcore %u: keymanager\n", lcore_id);
			continue;
		}

		/* the following lcores are assigned to workers */
		lf_worker_lcores[lcore_id] = true;
		lf_worker_lcore_map[worker_counter] = lcore_id;

		LF_LOG(DEBUG, "lcore %u: worker count %u\n", lcore_id, worker_counter);
		++worker_counter;
	}
	lf_nb_workers = worker_counter;

	if (lf_nb_workers == 0) {
		LF_LOG(ERR, "Not enough lcores: detected %d but require at least %d\n",
				rte_lcore_count(), nb_cores_required + 1);
		return -1;
	}

	return 0;
}

/**
 * Setup ports and rx/tx queues according the given application parameters.
 *
 * This function configures the queues for each worker context struct.
 * @param params Application parameters.
 * @return 0 on success
 */
static int
setup_rx_tx(struct lf_params *params)
{
	int res;
	uint16_t lcore_id, port_id;
	struct lf_worker_context *w_ctx;
	struct lf_setup_port_queue_pair port_queues[RTE_MAX_LCORE]
											   [RTE_MAX_ETHPORTS];

	res = lf_setup_ports(lf_worker_lcores, params, port_queues, &mirror_ctx);
	if (res < 0) {
		LF_LOG(ERR, "Failed to setup ports\n");
		return -1;
	}
	LF_LOG(DEBUG, "Setup ports done\n");

	RTE_LCORE_FOREACH(lcore_id) {
		w_ctx = &worker_contexts[lcore_id];
		w_ctx->max_rx_tx_index = 0;
		w_ctx->current_rx_tx_index = 0;
		RTE_ETH_FOREACH_DEV(port_id) {
			if (port_queues[lcore_id][port_id].rx_queue_id ==
					LF_SETUP_INVALID_ID) {
				continue;
			}
			w_ctx->rx_port_id[w_ctx->max_rx_tx_index] = port_id;
			w_ctx->tx_port_id[w_ctx->max_rx_tx_index] = port_id;
			w_ctx->rx_queue_id[w_ctx->max_rx_tx_index] =
					port_queues[lcore_id][port_id].rx_queue_id;
			w_ctx->tx_queue_id[w_ctx->max_rx_tx_index] =
					port_queues[lcore_id][port_id].tx_queue_id;
			w_ctx->tx_queue_id_by_port[port_id] =
					port_queues[lcore_id][port_id].tx_queue_id;

			w_ctx->tx_buffer[w_ctx->max_rx_tx_index] =
					port_queues[lcore_id][port_id].tx_buffer;
			w_ctx->tx_buffer_by_port[port_id] =
					port_queues[lcore_id][port_id].tx_buffer;

			w_ctx->max_rx_tx_index++;
		}
		LF_LOG(DEBUG, "lcore %u, nb_rx_tx %u\n", lcore_id,
				w_ctx->max_rx_tx_index);

		w_ctx->mirror_ctx = &mirror_ctx.workers[lcore_id];
	}
	return 0;
}

/**
 * Launch all remote lcores with their respective functionality.
 *
 * This function requires following variables to be initialized appropriately:
 * keymanager, keymanager_lcore, worker_contexts, worker_lcores, nb_workers.
 *
 * @return 0 on success.
 */
int
launch_lcores()
{
	/* launch keymanager */
	LF_LOG(NOTICE, "Launch Keymanager Service\n");
	(void)rte_eal_remote_launch(
			(lcore_function_t *)lf_keymanager_service_launch, &keymanager,
			lf_keymanager_lcore);

	/* launch workers */
	LF_LOG(NOTICE, "Launch workers\n");
	for (uint16_t lcore_id = 0; lcore_id < RTE_MAX_LCORE; ++lcore_id) {
		if (!lf_worker_lcores[lcore_id]) {
			continue;
		}
		(void)rte_eal_remote_launch((lcore_function_t *)lf_worker_run,
				&worker_contexts[lcore_id], lcore_id);
	}

	return 0;
}

int
main(int argc, char **argv)
{
	int res;
	uint16_t lcore_id, worker_id, worker_counter;
	struct lf_params params;
	struct lf_ratelimiter_worker *ratelimiter_workers[RTE_MAX_LCORE];

	/* Worker RCU QS Variable */
	struct rte_rcu_qsbr *qsv;

	LF_LOG(INFO, LF_VERSION_LONG "\n");

	/* set signal handler */
	lf_force_quit = false;
	(void)signal(SIGINT, signal_handler);
	(void)signal(SIGTERM, signal_handler);

	/* register lf log type */
	lf_logtype = rte_log_register("lf");
	if (lf_logtype < 0) {
		rte_exit(EXIT_FAILURE, "Cannot register log type");
	}
	/* init EAL */
	res = rte_eal_init(argc, argv);
	if (res < 0) {
		rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");
	}
	argc -= res;
	argv += res;

	/*
	 * Parse Application Parameters
	 * (parameters after the EAL ones)
	 */
	res = lf_params_parse(argc, argv, &params);
	if (res < 0) {
		rte_exit(EXIT_FAILURE, "Invalid application parameters\n");
	}

	/*
	 * Assign the available lcores to the managers and workers.
	 */
	res = assign_lcores(&params);
	if (res < 0) {
		rte_exit(EXIT_FAILURE, "Failed to distribute lcores.\n");
	}

	/*
	 * Initialize Worker Contexts
	 */
	res = lf_worker_init(lf_worker_lcores, worker_contexts);
	if (res < 0) {
		rte_exit(EXIT_FAILURE, "Failed to initialize worker contexts.\n");
	}

	/*
	 * Register MBuf dynamic fields
	 */
	res = register_dynfield();
	if (res != 0) {
		return -1;
	}

	/*
	 * Setup Ports and Queues
	 */
	res = setup_rx_tx(&params);
	if (res != 0) {
		rte_exit(EXIT_FAILURE, "Failed to setup port and queues.\n");
	}

	/*
	 * Setup Forwarding Logic
	 * Currently, we only use the forwarding port pair provided by the
	 * parameters.
	 */
	RTE_LCORE_FOREACH(lcore_id) {
		if (!lf_worker_lcores[lcore_id]) {
			continue;
		}
		memcpy(worker_contexts[lcore_id].port_pair, params.dst_port,
				sizeof(params.dst_port));
	}

	/*
	 * Initialize and launch IPC thread.
	 */
	res = lf_ipc_init(rte_eal_get_runtime_dir());
	if (res != 0) {
		rte_exit(EXIT_FAILURE, "Failed to load IPC\n");
	}
	/* Register Version IPC */
	res = lf_version_register_ipc();
	if (res != 0) {
		rte_exit(EXIT_FAILURE, "Failed to register version IPC\n");
	}

	/*
	 * Setup Worker RCU QS Mechanism
	 */
	res = init_rcu_qs(lf_nb_workers, &qsv);
	if (res != 0) {
		rte_exit(EXIT_FAILURE, "RCU QS variable initialization failed\n");
	}
	worker_counter = 0;
	RTE_LCORE_FOREACH(lcore_id) {
		if (!lf_worker_lcores[lcore_id]) {
			continue;
		}
		worker_contexts[lcore_id].qsv = qsv;
		worker_contexts[lcore_id].qsv_id = worker_counter;
		worker_counter++;
	}

	/*
	 * Setup Time Context
	 */
	RTE_LCORE_FOREACH(lcore_id) {
		if (!lf_worker_lcores[lcore_id]) {
			continue;
		}
		lf_time_worker_init(&worker_contexts[lcore_id].time);

		/* also set timestamp threshold in the worker's context */
		worker_contexts[lcore_id].timestamp_threshold =
				params.tf_threshold * LF_TIME_NS_IN_MS;
	}

	/*
	 * Setup Crypto Context
	 */
	RTE_LCORE_FOREACH(lcore_id) {
		if (!lf_worker_lcores[lcore_id]) {
			continue;
		}
		res = lf_crypto_hash_ctx_init(
				&worker_contexts[lcore_id].crypto_hash_ctx);
		if (res != 0) {
			rte_exit(EXIT_FAILURE, "Init crypto hash context failed\n");
		}
		res = lf_crypto_drkey_ctx_init(
				&worker_contexts[lcore_id].crypto_drkey_ctx);
		if (res != 0) {
			rte_exit(EXIT_FAILURE, "Init crypto DRKey context failed\n");
		}
	}

	/*
	 * Setup Key Manager
	 */
	LF_LOG(NOTICE, "Prepare Key Manager\n");
	res = lf_keymanager_init(&keymanager, lf_nb_workers, params.km_size, qsv);
	if (res < 0) {
		rte_exit(EXIT_FAILURE, "Unable to initiate keymanager\n");
	}
	worker_id = 0;
	RTE_LCORE_FOREACH(lcore_id) {
		if (!lf_worker_lcores[lcore_id]) {
			continue;
		}
		worker_contexts[lcore_id].key_manager = &keymanager.workers[worker_id];
		worker_id++;
	}
	res = lf_keymanager_register_ipc(&keymanager);
	if (res != 0) {
		rte_exit(EXIT_FAILURE, "Unable to register keymanager IPC\n");
	}
	res = lf_keymanager_register_telemetry(&keymanager);
	if (res != 0) {
		rte_exit(EXIT_FAILURE, "Unable to register keymanager telemetry\n");
	}

	/*
	 * Setup Rate Limiter
	 */
	LF_LOG(NOTICE, "Prepare Ratelimiter\n");
	worker_id = 0;
	RTE_LCORE_FOREACH(lcore_id) {
		if (!lf_worker_lcores[lcore_id]) {
			continue;
		}
		ratelimiter_workers[worker_id] = &worker_contexts[lcore_id].ratelimiter;
		worker_id++;
	}
	res = lf_ratelimiter_init(&ratelimiter, lf_worker_lcore_map, lf_nb_workers,
			params.rl_size, qsv, ratelimiter_workers);
	if (res < 0) {
		rte_exit(EXIT_FAILURE, "Unable to initiate ratelimiter\n");
	}
	res = lf_ratelimiter_register_ipc(&ratelimiter);
	if (res != 0) {
		rte_exit(EXIT_FAILURE, "Unable to register ratelimiter IPC\n");
	}

	/*
	 * Setup Duplicate Filter
	 */
	res = lf_duplicate_filter_init(&duplicate_filter, lf_worker_lcore_map,
			lf_nb_workers, params.bf_nb, params.bf_period * LF_TIME_NS_IN_MS,
			params.bf_hashes, params.bf_bytes, (unsigned int)rte_rand());
	if (res < 0) {
		rte_exit(EXIT_FAILURE, "Unable to initiate duplicate detection\n");
	}
	worker_id = 0;
	RTE_LCORE_FOREACH(lcore_id) {
		if (!lf_worker_lcores[lcore_id]) {
			continue;
		}
		worker_contexts[lcore_id].duplicate_filter =
				duplicate_filter.workers[worker_id];
		worker_id++;
	}

	/*
	 * Setup Statistics
	 */
	res = lf_statistics_init(&statistics, lf_worker_lcore_map, lf_nb_workers,
			qsv);
	if (res < 0) {
		rte_exit(EXIT_FAILURE, "Unable to initiate statistics\n");
	}
	worker_id = 0;
	RTE_LCORE_FOREACH(lcore_id) {
		if (!lf_worker_lcores[lcore_id]) {
			continue;
		}
		worker_contexts[lcore_id].statistics = statistics.worker[worker_id];
		worker_id++;
	}

	/*
	 * Setup Plugins
	 */
	lf_plugins_init(worker_contexts, lf_nb_workers);

	/*
	 * Setup Config Manager
	 */
	res = lf_configmanager_init(&configmanager, lf_nb_workers, qsv, &keymanager,
			&ratelimiter);
	if (res != 0) {
		rte_exit(EXIT_FAILURE, "Fail to init config manager.\n");
	}
	worker_id = 0;
	RTE_LCORE_FOREACH(lcore_id) {
		if (!lf_worker_lcores[lcore_id]) {
			continue;
		}
		worker_contexts[lcore_id].config = &configmanager.workers[worker_id];
		worker_id++;
	}
	res = lf_configmanager_register_ipc(&configmanager);
	if (res != 0) {
		rte_exit(EXIT_FAILURE, "Unable to register ratelimiter IPC.\n");
	}

	if (params.config_file[0] != '\0') {
		res = lf_configmanager_apply_config_file(&configmanager,
				params.config_file);
		if (res != 0) {
			rte_exit(EXIT_FAILURE, "Unable to apply config.\n");
		}
	}

#ifdef LF_PDUMP
	/* initialize packet capture framework */
	rte_pdump_init();
#endif

	/*
	 * Launch the different lcores.
	 */
	res = launch_lcores();
	if (res != 0) {
		rte_exit(EXIT_FAILURE, "Error while launching the lcores.\n");
	}

	LF_LOG(NOTICE, "Initialization completed\n");

	/*
	 * Wait for termination
	 * TODO: (fstreun) the main lcore currently waste a lot of cycles. Use the
	 * main core to run any management, such as the key manager.
	 */

	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		(void)rte_eal_wait_lcore(lcore_id);
		/* (fstreun): could check if workers terminate gracefully */
	}

	/*
	 * If this point is reached, the force-quit flag has been triggered, all
	 * lcores have returned, and the application can terminate.
	 */
	LF_LOG(INFO, "Initiating shutdown...\n");

#ifdef LF_PDUMP
	/* uninitialize packet capture framework */
	rte_pdump_uninit();
#endif

	(void)lf_setup_terminate(params.portmask, &mirror_ctx);

	lf_duplicate_filter_close(&duplicate_filter);
	lf_ratelimiter_close(&ratelimiter);
	lf_keymanager_close(&keymanager);
	lf_statistics_close(&statistics);

	/* clean up the EAL */
	(void)rte_eal_cleanup();
	LF_LOG(INFO, "Shutdown completed...\n");

	return 0;
}
