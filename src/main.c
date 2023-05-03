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
#include "lib/time/time.h"
#include "params.h"
#include "plugins/plugins.h"
#include "ratelimiter.h"
#include "setup.h"
#include "statistics.h"
#include "version.h"
#include "worker.h"
#include "worker_ct.h"

/**
 * This is the main application file.
 * It includes the setup of the EAL (DPDK) environment, the setup of the ports,
 * as well as the  initialization and management of all modules and all workers.
 */

#if LF_DISTRIBUTOR
#include "distributor.h"
#endif

uint16_t nb_workers;
static struct lf_worker_context worker_contexts[LF_MAX_WORKER];
uint16_t worker_lcores[RTE_MAX_LCORE];

static struct lf_configmanager configmanager;
static struct lf_statistics statistics;

static struct lf_keymanager keymanager;
uint16_t keymanager_lcore;

static struct lf_ratelimiter ratelimiter;
static struct lf_ratelimiter_worker *ratelimiter_workers[LF_MAX_WORKER];

static struct lf_duplicate_filter duplicate_filter;

/* Context of control traffic (ct) worker */
static struct lf_worker_ct worker_ct;

#if LF_DISTRIBUTOR
static struct lf_distributor_context distributor_contexts[LF_MAX_DISTRIBUTOR];
static struct lf_distributor_worker *distributor_workers[LF_MAX_WORKER];
static uint16_t distributor_lcores[LF_MAX_DISTRIBUTOR];
static uint16_t nb_distributors;
#endif


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
		(void)rte_free(*qsv);
		return -1;
	}
	return 0;
}

/**
 * Distribute the available lcores among manager threads, workers and
 * distributors if enables.
 *
 * This function sets the variables nb_workers,
 * worker_lcores, keymanager_lcore. If distributors are enabled, also
 * nb_distributor and distributor_lcores are also set.
 *
 * @return int 0 on success.
 */
int
assign_lcores(__rte_unused struct lf_params *params)
{
	uint16_t lcore_id, worker_id;
	uint16_t nb_cores_required;

	/* main lcore + key manager lcore + at least one worker lcore */
	nb_cores_required = 3;

#if LF_DISTRIBUTOR
	uint16_t distributor_id;
	/* add distributor lcores */
	nb_distributors = params->dist_cores;
	nb_cores_required += nb_distributors;
#endif

	if (nb_cores_required > rte_lcore_count()) {
		LF_LOG(ERR, "Not enough lcores: detected %d but require at least %d\n",
				rte_lcore_count(), nb_cores_required);
		return -1;
	}

	/*
	 * Distribute lcores
	 */
	keymanager_lcore = RTE_MAX_LCORE;

	worker_id = 0;
#if LF_DISTRIBUTOR
	distributor_id = 0;
#endif
	RTE_LCORE_FOREACH_WORKER(lcore_id) {

		/* first (non-main) lcore is assigned to the keymanager service */
		if (keymanager_lcore == RTE_MAX_LCORE) {
			keymanager_lcore = lcore_id;
			LF_LOG(DEBUG, "lcore %u: keymanager\n", lcore_id);
			continue;
		}

		/* the following lcores are assigned to the distributor */
#if LF_DISTRIBUTOR
		if (distributor_id < nb_distributors) {
			distributor_lcores[distributor_id] = lcore_id;
			LF_LOG(DEBUG, "lcore %u: distributor %u\n", lcore_id,
					distributor_id);
			++distributor_id;
			continue;
		}
#endif

		/* the following lcores are assigned to workers */
		worker_lcores[worker_id] = lcore_id;

		LF_LOG(DEBUG, "lcore %u: worker %u\n", lcore_id, worker_id);
		++worker_id;
	}
	nb_workers = worker_id;

	if (nb_workers == 0) {
		LF_LOG(ERR, "Not enough lcores: detected %d but require at least %d\n",
				rte_lcore_count(), nb_cores_required + 1);
		return -1;
	}

	return 0;
}

/**
 * Setup ports and rx/tx queues according the given application parameters
 * (params).
 *
 * This function requires following to be initialized appropriately:
 * worker_lcores, nb_workers
 * (If distributor is enabled: distributor_lcores, nb_distributor)
 *
 * This function configures the queues for each worker context struct.
 * If the control traffic worker is enabled, the queues for the control traffic.
 * If distributor is enabled, the queues for each distributor context.
 *
 * @param params Application parameters.
 * @return 0 on success
 */
static int
setup_port_and_queues(struct lf_params *params)
{
	int res;
	uint16_t worker_id;
	struct lf_distributor_port_queue *port_queues[LF_MAX_WORKER];
	struct lf_setup_ct_port_queue *ct_port_queue;

	/* Set the control traffic queues if the ct worker is enabled */
	if (params->ct_worker_enabled) {
		ct_port_queue = &worker_ct.signal_port_queue;
	} else {
		ct_port_queue = NULL;
	}

#if LF_DISTRIBUTOR
	for (uint16_t distributor_id = 0; distributor_id < nb_distributors;
			++distributor_id) {
		port_queues[distributor_id] =
				&distributor_contexts[distributor_id].queue;
	}
	res = lf_setup_ports(nb_distributors, distributor_lcores, params,
			port_queues, ct_port_queue);

	if (res < 0) {
		LF_LOG(ERR, "Application setup failed\n");
		return -1;
	}

	for (worker_id = 0; worker_id < nb_workers; ++worker_id) {
		distributor_workers[worker_id] = &worker_contexts[worker_id].distributor;
	}
	res = lf_distributor_init(distributor_lcores, nb_distributors,
			worker_lcores, nb_workers, distributor_contexts,
			distributor_workers);
	if (res < 0) {
		LF_LOG(ERR, "Distributor setup failed\n");
		return -1;
	}
#else
	for (worker_id = 0; worker_id < nb_workers; ++worker_id) {
		port_queues[worker_id] = &worker_contexts[worker_id].distributor.queue;
	}
	res = lf_setup_ports(nb_workers, worker_lcores, params, port_queues,
			ct_port_queue);
	if (res < 0) {
		LF_LOG(ERR, "Application setup failed\n");
		return -1;
	}
#endif /* LF_DISTRIBUTOR */

	/* TODO: Set forwarding direction in worker context */
	//for (worker_id = 0; worker_id < nb_workers; ++worker_id) {
	//	worker_contexts[worker_id].forwarding_direction =
	//			worker_contexts[worker_id].distributor.forwarding_direction;
	//}

	return 0;
}

/**
 * Launch all remote lcores with their respective functionality.
 *
 * This function requires following variables to be initialized appropriately:
 * keymanager, keymanager_lcore, worker_contexts, worker_lcores, nb_workers.
 * If distributors are enabled, also nb_distributor and distributor_lcores are
 * required.
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
			keymanager_lcore);

	/* launch workers */
	LF_LOG(NOTICE, "Launch workers\n");
	for (uint16_t worker_id = 0; worker_id < nb_workers; ++worker_id) {
		(void)rte_eal_remote_launch((lcore_function_t *)lf_worker_run,
				&worker_contexts[worker_id], worker_lcores[worker_id]);
	}

#if LF_DISTRIBUTOR
	/* launch distributors */
	LF_LOG(NOTICE, "Launch distributors\n");
	for (uint16_t distributor_id = 0; distributor_id < nb_distributors;
			++distributor_id) {
		(void)rte_eal_remote_launch((lcore_function_t *)lf_distributor_run,
				&distributor_contexts[distributor_id],
				distributor_lcores[distributor_id]);
	}
#endif
	return 0;
}

int
main(int argc, char **argv)
{
	int res;
	uint16_t lcore_id, worker_id;
	struct lf_params params;
	struct lf_config *global_config, *config;

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
	 * Load Global Config
	 */
	if (params.config_file[0] != '\0') {
		global_config = lf_config_new_from_file(params.config_file);
		if (global_config == NULL) {
			rte_exit(EXIT_FAILURE, "Failed to load config file %s\n",
					params.config_file);
		}
	} else {
		global_config = NULL;
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
	res = lf_worker_init(nb_workers, worker_lcores, worker_contexts);
	if (res < 0) {
		rte_exit(EXIT_FAILURE, "Failed to initialize worker contexts.\n");
	}

	/*
	 * Setup Ports and Queues
	 */
	res = setup_port_and_queues(&params);
	if (res != 0) {
		rte_exit(EXIT_FAILURE, "Failed to setup port and queues.\n");
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
	res = init_rcu_qs(nb_workers, &qsv);
	if (res != 0) {
		rte_exit(EXIT_FAILURE, "RCU QS variable initialization failed\n");
	}
	for (worker_id = 0; worker_id < nb_workers; ++worker_id) {
		worker_contexts[worker_id].qsv = qsv;
	}

	/*
	 * Setup Time Context
	 */
	for (worker_id = 0; worker_id < nb_workers; ++worker_id) {
		lf_time_worker_init(&worker_contexts[worker_id].time);

		/* also set timestamp threshold in the worker's context */
		worker_contexts[worker_id].timestamp_threshold =
				params.tf_threshold * LF_TIME_NS_IN_MS;
	}

	/*
	 * Setup Crypto Context
	 */
	for (worker_id = 0; worker_id < nb_workers; ++worker_id) {
		res = lf_crypto_hash_ctx_init(
				&worker_contexts[worker_id].crypto_hash_ctx);
		if (res != 0) {
			rte_exit(EXIT_FAILURE, "Init crypto hash context failed\n");
		}
		res = lf_crypto_drkey_ctx_init(
				&worker_contexts[worker_id].crypto_drkey_ctx);
		if (res != 0) {
			rte_exit(EXIT_FAILURE, "Init crypto DRKey context failed\n");
		}
	}

	/*
	 * Setup Key Manager
	 */
	LF_LOG(NOTICE, "Prepare Key Manager\n");
	res = lf_keymanager_init(&keymanager, nb_workers, params.km_size, qsv);
	if (res < 0) {
		rte_exit(EXIT_FAILURE, "Unable to initiate keymanager\n");
	}
	for (worker_id = 0; worker_id < nb_workers; ++worker_id) {
		worker_contexts[worker_id].key_manager = &keymanager.workers[worker_id];
	}
	res = lf_keymanager_register_ipc(&keymanager);
	if (res != 0) {
		rte_exit(EXIT_FAILURE, "Unable to register keymanager IPC\n");
	}
	res = lf_keymanager_register_telemetry(&keymanager);
	if (res != 0) {
		rte_exit(EXIT_FAILURE, "Unable to register keymanager telemetry\n");
	}

	/* apply config if provided */
	res = 0;
	if (params.km_config_file[0] != '\0') {
		/* load keymanager specific config */
		config = lf_config_new_from_file(params.km_config_file);
		if (config == NULL) {
			rte_exit(EXIT_FAILURE, "Failed to load keymanager config file %s\n",
					params.km_config_file);
		}
		res = lf_keymanager_apply_config(&keymanager, config);
		lf_config_free(config);
	} else if (global_config != NULL) {
		/* use global config */
		res = lf_keymanager_apply_config(&keymanager, global_config);
	}
	if (res != 0) {
		rte_exit(EXIT_FAILURE, "Failed to load ratelimiter config file %s\n",
				params.rl_config_file);
	}

	/*
	 * Setup Rate Limiter
	 */
	LF_LOG(NOTICE, "Prepare Ratelimiter\n");
	for (worker_id = 0; worker_id < nb_workers; ++worker_id) {
		ratelimiter_workers[worker_id] =
				&worker_contexts[worker_id].ratelimiter;
	}
	res = lf_ratelimiter_init(&ratelimiter, worker_lcores, nb_workers,
			params.rl_size, qsv, ratelimiter_workers);
	if (res < 0) {
		rte_exit(EXIT_FAILURE, "Unable to initiate ratelimiter\n");
	}
	res = lf_ratelimiter_register_ipc(&ratelimiter);
	if (res != 0) {
		rte_exit(EXIT_FAILURE, "Unable to register ratelimiter IPC\n");
	}

	/* apply config if provided */
	res = 0;
	if (params.rl_config_file[0] != '\0') {
		/* load keymanager specific config */
		config = lf_config_new_from_file(params.rl_config_file);
		if (config == NULL) {
			rte_exit(EXIT_FAILURE,
					"Failed to load ratelimiter config file %s\n",
					params.rl_config_file);
		}
		res = lf_ratelimiter_apply_config(&ratelimiter, config);
		lf_config_free(config);
	} else if (global_config != NULL) {
		/* use global config */
		res = lf_ratelimiter_apply_config(&ratelimiter, global_config);
	}
	if (res != 0) {
		rte_exit(EXIT_FAILURE, "Failed to load ratelimiter config file %s\n",
				params.rl_config_file);
	}

	/*
	 * Setup Duplicate Filter
	 */
	res = lf_duplicate_filter_init(&duplicate_filter, worker_lcores, nb_workers,
			params.bf_nb, params.bf_period * LF_TIME_NS_IN_MS, params.bf_hashes,
			params.bf_bytes, (unsigned int)rte_rand());
	if (res < 0) {
		rte_exit(EXIT_FAILURE, "Unable to initiate duplicate detection\n");
	}
	for (worker_id = 0; worker_id < nb_workers; ++worker_id) {
		worker_contexts[worker_id].duplicate_filter =
				duplicate_filter.workers[worker_id];
	}

	/*
	 * Setup Statistics
	 */
	res = lf_statistics_init(&statistics, worker_lcores, nb_workers, qsv);
	if (res < 0) {
		rte_exit(EXIT_FAILURE, "Unable to initiate statistics\n");
	}
	for (worker_id = 0; worker_id < nb_workers; ++worker_id) {
		worker_contexts[worker_id].statistics = statistics.worker[worker_id];
	}

	/*
	 * Setup Plugins
	 */
	lf_plugins_init(worker_contexts, nb_workers);

	if (global_config != NULL) {
		res = lf_plugins_apply_config(global_config);
		if (res != 0) {
			rte_exit(EXIT_FAILURE, "Failed to load config file %s\n",
					params.config_file);
		}
	}

	/*
	 * Setup Config Manager
	 */
	res = lf_configmanager_init(&configmanager, nb_workers, qsv);
	if (res != 0) {
		rte_exit(EXIT_FAILURE, "Fail to init config manager.\n");
	}
	for (worker_id = 0; worker_id < nb_workers; ++worker_id) {
		worker_contexts[worker_id].config = &configmanager.workers[worker_id];
	}
	res = lf_configmanager_register_ipc(&configmanager, &keymanager,
			&ratelimiter);
	if (res != 0) {
		rte_exit(EXIT_FAILURE, "Unable to register ratelimiter IPC.\n");
	}

	if (params.config_file[0] != '\0') {
		lf_configmanager_load_config(&configmanager, params.config_file);
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

	/* Run control traffic worker */
	if (params.ct_worker_enabled) {
		lf_worker_ct_run(&worker_ct);
	}

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

	(void)lf_setup_terminate(params.portmask);

	lf_duplicate_filter_close(&duplicate_filter);
	lf_ratelimiter_close(&ratelimiter);
	lf_keymanager_close(&keymanager);
	lf_statistics_close(&statistics);

	/* clean up the EAL */
	(void)rte_eal_cleanup();
	LF_LOG(INFO, "Shutdown completed...\n");

	return 0;
}