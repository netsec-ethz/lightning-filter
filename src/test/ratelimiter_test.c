/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#include <pthread.h>
#include <stdio.h>

#include <rte_malloc.h>
#include <rte_rcu_qsbr.h>

#include "../config.h"
#include "../lf.h"
#include "../lib/log/log.h"
#include "../lib/time/time.h"
#include "../ratelimiter.h"

#define TEST1_JSON "ratelimiter_test1.json"

volatile bool lf_force_quit = false;

static struct lf_ratelimiter_worker ratelimiter_workers[LF_MAX_WORKER];
uint16_t worker_lcores[LF_MAX_WORKER];

/**
 * Initialize the Worker RCU QS variable qsv and add it to each worker's
 * context.
 * @param nb_workers Number of workers
 * @return 0 on success.
 */
struct rte_rcu_qsbr *
new_rcu_qs(uint16_t nb_workers)
{
	struct rte_rcu_qsbr *qsv;
	size_t sz;
	LF_LOG(DEBUG, "Initialize the workers' RCU QS Variable (nb_workers: %u)\n",
			nb_workers);

	/* create RCU QSBR variable */
	sz = rte_rcu_qsbr_get_memsize(nb_workers);
	/* TODO: (streun) alloc different QS variable for each socket */
	qsv = (struct rte_rcu_qsbr *)rte_zmalloc(NULL, sz, RTE_CACHE_LINE_SIZE);
	if (qsv == NULL) {
		LF_LOG(ERR, "RCU QSBR alloc failed\n");
		return NULL;
	}

	/* initialize QS variable for all workers */
	if (rte_rcu_qsbr_init(qsv, nb_workers) != 0) {
		LF_LOG(ERR, "RCU QSBR init failed\n");
		rte_free(qsv);
		return NULL;
	}
	return qsv;
}

void
free_rcu_qs(struct rte_rcu_qsbr *qsv)
{
	rte_free(qsv);
}

struct lf_ratelimiter *
new_ratelimiter()
{
	int res;
	struct lf_ratelimiter *ratelimiter;
	int nb_workers = 2;
	int worker_id;
	struct rte_rcu_qsbr *qsv;
	struct lf_ratelimiter_worker *ratelimiter_workers_ptr[LF_MAX_WORKER];

	/* create worker context pointer array */
	for (worker_id = 0; worker_id < nb_workers; ++worker_id) {
		worker_lcores[worker_id] = worker_id;
		ratelimiter_workers_ptr[worker_id] = &ratelimiter_workers[worker_id];
	}

	qsv = new_rcu_qs(nb_workers);
	if (qsv == NULL) {
		return NULL;
	}

	ratelimiter = malloc(sizeof(struct lf_ratelimiter));
	if (ratelimiter == NULL) {
		printf("Error: malloc for ratelimiter\n");
		free_rcu_qs(qsv);
		return NULL;
	}

	res = lf_ratelimiter_init(ratelimiter, worker_lcores, nb_workers, 10, qsv,
			ratelimiter_workers_ptr);
	if (res < 0) {
		printf("Error: lf_ratelimiter_init\n");
		free(ratelimiter);
		free_rcu_qs(qsv);
		return NULL;
	}

	return ratelimiter;
}

int
test1()
{
	int res = 0, error_count = 0;
	struct lf_ratelimiter *rl;
	struct lf_ratelimiter_worker *rlw;
	struct lf_ratelimiter_pkt_ctx rl_pkt_ctx;
	uint64_t ns_now;

	struct lf_config_peer *peers[4];

	rl = new_ratelimiter();
	if (rl == NULL) {
		return 1;
	}
	printf("Initialized Ratelimiter\n");
	rlw = rl->workers[0];

	struct lf_config *config = lf_config_new_from_file(TEST1_JSON);
	if (config == NULL) {
		printf("Error: lf_config_new_from_file\n");
		return 1;
	}

	peers[0] = config->peers;
	peers[1] = peers[0]->next;
	peers[2] = peers[1]->next;
	peers[3] = peers[2]->next;

	res = lf_ratelimiter_apply_config(rl, config);
	if (res != 0) {
		printf("Error: lf_ratelimiter_apply_config\n");
		return 1;
	}

	res = lf_time_get(&ns_now);
	assert(res == 0);

	/* unknown key (AS and protocol) */
	res = lf_ratelimiter_worker_get_pkt_ctx(rlw, 1, 1, &rl_pkt_ctx);
	if (res != 0) {
		printf("Error: lf_ratelimiter_worker_get_pkt_ctx expected 0, got %d\n",
				res);
		error_count += 1;
	}
	if (rl_pkt_ctx.peer_ratelimit != &rlw->auth_peers) {
		printf("Error: lf_ratelimiter_worker_get_pkt_ctx expected auth peers "
			   "rate limit\n");
		error_count += 1;
	}

	/* AS packet rate limited */
	res = lf_ratelimiter_worker_apply(rlw, peers[1]->isd_as,
			peers[1]->drkey_protocol, 1, ns_now);
	if ((res & LF_RATELIMITER_RES_PKTS) == 0) {
		printf("Error: lf_ratelimiter_worker_apply expected "
			   "LF_RATELIMITER_RES_PKTS, got %d\n",
				res);
		error_count += 1;
	}

	/* AS byte rate limited */
	res = lf_ratelimiter_worker_apply(rlw, peers[2]->isd_as,
			peers[2]->drkey_protocol, 1, ns_now);
	if ((res & LF_RATELIMITER_RES_BYTES) == 0) {
		printf("Error: lf_ratelimiter_worker_apply expected "
			   "LF_RATELIMITER_RES_BYTES, got %d\n",
				res);
		error_count += 1;
	}

	/* AS rate limited */
	res = lf_ratelimiter_worker_apply(rlw, peers[3]->isd_as,
			peers[3]->drkey_protocol, 1, ns_now);
	if ((res & (LF_RATELIMITER_RES_BYTES | LF_RATELIMITER_RES_PKTS)) == 0) {
		printf("Error: lf_ratelimiter_worker_apply expected "
			   "LF_RATELIMITER_RES_BYTES | LF_RATELIMITER_RES_PKTS, got %d\n",
				res);
		error_count += 1;
	}

	/* overall rate limited */
	res = lf_ratelimiter_worker_apply(rlw, peers[0]->isd_as,
			peers[0]->drkey_protocol, 10000, ns_now);
	if ((res & (LF_RATELIMITER_RES_OVERALL_BYTES |
					   LF_RATELIMITER_RES_OVERALL_PKTS)) == 0) {
		printf("Error: lf_ratelimiter_worker_apply expected "
			   "LF_RATELIMITER_RES_OVERALL_BYTES | "
			   "LF_RATELIMITER_RES_OVERALL_PKTS, got %d\n",
				res);
		error_count += 1;
	}

	/* Not rate limited (AS and System) */
	res = lf_ratelimiter_worker_apply(rlw, peers[0]->isd_as,
			peers[0]->drkey_protocol, 10, ns_now);
	if (res != 0) {
		printf("Error: lf_ratelimiter_worker_apply expected 0, got %d\n", res);
		error_count += 1;
	}


	/* best-effort rate limited */
	res = lf_ratelimiter_worker_apply_best_effort(rlw, 100, ns_now);
	if (res == 0) {
		printf("Error: lf_ratelimiter_worker_apply_best_effort expected != 0, "
			   "got %d\n",
				res);
		error_count += 1;
	}

	/* best-effort not rate limited */
	res = lf_ratelimiter_worker_apply_best_effort(rlw, 1, ns_now);
	if (res != 0) {
		printf("Error: lf_ratelimiter_worker_apply_best_effort expected 0, got "
			   "%d\n",
				res);
		error_count += 1;
	}

	/*
	 * Update config:
	 * set rate limit for peer 0 (no rate limits) to 0.
	 */
	config->peers[0].ratelimit.byte_rate = 0;
	config->peers[0].ratelimit.byte_rate = 0;
	config->peers[0].ratelimit.packet_burst = 0;
	config->peers[0].ratelimit.packet_burst = 0;

	res = lf_ratelimiter_apply_config(rl, config);
	if (res != 0) {
		printf("Error: lf_ratelimiter_apply_config\n");
		return 1;
	}

	/* Change to rate limited */
	res = lf_ratelimiter_worker_apply(rlw, peers[0]->isd_as,
			peers[0]->drkey_protocol, 1, ns_now);
	if (res == 0) {
		printf("Error: lf_ratelimiter_worker_apply expected != 0, got %d\n",
				res);
		error_count += 1;
	}

	lf_ratelimiter_close(rl);

	return error_count;
}

int
main(int argc, char *argv[])
{
	int res = rte_eal_init(argc, argv);
	if (res < 0) {
		return -1;
	}
	int error_counter = 0;

	error_counter += test1();

	if (error_counter > 0) {
		printf("Error Count: %d\n", error_counter);
		return 1;
	}

	printf("All tests passed!\n");
	return 0;
}