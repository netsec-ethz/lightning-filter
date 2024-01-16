/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#include <inttypes.h>
#include <malloc.h>

#include <rte_rcu_qsbr.h>

static int
new_rcu_qs(uint16_t nb_workers, struct rte_rcu_qsbr **qsv)
{
	size_t sz;

	/* create RCU QSBR variable */
	sz = rte_rcu_qsbr_get_memsize(nb_workers);
	*qsv = (struct rte_rcu_qsbr *)calloc(sz, 1);
	if (*qsv == NULL) {
		printf("RCU QSBR alloc failed\n");
		return -1;
	}

	/* initialize QS variable for all workers */
	if (rte_rcu_qsbr_init(*qsv, nb_workers) != 0) {
		printf("RCU QSBR init failed\n");
		free(*qsv);
		return -1;
	}

	for (int worker_id = 0; worker_id < nb_workers; ++worker_id) {
		if (rte_rcu_qsbr_thread_register(*qsv, worker_id) != 0) {
			printf("Register for QS Variable failed\n");
			return 1;
		}
		(void)rte_rcu_qsbr_thread_online(*qsv, worker_id);
	}

	return 0;
}


static void
free_rcu_qs(uint16_t nb_workers, struct rte_rcu_qsbr *qsv)
{
	for (int worker_id = 0; worker_id < nb_workers; ++worker_id) {
		(void)rte_rcu_qsbr_thread_offline(qsv, worker_id);
		(void)rte_rcu_qsbr_thread_unregister(qsv, worker_id);
	}

	free(qsv);
}

int
lf_ratelimiter_tb()
{
	int res;
	int nb_workers = 2;
	struct rte_rcu_qsbr *qsv;
	uint64_t t;

	res = new_rcu_qs(nb_workers, &qsv);

	t = rte_rcu_qsbr_start(qsv);

	res = rte_rcu_qsbr_check(qsv, t, false);
	if (res != 0) {
		printf("Error: qsbr check succeeds even though no worker has passed "
			   "through.\n");
		return -1;
	}

	for (int worker_id = 0; worker_id < nb_workers; ++worker_id) {
		(void)rte_rcu_qsbr_quiescent(qsv, worker_id);
	}

	res = rte_rcu_qsbr_check(qsv, t, false);
	if (res != 1) {
		printf("Error: qsbr check fails even though all worker have passed "
			   "through.\n");
		return -1;
	}

	free_rcu_qs(nb_workers, qsv);

	return 0;
}


int
test_multiple_writers()
{
	int res;
	int nb_workers = 2;
	struct rte_rcu_qsbr *qsv;
	uint64_t t1, t2;

	res = new_rcu_qs(nb_workers, &qsv);

	t1 = rte_rcu_qsbr_start(qsv);
	t2 = rte_rcu_qsbr_start(qsv);

	res = rte_rcu_qsbr_check(qsv, t1, false);
	if (res != 0) {
		printf("Error: t1 qsbr check succeeds even though no worker has passed "
			   "through.\n");
		return -1;
	}

	res = rte_rcu_qsbr_check(qsv, t2, false);
	if (res != 0) {
		printf("Error: t2 qsbr check succeeds even though no worker has passed "
			   "through.\n");
		return -1;
	}

	for (int worker_id = 0; worker_id < nb_workers; ++worker_id) {
		(void)rte_rcu_qsbr_quiescent(qsv, worker_id);
	}

	res = rte_rcu_qsbr_check(qsv, t1, false);
	if (res != 1) {
		printf("Error: t1 qsbr check fails even though all worker have passed "
			   "through.\n");
		return -1;
	}

	res = rte_rcu_qsbr_check(qsv, t2, false);
	if (res != 1) {
		printf("Error: t2 qsbr check fails even though all worker have passed "
			   "through.\n");
		return -1;
	}

	t1 = rte_rcu_qsbr_start(qsv);
	(void)rte_rcu_qsbr_quiescent(qsv, 0);
	t2 = rte_rcu_qsbr_start(qsv);
	(void)rte_rcu_qsbr_quiescent(qsv, 1);

	res = rte_rcu_qsbr_check(qsv, t1, false);
	if (res != 1) {
		printf("Error: t1 qsbr check fails even though all worker have passed "
			   "through.\n");
		return -1;
	}

	res = rte_rcu_qsbr_check(qsv, t2, false);
	if (res != 0) {
		printf("Error: t2 qsbr check succeeds even though no worker has passed "
			   "through.\n");
		return -1;
	}

	(void)rte_rcu_qsbr_quiescent(qsv, 0);

	res = rte_rcu_qsbr_check(qsv, t2, false);
	if (res != 1) {
		printf("Error: t2 qsbr check fails even though all worker have passed "
			   "through.\n");
		return -1;
	}

	free_rcu_qs(nb_workers, qsv);

	return 0;
}

int
main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	int res;

	res = lf_ratelimiter_tb();

	res += test_multiple_writers();

	if (res == 0) {
		printf("All test passed\n");
	}

	return res;
}