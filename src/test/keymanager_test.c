/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#include <stdio.h>

#include <rte_malloc.h>
#include <rte_rcu_qsbr.h>

#include "../config.h"
#include "../keymanager.h"
#include "../lf.h"
#include "../lib/log/log.h"
#include "../lib/time/time.h"

#define TEST1_JSON "keymanager_test1.json"
#define TEST2_JSON "keymanager_test2.json"

#define LF_TEST_NO_RCU 1

volatile bool lf_force_quit = false;


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

void
free_test_context(struct lf_keymanager *km)
{
	lf_keymanager_close(km);
	free(km);
}

struct lf_keymanager *
new_test_context()
{
	int res;
	struct lf_keymanager *keymanager;
	int nb_workers = 2;
	struct rte_rcu_qsbr *qsv;

	qsv = new_rcu_qs(nb_workers);
	if (qsv == NULL) {
		return NULL;
	}

	keymanager = malloc(sizeof(struct lf_keymanager));
	if (keymanager == NULL) {
		printf("Error: malloc for keymanager\n");
		free_rcu_qs(qsv);
		return NULL;
	}

	res = lf_keymanager_init(keymanager, nb_workers, 10, qsv);
	if (res < 0) {
		printf("Error: lf_keymanager_init\n");
		free(keymanager);
		free_rcu_qs(qsv);
		return NULL;
	}

	return keymanager;
}

int
test1()
{
	int res = 0, error_count = 0;
	struct lf_keymanager *km;
	struct lf_keymanager_worker *kmw;
	uint64_t ns_now;
	struct lf_crypto_drkey drkey;
	struct lf_host_addr src_host_addr;
	struct lf_host_addr dst_host_addr;

	uint32_t src_addr = 0;
	uint32_t dst_addr = 0;

	src_host_addr.addr = &src_addr;
	src_host_addr.type_length = 0x0;
	dst_host_addr.addr = &dst_addr;
	dst_host_addr.type_length = 0x0;

	km = new_test_context();
	if (km == NULL) {
		return 1;
	}

	kmw = &km->workers[0];

	struct lf_config *config = lf_config_new_from_file(TEST1_JSON);
	if (config == NULL) {
		printf("Error: lf_config_new_from_file\n");
		return 1;
	}

	res = lf_keymanager_apply_config(km, config);
	if (res != 0) {
		printf("Error: lf_keymanager_apply_config\n");
		return 1;
	}

	res = lf_time_get(&ns_now);
	if (res != 0) {
		printf("Error: Failed to get time (res = %d)\n", res);
		error_count += 1;
		return error_count;
	}

	res = lf_keymanager_worker_inbound_get_drkey(kmw, config->peers->isd_as,
			&src_host_addr, &dst_host_addr, config->peers->drkey_protocol,
			ns_now, 0, &drkey);
	if (res != 0) {
		printf("Error: lf_keymanager_worker_inbound_get_drkey ns_now = %ld "
			   "(expected = 0, res = %d)\n",
				ns_now, res);
		error_count += 1;
	}

	res = lf_keymanager_worker_outbound_get_drkey(kmw, config->peers->isd_as,
			&dst_host_addr, &src_host_addr, config->peers->drkey_protocol,
			ns_now, &drkey);
	if (res != 0) {
		printf("Error: lf_keymanager_worker_outbound_get_drkey (expected = 0, "
			   "res = %d)\n",
				res);
		error_count += 1;
	}

	ns_now = ns_now + 20 * LF_TIME_NS_IN_S; /* 20 seconds (the validity period
	                            of the mock keys is 10 seconds) */
	res = lf_keymanager_worker_inbound_get_drkey(kmw, config->peers->isd_as,
			&src_host_addr, &dst_host_addr, config->peers->drkey_protocol,
			ns_now, 0, &drkey);
	if (res != -2) {
		printf("Error: ns_now = ns_now + 20*1e9; "
			   "lf_keymanager_worker_inbound_get_drkey (expected = -2, res = "
			   "%d)\n",
				res);
		error_count += 1;
	}

	res = lf_keymanager_worker_outbound_get_drkey(kmw, config->peers->isd_as,
			&dst_host_addr, &src_host_addr, config->peers->drkey_protocol,
			ns_now, &drkey);
	if (res != -2) {
		printf("Error: ns_now = ns_now + 20*1e9; "
			   "lf_keymanager_worker_outbound_get_drkey (expected = -2, res = "
			   "%d)\n",
				res);
		error_count += 1;
	}

	free_test_context(km);

	return error_count;
}

/**
 * Test that the same key K_{A:HA->B:HB} is derived by a keymanager in AS A and
 * a keymanager in AS B.
 *
 * @return int
 */
int
test2()
{
	int res = 0, error_count = 0;
	struct lf_keymanager *km1, *km2;
	struct lf_keymanager_worker *kmw1, *kmw2;
	uint64_t ns_now;
	struct lf_crypto_drkey drkey1, drkey2;
	struct lf_host_addr src_host_addr;
	struct lf_host_addr dst_host_addr;
	struct lf_config *config1, *config2;

	uint32_t src_addr = 0;
	uint32_t dst_addr = 0;

	src_host_addr.addr = &src_addr;
	src_host_addr.type_length = 0x0;
	dst_host_addr.addr = &dst_addr;
	dst_host_addr.type_length = 0x0;

	km1 = new_test_context();
	if (km1 == NULL) {
		return 1;
	}

	kmw1 = &km1->workers[0];
	config1 = lf_config_new_from_file(TEST1_JSON);
	if (config1 == NULL) {
		printf("Error: lf_config_new_from_file\n");
		return 1;
	}
	res = lf_keymanager_apply_config(km1, config1);
	if (res != 0) {
		printf("Error: lf_keymanager_apply_config\n");
		return 1;
	}

	res = lf_time_get(&ns_now);
	if (res != 0) {
		printf("Error: Failed to get time (res = %d)\n", res);
		error_count += 1;
		return error_count;
	}

	res = lf_keymanager_worker_outbound_get_drkey(kmw1, config1->peers->isd_as,
			&dst_host_addr, &src_host_addr, config1->peers->drkey_protocol,
			ns_now, &drkey1);
	if (res != 0) {
		printf("Error: lf_keymanager_worker_outbound_get_drkey\n");
		error_count += 1;
	}

	km2 = new_test_context();
	if (km2 == NULL) {
		return 1;
	}
	kmw2 = &km2->workers[0];
	config2 = lf_config_new_from_file(TEST2_JSON);
	if (config2 == NULL) {
		printf("Error: lf_config_new_from_file\n");
		return 1;
	}
	res = lf_keymanager_apply_config(km2, config2);
	if (res != 0) {
		printf("Error: lf_keymanager_apply_config\n");
		return 1;
	}

	res = lf_keymanager_worker_inbound_get_drkey(kmw2, config2->peers->isd_as,
			&src_host_addr, &dst_host_addr, config2->peers->drkey_protocol,
			ns_now, 0, &drkey2);
	if (res != 0) {
		printf("Error: lf_keymanager_worker_inbound_get_drkey\n");
		error_count += 1;
	}


	/* compare DRKeys */

	if (memcmp(&drkey1, &drkey2, sizeof(drkey1)) != 0) {
		printf("Error: DRKey are not the same\n");
		error_count += 1;
	}

	free_test_context(km1);
	free_test_context(km2);

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
	error_counter += test2();

	if (error_counter > 0) {
		printf("Error Count: %d\n", error_counter);
		return 1;
	}

	printf("All tests passed!\n");
	return 0;
}