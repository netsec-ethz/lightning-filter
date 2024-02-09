/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#include <stdio.h>

#include <rte_malloc.h>
#include <rte_rcu_qsbr.h>

#include "../config.h"
#include "../drkey.h"
#include "../keyfetcher.h"
#include "../keymanager.h"
#include "../lf.h"
#include "../lib/log/log.h"
#include "../lib/time/time.h"

#define TEST1_JSON "keymanager_test1.json"
#define TEST2_JSON "keymanager_test2.json"
#define TEST3_JSON "keymanager_test3.json"

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

void
print_keys(uint8_t expected[LF_CRYPTO_DRKEY_SIZE],
		uint8_t actual[LF_CRYPTO_DRKEY_SIZE])
{
	printf("Expected: \t");
	for (int i = 0; i < LF_CRYPTO_DRKEY_SIZE; i++)
		printf("%02hhx", expected[i]);
	printf("\nGot: \t\t");
	for (int i = 0; i < LF_CRYPTO_DRKEY_SIZE; i++) printf("%02hhx", actual[i]);
	printf("\n");
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

	uint64_t ns_drkey_epoch_start;
	res = lf_keymanager_worker_inbound_get_drkey(kmw, config->peers->isd_as,
			&src_host_addr, &dst_host_addr, config->peers->drkey_protocol,
			ns_now, 0, &ns_drkey_epoch_start, &drkey);
	if (res != 0) {
		printf("Error: lf_keymanager_worker_inbound_get_drkey ns_now = %ld "
			   "(expected = 0, res = %d)\n",
				ns_now, res);
		error_count += 1;
	}

	res = lf_keymanager_worker_outbound_get_drkey(kmw, config->peers->isd_as,
			&dst_host_addr, &src_host_addr, config->peers->drkey_protocol,
			ns_now, &ns_drkey_epoch_start, &drkey);
	if (res != 0) {
		printf("Error: lf_keymanager_worker_outbound_get_drkey (expected = 0, "
			   "res = %d)\n",
				res);
		error_count += 1;
	}

	ns_now =
			ns_now +
			3 * 24 * 3600 * LF_TIME_NS_IN_S; // 3 days (the max validity period)
	res = lf_keymanager_worker_inbound_get_drkey(kmw, config->peers->isd_as,
			&src_host_addr, &dst_host_addr, config->peers->drkey_protocol,
			ns_now, 0, &ns_drkey_epoch_start, &drkey);
	if (res != -2) {
		printf("Error: ns_now = ns_now + 3*24*3600*1e9; "
			   "lf_keymanager_worker_inbound_get_drkey (expected = -2, res = "
			   "%d)\n",
				res);
		error_count += 1;
	}

	res = lf_keymanager_worker_outbound_get_drkey(kmw, config->peers->isd_as,
			&dst_host_addr, &src_host_addr, config->peers->drkey_protocol,
			ns_now, &ns_drkey_epoch_start, &drkey);
	if (res != -2) {
		printf("Error: ns_now = ns_now + 3*24*3600*1e9; "
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

	uint64_t ns_drkey_epoch_start;
	res = lf_keymanager_worker_outbound_get_drkey(kmw1, config1->peers->isd_as,
			&dst_host_addr, &src_host_addr, config1->peers->drkey_protocol,
			ns_now, &ns_drkey_epoch_start, &drkey1);
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
			ns_now, 0, &ns_drkey_epoch_start, &drkey2);
	if (res != 0) {
		printf("Error: lf_keymanager_worker_inbound_get_drkey\n");
		error_count += 1;
	}


	/* compare DRKeys */

	if (memcmp(&drkey1, &drkey2, sizeof(drkey1)) != 0) {
		printf("Error: DRKey are not the same\n");
		error_count += 1;
		print_keys(drkey1.key, drkey2.key);
	}

	free_test_context(km1);
	free_test_context(km2);

	return error_count;
}

/**
 * Test that the DRKey derivation is correct.
 *
 * @return int
 */
int
test3()
{
	int error_count = 0;
	struct lf_keymanager *km;
	struct lf_keymanager_worker *kmw;
	struct lf_crypto_drkey drkey;
	struct lf_crypto_drkey as_as_zero_drkey, as_as_drkey;
	struct lf_host_addr src_host_addr;
	struct lf_host_addr dst_host_addr;

	const uint8_t zero_key[LF_CRYPTO_DRKEY_SIZE] = { 0 };
	const uint8_t random_key[LF_CRYPTO_DRKEY_SIZE] = { 0x01, 0x23, 0x45, 0x67,
		0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
		0xef };

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

	lf_crypto_drkey_from_buf(&kmw->drkey_ctx, zero_key, &as_as_zero_drkey);
	lf_crypto_drkey_from_buf(&kmw->drkey_ctx, random_key, &as_as_drkey);

	// test most general derivation
	uint8_t expected_key_1[LF_CRYPTO_DRKEY_SIZE] = { 0x82, 0x67, 0xa4, 0xe9,
		0x10, 0x60, 0x8f, 0xa8, 0xdd, 0x46, 0xb1, 0x1b, 0x43, 0x95, 0x97,
		0x49 };
	lf_drkey_derive_host_host_from_as_as(&kmw->drkey_ctx, &as_as_zero_drkey,
			&src_host_addr, &dst_host_addr, 0, &drkey);

	if (memcmp(expected_key_1, drkey.key, sizeof expected_key_1) != 0) {
		printf("Error: DRKey derivation wrong\n");
		print_keys(expected_key_1, drkey.key);
		error_count += 1;
	}

	// test IPv4 addresses
	src_addr = 0x0202f80a; // 10.248.2.2
	dst_addr = 0x0505f80a; // 10.248.5.5

	uint8_t expected_key_2[LF_CRYPTO_DRKEY_SIZE] = { 0x75, 0xde, 0xfa, 0x86,
		0xd5, 0x6d, 0x26, 0x5b, 0x0c, 0xc7, 0xe6, 0x31, 0x3a, 0x9a, 0x13,
		0x14 };
	lf_drkey_derive_host_host_from_as_as(&kmw->drkey_ctx, &as_as_drkey,
			&src_host_addr, &dst_host_addr, 0, &drkey);

	if (memcmp(expected_key_2, drkey.key, sizeof expected_key_2) != 0) {
		printf("Error: DRKey derivation wrong\n");
		print_keys(expected_key_2, drkey.key);
		error_count += 1;
	}

	// test DRKey protocol number
	uint8_t expected_key_3[LF_CRYPTO_DRKEY_SIZE] = { 0x81, 0xc0, 0x7f, 0xbc,
		0x5c, 0xdd, 0xb1, 0xda, 0x18, 0xaa, 0xa0, 0x56, 0xbc, 0x22, 0xef,
		0x56 };
	lf_drkey_derive_host_host_from_as_as(&kmw->drkey_ctx, &as_as_drkey,
			&src_host_addr, &dst_host_addr, 0x0300, &drkey);

	if (memcmp(expected_key_3, drkey.key, sizeof expected_key_3) != 0) {
		printf("Error: DRKey derivation wrong\n");
		print_keys(expected_key_3, drkey.key);
		error_count += 1;
	}

	// test IPv4 as IPv6 addresses
	uint8_t src_addr_ipv6[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0xFF, 0xFF, 0x0a, 0xf8, 0x02, 0x02 }; // 10.248.2.2
	uint8_t dst_addr_ipv6[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0xFF, 0xFF, 0x0a, 0xf8, 0x05, 0x05 }; // 10.248.5.5

	src_host_addr.addr = &src_addr_ipv6;
	src_host_addr.type_length = 0x03;
	dst_host_addr.addr = &dst_addr_ipv6;
	dst_host_addr.type_length = 0x03;

	lf_drkey_derive_host_host_from_as_as(&kmw->drkey_ctx, &as_as_drkey,
			&src_host_addr, &dst_host_addr, 0, &drkey);

	if (memcmp(expected_key_2, drkey.key, sizeof expected_key_2) != 0) {
		printf("Error: DRKey derivation wrong\n");
		print_keys(expected_key_2, drkey.key);
		error_count += 1;
	}

	free_test_context(km);

	return error_count;
}

/**
 * Test that the config replacement changes keys as expected.
 *
 * @return int
 */
int
test4()
{
	int res = 0, error_count = 0;
	struct lf_keymanager *km = NULL;
	struct lf_config *config1 = NULL;
	struct lf_config *config3 = NULL;
	uint64_t ns_timestamp = 1702422000 * LF_TIME_NS_IN_S;

	struct lf_keymanager_dictionary_key key;
	struct lf_keyfetcher_sv_dictionary_data *shared_secret_node;
	struct lf_keymanager_key_container asas_key1, asas_key3;

	km = new_test_context();
	if (km == NULL) {
		return 1;
	}

	config1 = lf_config_new_from_file(TEST1_JSON);
	if (config1 == NULL) {
		printf("Error: lf_config_new_from_file\n");
		error_count = 1;
		goto exit;
	}

	res = lf_keymanager_apply_config(km, config1);
	if (res != 0) {
		printf("Error: lf_keymanager_apply_config\n");
		error_count = 1;
		goto exit;
	}

	key.as = config1->peers->isd_as;
	key.drkey_protocol = config1->peers->drkey_protocol;
	res = lf_keyfetcher_fetch_as_as_key(km->fetcher, km->src_as, key.as,
			key.drkey_protocol, ns_timestamp, &asas_key1);
	if (res != 0) {
		printf("Error: lf_keymanager_derive_shared_key\n");
		error_count += 1;
	}

	config3 = lf_config_new_from_file(TEST3_JSON);
	if (config3 == NULL) {
		printf("Error: lf_config_new_from_file\n");
		error_count = 1;
		goto exit;
	}

	// apply new config with additional key
	res = lf_keymanager_apply_config(km, config3);
	if (res != 0) {
		printf("Error: lf_keymanager_apply_config\n");
		error_count = 1;
		goto exit;
	}

	res = rte_hash_lookup_data(km->fetcher->dict, &key,
			(void **)&shared_secret_node);
	if (res != 0) {
		printf("Error: rte_hash_lookup_data\n");
		error_count = 1;
		goto exit;
	}

	res = lf_keyfetcher_fetch_as_as_key(km->fetcher, km->src_as, key.as,
			key.drkey_protocol, ns_timestamp, &asas_key3);
	if (res != 0) {
		printf("Error: lf_keymanager_derive_shared_key\n");
		error_count += 1;
	}

	if (memcmp(asas_key1.key.key, asas_key3.key.key,
				sizeof asas_key1.key.key) == 0) {
		printf("Error: Key replacement failed\n");
		error_count += 1;
	}

exit:
	if (config3 != NULL) {
		free(config3);
	}
	if (config1 != NULL) {
		free(config1);
	}
	if (km != NULL) {
		free_test_context(km);
	}

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
	error_counter += test3();
	error_counter += test4();

	if (error_counter > 0) {
		printf("Error Count: %d\n", error_counter);
		return 1;
	}

	printf("All tests passed!\n");
	return 0;
}