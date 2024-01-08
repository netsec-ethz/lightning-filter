/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#include <stdio.h>

#include <rte_errno.h>
#include <rte_jhash.h>
#include <rte_malloc.h>

#include "asdict.h"

unsigned int counter = 0;

struct lf_asdict *
lf_asdict_new_with_data(int initial_size, int data_size)
{
	struct lf_asdict *dic;
	struct rte_hash_parameters params = { 0 };
	char name[RTE_HASH_NAMESIZE];

	if (initial_size <= 0) {
		return NULL;
	}
	if (data_size <= 0) {
		return NULL;
	}

	/* DPDK hash table entry must be at least 8 (undocumented) */
	initial_size = initial_size < 8 ? 8 : initial_size;

	dic = rte_malloc(NULL, sizeof(struct lf_asdict), 0);
	if (dic == NULL) {
		return NULL;
	}
	dic->size = initial_size;
	dic->data_size = data_size;

	dic->data_array = rte_calloc(NULL, initial_size, data_size, 0);
	if (dic->data_array == NULL) {
		free(dic);
		return NULL;
	}

	/* Generate a unique name for the DPDK hash table, which is required by the
	 * implementation. */
	snprintf(name, sizeof(name), "hash_table_%d\n", counter);
	counter += 1;

	/*
	 * Setup DPDK hash table
	 */
	params.name = name;
	params.entries = initial_size;
	params.key_len = sizeof(uint64_t);
	params.hash_func = rte_jhash;
	params.hash_func_init_val = 0;
	/* (fstreun) potentially use different asdict for different sockets */
	params.socket_id = rte_socket_id();

	/* ensure that insertion always succeeds */
	params.extra_flag = RTE_HASH_EXTRA_FLAGS_EXT_TABLE;

	dic->hash_table = rte_hash_create(&params);

	if (dic->hash_table == NULL) {
		free(dic->data_array);
		rte_free(dic);
		return NULL;
	}

	return dic;
}

void
lf_asdict_free(struct lf_asdict *dic)
{
	rte_free(dic->data_array);
	rte_hash_free(dic->hash_table);
	rte_free(dic);
}

int
lf_asdict_add(struct lf_asdict *dic, uint64_t key)
{
	int res;

	res = rte_hash_add_key(dic->hash_table, &key);
	if (res < 0) {
		return res;
	}

	return res;
}

int
lf_asdict_add_with_data(struct lf_asdict *dic, uint64_t key, void **data)
{
	int res;

	res = rte_hash_add_key(dic->hash_table, &key);
	if (res < 0) {
		return res;
	}

	*data = (char *)dic->data_array + res * dic->data_size;

	return res;
}

int
lf_asdict_lookup(const struct lf_asdict *dic, uint64_t key)
{
	int res;

	res = rte_hash_lookup(dic->hash_table, &key);
	if (res < 0) {
		return res;
	}

	return res;
}

int
lf_asdict_lookup_with_data(const struct lf_asdict *dic, uint64_t key,
		void **data)
{
	int res;

	res = rte_hash_lookup(dic->hash_table, &key);
	if (res < 0) {
		return res;
	}

	*data = (char *)dic->data_array + res * dic->data_size;

	return res;
}

int
lf_asdict_del(struct lf_asdict *dic, uint64_t key)
{
	int res;

	res = rte_hash_del_key(dic->hash_table, &key);
	if (res < 0) {
		return res;
	}

	return res;
}

int
lf_asdict_iterator_init(const struct lf_asdict *dic,
		struct lf_asdict_iterator *iter)
{
	(void)dic;
	iter->rte_hash_iterator = 0;
	return 0;
}

int
lf_asdict_iterate(const struct lf_asdict *dic, const uint64_t **key,
		struct lf_asdict_iterator *iter)
{
	int res;
	void *null_data;

	res = rte_hash_iterate(dic->hash_table, (const void **)key, &null_data,
			&iter->rte_hash_iterator);
	if (res < 0) {
		return res;
	}

	return res;
}

int
lf_asdict_iterate_with_data(const struct lf_asdict *dic, const uint64_t **key,
		void **data, struct lf_asdict_iterator *iter)
{
	int res;
	void *null_data;

	res = rte_hash_iterate(dic->hash_table, (const void **)key, &null_data,
			&iter->rte_hash_iterator);
	if (res < 0) {
		return res;
	}

	*data = (char *)dic->data_array + res * dic->data_size;
	return res;
}

#undef hash_func