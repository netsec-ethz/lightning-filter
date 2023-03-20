/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#include <stdarg.h>
#include <stdio.h>

#include <rte_eal.h>
#include <rte_malloc.h>

#include "../asdict.h"

struct simple_value {
	int i;
};

int
test1()
{
	int res;
	struct lf_asdict *dict;
	struct simple_value *value;
	struct lf_asdict_iterator iter;
	uint64_t *key;


	int val[] = { 100, 200, 300, 400 };
	const int initial_size = sizeof(val) / sizeof(*val);

	dict = lf_asdict_new_with_data(initial_size, sizeof(struct simple_value));
	if (dict == NULL) {
		printf("Dict New Failed\n");
		return 1;
	}

	for (int i = 0; i < initial_size; ++i) {
		res = lf_asdict_add_with_data(dict, i, (void **)&value);
		if (res < 0) {
			printf("Dict Add Failed (i = %d)\n", i);
			return 1;
		}
		value->i = val[i];
	}

	for (int i = 0; i < initial_size; ++i) {
		res = lf_asdict_lookup_with_data(dict, i, (void **)&value);
		if (res < 0) {
			printf("Dict Find Failed (i = %d)\n", i);
			return 1;
		}
		if (value->i != val[i]) {
			printf("Wrong Value (i = %d)\n", i);
			return 1;
		}
	}

	res = lf_asdict_iterator_init(dict, &iter);
	if (res != 0) {
		printf("Iterator initiation failes\n");
		return 1;
	}

	for (int i = 0; i < initial_size; ++i) {
		res = lf_asdict_iterate_with_data(dict, &key, (void **)&value, &iter);
		if (res < 0) {
			printf("Iteration does not return the i-th value (i = %d)\n", i);
			return 1;
		}
	}

	res = lf_asdict_iterate_with_data(dict, &key, (void **)&value, &iter);
	if (res >= 0) {
		printf("Iteration returns value after last\n");
		return 1;
	}

	int count = 0;
	LF_ASDICT_WITH_DATA_FOREACH(dict, &key, res, (void **)&value, &iter)
	{
		++count;
	}
	if (count != initial_size) {
		printf("Wrong number of iterations\n");
		return 1;
	}

	lf_asdict_free(dict);

	return 0;
}

int
main(int argc, char *argv[])
{
	int ret = rte_eal_init(argc, argv);
	int error_counter = 0;

	error_counter += test1();

	if (error_counter > 0) {
		printf("Error Count: %d\n", error_counter);
		return 1;
	}

	printf("All tests passed!\n");
	return 0;
}