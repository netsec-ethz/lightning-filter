/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */


#ifndef LF_ASDICT_H
#define LF_ASDICT_H

#include <stdint.h> /* uint32_t */
#include <stdlib.h> /* malloc/calloc */
#include <string.h> /* memcpy/memcmp */
#include <xmmintrin.h>

#include <rte_hash.h>

struct lf_asdict {
	struct rte_hash *hash_table;
	void *data_array;

	size_t size;
	size_t data_size;
};

struct lf_asdict_iterator {
	uint32_t rte_hash_iterator;
};

/**
 * Generate new AS dictionary, which is able to store a fixed number of entries.
 * Each entry linked to some data of arbitrary size and an unique id.
 * The id is between 0 (included) and dictionary's size (excluded).
 * The dictionary can be read by multiple threads at once. Concurrent writes are
 * not supported.
 * @param initial_size: number of entries the dictionary can store.
 * @param data_size: size of an entry's data structure.
 * @return new AS dictionary structure.
 */
struct lf_asdict *
lf_asdict_new_with_data(int initial_size, int data_size);

/**
 * Free the AS dictionary and the data.
 */
void
lf_asdict_free(struct lf_asdict *dic);

/**
 * Add new node do dictionary.
 * @return Returns the entry's id, i.e., a positive number (including 0). If
 * something failed, e.g., if there is no space in the hash for the key, a
 * negative number is returned.
 */
int
lf_asdict_add(struct lf_asdict *dic, uint64_t key);

/**
 * Add new node do dictionary.
 * @return Returns the entry's id, i.e., a positive number (including 0). If
 * something failed, e.g., if there is no space in the hash for the key, a
 * negative number is returned.
 */
int
lf_asdict_add_with_data(struct lf_asdict *dic, uint64_t key, void **data);

/**
 * Find the node for the given key.
 * @return Returns the entry's id, i.e., a positive number (including 0). If the
 * key cannot be found a negative number is returned.
 */
int
lf_asdict_lookup(const struct lf_asdict *dic, uint64_t key);

/**
 * Find the node for the given key.
 * @return Returns the entry's id, i.e., a positive number (including 0). If the
 * key cannot be found a negative number is returned.
 */
int
lf_asdict_lookup_with_data(const struct lf_asdict *dic, uint64_t key,
		void **data);

/**
 * Removes entry from dictionary including the data associated to the entry.
 * @return Returns the entry's id, i.e., a positive number (including 0). If the
 * key cannot be found a negative number is returned.
 */
int
lf_asdict_del(struct lf_asdict *dic, uint64_t key);

/**
 * Initialize dictionary iterator.
 * @param dic dictionary to iterate over.
 * @param iter iterator struct.
 * @return 0 on success.
 */
int
lf_asdict_iterator_init(const struct lf_asdict *dic,
		struct lf_asdict_iterator *iter);

/**
 * Iterate through the dictionary and returning key-value paris.
 * @param dic  dictionary to iterate over.
 * @param key Output containing the key of the current AS.
 * @param iter Struct to iterate. Should be initialized with
 * lf_asdict_iterator_init to start.
 * @return Returns the entry's id, i.e., a positive number (including 0). If the
 * key cannot be found a negative number is returned.
 */
int
lf_asdict_iterate(const struct lf_asdict *dic, const uint64_t **key,
		struct lf_asdict_iterator *iter);

/**
 * Iterate through the dictionary and returning key-value paris.
 * @param dic  dictionary to iterate over.
 * @param key Output containing the key of the current AS.
 * @param data Output containing the data associated with the current AS.
 * @param iter Struct to iterate. Should be initialized with
 * lf_asdict_iterator_init to start.
 * @return negative number if iteration reached end or an error occurred.
 */
int
lf_asdict_iterate_with_data(const struct lf_asdict *dic, const uint64_t **key,
		void **data, struct lf_asdict_iterator *iter);

#define LF_ASDICT_WITH_DATA_FOREACH(dic, key, id, data, iter)          \
	for (lf_asdict_iterator_init(dic, iter);                           \
			(id = lf_asdict_iterate_with_data(dic, key, (void **)data, \
					 iter)) >= 0;)

#define LF_ASDICT_FOREACH(dic, key, id, iter) \
	for (lf_asdict_iterator_init(dic, iter);  \
			(id = lf_asdict_iterate(dic, key, iter)) >= 0;)

#endif /* LF_FLOWDICT_H */