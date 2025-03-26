/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#ifndef LF_TELEMETRY_COUNTERS_H
#define LF_TELEMETRY_COUNTERS_H

#include <rte_telemetry.h>

/**
 * Helper functions to create counters.
 * See the worker counter in statistics on how to use them.
 */

/**
 * Macro to define all fields of a counter.
 */
#define LF_TELEMETRY_FIELD_DECL(TYPE, NAME) TYPE NAME;

/**
 * Macro to reset all fields of a counter.
 */
#define LF_TELEMETRY_FIELD_RESET(TYPE, NAME) (counter)->NAME = 0;

/**
 * Macro to declare all fields names of a counter.
 */
#define LF_TELEMETRY_FIELD_NAME(TYPE, NAME) { #NAME },

/**
 * Macro to add all fields of two counters together.
 * Expects a, b and res to be pointers to the respective counters.
 */
#define LF_TELEMETRY_FIELD_OP_ADD(TYPE, NAME) \
	(res)->NAME = (a)->NAME + (b)->NAME;

/**
 * Macro to add all fields of a counter to a telemetry dictionary.
 * Expects d to be a pointer to the telemetry dictionary and c to be a pointer
 * to the counter.
 */
#define LF_TELEMETRY_FIELD_ADD_DICT(TYPE, NAME) \
	rte_tel_data_add_dict_uint(d, #NAME, (c)->NAME);

#endif /* LF_TELEMETRY_COUNTERS_H */