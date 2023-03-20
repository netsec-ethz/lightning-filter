/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#ifndef LF_TELEMETRY_COUNTERS_H
#define LF_TELEMETRY_COUNTERS_H

#define LF_TELEMETRY_FIELD_NAME_MAX 64

/**
 * Struct to store a counter's name.
 */
struct lf_telemetry_field_name {
	char name[LF_TELEMETRY_FIELD_NAME_MAX];
};

/**
 * Helper functions to create counters.
 * See the worker counter in statistics on how to use them.
 */
#define LF_TELEMETRY_FIELD_DECL(TYPE, NAME)  TYPE NAME;
#define LF_TELEMETRY_FIELD_RESET(TYPE, NAME) (counter)->NAME = 0;
#define LF_TELEMETRY_FIELD_NAME(TYPE, NAME)  { #NAME },
#define LF_TELEMETRY_FIELD_OP_ADD(TYPE, NAME) \
	(res)->NAME = (a)->NAME + (b)->NAME;

#endif /* LF_TELEMETRY_COUNTERS_H */