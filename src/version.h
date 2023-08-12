/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#ifndef LF_VERSION_H
#define LF_VERSION_H

#include <malloc.h>
#include <stdlib.h>
#include <string.h>

/**
 * This file provides version information, including various compile time
 * options.
 * Furthermore, the version information can be exposed through the IPC
 * interface.
 */

/* Stringify Macro Values */
#define xstr(a) str(a)
#define str(a)  #a

#define LF_VERSION_MAJOR 0
#define LF_VERSION_MINOR 1
#define LF_VERSION_PATCH 0

#define LF_VERSION \
	xstr(LF_VERSION_MAJOR) "." xstr(LF_VERSION_MINOR) "." xstr(LF_VERSION_PATCH)

#define LF_VERSION_GIT_STRING xstr(LF_VERSION_GIT)

#define LF_VERSION_LONG LF_VERSION "- Git: " LF_VERSION_GIT_STRING

#define LF_VERSION_OPTIONS_STRING(CO) #CO ": " xstr(CO) "\n"

#define LF_VERSION_MAIN_OPTIONS(M) \
	M(LF_WORKER)                   \
	M(LF_DRKEY_FETCHER)            \
	M(LF_CBCMAC)                   \
	M(LF_LOG_DP_LEVEL)
#define LF_VERSION_MAIN_OPTIONS_STRING \
	LF_VERSION_MAIN_OPTIONS(LF_VERSION_OPTIONS_STRING)

#define LF_VERSION_FEATURE_OPTIONS(M) \
	M(LF_IPV6)                        \
	M(LF_OFFLOAD_CKSUM)               \
	M(LF_JUMBO_FRAME)
#define LF_VERSION_FEATURE_OPTIONS_STRING \
	LF_VERSION_FEATURE_OPTIONS(LF_VERSION_OPTIONS_STRING)

#define LF_VERSION_OMIT_OPTIONS(M)    \
	M(LF_WORKER_OMIT_TIME_UPDATE)     \
	M(LF_WORKER_OMIT_KEY_GET)         \
	M(LF_WORKER_OMIT_DECAPSULATION)   \
	M(LF_WORKER_OMIT_HASH_CHECK)      \
	M(LF_WORKER_OMIT_MAC_CHECK)       \
	M(LF_WORKER_OMIT_TIMESTAMP_CHECK) \
	M(LF_WORKER_OMIT_DUPLICATE_CHECK) \
	M(LF_WORKER_OMIT_RATELIMIT_CHECK)
#define LF_VERSION_OMIT_OPTIONS_STRING \
	LF_VERSION_OMIT_OPTIONS(LF_VERSION_OPTIONS_STRING)

#define LF_VERSION_IGNORE_CHECK_OPTIONS(M)   \
	M(LF_WORKER_IGNORE_MAC_CHECK)            \
	M(LF_WORKER_IGNORE_TIMESTAMP_CHECK)      \
	M(LF_WORKER_IGNORE_DUPLICATE_CHECK)      \
	M(LF_WORKER_IGNORE_HASH_CHECK)           \
	M(LF_WORKER_IGNORE_PATH_TIMESTAMP_CHECK) \
	M(LF_WORKER_IGNORE_KEY_VALIDITY_CHECK)
#define LF_VERSION_IGNORE_CHECK_OPTIONS_STRING \
	LF_VERSION_IGNORE_CHECK_OPTIONS(LF_VERSION_OPTIONS_STRING)

// clang-format off
#define LF_VERSION_ALL 						\
	LF_VERSION_LONG "\n"                    \
	"- Main Options -\n" 					\
	LF_VERSION_MAIN_OPTIONS_STRING			\
	"- Feature Options -\n" 				\
	LF_VERSION_FEATURE_OPTIONS_STRING		\
	"- Omit Options -\n" 					\
	LF_VERSION_OMIT_OPTIONS_STRING 			\
	"- Ignore Checks Options -\n"			\
	LF_VERSION_IGNORE_CHECK_OPTIONS_STRING	\
	"- Plugins -\n" 						\
	xstr(LF_PLUGINS)
// clang-format on

/**
 * Register version IPC commands.
 */
int
lf_version_register_ipc();

#endif /* LF_VERSION_H */