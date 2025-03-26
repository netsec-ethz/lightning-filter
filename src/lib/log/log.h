/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#ifndef LF_LOG_H
#define LF_LOG_H

#include <inttypes.h>

/* Log levels equivalent to DPDK log levels */
#define LF_LOG_EMERG   1U           /**< System is unusable.               */
#define LF_LOG_ALERT   2U           /**< Action must be taken immediately. */
#define LF_LOG_CRIT    3U           /**< Critical conditions.              */
#define LF_LOG_ERR     4U           /**< Error conditions.                 */
#define LF_LOG_WARNING 5U           /**< Warning conditions.               */
#define LF_LOG_NOTICE  6U           /**< Normal but significant condition. */
#define LF_LOG_INFO    7U           /**< Informational.                    */
#define LF_LOG_DEBUG   8U           /**< Debug-level messages.             */
#define LF_LOG_MAX     LF_LOG_DEBUG /**< Most detailed log level.          */
#define LF_LOG_MIN     LF_LOG_EMERG /**< Least detailed log level.         */

/* Log level strings */
#define LF_LOG_STRING_EMERG   "EMERGENCY"
#define LF_LOG_STRING_ALERT   "ALERT"
#define LF_LOG_STRING_CRIT    "CRITICAL"
#define LF_LOG_STRING_ERR     "ERROR"
#define LF_LOG_STRING_WARNING "WARNING"
#define LF_LOG_STRING_NOTICE  "NOTICE"
#define LF_LOG_STRING_INFO    "INFO"
#define LF_LOG_STRING_DEBUG   "DEBUG"

/**
 * Generates a log message.
 */
void
lf_log(uint32_t level, const char *format, ...);

/**
 * Generates a log message.
 * The LF_LOG() is a helper that prefixes the string with "LF LOG_LEVEL:".
 * The log level is expanded with LF_LOG_ such that the short name can be used.
 */
#define LF_LOG(l, ...) \
	lf_log(LF_LOG_##l, "LF " LF_LOG_STRING_##l ": " __VA_ARGS__)

/* Minimal log level for logs in data path */
#ifndef LF_LOG_DP_LEVEL
#define LF_LOG_DP_LEVEL LF_LOG_WARNING
#endif

/*
 * Generates a log message for data path.
 * If the log level is lower than LF_LOG_DP_LEVEL, the log is removed at compile
 * time.
 */
#define LF_LOG_DP(level, ...) \
	((LF_LOG_##level <= LF_LOG_DP_LEVEL) ? LF_LOG(level, __VA_ARGS__) : (void)0)

void
lf_print(const char *format, ...);

#define PRIISDAS "%u-%x:%x:%x"
#define PRIISDAS_VAL(isd_as)                         \
	(unsigned int)((isd_as) >> 48 & 0XFFFF),         \
			(unsigned int)((isd_as) >> 32 & 0XFFFF), \
			(unsigned int)((isd_as) >> 16 & 0XFFFF), \
			(unsigned int)((isd_as) >> 0 & 0XFFFF)

#endif /* LF_LOG_H */