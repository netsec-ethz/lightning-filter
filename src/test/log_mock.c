/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#include <stdarg.h>
#include <stdio.h>

#include "../lib/log/log.h"

/*
 * Mock definition of the log function, which simply prints the log to stdout.
 */

void
lf_log(uint32_t level, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	printf("LOG [%d]: ", level);
	vprintf(fmt, args);
	va_end(args);
}

void
lf_print(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	(void)vprintf(fmt, args);
	va_end(args);
}