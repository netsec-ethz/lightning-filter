/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#include <stdio.h>

#include "lib/ipc/ipc.h"
#include "version.h"

int
ipc_version(const char *cmd, const char *p, char *out_buf, size_t buf_len)
{
	(void)cmd; /* unused */

	if (p == NULL) {
		return snprintf(out_buf, buf_len, "%s", LF_VERSION);
	}

	if (strcmp(p, "all") == 0) {
		return snprintf(out_buf, buf_len, "%s", LF_VERSION_ALL);
	}

	return -1;
}

int
lf_version_register_ipc()
{
	return lf_ipc_register_cmd("/version", ipc_version,
			"Prints current version");
}