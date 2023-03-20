/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#ifndef LF_IPC_H
#define LF_IPC_H

typedef int (*lf_ipc_cb)(const char *cmd, const char *params, char *out_buf,
		size_t buf_len);

/**
 * Register a new command for the IPC API.
 *
 * @param cmd String of the command starting with a back slash (e.g.,
 * "/version/all").
 * @param fn Pointer to function, which should be called for this specific
 * command.
 * @param help String of an helper text.
 * @return int 0 on success.
 */
int
lf_ipc_register_cmd(const char *cmd, lf_ipc_cb fn, const char *help);

/**
 * Initialize and launch IPC thread.
 * @param runtime_dir EAL runtime directory, which determines the socket path.
 * @return 0 on success.
 */
int
lf_ipc_init(const char *runtime_dir);

#endif /* LF_IPC_H */