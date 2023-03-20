/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#ifndef LF_WORKER_CT_H
#define LF_WORKER_CT_H

#include "setup.h"

/**
 * The control traffic (ct) worker is responsible to handle control traffic
 * packets, such as ARP requests.
 */

struct lf_worker_ct {
	struct lf_setup_ct_port_queue signal_port_queue;
};

/**
 * Launch function of control traffic (ct) worker.
 *
 * @param ctx The ct worker context.
 * @return Returns 0 if the ct worker terminates without error.
 */
int
lf_worker_ct_run(struct lf_worker_ct *ctx);

#endif /* LF_WORKER_CT_H */