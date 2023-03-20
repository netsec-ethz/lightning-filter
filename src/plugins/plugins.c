/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#include <stdint.h>

#include "plugins.h"

int
lf_plugins_init(struct lf_worker_context *workers, uint16_t nb_workers)
{
	int res = 0;

	LF_PLUGINS_LOG(NOTICE, "Initiating Plugins\n");

#if LF_PLUGIN_DST_RATELIMITER
	res |= lf_dst_ratelimiter_init(nb_workers);
#endif

#if LF_PLUGIN_WG_RATELIMITER
	res |= lf_wg_ratelimiter_init(workers, nb_workers);
#endif

	(void)workers;
	(void)nb_workers;
	return res;
}

int
lf_plugins_apply_config(const struct lf_config *config)
{
	int res = 0;

#if LF_PLUGIN_DST_RATELIMITER
	res |= lf_dst_ratelimiter_apply_config(config);
#endif

#if LF_PLUGIN_WG_RATELIMITER
	res |= lf_wg_ratelimiter_apply_config(config);
#endif

	(void)config;
	return res;
}