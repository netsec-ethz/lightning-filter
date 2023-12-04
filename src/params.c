/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rte_ethdev.h>
#include <rte_string_fns.h>

#include "lf.h"
#include "lib/log/log.h"
#include "params.h"
#include "version.h"

static const struct lf_params default_params = {
	/* config */
	.config_file = "",

	/* setup (port, queues, and mirrors) */
	.portmask = 0,
	.rx_portmask = 0,
	.tx_portmask = 0,
	.mtu = 1500,
	.disable_mirrors = false,

	/* timestamp filter */
	.tf_threshold = 1000,

	/* duplicate filter (bloom filter) */
	.bf_nb = 3,
	.bf_period = 500,
	.bf_hashes = 7,     /* roughly -log2(0.01) */
	.bf_bytes = 131072, /* 2^20 / 8 */

	/* ratelimiter */
	.rl_size = 1024,

	/* keymanager */
	.km_size = 1024,
};

#define LF_MAX_PORTPAIRS (2 * RTE_MAX_ETHPORTS)

struct lf_portpair {
	uint16_t rx_port;
	uint16_t tx_port;
	enum lf_forwarding_direction forwarding_direction;
};

/* short options */
static const char short_options[] = "v:" /* version */
									"p:" /* portmask */
									"c:" /* config file */
		;

/* long options */
#define CMD_LINE_OPT_VERSION         "version"
#define CMD_LINE_OPT_CONFIG_FILE     "config-file"
#define CMD_LINE_OPT_PORTMASK        "portmask"
#define CMD_LINE_OPT_PROMISCUOUS     "promiscuous"
#define CMD_LINE_OPT_PORTMAP         "portmap"
#define CMD_LINE_OPT_MTU             "mtu"
#define CMD_LINE_OPT_TF_THRESHOLD    "tf-threshold"
#define CMD_LINE_OPT_BF_NB           "bf-nb"
#define CMD_LINE_OPT_BF_PERIOD       "bf-period"
#define CMD_LINE_OPT_BF_HASHES       "bf-hashes"
#define CMD_LINE_OPT_BF_BYTES        "bf-bytes"
#define CMD_LINE_OPT_RL_SIZE         "rl-size"
#define CMD_LINE_OPT_KM_SIZE         "km-size"
#define CMD_LINE_OPT_DISABLE_MIRRORS "disable-mirrors"

/* map long options to number */
enum {
	/* long options mapped to a short option */
	CMD_LINE_OPT_VERSION_NUM = 'v',
	CMD_LINE_OPT_CONFIG_FILE_NUM = 'c',
	CMD_LINE_OPT_PORTMASK_NUM = 'p',
	/* first long only option value must be >= 256, so that we won't
	 * conflict with short options */
	CMD_LINE_OPT_PROMISCUOUS_NUM = 256,
	CMD_LINE_OPT_PORTMAP_NUM,
	CMD_LINE_OPT_MTU_NUM,
	CMD_LINE_OPT_TF_THRESHOLD_NUM,
	CMD_LINE_OPT_BF_NB_NUM,
	CMD_LINE_OPT_BF_PERIOD_NUM,
	CMD_LINE_OPT_BF_HASHES_NUM,
	CMD_LINE_OPT_BF_BYTES_NUM,
	CMD_LINE_OPT_RL_CONFIG_FILE_NUM,
	CMD_LINE_OPT_RL_SIZE_NUM,
	CMD_LINE_OPT_KM_CONFIG_FILE_NUM,
	CMD_LINE_OPT_KM_SIZE_NUM,
	CMD_LINE_OPT_DISABLE_MIRRORS_NUM,
};

static const struct option long_options[] = {
	{ CMD_LINE_OPT_VERSION, optional_argument, 0, CMD_LINE_OPT_VERSION_NUM },
	{ CMD_LINE_OPT_CONFIG_FILE, required_argument, 0,
			CMD_LINE_OPT_CONFIG_FILE_NUM },
	{ CMD_LINE_OPT_PORTMASK, required_argument, 0, CMD_LINE_OPT_PORTMASK_NUM },
	{ CMD_LINE_OPT_PROMISCUOUS, required_argument, 0,
			CMD_LINE_OPT_PROMISCUOUS_NUM },
	{ CMD_LINE_OPT_PORTMAP, required_argument, 0, CMD_LINE_OPT_PORTMAP_NUM },
	{ CMD_LINE_OPT_MTU, required_argument, 0, CMD_LINE_OPT_MTU_NUM },
	{ CMD_LINE_OPT_TF_THRESHOLD, required_argument, 0,
			CMD_LINE_OPT_TF_THRESHOLD_NUM },
	{ CMD_LINE_OPT_BF_NB, required_argument, 0, CMD_LINE_OPT_BF_NB_NUM },
	{ CMD_LINE_OPT_BF_PERIOD, required_argument, 0,
			CMD_LINE_OPT_BF_PERIOD_NUM },
	{ CMD_LINE_OPT_BF_HASHES, required_argument, 0,
			CMD_LINE_OPT_BF_HASHES_NUM },
	{ CMD_LINE_OPT_BF_BYTES, required_argument, 0, CMD_LINE_OPT_BF_BYTES_NUM },
	{ CMD_LINE_OPT_RL_SIZE, required_argument, 0, CMD_LINE_OPT_RL_SIZE_NUM },
	{ CMD_LINE_OPT_KM_SIZE, required_argument, 0, CMD_LINE_OPT_KM_SIZE_NUM },
	{ CMD_LINE_OPT_DISABLE_MIRRORS, no_argument, 0,
			CMD_LINE_OPT_DISABLE_MIRRORS_NUM },
	{ NULL, 0, 0, 0 },
};

/* display application usage */
static void
lf_usage(const char *prgname)
{
	lf_print(
			"Usage:\n"
			"%s [EAL options] --\n"
			"  -h, --help: print this message.\n"
			"  -v, --version: print all version relevant information.\n"
			"  -c, --config-file=CONFIG_FILE\n"
			"         configuration file to be loaded\n"
			"  -p, --portmask=PORTMASK\n"
			"         hexadecimal bitmask of ports to configure\n"
			"  --promiscuous=PORTMASK\n"
			"         hexadecimal bitmask of ports to run in promiscuous mode\n"
			"  --portmap=PORTMAP:\n"
			"         Configure forwarding port pair mapping and expected\n"
			"         packet direction\n"
			"         (default: adjacent ports are mutually mapped to each\n"
			"         other accepting both directions)\n"
			"  --mtu=NUMBER:\n"
			"         Set maximum transmission unit (MTU) of the ports "
			"(default: 1500)\n"
			"  --tf-threshold=NUM:\n"
			"         Timestamp filter threshold in milliseconds "
			"(default: 1000)\n"
			"  --bf-nb=NUMBER:\n"
			"         Number of Bloom filters used\n"
			"  --bf-period=PERIOD:\n"
			"         Period between Bloom filter rotation in milliseconds\n"
			"  --bf-hashes=NUM:\n"
			"         Number of hash values used for the Bloom filters\n"
			"  --bf-bytes=NUM\n"
			"         Size of each Bloom filter bit arrays in bytes\n"
			"         Must be a power of 2 and at least 8\n"
			"  --rl-size=NUM\n"
			"         Size of ratelimiter hash table.\n"
			"  --km-size=NUM\n"
			"         Size of keymanager hash table.\n"
			"  --disable-mirrors\n"
			"         Disables mirrors for all ports.\n",
			prgname);
}

static int
parse_uint(const char *string, unsigned int *integer)
{
	unsigned long ul;
	char *end = NULL;

	/* parse decimal string */
	ul = strtoul(string, &end, 10);
	if ((string[0] == '\0') || (end == NULL) || (*end != '\0')) {
		return -1;
	}
	if (ul > UINT_MAX) {
		return -1;
	}
	*integer = ul;
	return 0;
}

static int
parse_portmask(const char *portmask_str, uint32_t *portmask)
{
	char *end = NULL;
	unsigned long pm = 0;

	/* parse string to number */
	pm = strtoul(portmask_str, &end, 0);
	if ((portmask_str[0] == '\0') || (end == NULL) || (*end != '\0')) {
		return -1;
	}

	*portmask = pm;
	return 0;
}

/**
 * Parse portmap string and create port pairs.
 * Inspired by DPDK (v21.08) example l2fwd.
 */
static int
parse_portmap(const char *q_arg, struct lf_portpair portpairs[LF_MAX_PORTPAIRS],
		uint16_t *nb_portpairs)
{
	enum fieldnames { FLD_PORT1 = 0, FLD_PORT2, FLD_DIRECTION, _NUM_FLD };
	unsigned long int_fld[2];
	const char *p, *p0 = q_arg;
	char *str_fld[_NUM_FLD];
	unsigned int size, num_fld;
	char s[256];
	char *end;
	int i;

	unsigned int nb_port_pair_params = 0;

	while ((p = strchr(p0, '(')) != NULL) {
		++p;
		p0 = strchr(p, ')');
		if (p0 == NULL) {
			return -1;
		}

		size = p0 - p;
		if (size >= sizeof(s)) {
			return -1;
		}

		(void)memcpy(s, p, size);
		s[size] = '\0';
		num_fld = rte_strsplit(s, sizeof(s), str_fld, _NUM_FLD, ',');
		if (!(num_fld == 2 || num_fld == 3)) {
			return -1;
		}

		for (i = 0; i < 2; i++) {
			errno = 0;
			int_fld[i] = strtoul(str_fld[i], &end, 0);
			if (errno != 0 || end == str_fld[i] ||
					int_fld[i] >= LF_MAX_PORTPAIRS) {
				return -1;
			}
		}

		portpairs[nb_port_pair_params].rx_port = (uint16_t)int_fld[FLD_PORT1];
		portpairs[nb_port_pair_params].tx_port = (uint16_t)int_fld[FLD_PORT2];

		if (num_fld == 3) {
			if (strncmp(str_fld[2], "i", 1) == 0) {
				portpairs[nb_port_pair_params].forwarding_direction =
						LF_FORWARDING_DIRECTION_INBOUND;
			} else if (strncmp(str_fld[2], "o", 1) == 0) {
				portpairs[nb_port_pair_params].forwarding_direction =
						LF_FORWARDING_DIRECTION_OUTBOUND;
			} else {
				return -1;
			}
		} else {
			portpairs[nb_port_pair_params].forwarding_direction =
					LF_FORWARDING_DIRECTION_BOTH;
		}

		if (nb_port_pair_params >= LF_MAX_PORTPAIRS) {
			LF_LOG(ERR, "Exceeded max number of port pair params: %u\n",
					nb_port_pair_params);
			return -1;
		}
		++nb_port_pair_params;
	}

	*nb_portpairs = nb_port_pair_params;
	return 0;
}

/**
 * Transforms an array of portpairs into an array of portmaps.
 * All the used ports have to be enabled in the portmask.
 * Additionally, rx and tx portmasks are set.
 */
static int
set_portmap_from_portpairs(uint32_t portmask,
		const struct lf_portpair portpairs[LF_MAX_PORTPAIRS],
		uint16_t nb_portpairs, uint16_t dst_port[RTE_MAX_ETHPORTS],
		enum lf_forwarding_direction forwarding_direction[RTE_MAX_ETHPORTS],
		uint32_t *rx_portmask_ptr, uint32_t *tx_portmask_ptr)
{
	uint16_t port_id, rx_port_id, tx_port_id, i;
	uint32_t rx_portmask = 0, tx_portmask = 0;

	/* reset portmap */
	for (port_id = 0; port_id < RTE_MAX_ETHPORTS; ++port_id) {
		dst_port[port_id] = RTE_MAX_ETHPORTS;
		forwarding_direction[port_id] = LF_FORWARDING_DIRECTION_BOTH;
	}

	/* populate portmap */
	for (i = 0; i < nb_portpairs; ++i) {
		rx_port_id = portpairs[i].rx_port;
		tx_port_id = portpairs[i].tx_port;

		/* check if ports are enabled */
		if ((portmask & (1 << rx_port_id)) == 0) {
			LF_LOG(ERR, "Port %u is not enabled\n", rx_port_id);
			return -1;
		}
		if ((portmask & (1 << tx_port_id)) == 0) {
			LF_LOG(ERR, "Port %u is not enabled\n", tx_port_id);
			return -1;
		}

		/* check if ports are already used as receiving
		 * or transmitting ports, respectively. */
		if (rx_portmask & (1 << rx_port_id)) {
			LF_LOG(ERR, "Port %u is used as rx port in multiple port pairs\n",
					rx_port_id);
			return -1;
		}
		if (tx_portmask & (1 << tx_port_id)) {
			LF_LOG(ERR, "Port %u is used as tx port in multiple port pairs\n",
					tx_port_id);
			return -1;
		}

		/* set portmap value */
		dst_port[rx_port_id] = tx_port_id;
		forwarding_direction[rx_port_id] = portpairs[i].forwarding_direction;
		rx_portmask |= (1 << rx_port_id);
		tx_portmask |= (1 << tx_port_id);
	}

	/* set return rx_portmask and tx_portmask */
	*rx_portmask_ptr = rx_portmask;
	*tx_portmask_ptr = tx_portmask;

	return 0;
}

static int
set_portmap_default(uint32_t portmask, uint16_t dst_port[RTE_MAX_ETHPORTS],
		enum lf_forwarding_direction forwarding_direction[RTE_MAX_ETHPORTS],
		uint32_t *rx_portmask_ptr, uint32_t *tx_portmask_ptr)
{
	unsigned int nb_ports_in_mask = 0;
	uint16_t port_id, last_port = -1;

	/* reset portmap */
	for (port_id = 0; port_id < RTE_MAX_ETHPORTS; ++port_id) {
		dst_port[port_id] = RTE_MAX_ETHPORTS;
		forwarding_direction[port_id] = LF_FORWARDING_DIRECTION_BOTH;
	}

	for (port_id = 0; port_id < RTE_MAX_ETHPORTS; ++port_id) {
		/* skip ports that are not enabled */
		if ((portmask & (1 << port_id)) == 0) {
			continue;
		}

		if (nb_ports_in_mask % 2) {
			dst_port[port_id] = last_port;
			forwarding_direction[port_id] = LF_FORWARDING_DIRECTION_BOTH;

			dst_port[last_port] = port_id;
			forwarding_direction[last_port] = LF_FORWARDING_DIRECTION_BOTH;
		} else {
			last_port = port_id;
		}

		nb_ports_in_mask++;
	}

	if (nb_ports_in_mask % 2) {
		LF_LOG(NOTICE, "Odd number of ports in portmask\n");
		dst_port[last_port] = last_port;
		forwarding_direction[last_port] = LF_FORWARDING_DIRECTION_BOTH;
	}

	/* set return rx_portmask and tx_portmask */
	*rx_portmask_ptr = portmask;
	*tx_portmask_ptr = portmask;

	return 0;
}

int
lf_params_parse(int argc, char **argv, struct lf_params *params)
{
	int res;
	uint16_t nb_ports_avail;
	uint16_t nb_portpairs = 0;
	struct lf_portpair portpairs[LF_MAX_PORTPAIRS];

	/*
	 * default parametres
	 */
	*params = default_params;

	/*
	 * parse input
	 */
	int opt;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, short_options, long_options,
					&option_index)) != EOF) {
		switch (opt) {
		/* version */
		case 'v':
			lf_print(LF_VERSION_ALL "\n");
			break;
		/* config file */
		case 'c':
			if (strlen(optarg) > PATH_MAX || strlen(optarg) == 0) {
				LF_LOG(ERR, "Invalid config file name\n");
				return -1;
			}
			(void)strcpy(params->config_file, optarg);
			break;
		/* portmask */
		case 'p':
			res = parse_portmask(optarg, &params->portmask);
			if (res != 0) {
				LF_LOG(ERR, "Failed to parse portmask\n");
				return -1;
			}
			if (params->portmask == 0) {
				LF_LOG(ERR, "Invalid portmask\n");
				return -1;
			}
			break;
		/* promiscuous */
		case CMD_LINE_OPT_PROMISCUOUS_NUM:
			res = parse_portmask(optarg, &params->promiscuous);
			if (res != 0) {
				LF_LOG(ERR, "Failed to parse promiscuous portmask\n");
				return -1;
			}
			break;
		/* portmap */
		case CMD_LINE_OPT_PORTMAP_NUM:
			res = parse_portmap(optarg, portpairs, &nb_portpairs);
			if (res != 0) {
				LF_LOG(ERR, "Failed to parse portmap\n");
				return -1;
			}
			if (nb_portpairs == 0) {
				LF_LOG(ERR, "Invalid portmap\n");
				return -1;
			}
			break;
		/* mtu */
		case CMD_LINE_OPT_MTU_NUM:
			res = parse_uint(optarg, &params->mtu);
			if (res != 0) {
				LF_LOG(ERR, "Failed to parse MTU\n");
				return -1;
			}
			if (params->mtu == 0) {
				LF_LOG(ERR, "Invalid MTU\n");
				return -1;
			}
			break;
		case CMD_LINE_OPT_TF_THRESHOLD_NUM:
			res = parse_uint(optarg, &params->tf_threshold);
			if (res != 0 || params->tf_threshold == 0) {
				LF_LOG(ERR, "Invalid tf-threshold\n");
				return -1;
			}
			break;
		case CMD_LINE_OPT_BF_NB_NUM:
			res = parse_uint(optarg, &params->bf_period);
			if (res != 0 || params->bf_nb == 0) {
				LF_LOG(ERR, "Invalid bf-period\n");
				return -1;
			}
			break;
		case CMD_LINE_OPT_BF_PERIOD_NUM:
			res = parse_uint(optarg, &params->bf_period);
			if (res != 0 || params->bf_period == 0) {
				LF_LOG(ERR, "Invalid bf-period\n");
				return -1;
			}
			break;
		case CMD_LINE_OPT_BF_HASHES_NUM:
			res = parse_uint(optarg, &params->bf_hashes);
			if (res != 0 || params->bf_hashes == 0) {
				LF_LOG(ERR, "Invalid bf-hashes\n");
				return -1;
			}
			break;
		case CMD_LINE_OPT_BF_BYTES_NUM:
			res = parse_uint(optarg, &params->bf_bytes);
			if (res != 0 || params->bf_bytes == 0) {
				LF_LOG(ERR, "Invalid bf-bytes\n");
				return -1;
			}
			break;
		case CMD_LINE_OPT_RL_SIZE_NUM:
			res = parse_uint(optarg, &params->rl_size);
			if (res != 0 || params->rl_size == 0) {
				LF_LOG(ERR, "Invalid rl-size\n");
				return -1;
			}
			break;
		case CMD_LINE_OPT_KM_SIZE_NUM:
			res = parse_uint(optarg, &params->km_size);
			if (res != 0 || params->km_size == 0) {
				LF_LOG(ERR, "Invalid km-size\n");
				return -1;
			}
			break;
		/* disable mirrors for all ports */
		case CMD_LINE_OPT_DISABLE_MIRRORS_NUM:
			params->disable_mirrors = true;
			break;
		/* unknown option */
		default:
			(void)lf_usage(prgname);
			return -1;
		}
	}

	/*
	 * Check compatibility of parameters,
	 * reduce/simplify them,
	 * and populate return parameters.
	 */

	/* check ports availability */
	nb_ports_avail = rte_eth_dev_count_avail();
	if (nb_ports_avail == 0) {
		LF_LOG(ERR, "No Ethernet ports available\n");
		return -1;
	}

	/* check port mask to possible port mask */
	if (params->portmask & ~((1 << nb_ports_avail) - 1)) {
		LF_LOG(ERR, "Invalid portmask; possible (0x%" PRIx16 ")\n",
				(1 << nb_ports_avail) - 1);
		return -1;
	}

	/* check and set portmap */
	if (nb_portpairs == 0) {
		res = set_portmap_default(params->portmask, params->dst_port,
				params->forwarding_direction, &params->rx_portmask,
				&params->tx_portmask);
	} else {
		res = set_portmap_from_portpairs(params->portmask, portpairs,
				nb_portpairs, params->dst_port, params->forwarding_direction,
				&params->rx_portmask, &params->tx_portmask);
	}

	if (res != 0) {
		LF_LOG(ERR, "Failed to create portmap\n");
		return -1;
	}

	/* set reduced portmask */
	params->portmask = (params->rx_portmask | params->tx_portmask);

	/* cleanup */
	if (optind >= 0) {
		argv[optind - 1] = prgname;
	}

	res = optind - 1;
	optind = 1; /* reset getopt lib */
	return res;
}