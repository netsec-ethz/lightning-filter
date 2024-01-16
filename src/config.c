/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <rte_byteorder.h>

#include "config.h"
#include "lf.h"
#include "lib/json-parser/json.h"
#include "lib/json-parser/lf_json_util.h"
#include "lib/log/log.h"

/*
 * JSON Field Identifiers
 */
#define FIELD_ISD_AS "isd_as"
#define FIELD_PEERS  "peers"

#define FIELD_RATELIMIT    "ratelimit"
#define FIELD_PACKET_RATE  "packet_rate"
#define FIELD_PACKET_BURST "packet_burst"
#define FIELD_BYTE_RATE    "byte_rate"
#define FIELD_BYTE_BURST   "byte_burst"

#define FIELD_PORT       "port"
#define FIELD_IP         "ip"
#define FIELD_IPV6       "ipv6"
#define FIELD_IP_PUBLIC  "ip_public"
#define FIELD_IP_PRIVATE "ip_private"
#define FIELD_ETHER      "ether"

#define FIELD_AUTH_PEERS  "auth_peers"
#define FIELD_BEST_EFFORT "best_effort"

#define FIELD_INBOUND  "inbound"
#define FIELD_OUTBOUND "outbound"

#define FIELD_DRKEY_PROTOCOL     "drkey_protocol"
#define FIELD_DRKEY_SERVICE_ADDR "drkey_service_addr"

#define FIELD_SHARED_SECRET "shared_secret"
#define FIELD_NOT_BEFORE    "not_before"
#define FIELD_SECRET_VALUE  "sv"

#define FIELD_DST_RATELIMITER "dst_ratelimiter"

#define FIELD_WG_RATELIMITER           "wg_ratelimiter"
#define FIELD_WG_RATELIMITER_HANDSHAKE FIELD_RATELIMIT "_handshake"
#define FIELD_WG_RATELIMITER_DATA      FIELD_RATELIMIT "_data"

/* potential value for the ether field of a packet modifier */
#define VALUE_ETHER_SRC_ADDR "src_addr"

/**
 * Ratelimit struct with the rate set to 0.
 *
 */
#define zero_ratelimit           \
	(struct lf_config_ratelimit) \
	{                            \
		0                        \
	}

/**
 * Packet modification struct with no modification enabled.
 */
#define default_pkt_mod        \
	(struct lf_config_pkt_mod) \
	{                          \
		0                      \
	}

/**
 * Initialize peer struct with default values.
 *
 * @param config_peer Struct to be initialized.
 */
void
peer_init(struct lf_config_peer *config_peer)
{
	*config_peer = (struct lf_config_peer){
		.drkey_protocol = rte_cpu_to_be_16(LF_DRKEY_PROTOCOL),
		.ip = 0,
		.isd_as = 1,
		.next = NULL,

		.shared_secret_configured_option = false,
		.shared_secrets = { 0 },

		/* per default no rate limit is defined for a peer */
		.ratelimit_option = false,
		.ratelimit = zero_ratelimit,
	};
}

/**
 * The rate limit struct consists of byte as well as packet rate and burst
 * sizes. Per default, all values are set to zero. If the burst size is not
 * provided, the value of the rate is used.
 *
 * @return Returns 0 on success.
 */
static int
parse_ratelimit(json_value *json_val, struct lf_config_ratelimit *ratelimit)
{

	int res, error_count = 0;
	unsigned int length;
	unsigned int i;
	char *field_name;
	json_value *field_value;
	bool packet_burst_set = false, byte_burst_set = false;

	/* Initialize ratelimit struct. Set all to 0. */
	(void)memset(ratelimit, 0, sizeof *ratelimit);

	if (json_val == NULL) {
		return -1;
	}

	if (json_val->type != json_object) {
		return -1;
	}

	length = json_val->u.object.length;

	for (i = 0; i < length; ++i) {
		field_name = json_val->u.object.values[i].name;
		field_value = json_val->u.object.values[i].value;

		if (strcmp(field_name, FIELD_BYTE_RATE) == 0) {
			res = lf_json_parse_uint64(field_value, &ratelimit->byte_rate);
			if (res != 0) {
				LF_LOG(ERR, "Invalid byte rate (%d:%d)\n", field_value->line,
						field_value->col);
				error_count++;
			}
		} else if (strcmp(field_name, FIELD_BYTE_BURST) == 0) {
			res = lf_json_parse_uint64(field_value, &ratelimit->byte_burst);
			if (res != 0) {
				LF_LOG(ERR, "Invalid byte burst (%d:%d)\n", field_value->line,
						field_value->col);
				error_count++;
			}
			byte_burst_set = true;
		} else if (strcmp(field_name, FIELD_PACKET_RATE) == 0) {
			res = lf_json_parse_uint64(field_value, &ratelimit->packet_rate);
			if (res != 0) {
				LF_LOG(ERR, "Invalid packet rate (%d:%d)\n", field_value->line,
						field_value->col);
				error_count++;
			}
		} else if (strcmp(field_name, FIELD_PACKET_BURST) == 0) {
			res = lf_json_parse_uint64(field_value, &ratelimit->packet_burst);
			if (res != 0) {
				LF_LOG(ERR, "Invalid packet burst (%d:%d)\n", field_value->line,
						field_value->col);
				error_count++;
			}
			packet_burst_set = true;
		} else {
			LF_LOG(ERR, "Unknown field %s (%d:%d)\n", field_name,
					field_value->line, field_value->col);
			error_count++;
		}
	}

	/* set default values for burst size */
	if (!byte_burst_set) {
		ratelimit->byte_burst = ratelimit->byte_rate;
	}
	if (!packet_burst_set) {
		ratelimit->packet_burst = ratelimit->packet_rate;
	}

	return 0;
}

/**
 * The shared_secret struct consists of a key and a timestamp.
 * This should be used for preconfigured keys.
 *
 * @return Returns 0 on success.
 */
static int
parse_shared_secret(json_value *json_val,
		struct lf_config_shared_secret *shared_secret)
{
	int res, error_count = 0;
	unsigned int length;
	unsigned int i;
	char *field_name;
	json_value *field_value;
	bool sv_flag = false, ts_flag = false;

	/* Initialize drkey struct. Set all to 0. */
	(void)memset(shared_secret, 0, sizeof *shared_secret);

	if (json_val == NULL) {
		return -1;
	}

	if (json_val->type != json_object) {
		return -1;
	}

	length = json_val->u.object.length;

	for (i = 0; i < length; ++i) {
		field_name = json_val->u.object.values[i].name;
		field_value = json_val->u.object.values[i].value;

		if (strcmp(field_name, FIELD_SECRET_VALUE) == 0) {
			res = lf_json_parse_byte_buffer(field_value, LF_CRYPTO_DRKEY_SIZE,
					shared_secret->sv);
			if (res != 0) {
				LF_LOG(ERR, "Invalid shared secret (%d:%d)\n",
						field_value->line, field_value->col);
				error_count++;
			}
			sv_flag = true;
		} else if (strcmp(field_name, FIELD_NOT_BEFORE) == 0) {
			res = lf_json_parse_timestamp(field_value,
					&shared_secret->not_before);
			if (res != 0) {
				LF_LOG(ERR, "Invalid timestamp (%d:%d)\n", field_value->line,
						field_value->col);
				error_count++;
			}
			ts_flag = true;
		} else {
			LF_LOG(ERR, "Unknown field %s (%d:%d)\n", field_name,
					field_value->line, field_value->col);
			error_count++;
		}
	}

	if (error_count > 0) {
		return -1;
	}

	if (!sv_flag || !ts_flag) {
		LF_LOG(ERR, "Invalid shared secret configuration. Need to define both "
					"secret value "
					"and not before timestamp.\n");
		return -1;
	}

	return 0;
}
static int
parse_shared_secret_list(json_value *json_val,
		struct lf_config_shared_secret shared_secret[LF_CONFIG_SV_MAX])
{
	unsigned int length;
	unsigned int i;
	unsigned int res;

	if (json_val == NULL) {
		return -1;
	}

	if (json_val->type != json_array) {
		return -1;
	}

	length = json_val->u.array.length;
	if (length > LF_CONFIG_SV_MAX) {
		LF_LOG(ERR, "Exceed shared secret limit (%d:%d)\n", json_val->line,
				json_val->col);
		return -1;
	}
	if (length < 1) {
		LF_LOG(ERR, "Must define at least one shared secret (%d:%d)\n",
				json_val->line, json_val->col);
		return -1;
	}

	for (i = 0; i < length; ++i) {
		res = parse_shared_secret(json_val->u.array.values[i],
				&shared_secret[i]);
		if (res != 0) {
			return -1;
		}
	}

	return 0;
}

static int
parse_peer(json_value *json_val, struct lf_config_peer *peer)
{
	int res;
	int error_count;
	unsigned int length;
	unsigned int i;
	char *field_name;
	json_value *field_value;

	if (json_val == NULL) {
		return -1;
	}

	if (json_val->type != json_object) {
		return -1;
	}

	length = json_val->u.object.length;
	error_count = 0;
	for (i = 0; i < length; ++i) {
		field_name = json_val->u.object.values[i].name;
		field_value = json_val->u.object.values[i].value;

		if (strcmp(field_name, FIELD_ISD_AS) == 0) {
			res = lf_json_parse_isd_as_be(field_value, &peer->isd_as);
			if (res != 0) {
				LF_LOG(ERR, "Invalid ISD AS address (%d:%d)\n",
						field_value->line, field_value->col);
				error_count++;
			}
		} else if (strcmp(field_name, FIELD_DRKEY_PROTOCOL) == 0) {
			res = lf_json_parse_uint16(field_value, &peer->drkey_protocol);
			if (res != 0) {
				LF_LOG(ERR, "Invalid ISD AS address (%d:%d)\n",
						field_value->line, field_value->col);
				error_count++;
			}
			/* set to network byte order */
			peer->drkey_protocol = rte_cpu_to_be_16(peer->drkey_protocol);
		} else if (strcmp(field_name, FIELD_IP) == 0) {
			res = lf_json_parse_ipv4(field_value, &peer->ip);
			if (res != 0) {
				LF_LOG(ERR, "Invalid IP address (%d:%d)\n", field_value->line,
						field_value->col);
				error_count++;
			}
		} else if (strcmp(field_name, FIELD_RATELIMIT) == 0) {
			res = parse_ratelimit(field_value, &peer->ratelimit);
			if (res != 0) {
				LF_LOG(ERR, "Invalid ratelimit (%d:%d)\n", field_value->line,
						field_value->col);
				error_count++;
			}
			peer->ratelimit_option = true;
		} else if (strcmp(field_name, FIELD_SHARED_SECRET) == 0) {
			res = parse_shared_secret_list(field_value, peer->shared_secrets);
			if (res != 0) {
				LF_LOG(ERR, "Invalid shared secret (%d:%d)\n",
						field_value->line, field_value->col);
				error_count++;
			}
			peer->shared_secret_configured_option = true;
		} else {
			LF_LOG(ERR, "Unknown field %s (%d:%d)\n", field_name,
					field_value->line, field_value->col);
			error_count++;
		}
	}

	if (error_count > 0) {
		return -1;
	} else {
		return 0;
	}
}

static int
parse_peer_list(json_value *json_val, struct lf_config *config)
{
	int res;
	unsigned int length;
	unsigned int i;
	json_value *peer_json_val;
	struct lf_config_peer *peer;
	struct lf_config_peer *current_peer, *next_peer;

	if (json_val == NULL) {
		return -1;
	}

	if (json_val->type != json_array) {
		return -1;
	}

	length = json_val->u.array.length;
	if (length > LF_CONFIG_PEERS_MAX) {
		LF_LOG(ERR, "Exceed peer limit (%d:%d)\n", json_val->line,
				json_val->col);
		return -1;
	}

	assert(config->peers == NULL);
	assert(config->nb_peers == 0);

	res = 0;
	for (i = 0; i < length; ++i) {
		/*
		 * Iterate the array in reverse order,
		 * such that the linked list is in same order.
		 */
		peer_json_val = json_val->u.array.values[length - 1 - i];

		/*
		 * Create new peer struct according the configuration.
		 */
		peer = malloc(sizeof(struct lf_config_peer));
		if (peer == NULL) {
			LF_LOG(ERR, "Failed to allocate memory for peer (%d:%d)\n",
					json_val->line, json_val->col);
			res = -1;
			break;
		}
		peer_init(peer);
		res = parse_peer(peer_json_val, peer);
		if (res != 0) {
			free(peer);
			break;
		}

		/*
		 * Extend peer list with new peer.
		 */
		peer->next = config->peers;
		config->peers = peer;
		config->nb_peers++;
	}

	if (res != 0) {
		/* Something went wrong. Remove all parsed peers. */
		current_peer = config->peers;
		while (current_peer != NULL) {
			next_peer = current_peer->next;
			free(current_peer);
			current_peer = next_peer;
		}
		config->nb_peers = 0;
		return -1;
	}

	return 0;
}

static int
parse_pkt_mod_ether(json_value *json_val, struct lf_config_pkt_mod *pkt_mod)
{
	int res;

	if (json_val->type != json_string) {
		goto err;
	}

	if (strcmp(json_val->u.string.ptr, VALUE_ETHER_SRC_ADDR) == 0) {
		pkt_mod->ether_switch = true;
		return 0;
	}

	res = lf_json_parse_ether(json_val, pkt_mod->ether);
	if (res == 0) {
		pkt_mod->ether_option = true;
		return 0;
	}

err:
	LF_LOG(ERR,
			"Invalid Ether field. Must be either %s or a valid Ethernet "
			"address (%d:%d)\n",
			VALUE_ETHER_SRC_ADDR, json_val->line, json_val->col);
	return -1;
}

static int
parse_pkt_mod(json_value *json_val, struct lf_config_pkt_mod *pkt_mod)
{
	int res = 0;
	int error_count;
	unsigned int length, i;
	char *field_name;
	json_value *field_value;

	if (json_val == NULL) {
		return -1;
	}

	if (json_val->type != json_object) {
		return -1;
	}

	length = json_val->u.object.length;
	error_count = 0;

	for (i = 0; i < length; ++i) {
		field_name = json_val->u.object.values[i].name;
		field_value = json_val->u.object.values[i].value;

		if (strcmp(field_name, FIELD_ETHER) == 0) {
			res = parse_pkt_mod_ether(field_value, pkt_mod);
			if (res != 0) {
				LF_LOG(ERR, "Invalid pkt mod Ether field (%d:%d)\n",
						field_value->line, field_value->col);
				error_count++;
			}
		} else if (strcmp(field_name, FIELD_IPV6) == 0) {
#if LF_IPV6
			res = lf_json_parse_ipv6(field_value, pkt_mod->ipv6);
			if (res != 0) {
				LF_LOG(ERR, "Invalid IPv6 address (%d:%d)\n", field_value->line,
						field_value->col);
				error_count++;
			}
#else
			LF_LOG(ERR, "Detected IPv6 address but IPv6 is disabled (%d:%d)\n",
					field_value->line, field_value->col);
			error_count++;
#endif
		} else if (strcmp(field_name, FIELD_IP) == 0) {
#if !LF_IPV6
			res = lf_json_parse_ipv4(field_value, &pkt_mod->ip);
			if (res != 0) {
				LF_LOG(ERR, "Invalid IPv4 address (%d:%d)\n", field_value->line,
						field_value->col);
				error_count++;
			}
			pkt_mod->ip_option = true;
#else
			LF_LOG(ERR, "Detected IPv4 address but IPv6 is enabled (%d:%d)\n",
					field_value->line, field_value->col);
			error_count++;
#endif
		} else {
			LF_LOG(ERR, "Unknown field %s (%d:%d)\n", field_name,
					field_value->line, field_value->col);
			error_count++;
		}
	}

	if (error_count > 0) {
		return -1;
	} else {
		return 0;
	}
}

static int
parse_auth_peers(json_value *json_val, struct lf_config_auth_peers *best_effort)
{
	int res;
	int error_count;
	unsigned int length;
	unsigned int i;
	char *field_name;
	json_value *field_value;

	if (json_val == NULL) {
		return -1;
	}

	if (json_val->type != json_object) {
		return -1;
	}

	length = json_val->u.object.length;
	error_count = 0;
	for (i = 0; i < length; ++i) {
		field_name = json_val->u.object.values[i].name;
		field_value = json_val->u.object.values[i].value;

		if (strcmp(field_name, FIELD_RATELIMIT) == 0) {
			res = parse_ratelimit(field_value, &best_effort->ratelimit);
			if (res != 0) {
				LF_LOG(ERR, "Invalid ratelimit (%d:%d)\n", field_value->line,
						field_value->col);
				error_count++;
			}
		} else {
			LF_LOG(ERR, "Unknown field %s (%d:%d)\n", field_name,
					field_value->line, field_value->col);
			error_count++;
		}
	}

	if (error_count > 0) {
		return -1;
	} else {
		return 0;
	}
}

static int
parse_best_effort(json_value *json_val,
		struct lf_config_best_effort *best_effort)
{
	int res;
	int error_count;
	unsigned int length;
	unsigned int i;
	char *field_name;
	json_value *field_value;

	if (json_val == NULL) {
		return -1;
	}

	if (json_val->type != json_object) {
		return -1;
	}

	length = json_val->u.object.length;
	error_count = 0;
	for (i = 0; i < length; ++i) {
		field_name = json_val->u.object.values[i].name;
		field_value = json_val->u.object.values[i].value;

		if (strcmp(field_name, FIELD_RATELIMIT) == 0) {
			res = parse_ratelimit(field_value, &best_effort->ratelimit);
			if (res != 0) {
				LF_LOG(ERR, "Invalid ratelimit (%d:%d)\n", field_value->line,
						field_value->col);
				error_count++;
			}
		} else {
			LF_LOG(ERR, "Unknown field %s (%d:%d)\n", field_name,
					field_value->line, field_value->col);
			error_count++;
		}
	}

	if (error_count > 0) {
		return -1;
	} else {
		return 0;
	}
}

/**
 * Configuration parser for destination ratelimiter plugin.
 */
static int
parse_dst_ratelimiter(json_value *json_val,
		struct lf_config_dst_ratelimiter *dst_ratelimiter)
{
	int res;
	int error_count;
	unsigned int length;
	unsigned int i;
	char *field_name;
	json_value *field_value;

#if !LF_PLUGIN_DST_RATELIMITER
	LF_LOG(CRIT,
			"Config for inactive plugin dst_ratelimiter detected (%d:%d)\n",
			json_val->line, json_val->col);
#endif

	if (json_val == NULL) {
		return -1;
	}

	if (json_val->type != json_object) {
		return -1;
	}

	length = json_val->u.object.length;
	error_count = 0;
	for (i = 0; i < length; ++i) {
		field_name = json_val->u.object.values[i].name;
		field_value = json_val->u.object.values[i].value;

		if (strcmp(field_name, FIELD_IP) == 0) {
			res = lf_json_parse_ipv4(field_value, &dst_ratelimiter->dst_ip);
			if (res != 0) {
				LF_LOG(ERR, "Invalid byte rate (%d:%d)\n", field_value->line,
						field_value->col);
				error_count++;
			}
		} else if (strcmp(field_name, FIELD_RATELIMIT) == 0) {
			res = parse_ratelimit(field_value, &dst_ratelimiter->ratelimit);
			if (res != 0) {
				LF_LOG(ERR, "Invalid byte rate (%d:%d)\n", field_value->line,
						field_value->col);
				error_count++;
			}
		} else {
			LF_LOG(ERR, "Unknown field %s (%d:%d)\n", field_name,
					field_value->line, field_value->col);
			error_count++;
		}
	}

	if (error_count > 0) {
		return -1;
	} else {
		return 0;
	}
}

/**
 * Configuration parser for WireGuard ratelimiter plugin.
 */
static int
parse_wg_ratelimiter(json_value *json_val,
		struct lf_config_wg_ratelimiter *wg_ratelimiter)
{
	int res;
	int error_count;
	unsigned int length;
	unsigned int i;
	char *field_name;
	json_value *field_value;

#if !LF_PLUGIN_WG_RATELIMITER
	LF_LOG(CRIT, "Config for inactive plugin wg_ratelimiter detected (%d:%d)\n",
			json_val->line, json_val->col);
#endif

	if (json_val == NULL) {
		return -1;
	}

	if (json_val->type != json_object) {
		return -1;
	}

	length = json_val->u.object.length;
	error_count = 0;
	for (i = 0; i < length; ++i) {
		field_name = json_val->u.object.values[i].name;
		field_value = json_val->u.object.values[i].value;

		if (strcmp(field_name, FIELD_PORT) == 0) {
			res = lf_json_parse_port(field_value, &wg_ratelimiter->wg_port);
			if (res != 0) {
				LF_LOG(ERR, "Invalid port number (%d:%d)\n", field_value->line,
						field_value->col);
				error_count++;
			}
		} else if (strcmp(field_name, FIELD_WG_RATELIMITER_HANDSHAKE) == 0) {
			res = parse_ratelimit(field_value,
					&wg_ratelimiter->handshake_ratelimit);
			if (res != 0) {
				LF_LOG(ERR, "Invalid byte rate (%d:%d)\n", field_value->line,
						field_value->col);
				error_count++;
			}
		} else if (strcmp(field_name, FIELD_WG_RATELIMITER_DATA) == 0) {
			res = parse_ratelimit(field_value, &wg_ratelimiter->data_ratelimit);
			if (res != 0) {
				LF_LOG(ERR, "Invalid byte rate (%d:%d)\n", field_value->line,
						field_value->col);
				error_count++;
			}
		} else {
			LF_LOG(ERR, "Unknown field %s (%d:%d)\n", field_name,
					field_value->line, field_value->col);
			error_count++;
		}
	}

	if (error_count > 0) {
		return -1;
	} else {
		return 0;
	}
}

/**
 * Main config json parsing function.
 * @return number of errors.
 */
static int
parse_config(json_value *json_val, struct lf_config *config)
{
	int res = 0;
	int error_count;
	unsigned int length, i;
	char *field_name;
	json_value *field_value;

	if (json_val == NULL) {
		return -1;
	}

	if (json_val->type != json_object) {
		return -1;
	}

	length = json_val->u.object.length;
	error_count = 0;
	for (i = 0; i < length; ++i) {
		field_name = json_val->u.object.values[i].name;
		field_value = json_val->u.object.values[i].value;

		if (strcmp(field_name, FIELD_ISD_AS) == 0) {
			res = lf_json_parse_isd_as_be(field_value, &config->isd_as);
			if (res != 0) {
				LF_LOG(ERR, "Invalid ISD AS field (%d:%d)\n", field_value->line,
						field_value->col);
				error_count++;
			}
		} else if (strcmp(field_name, FIELD_DRKEY_PROTOCOL) == 0) {
			res = lf_json_parse_uint16(field_value, &config->drkey_protocol);
			if (res != 0) {
				LF_LOG(ERR, "Invalid ISD AS address (%d:%d)\n",
						field_value->line, field_value->col);
				error_count++;
			}
			/* set to network byte order */
			config->drkey_protocol = rte_cpu_to_be_16(config->drkey_protocol);
		} else if (strcmp(field_name, FIELD_RATELIMIT) == 0) {
			res = parse_ratelimit(field_value, &config->ratelimit);
			if (res != 0) {
				LF_LOG(ERR, "Invalid overall rate limit (%u:%u)\n",
						field_value->line, field_value->col);
				error_count++;
			}
		} else if (strcmp(field_name, FIELD_PEERS) == 0) {
			res = parse_peer_list(field_value, config);
			if (res != 0) {
				LF_LOG(ERR, "Invalid peers (%u:%u)\n", field_value->line,
						field_value->col);
				error_count++;
			}
		} else if (strcmp(field_name, FIELD_INBOUND) == 0) {
			res = parse_pkt_mod(field_value, &config->inbound_next_hop);
			if (res != 0) {
				LF_LOG(ERR, "Invalid inbound config (%u:%u)\n",
						field_value->line, field_value->col);
				error_count++;
			}
		} else if (strcmp(field_name, FIELD_OUTBOUND) == 0) {
			res = parse_pkt_mod(field_value, &config->outbound_next_hop);
			if (res != 0) {
				LF_LOG(ERR, "Invalid outbound config (%u:%u)\n",
						field_value->line, field_value->col);
				error_count++;
			}
		} else if (strcmp(field_name, FIELD_AUTH_PEERS) == 0) {
			res = parse_auth_peers(field_value, &config->auth_peers);
			if (res != 0) {
				LF_LOG(ERR, "Invalid auth_peers config (%u:%u)\n",
						field_value->line, field_value->col);
				error_count++;
			}
		} else if (strcmp(field_name, FIELD_BEST_EFFORT) == 0) {
			res = parse_best_effort(field_value, &config->best_effort);
			if (res != 0) {
				LF_LOG(ERR, "Invalid best_effort config (%u:%u)\n",
						field_value->line, field_value->col);
				error_count++;
			}
		} else if (strcmp(field_name, FIELD_DRKEY_SERVICE_ADDR) == 0) {
			/* TODO: check addr format */
			res = lf_json_parse_string(field_value, config->drkey_service_addr,
					sizeof config->drkey_service_addr);
			if (res != 0) {
				LF_LOG(ERR, "Invalid DRKey service address (%u:%u)\n",
						field_value->line, field_value->col);
				error_count++;
			}
		} else if (strcmp(field_name, FIELD_PORT) == 0) {
			res = lf_json_parse_port(field_value, &config->port);
			if (res != 0) {
				LF_LOG(ERR, "Invalid port number (%u:%u)\n", field_value->line,
						field_value->col);
				error_count++;
			}
		} else if (strcmp(field_name, FIELD_IP_PUBLIC) == 0) {
			res = lf_json_parse_ipv4(field_value, &config->ip_public);
			if (res != 0) {
				LF_LOG(ERR, "Invalid public IP (%u:%u)\n", field_value->line,
						field_value->col);
				error_count++;
			}
			config->option_ip_public = true;
		} else if (strcmp(field_name, FIELD_DST_RATELIMITER) == 0) {
			res = parse_dst_ratelimiter(field_value, &config->dst_ratelimiter);
			if (res != 0) {
				LF_LOG(ERR, "Invalid dst ratelimiter config (%u:%u)\n",
						field_value->line, field_value->col);
				error_count++;
			}
		} else if (strcmp(field_name, FIELD_WG_RATELIMITER) == 0) {
			res = parse_wg_ratelimiter(field_value, &config->wg_ratelimiter);
			if (res != 0) {
				LF_LOG(ERR, "Invalid wg ratelimiter config (%u:%u)\n",
						field_value->line, field_value->col);
				error_count++;
			}
		} else {
			LF_LOG(ERR, "Unknown field %s (%d:%d)\n", field_name,
					field_value->line, field_value->col);
			error_count++;
		}
	}

	if (error_count > 0) {
		return -1;
	} else {
		return 0;
	}
}

struct lf_config *
lf_config_new_from_file(const char *filename)
{
	int res;
	struct lf_config *config;
	json_value *json_val;
	struct stat filestatus;
	size_t file_size;
	char *file_content;
	FILE *file;

	LF_LOG(DEBUG, "Parse config file %s\n", filename);

	file = fopen(filename, "rt");
	if (file == NULL) {
		LF_LOG(ERR, "Unable to open %s\n", filename);
		return NULL;
	}

	if (fstat(fileno(file), &filestatus) != 0) {
		LF_LOG(ERR, "Unable to fstat %s\n", filename);
		(void)fclose(file);
		return NULL;
	}

	file_size = filestatus.st_size;
	file_content = (char *)malloc(file_size);
	if (file_content == NULL) {
		LF_LOG(ERR, "Unable to allocate %d bytes\n", file_size);
		(void)fclose(file);
		return NULL;
	}

	if (fread(file_content, file_size, 1, file) != 1) {
		LF_LOG(ERR, "Unable to read content of %s\n", filename);
		(void)fclose(file);
		free(file_content);
		return NULL;
	}

	(void)fclose(file);

	/* Initialize config struct. Set all to 0. */
	config = lf_config_new();
	if (config == NULL) {
		free(file_content);
		return NULL;
	}

	json_val = json_parse(file_content, file_size);
	if (json_val == NULL) {
		LF_LOG(ERR, "Unable to parse json.\n");
		free(file_content);
		free(config);
		return NULL;
	}

	res = parse_config(json_val, config);
	if (res != 0) {
		LF_LOG(ERR, "Unable to parse config.\n");
		free(file_content);
		free(config);
		json_value_free(json_val);
		return NULL;
	}

	free(file_content);
	json_value_free(json_val);

	return config;
}

void
lf_config_init(struct lf_config *config)
{
	*config = (struct lf_config) {
		.isd_as = 0,
		.drkey_protocol = LF_DRKEY_PROTOCOL,

		/* Rate limits */
		.ratelimit = zero_ratelimit,
		.best_effort = {
			.ratelimit = zero_ratelimit,
		},

		/* Remote peers */
		.nb_peers = 0,
		.peers = NULL,

		/* Packet modifiers */
		.inbound_next_hop = default_pkt_mod,
		.outbound_next_hop = default_pkt_mod,

		/*
		 * SCION DRKey service
		 */
		.drkey_service_addr = {0},

		/*
		 * LF over IP options
		 */
		.port = rte_cpu_to_be_16(LF_DEFAULT_UDP_PORT),
		.option_ip_public = false,
		.ip_public = 0,

		/*
		 * Plugin configurations
		 */
		.wg_ratelimiter = {
			.wg_port = rte_cpu_to_be_16(51820),
			.data_ratelimit = zero_ratelimit,
			.handshake_ratelimit = zero_ratelimit,
		},
		.dst_ratelimiter = {
			.dst_ip = 0,
			.ratelimit = zero_ratelimit,
		},
	};
}

struct lf_config *
lf_config_new()
{
	struct lf_config *config;
	/* Initialize config struct. Set all to 0. */
	config = malloc(sizeof(*config));
	if (config != NULL) {
		lf_config_init(config);
		return config;
	} else {
		LF_LOG(ERR, "Unable to allocate config struct.\n");
		return NULL;
	}
}

void
lf_config_free(struct lf_config *config)
{
	struct lf_config_peer *current_peer, *next_peer;

	current_peer = config->peers;
	while (current_peer != NULL) {
		next_peer = current_peer->next;
		free(current_peer);
		current_peer = next_peer;
	}

	free(config);
}