/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#include <arpa/inet.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <rte_byteorder.h>

#include "../config.h"
#include "../lib/utils/parse.h"

#define PRIIP "%d.%d.%d.%d"
#define PRIIP_VAL(ip) \
	(ip & 0xFF), ((ip >> 8) & 0xFF), ((ip >> 16) & 0xFF), ((ip >> 24) & 0xFF)

int
init_test1_config(struct lf_config *config)
{
	uint32_t ip_public, ip;
	uint64_t ia;

	inet_pton(AF_INET, "10.0.1.2", &ip);
	inet_pton(AF_INET, "100.200.50.150", &ip_public);
	*config = (struct lf_config){
		.isd_as = rte_cpu_to_be_64(0x000001000f00000001U), // 1-f:0:1
		.drkey_protocol = rte_cpu_to_be_64(3),

		.ratelimit = {
			.byte_rate = 9223372036854775807,
			.byte_burst = 9223372036854775807, /* per default same as rate */
			.packet_rate = 9223372036854775807,
			.packet_burst = 9223372036854775807, /* per default same as rate */
		},

		.auth_peers = {
			.ratelimit = {
				.byte_rate = 9223372036854775807,
				.byte_burst = 9223372036854775807, /* per default same as rate */
				.packet_rate = 9223372036854775807,
				.packet_burst = 9223372036854775807, /* per default same as rate */
			}
		},

		.best_effort = {
			.ratelimit = {
				.byte_rate = 9223372036854775807,
				.byte_burst = 9223372036854775807, /* per default same as rate */
				.packet_rate = 9223372036854775807,
				.packet_burst = 9223372036854775807, /* per default same as rate */
			}
		},

		.inbound_next_hop = {
				.ether_switch = true,
				.ether_option = false,
				.ip_option = true,
				.ip = ip,
		},
		.outbound_next_hop = {
				.ether_switch = false,
				.ether_option = true,
				.ether = { 0x00, 0x76, 0x65, 0x74, 0x68, 0x18 },
				.ip_option = true,
				.ip = ip,
		},

		.drkey_service_addr = "127.0.0.1:30255",

		.port = rte_cpu_to_be_16(49149),
		.option_ip_public = true,
		.ip_public = ip_public,
	
		/*
		 * Plugin configurations
		 */

		.dst_ratelimiter = {
			.dst_ip = ip,
			.ratelimit = {
				.byte_rate = 100000,
				.byte_burst = 100000,
				.packet_rate = 100000,
				.packet_burst = 100000,
			}
		},
		.wg_ratelimiter = {
			.wg_port = rte_cpu_to_be_16(51820),
			.handshake_ratelimit = {
				.byte_rate = 50000000,
				.byte_burst = 1000000,
				.packet_rate = 400000,
				.packet_burst = 400000,
			},
			.data_ratelimit = {
				.byte_rate = 5000000000,
				.byte_burst = 100000000,
				.packet_rate = 40000000,
				.packet_burst = 40000000,
			}
		},
	};

	struct lf_config_peer *peer0;
	peer0 = malloc(sizeof *peer0);
	*peer0 = (struct lf_config_peer){
		.isd_as = 0,
		.drkey_protocol = rte_cpu_to_be_16(3),
		.ratelimit_option = true,
		.ratelimit = {
			.byte_rate = 9223372036854775807,
			.byte_burst = 9223372036854775807, /* per default same as rate */
			.packet_rate = 9223372036854775807,
			.packet_burst = 9223372036854775807, /* per default same as rate */
		},
	};

	struct lf_config_peer *peer1;
	peer1 = malloc(sizeof *peer1);
	inet_pton(AF_INET, "10.248.2.1", &ip);
	*peer1 = (struct lf_config_peer){
		.isd_as = rte_cpu_to_be_64(0xffffffff0000ffffu), // 65535-ffff:0:ffff,
		.drkey_protocol = rte_cpu_to_be_16(0),
		.ip = ip,
		.ratelimit_option = true,
		.ratelimit = {
			.byte_rate = 1,
			.byte_burst = 1, /* per default same as rate */
			.packet_rate = 1,
			.packet_burst = 1, /* per default same as rate */
		},
	};

	struct lf_config_peer *peer2;
	peer1 = malloc(sizeof *peer2);
	lf_parse_isd_as("0-1", &ia);
	*peer1 = (struct lf_config_peer){
		.isd_as = rte_cpu_to_be_64(ia),
		.drkey_protocol = rte_cpu_to_be_16(0),
		.ratelimit_option = false,
	};

	config->nb_peers = 3;
	config->peers = peer0;
	peer0->next = peer1;
	peer1->next = NULL;

	return 0;
}

int
check_drkey_service_addr(char *addr, char addr_exp[48])
{
	if (memcmp(addr, addr_exp, 48) != 0) {
		printf("Error DRKey service addr: expected %s but got %s\n", addr_exp,
				addr);
		return 1;
	}
	return 0;
}

/**
 * Compare ether addresses.
 * If fails, error is printed and 1 is returned.
 * Otherwise, 0 is returned.
 */
int
check_ether(uint8_t ether[6], uint8_t ether_exp[6])
{
	if (memcmp(ether, ether_exp, 6) != 0) {
		printf("Error ether: expected %02x:%02x:%02x:%02x:%02x:%02x got "
			   "%02x:%02x:%02x:%02x:%02x:%02x\n",
				ether_exp[0], ether_exp[1], ether_exp[2], ether_exp[3],
				ether_exp[4], ether_exp[5], ether[0], ether[1], ether[2],
				ether[3], ether[4], ether[5]);
		return 1;
	}
	return 0;
}

int
check_ratelimit(struct lf_config_ratelimit *config,
		struct lf_config_ratelimit *config_exp)
{
	int error_count = 0;

	if (config->byte_rate != config_exp->byte_rate) {
		error_count++;
		printf("Error: byte_rate = %ld, expected = %ld\n", config->byte_rate,
				config_exp->byte_rate);
	}

	if (config->byte_burst != config_exp->byte_burst) {
		error_count++;
		printf("Error: byte_burst = %ld, expected = %ld\n", config->byte_burst,
				config_exp->byte_burst);
	}

	if (config->packet_rate != config_exp->packet_rate) {
		error_count++;
		printf("Error: packet_rate = %ld, expected = %ld\n",
				config->packet_rate, config_exp->packet_rate);
	}

	if (config->packet_burst != config_exp->packet_burst) {
		error_count++;
		printf("Error: packet_burst = %ld, expected = %ld\n",
				config->packet_burst, config_exp->packet_burst);
	}

	return error_count;
}

/**
 * Compare peer structs.
 * If fails, error is printed and number of errors is returned.
 * Otherwise, 0 is returned.
 */
int
check_peer(struct lf_config_peer *peer, struct lf_config_peer *peer_exp)
{
	int res;
	int error_count = 0;

	if (peer->isd_as != peer_exp->isd_as) {
		printf("Error: ids_as = %ld, expected = %ld\n", peer->isd_as,
				peer_exp->isd_as);
		error_count++;
	}

	if (peer->ip != peer_exp->ip) {
		printf("Error: ip = " PRIIP ", expected = " PRIIP "\n",
				PRIIP_VAL(peer->ip), PRIIP_VAL(peer_exp->ip));
		error_count++;
	}

	if (peer->ratelimit_option != peer_exp->ratelimit_option) {
		printf("Error: ratelimit_option = %d, expected = %d\n",
				peer->ratelimit_option, peer_exp->ratelimit_option);
		error_count++;
	}

	if (peer->ratelimit_option) {
		res = check_ratelimit(&peer->ratelimit, &peer_exp->ratelimit);
		if (res != 0) {
			printf("Error: peer rate limit");
			error_count += res;
		}
	}

	if (peer->drkey_protocol != peer_exp->drkey_protocol) {
		error_count++;
		printf("Error: drkey_protocol = %u, expected = %u\n",
				peer->drkey_protocol, peer_exp->drkey_protocol);
	}

	return error_count;
}

int
check_modifier(struct lf_config_pkt_mod *pmod,
		struct lf_config_pkt_mod *pmod_exp)
{
	int error_count = 0;

	if (pmod->ether_option != pmod_exp->ether_option) {
		printf("Error: ether_option = %d, expected = %d\n", pmod->ether_option,
				pmod_exp->ether_option);
		error_count++;
	}

	if (pmod->ip_option != pmod_exp->ip_option) {
		printf("Error: ip_option = %d, expected = %d\n", pmod->ip_option,
				pmod_exp->ip_option);
		error_count++;
	}

	if (pmod->ether_option) {
		if (check_ether(pmod->ether, pmod_exp->ether) != 0) {
			error_count++;
		}
	}

	if (pmod->ip_option) {
		if (pmod->ip != pmod_exp->ip) {
			printf("Error: ip = %d, expected = %d\n", pmod->ip, pmod_exp->ip);
			error_count++;
		}
	}

	return error_count;
}

int
check_ratelimiter()
{
	int error_count = 0;
	return error_count;
}

int
check_dst_ratelimiter(struct lf_config_dst_ratelimiter *config,
		struct lf_config_dst_ratelimiter *config_exp)
{
	int error_count = 0;

	if (config->dst_ip != config_exp->dst_ip) {
		error_count++;
		printf("Error: dst_ip = " PRIIP ", expected = " PRIIP "\n",
				PRIIP_VAL(config->dst_ip), PRIIP_VAL(config_exp->dst_ip));
	}

	error_count += check_ratelimit(&config->ratelimit, &config_exp->ratelimit);

	return error_count;
}

int
check_wg_ratelimiter(struct lf_config_wg_ratelimiter *config,
		struct lf_config_wg_ratelimiter *config_exp)
{
	int res;
	int error_count = 0;

	if (config->wg_port != config_exp->wg_port) {
		error_count++;
		printf("Error: wg_port = %d, expected = %d (big endian)\n",
				config->wg_port, config_exp->wg_port);
	}

	res = check_ratelimit(&config->handshake_ratelimit,
			&config_exp->handshake_ratelimit);
	if (res != 0) {
		printf("Error: handshake_ratelimit");
		error_count += res;
	}

	res = check_ratelimit(&config->data_ratelimit, &config_exp->data_ratelimit);
	if (res != 0) {
		printf("Error: data_ratelimit");
		error_count += res;
	}

	return error_count;
}

/**
 * Compare config structs ignoring peers.
 * If fails, error is printed and number of errors is returned.
 * Otherwise, 0 is returned.
 */
int
check_config(struct lf_config *config, struct lf_config *config_exp)
{
	int res;
	int error_count = 0;
	struct lf_config_peer *peer;
	struct lf_config_peer *peer_exp;
	int peer_counter;

	if (config_exp->isd_as != config->isd_as) {
		error_count++;
		printf("Error: ids_as = %ld, expected = %ld\n", config->isd_as,
				config_exp->isd_as);
	}

	res = check_ratelimit(&config->ratelimit, &config_exp->ratelimit);
	if (res != 0) {
		error_count += res;
	}

	if (check_drkey_service_addr(config->drkey_service_addr,
				config_exp->drkey_service_addr)) {
		error_count++;
	}

	res = check_ratelimit(&config->best_effort.ratelimit,
			&config_exp->best_effort.ratelimit);
	if (res != 0) {
		printf("Error: best-effort rate limit\n");
		error_count += res;
	}

	res = check_modifier(&config->inbound_next_hop,
			&config_exp->inbound_next_hop);
	if (res != 0) {
		printf("Error: Inbound\n");
		error_count += res;
	}

	res = check_modifier(&config->outbound_next_hop,
			&config_exp->outbound_next_hop);
	if (res != 0) {
		printf("Error: Outbound\n");
		error_count += res;
	}

	if (config_exp->port != config->port) {
		error_count++;
		printf("Error: port = %u, expected = %u (big endian)\n", config->port,
				config_exp->port);
	}

	if (config_exp->option_ip_public != config->option_ip_public) {
		error_count++;
		printf("Error: option_ip_public = %u, expected = %u (big endian)\n",
				config->option_ip_public, config_exp->option_ip_public);
	}

	if (config_exp->option_ip_public) {
		if (config_exp->ip_public != config->ip_public) {
			error_count++;
			printf("Error: ip_public = " PRIIP ", expected = " PRIIP
				   "(big endian)\n",
					PRIIP_VAL(config->ip_public),
					PRIIP_VAL(config_exp->ip_public));
		}
	}

	/* Config for plugins */
	res = check_dst_ratelimiter(&config->dst_ratelimiter,
			&config_exp->dst_ratelimiter);
	if (res != 0) {
		printf("Error: dst_ratelimiter\n");
		error_count += res;
	}

	res = check_wg_ratelimiter(&config->wg_ratelimiter,
			&config_exp->wg_ratelimiter);
	if (res != 0) {
		printf("Error: wg_ratelimiter\n");
		error_count += res;
	}

	if (config->nb_peers != config_exp->nb_peers) {
		error_count++;
		printf("Error: nb_peers = %ld, expected %ld\n", config->nb_peers,
				config_exp->nb_peers);
	} else {

		peer = config->peers;
		peer_exp = config_exp->peers;
		for (peer_counter = 0; peer_counter <= config->nb_peers;
				++peer_counter) {
			if (peer == NULL) {
				printf("Error: Found %d peers but nb_peers is %ld",
						peer_counter, config->nb_peers);
				error_count++;
				break;
			}
			if (peer_exp == NULL) {
				printf("Fatal: Expected structure is faulty: Found %d peers "
					   "but nb_peers is %ld",
						peer_counter, config->nb_peers);
				error_count++;
				break;
			}
			res = check_peer(peer, peer_exp);
			if (res != 0) {
				error_count += res;
				printf("Error: Peer number %d\n", peer_counter);
			}
		}
	}

	return error_count;
}

int
test1()
{
	int res;
	int error_count = 0;
	const char *filename = "config_parser_test1.json";

	struct lf_config *config;
	struct lf_config *config_exp;

	config_exp = lf_config_new();
	init_test1_config(config_exp);

	config = lf_config_new_from_file(filename);
	if (config == NULL) {
		printf("Error: lf_config_new_from_file");
		return 1;
	}

	res = check_config(config, config_exp);
	if (res != 0) {
		error_count += res;
	}

	lf_config_free(config);
	lf_config_free(config_exp);
	return error_count;
}

int
main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	int error_counter = 0;

	error_counter += test1();

	if (error_counter > 0) {
		printf("Error Count: %d\n", error_counter);
		return 1;
	}

	printf("All tests passed!\n");
	return 0;
}