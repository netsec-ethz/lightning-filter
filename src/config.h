/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#ifndef LF_CONFIG_H
#define LF_CONFIG_H

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>

#include "lib/crypto/crypto.h"

/**
 * This module defines the config structure and offers functionality to parse a
 * JSON configuration file, check its format, and return a C struct representing
 * the parsed configuration. For values that are not provided in the
 * configuration file, default values are set.
 */

#define LF_CONFIG_PEERS_MAX 1000000 /* 1'000'000 */

/*
 * Maximum number of SV that can be configured per peer
 */
#define LF_CONFIG_SV_MAX 5

/*
 * Rate limits are always defined for bytes and packets.
 */
struct lf_config_ratelimit {
	uint64_t byte_rate;
	uint64_t byte_burst;
	uint64_t packet_rate;
	uint64_t packet_burst;
};

struct lf_config_shared_secret {
	uint8_t sv[LF_CRYPTO_DRKEY_SIZE];
	uint64_t not_before;
};

struct lf_config_peer {
	/* peer identifier */
	uint64_t isd_as;         /* in network byte order */
	uint16_t drkey_protocol; /* in network byte order */

	/* rate limit */
	bool ratelimit_option; /* if a rate limit is defined */
	struct lf_config_ratelimit ratelimit;

	/* preconfigured shared keys */
	bool shared_secret_configured_option; /* if shared secrets are defined*/
	struct lf_config_shared_secret shared_secrets[LF_CONFIG_SV_MAX];

	/* LF-IP: ip -> isd_as map (TODO: move this to a separate map) */
	uint32_t ip; /* in network byte order */

	/*
	 * Pointer to the next peer (for the linked list represenation).
	 * Allows for an arbitrary number of peers.
	 */
	struct lf_config_peer *next;
};

struct lf_config_auth_peers {
	struct lf_config_ratelimit ratelimit;
};
struct lf_config_best_effort {
	struct lf_config_ratelimit ratelimit;
};

/**
 * Struct with optional packet fields to define packet modifications.
 */
struct lf_config_pkt_mod {
	/*
	 * Ethernet Layer Modifiers
	 * At most one option can be active!
	 */
	/* Switch destination and source Ethernet address */
	bool ether_switch;
	/* set destination Ethernet address to specific value */
	bool ether_option;
	uint8_t ether[6]; /* Ethernet destination address */

	/*
	 * IP Layer Modifiers
	 */
	/* set destination IP address to specific value */
	bool ip_option;
#if LF_IPV6
	uint8_t ipv6[16];
#else
	uint32_t ip; /* in network byte order */
#endif
};

struct lf_config_dst_ratelimiter {
	uint32_t dst_ip; /* in network byte order */
	struct lf_config_ratelimit ratelimit;
};

struct lf_config_wg_ratelimiter {
	uint16_t wg_port; /* in network byte order */
	struct lf_config_ratelimit handshake_ratelimit;
	struct lf_config_ratelimit data_ratelimit;
};

struct lf_config {
	/* Local ISD AS number */
	uint64_t isd_as; /* in network byte order */

	/*
	 * DRKey protocol number used for outbound traffic.
	 */
	uint16_t drkey_protocol; /* in network byte order */

	/* Overall rate limit */
	struct lf_config_ratelimit ratelimit;
	/* auth peers rate limit */
	struct lf_config_auth_peers auth_peers;
	/* best effort rate limit */
	struct lf_config_best_effort best_effort;

	/* Linked list of peers */
	size_t nb_peers;
	struct lf_config_peer *peers;

	/* Packet modifiers for inbound and outbound packets */
	struct lf_config_pkt_mod inbound_next_hop;
	struct lf_config_pkt_mod outbound_next_hop;

	/*
	 * SCION DRKey service
	 */
	/* address of control service */
	char drkey_service_addr[48]; /* "127.0.0.1:30255" */

	/*
	 * LF over IP options
	 */
	/* UDP port */
	uint16_t port; /* in network byte order */
	/* Optional public IP address to be used (e.g., behind a NAT) */
	bool option_ip_public;
	uint32_t ip_public; /* in network byte order */

	/*
	 * Plugins
	 */
	struct lf_config_dst_ratelimiter dst_ratelimiter;
	struct lf_config_wg_ratelimiter wg_ratelimiter;
};

/**
 * Initialize config struct with default values.
 * @param config Config struct to be initialized.
 */
void
lf_config_init(struct lf_config *config);

/**
 * Create new config struct from json file.
 * @return Returns new config struct if succeeds.
 * Otherwise, NULL.
 */
struct lf_config *
lf_config_new_from_file(const char *filename);

/**
 * Create new config struct with default values (see lf_config_init()).
 * @return Returns new config struct if succeeds.
 * Otherwise, NULL.
 */
struct lf_config *
lf_config_new();

/**
 * Free config struct memory.
 */
void
lf_config_free(struct lf_config *config);

#endif /* LF_CONFIG_H */