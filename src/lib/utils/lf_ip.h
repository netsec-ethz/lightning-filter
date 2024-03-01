/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#ifndef LF_IP_H
#define LF_IP_H

#include <stdint.h>

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_udp.h>

#include "../../worker.h"
#include "../crypto/crypto.h"
#include "packet.h"

struct lf_ip_hdr {
	uint64_t src_as;
	uint16_t drkey_protocol;         /* DRKey protocol (or payload length) */
	uint8_t rsv;                     /* reserved authenticated fields */
	uint8_t next_proto_id;           /* payload proto identifier */
	uint64_t timestamp;              /* timestamp in nanoseconds */
	uint8_t hash[20];                /* payload hash */
	uint8_t mac[LF_CRYPTO_MAC_SIZE]; /* lf header MAC */
} __attribute__((__packed__));

#define LF_ENCAPS_HDR_LEN \
	(sizeof(struct rte_udp_hdr) + sizeof(struct lf_ip_hdr))


static inline unsigned int
get_lf_hdr(const struct rte_mbuf *m, unsigned int offset,
		struct lf_ip_hdr **lf_hdr_ptr)
{
	if (unlikely(sizeof(struct lf_ip_hdr) > m->data_len - offset)) {
		LF_WORKER_LOG_DP(NOTICE,
				"Not yet implemented: LF header exceeds first buffer "
				"segment.\n");
		return 0;
	}

	*lf_hdr_ptr = rte_pktmbuf_mtod_offset(m, struct lf_ip_hdr *, offset);
	offset += sizeof(struct lf_ip_hdr);

	return offset;
}

/**
 * @param offset Offset to memory after the lf header.
 * @return Size of the UDP/LF header construct, which has been removed.
 */
static inline int
lf_decapsulate_pkt(struct rte_mbuf *m, unsigned int offset,
		struct rte_ipv4_hdr *ipv4_hdr, struct lf_ip_hdr *lf_hdr)
{
	/* reconstruct old IP header */
	ipv4_hdr->next_proto_id = lf_hdr->next_proto_id;
	ipv4_hdr->total_length = rte_cpu_to_be_16(
			rte_be_to_cpu_16(ipv4_hdr->total_length) - LF_ENCAPS_HDR_LEN);


	/* move everything before the udp/lf header */
	(void)memmove(rte_pktmbuf_mtod(m, uint8_t *) + LF_ENCAPS_HDR_LEN,
			rte_pktmbuf_mtod(m, uint8_t *), offset - LF_ENCAPS_HDR_LEN);

	/* move packet start in mbuf and adjust offset */
	(void)rte_pktmbuf_adj(m, LF_ENCAPS_HDR_LEN);

	return LF_ENCAPS_HDR_LEN;
}


/**
 * Add UDP and LF headers to encapsulate the IP payload.
 * The following IP header fields are adjusted:
 * payload_proto (= UDP), payload_length (= old_payload_lengt + sizeof(UDP/LF)).
 * The following UDP header fields are set:
 * dgram_len (= length of datagram).
 * The following LF header fields are set:
 * next_proto_id (= ipv4_hdr.next_proto_id)
 *
 * Other fields are not adjusted or set.
 *
 * @param offset Offset to memory after the ethernet and IP header.
 * @param l3_hdr Pointer to L3 header.
 * @param l3_proto L3 protocol type according to the ethernet header (network
 * byte order). Must be either IPV4 or IPV6!
 * @return Size of the UDP/LF headers, which have been added.
 * - Negative number if an error occurred.
 */
static inline int
lf_add_udp_lf_hdr(struct rte_mbuf *m, unsigned int offset, void *l3_hdr,
		uint16_t l3_proto, struct rte_udp_hdr **udp_hdr_ptr,
		struct lf_ip_hdr **lf_hdr_ptr)
{
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_ipv6_hdr *ipv6_hdr;
	struct rte_udp_hdr *udp_hdr;
	struct lf_ip_hdr *lf_hdr;

	/* Move packet start. Assume there is enough headroom */
	char *p = rte_pktmbuf_prepend(m, LF_ENCAPS_HDR_LEN);
	if (unlikely(p == NULL)) {
		LF_WORKER_LOG_DP(ERR,
				"Not enough headroom to add UDP/LF encapsulation headers.\n");
		return -1;
	}

	/* move memory and IP header ptr */
	(void)memmove(rte_pktmbuf_mtod(m, uint8_t *),
			rte_pktmbuf_mtod(m, uint8_t *) + LF_ENCAPS_HDR_LEN, offset);
	if (unlikely(LF_ENCAPS_HDR_LEN % 2 != 0)) {
		LF_WORKER_LOG_DP(ERR, "Ether header move ignores alignment of 2!\n");
		return -1;
	}
	l3_hdr = (void *)((uint8_t *)l3_hdr - LF_ENCAPS_HDR_LEN);

	offset = lf_get_udp_hdr(m, offset, &udp_hdr);
	if (unlikely(offset == 0)) {
		return -1;
	}

	offset = get_lf_hdr(m, offset, &lf_hdr);
	if (unlikely(offset == 0)) {
		return -1;
	}

	if (l3_proto == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
		ipv4_hdr = (struct rte_ipv4_hdr *)l3_hdr;

		/* generate LF Header */
		lf_hdr->next_proto_id = ipv4_hdr->next_proto_id;

		/* generate UDP Header */
		udp_hdr->dgram_len = rte_cpu_to_be_16(
				LF_ENCAPS_HDR_LEN + rte_be_to_cpu_16(ipv4_hdr->total_length) -
				rte_ipv4_hdr_len(ipv4_hdr));

		/* IP Header */
		ipv4_hdr->next_proto_id = IP_PROTO_ID_UDP;
		ipv4_hdr->total_length = rte_cpu_to_be_16(
				rte_be_to_cpu_16(ipv4_hdr->total_length) + LF_ENCAPS_HDR_LEN);
	} else {
		ipv6_hdr = (struct rte_ipv6_hdr *)l3_hdr;

		/* generate LF Header */
		lf_hdr->next_proto_id = ipv6_hdr->proto;

		/* generate UDP Header */
		udp_hdr->dgram_len = rte_cpu_to_be_16(
				rte_be_to_cpu_16(ipv6_hdr->payload_len) + LF_ENCAPS_HDR_LEN);

		/* IP Header */
		ipv6_hdr->proto = IP_PROTO_ID_UDP;
		ipv6_hdr->payload_len = rte_cpu_to_be_16(
				rte_be_to_cpu_16(ipv6_hdr->payload_len) + LF_ENCAPS_HDR_LEN);
	}
	*udp_hdr_ptr = udp_hdr;
	*lf_hdr_ptr = lf_hdr;
	return LF_ENCAPS_HDR_LEN;
}

#endif /* LF_IP_H */
