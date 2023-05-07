/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#ifndef LF_UTILS_PACKET_H
#define LF_UTILS_PACKET_H

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include "../../lib/log/log.h"
#include "../../worker.h"

#define IP_PROTO_ID_UDP   0x11
#define IP_PROTO_ID_TCP   0x06
#define IP_PROTO_ID_ICMP  1
#define IP_PROTO_ID_ICMP6 58 // ICMP for IPv6

#define TCP_HDR_LEN(tcp_hdr) ((tcp_hdr)->data_off * 4)

#define PRIIPV6 \
	"%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x"
#define PRIIPV6_VAL(ipv6)                                             \
	(ipv6)[0], (ipv6)[1], (ipv6)[2], (ipv6)[3], (ipv6)[4], (ipv6)[5], \
			(ipv6)[6], (ipv6)[7], (ipv6)[8], (ipv6)[9], (ipv6)[10],   \
			(ipv6)[11], (ipv6)[12], (ipv6)[13], (ipv6)[14], (ipv6)[15]

#define PRIIP "%d.%d.%d.%d"
#define PRIIP_VAL(ip)                                         \
	((ip)&0xFF), (((ip) >> 8) & 0xFF), (((ip) >> 16) & 0xFF), \
			(((ip) >> 24) & 0xFF)

static inline unsigned int
lf_get_eth_hdr(const struct lf_worker_context *worker_context,
		const struct rte_mbuf *m, unsigned int offset,
		struct rte_ether_hdr **ether_hdr_ptr)
{
	if (unlikely(sizeof(struct rte_ether_hdr) > m->data_len - offset)) {
		LF_WORKER_LOG(NOTICE,
				"Unsupported packet: Ethernet header exceeds first buffer "
				"segment.\n");
		return 0;
	}

	*ether_hdr_ptr = rte_pktmbuf_mtod_offset(m, struct rte_ether_hdr *, offset);
	offset += sizeof(struct rte_ether_hdr);

	return offset;
	(void)worker_context;
}

struct lf_ether_hdr_aligned {
	uint8_t val1;
	uint8_t val2;
} __rte_aligned(2);
/**
 * The rte_ether_hdr has to be 2 byte aligned!
 * The function lf_ether_hdr_move should be used when moving the rte_ether_hdr
 * by an offset. Important: The offset must be
 */
#define lf_ether_hdr_move(ether_hdr, offset)                              \
	(struct rte_ether_hdr *)((struct lf_ether_hdr_aligned *)(ether_hdr) + \
							 ((offset) /                                  \
									 (int)_Alignof(                       \
											 struct lf_ether_hdr_aligned)))


static inline unsigned int
lf_get_ipv6_hdr(const struct lf_worker_context *worker_context,
		const struct rte_mbuf *m, unsigned int offset,
		struct rte_ipv6_hdr **ipv6_hdr_ptr)
{
	if (unlikely(sizeof(struct rte_ipv6_hdr) > m->data_len - offset)) {
		LF_WORKER_LOG(NOTICE,
				"Unsupported packet: IPv6 header exceeds first buffer "
				"segment.\n");
		return 0;
	}

	*ipv6_hdr_ptr = rte_pktmbuf_mtod_offset(m, struct rte_ipv6_hdr *, offset);

	return offset + sizeof(struct rte_ipv6_hdr);
	(void)worker_context;
}

static inline unsigned int
lf_get_ip_hdr(const struct lf_worker_context *worker_context,
		const struct rte_mbuf *m, unsigned int offset,
		struct rte_ipv4_hdr **ipv4_hdr_ptr)
{
	uint16_t ipv4_hdr_length;

	if (unlikely(sizeof(struct rte_ipv4_hdr) > m->data_len - offset)) {
		LF_WORKER_LOG(NOTICE,
				"Unsupported packet: IP header exceeds first buffer "
				"segment.\n");
		return 0;
	}

	*ipv4_hdr_ptr = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, offset);
	ipv4_hdr_length = rte_ipv4_hdr_len(*ipv4_hdr_ptr);

	if (unlikely(ipv4_hdr_length < sizeof(struct rte_ipv4_hdr))) {
		LF_WORKER_LOG(NOTICE, "Invalid IP header: length too small.\n");
		return 0;
	}

	if (unlikely(ipv4_hdr_length > m->data_len - offset)) {
		LF_WORKER_LOG(NOTICE,
				"Not yet implemented: IP header exceeds first buffer "
				"segment.\n");
		return 0;
	}

	offset += ipv4_hdr_length;

	return offset;
	(void)worker_context;
}

static inline unsigned int
lf_get_udp_hdr(const struct lf_worker_context *worker_context,
		const struct rte_mbuf *m, unsigned int offset,
		struct rte_udp_hdr **udp_hdr_ptr)
{
	if (unlikely(sizeof(struct rte_udp_hdr) > m->data_len - offset)) {
		LF_WORKER_LOG(NOTICE,
				"Not yet implemented: UDP header exceeds first buffer "
				"segment.\n");
		return 0;
	}

	*udp_hdr_ptr = rte_pktmbuf_mtod_offset(m, struct rte_udp_hdr *, offset);
	offset += sizeof(struct rte_udp_hdr);
	return offset;
	(void)worker_context;
}

static inline unsigned int
lf_get_tcp_hdr(const struct lf_worker_context *worker_context,
		const struct rte_mbuf *m, unsigned int offset,
		struct rte_tcp_hdr **tcp_hdr_ptr)
{
	if (unlikely(sizeof(struct rte_tcp_hdr) > m->data_len - offset)) {
		LF_WORKER_LOG(NOTICE,
				"Not yet implemented: TCP header exceeds first buffer "
				"segment.\n");
		return 0;
	}

	*tcp_hdr_ptr = rte_pktmbuf_mtod_offset(m, struct rte_tcp_hdr *, offset);
	offset += sizeof(struct rte_tcp_hdr);
	return offset;
	(void)worker_context;
}

/**
 * Fix L2 and L3 checksum.
 * @param offload_cksum: Boolean to indicate if checksum calculation should be
 * offloaded to the port.
 */
static inline void
lf_pktv6_set_cksum(const struct lf_worker_context *worker_context,
		struct rte_mbuf *m, const struct rte_ether_hdr *ether_hdr,
		struct rte_ipv6_hdr *ipv6_hdr, bool offload_cksum)
{
	unsigned int offset = sizeof(*ether_hdr) + sizeof(*ipv6_hdr);

	m->l2_len = sizeof(*ether_hdr);
	m->l3_len = sizeof(*ipv6_hdr);

	if (offload_cksum) {
		m->ol_flags |= RTE_MBUF_F_TX_IPV6;

		if (ipv6_hdr->proto == IP_PROTO_ID_UDP) {
			struct rte_udp_hdr *udp_hdr;
			offset = lf_get_udp_hdr(worker_context, m, offset, &udp_hdr);
			if (offset == 0) {
				return;
			}
			m->l4_len = sizeof(struct rte_udp_hdr);
			m->ol_flags |= RTE_MBUF_F_TX_UDP_CKSUM;
			udp_hdr->dgram_cksum = rte_ipv6_phdr_cksum(ipv6_hdr, m->ol_flags);
		} else if (ipv6_hdr->proto == IP_PROTO_ID_TCP) {
			struct rte_tcp_hdr *tcp_hdr;
			offset = lf_get_tcp_hdr(worker_context, m, offset, &tcp_hdr);
			if (offset == 0) {
				return;
			}
			m->l4_len = sizeof(struct rte_tcp_hdr);
			m->ol_flags |= RTE_MBUF_F_TX_TCP_CKSUM;
			tcp_hdr->cksum = rte_ipv6_phdr_cksum(ipv6_hdr, m->ol_flags);
		}
	} else {
		if (ipv6_hdr->proto == IP_PROTO_ID_UDP) {
			struct rte_udp_hdr *udp_hdr;
			offset = lf_get_udp_hdr(worker_context, m, offset, &udp_hdr);
			if (offset == 0) {
				return;
			}
			udp_hdr->dgram_cksum = 0;
			udp_hdr->dgram_cksum = rte_ipv6_udptcp_cksum(ipv6_hdr, udp_hdr);
		} else if (ipv6_hdr->proto == IP_PROTO_ID_TCP) {
			struct rte_tcp_hdr *tcp_hdr;
			offset = lf_get_tcp_hdr(worker_context, m, offset, &tcp_hdr);
			if (offset == 0) {
				return;
			}
			tcp_hdr->cksum = 0;
			tcp_hdr->cksum = rte_ipv6_udptcp_cksum(ipv6_hdr, tcp_hdr);
		}
	}
}

/**
 * Fix L2 and L3 checksum.
 * @param offload_cksum: Boolean to indicate if checksum calculation should be
 * offloaded to the port.
 */
static inline void
lf_pkt_set_cksum(const struct lf_worker_context *worker_context,
		struct rte_mbuf *m, const struct rte_ether_hdr *ether_hdr,
		struct rte_ipv4_hdr *ipv4_hdr, bool offload_cksum)
{
	unsigned int offset = sizeof(*ether_hdr) + rte_ipv4_hdr_len(ipv4_hdr);

	m->l2_len = sizeof(*ether_hdr);
	m->l3_len = rte_ipv4_hdr_len(ipv4_hdr);

	if (offload_cksum) {
		m->ol_flags |= RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM;
		ipv4_hdr->hdr_checksum = 0;

		if (ipv4_hdr->next_proto_id == IP_PROTO_ID_UDP) {
			struct rte_udp_hdr *udp_hdr;
			offset = lf_get_udp_hdr(worker_context, m, offset, &udp_hdr);
			if (offset == 0) {
				return;
			}
			m->l4_len = sizeof(struct rte_udp_hdr);
			m->ol_flags |= RTE_MBUF_F_TX_UDP_CKSUM;
			udp_hdr->dgram_cksum = rte_ipv4_phdr_cksum(ipv4_hdr, m->ol_flags);
		} else if (ipv4_hdr->next_proto_id == IP_PROTO_ID_TCP) {
			struct rte_tcp_hdr *tcp_hdr;
			offset = lf_get_tcp_hdr(worker_context, m, offset, &tcp_hdr);
			if (offset == 0) {
				return;
			}
			m->l4_len = sizeof(struct rte_tcp_hdr);
			m->ol_flags |= RTE_MBUF_F_TX_TCP_CKSUM;
			tcp_hdr->cksum = rte_ipv4_phdr_cksum(ipv4_hdr, m->ol_flags);
		}
	} else {
		ipv4_hdr->hdr_checksum = 0;
		if (ipv4_hdr->next_proto_id == IP_PROTO_ID_UDP) {
			struct rte_udp_hdr *udp_hdr;
			offset = lf_get_udp_hdr(worker_context, m, offset, &udp_hdr);
			if (offset == 0) {
				return;
			}
			udp_hdr->dgram_cksum = 0;
			udp_hdr->dgram_cksum = rte_ipv4_udptcp_cksum(ipv4_hdr, udp_hdr);
		} else if (ipv4_hdr->next_proto_id == IP_PROTO_ID_TCP) {
			struct rte_tcp_hdr *tcp_hdr;
			offset = lf_get_tcp_hdr(worker_context, m, offset, &tcp_hdr);
			if (offset == 0) {
				return;
			}
			tcp_hdr->cksum = 0;
			tcp_hdr->cksum = rte_ipv4_udptcp_cksum(ipv4_hdr, tcp_hdr);
		}
		ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);
	}
}

struct lf_icmpv6_hdr {
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
};

static inline unsigned int
lf_get_icmpv6_hdr(const struct lf_worker_context *worker_context,
		const struct rte_mbuf *m, unsigned int offset,
		struct lf_icmpv6_hdr **icmpv6_hdr_ptr)
{
	if (unlikely(sizeof(struct lf_icmpv6_hdr) > m->data_len - offset)) {
		LF_WORKER_LOG(NOTICE,
				"Unsupported packet: ICMPv6 header exceeds first buffer "
				"segment.\n");
		return 0;
	}

	*icmpv6_hdr_ptr =
			rte_pktmbuf_mtod_offset(m, struct lf_icmpv6_hdr *, offset);

	return offset + sizeof(struct lf_icmpv6_hdr);
	(void)worker_context;
}

#endif /* LF_UTILS_PACKET_H */
