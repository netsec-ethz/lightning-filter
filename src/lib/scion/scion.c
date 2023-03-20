/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#include <rte_udp.h>

#include "../../worker.h"
#include "../utils/packet.h"
#include "scion.h"

unsigned int
scion_skip_gateway_frame_hdr(const struct lf_worker_context *worker_context,
		const struct rte_mbuf *m, unsigned int offset, uint16_t frame_len,
		struct rte_ipv4_hdr **enc_ipv4_hdr)
{
	struct scion_gateway_frame_hdr *frame_hdr;
	struct rte_ipv4_hdr *ipv4_hdr;

	offset = scion_get_gateway_frame_hdr(worker_context, m, offset, &frame_hdr);
	if (offset == 0) {
		return 0;
	}

	if (frame_hdr->version != 0) {
		LF_WORKER_LOG(NOTICE, "Unknown SIG frame header version (%u)\n",
				frame_hdr->version);
		return 0;
	}

	if (rte_be_to_cpu_16(frame_hdr->index) != 0) {
		LF_WORKER_LOG(NOTICE,
				"Not yet implemented: SIG frame contains trailing "
				"part of an IP packet.\n");
		return 0;
	}

	if ((frame_hdr->reserved_stream &
				rte_cpu_to_be_32(SCION_GATEWAY_FRAME_RSV_MASK)) != 0) {
		LF_WORKER_LOG(DEBUG,
				"Unknown SIG frame header reserved fields (%X).\n");
		return 0;
	}

	offset = lf_get_ip_hdr(worker_context, m, offset, &ipv4_hdr);
	if (offset == 0) {
		return 0;
	}

	if (frame_len != sizeof(struct scion_gateway_frame_hdr) +
							 rte_be_to_cpu_16(ipv4_hdr->total_length)) {
		LF_WORKER_LOG(NOTICE,
				"SIG frame length (%u) does not match SCION/UDP payload length "
				"(%u). The frame potentially contains multiple IP packets (not "
				"supported yet).\n",
				sizeof(struct scion_gateway_frame_hdr) +
						rte_be_to_cpu_16(ipv4_hdr->total_length),
				frame_len);
		return 0;
	}

	*enc_ipv4_hdr = ipv4_hdr;
	return offset;
}

int
scion_skip_gateway(const struct lf_worker_context *worker_context,
		uint16_t sig_port, const struct rte_mbuf *m,
		struct rte_ipv4_hdr **enc_ipv4_hdr)
{
	unsigned int offset;
	struct rte_ether_hdr *ether_hdr;
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_udp_hdr *udp_hdr;
	struct scion_cmn_hdr *scion_cmn_hdr;
	struct rte_udp_hdr *scion_udp_hdr;
	uint8_t next_hdr;

	if (unlikely(m->data_len != m->pkt_len)) {
		LF_WORKER_LOG(NOTICE,
				"Not yet implemented: buffer with multiple segments "
				"received.\n");
		return -1;
	}

	offset = 0;
	offset = lf_get_eth_hdr(worker_context, m, offset, &ether_hdr);
	if (unlikely(offset == 0)) {
		return -1;
	}

	if (unlikely(ether_hdr->ether_type !=
				 rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))) {
		LF_WORKER_LOG(NOTICE,
				"Unsupported packet type %#X: must be IPv4 (%#X).\n",
				rte_be_to_cpu_16(ether_hdr->ether_type), RTE_ETHER_TYPE_IPV4);
		return 0;
	}

	offset = lf_get_ip_hdr(worker_context, m, offset, &ipv4_hdr);
	if (unlikely(offset == 0)) {
		return -1;
	}
	if (ipv4_hdr->next_proto_id != IP_PROTO_ID_UDP) {
		/* Probably intra AS traffic: forward without checks */
		/* TODO: add flow classification */
		LF_WORKER_LOG(DEBUG, "IPv4 packet type is not UDP (%#X) but %#X.\n",
				IP_PROTO_ID_UDP, ipv4_hdr->next_proto_id);
		return 0;
	}

	offset = lf_get_udp_hdr(worker_context, m, offset, &udp_hdr);
	if (unlikely(offset == 0)) {
		return -1;
	}
	/* TODO: check UDP port is SCION port */

	if (scion_get_cmn_hdr(worker_context, m, offset, &scion_cmn_hdr) == 0) {
		return -1;
	}
	offset += SCION_HDR_LEN(scion_cmn_hdr);
	if (unlikely(offset > m->data_len)) {
		LF_WORKER_LOG(NOTICE,
				"Not yet implemented: SCION header exceeds first buffer "
				"segment.\n");
		return -1;
	}

	offset = scion_skip_extension_hdr(worker_context, m, scion_cmn_hdr, offset,
			&next_hdr);
	if (offset == 0) {
		return -1;
	}
	if (next_hdr != IPPROTO_UDP) {
		LF_WORKER_LOG(DEBUG, "SCION packet type is not UDP (%#X) but %#X.\n",
				IPPROTO_UDP, next_hdr);
		return 0;
	}

	offset = lf_get_udp_hdr(worker_context, m, offset, &scion_udp_hdr);
	if (offset == 0) {
		return -1;
	}
	if (rte_be_to_cpu_16(scion_udp_hdr->dst_port) != sig_port) {
		LF_WORKER_LOG(DEBUG, "SCION UDP port is not SIG port (%u) but %u.\n",
				sig_port, rte_be_to_cpu_16(scion_udp_hdr->dst_port));
		return 0;
	}

	offset = scion_skip_gateway_frame_hdr(worker_context, m, offset,
			rte_be_to_cpu_16(scion_udp_hdr->dgram_len) -
					sizeof(struct rte_udp_hdr),
			enc_ipv4_hdr);
	if (offset == 0) {
		return -1;
	}

	assert(offset <= INT_MAX);
	return (int)offset;
}
