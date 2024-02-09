/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#include <stdint.h>

#include <rte_branch_prediction.h>
#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_mbuf_core.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include "config.h"
#include "configmanager.h"
#include "lf.h"
#include "lib/crypto/crypto.h"
#include "lib/scion/scion.h"
#include "lib/utils/packet.h"
#include "statistics.h"
#include "worker.h"

struct scion_mac_input {
	// scion authenticator option metadata
	uint8_t hdr_len;
	uint8_t payload_protocol;
	uint16_t payload_length;
	uint8_t algorithm;
	uint8_t time_stamp[3];
	uint8_t reserved;
	uint8_t sequence_number[3];

	// hash
	uint8_t hash[20];
} __attribute__((__packed__));

#define SPAO_GET_MAC_INPUT(spao_hdr) \
	((struct scion_mac_input *)((uint8_t *)(spao_hdr) + 2))

/**
 * Structure to store information of a parsed inter-AS packet, which is supposed
 * to be handled by LightningFilter.
 */
struct parsed_pkt {
	struct rte_ether_hdr *ether_hdr;
	union {
		void *l3_hdr;
		struct rte_ipv4_hdr *ipv4_hdr;
		struct rte_ipv6_hdr *ipv6_hdr;
	};
	struct rte_udp_hdr *udp_hdr;

	struct scion_cmn_hdr *scion_cmn_hdr;

	struct scion_addr_ia_hdr *scion_addr_ia_hdr;
	uint32_t scion_addr_hdr_len;

	void *scion_path_hdr;
	uint32_t scion_path_hdr_len;
	uint32_t path_timestamp;

	/* Offset to the memory after the SCION path,
	 * i.e., to the payload or SCION extension headers. */
	unsigned int offset;

	struct scion_pao *spao_hdr;
};

/**
 * Move pointers in the parsed_pkt struct by a certain offset.
 */
static inline void
pkt_hdrs_move(struct parsed_pkt *parsed_pkt, int offset)
{
	parsed_pkt->ether_hdr = lf_ether_hdr_move(parsed_pkt->ether_hdr, offset);
	parsed_pkt->l3_hdr = (void *)((uint8_t *)parsed_pkt->l3_hdr + offset);
	parsed_pkt->udp_hdr =
			(struct rte_udp_hdr *)((uint8_t *)parsed_pkt->udp_hdr + offset);
	parsed_pkt->scion_cmn_hdr =
			(struct scion_cmn_hdr *)((uint8_t *)parsed_pkt->scion_cmn_hdr +
									 offset);
	parsed_pkt->scion_addr_ia_hdr = (struct scion_addr_ia_hdr
					*)((uint8_t *)parsed_pkt->scion_addr_ia_hdr + offset);
	parsed_pkt->scion_path_hdr =
			(void *)((uint8_t *)parsed_pkt->scion_path_hdr + offset);
}

/**
 * Structure to store SPAO data, as well as, payload information.
 * Furthermore, this structure also acts as storage for values that are
 * temporarily overwritten for the MAC computation.
 */
struct parsed_spao {
	/* Pointer to the SPAO header. */
	struct scion_packet_authenticator_opt *spao_hdr;

	/* Protocol of the next layer */
	uint8_t payload_protocol;
	/* Offset to the next layer */
	unsigned int payload_offset;
	/* Length of the next layer. */
	unsigned int payload_length;

	/*
	 * Temporary storage for overwritten values.
	 */
	uint8_t hdr_len_old;
	uint8_t upper_layer_protocol_old;
	uint16_t upper_layer_length_old;
};

/**
 * @param offset: Offset to header after SCION common, address and path header
 * @param next_hdr_ptr: Return next hdr protocol number.
 * @return length of SCION extension headers on success. If the packet does not
 * contain a SPAO header, 0 is returned. If an error occurs a negative number is
 * returned.
 */
static inline int
get_spao_hdr(const struct rte_mbuf *m, unsigned int offset,
		const struct scion_cmn_hdr *scion_cmn_hdr,
		struct scion_packet_authenticator_opt **spao_hdr_ptr, uint8_t *next_hdr)
{
	struct scion_ext_hdr *scion_ext_hdr;
	struct scion_ext_tlv_hdr *tlv_hdr;
	int ext_hdr_len;
	unsigned int offset_max;

	*next_hdr = scion_cmn_hdr->next_hdr;

	ext_hdr_len = 0;

	/* skip HBH header and adjust next_hdr and offset*/
	if (likely(*next_hdr == SCION_PROTOCOL_HBH)) {
		if (unlikely(scion_get_ext_hdr(m, offset, &scion_ext_hdr) == 0)) {
			return -1;
		}

		offset += SCION_EXT_HDR_LEN(scion_ext_hdr);
		if (unlikely(offset > m->data_len)) {
			LF_WORKER_LOG_DP(NOTICE,
					"SCION HBH extension header length (%u) larger than "
					"data len (%u).",
					SCION_EXT_HDR_LEN(scion_ext_hdr), m->data_len);
			return -1;
		}
		ext_hdr_len += SCION_EXT_HDR_LEN(scion_ext_hdr);

		*next_hdr = scion_ext_hdr->next_hdr;
	}

	/* check if E2E extension headers are present */
	if (unlikely(*next_hdr != SCION_PROTOCOL_E2E)) {
		LF_WORKER_LOG_DP(NOTICE, "No SCION E2E extension header found.\n");
		/* No SPAO header detected */
		return 0;
	}

	if (unlikely(scion_get_ext_hdr(m, offset, &scion_ext_hdr) == 0)) {
		return -1;
	}
	*next_hdr = scion_ext_hdr->next_hdr;

	/* get and check size of scion extension header */
	offset_max = offset + SCION_EXT_HDR_LEN(scion_ext_hdr);
	if (unlikely(offset_max > m->data_len)) {
		LF_WORKER_LOG_DP(NOTICE,
				"SCION E2E extension header length (%u) larger than data "
				"len (%u).",
				SCION_EXT_HDR_LEN(scion_ext_hdr), m->data_len);
		return -1;
	}
	ext_hdr_len += SCION_EXT_HDR_LEN(scion_ext_hdr);

	/* skip E2E header */
	offset += 2;
	while (offset < offset_max) {
		tlv_hdr =
				rte_pktmbuf_mtod_offset(m, struct scion_ext_tlv_hdr *, offset);
		if (tlv_hdr->type == SCION_E2E_OPTION_TYPE_SPAO) {
			/* found a SPAO header */
			if (tlv_hdr->data_len + 2 + offset > offset_max) {
				LF_WORKER_LOG_DP(NOTICE, "Invalid SCION packet: SPAO length "
										 "exceeds extension header length.\n");
				return -1;
			}

			if (tlv_hdr->data_len + 2 !=
					sizeof(struct scion_packet_authenticator_opt)) {
				/* incompatible SPAO size */
				return -1;
			}
			*spao_hdr_ptr =
					(struct scion_packet_authenticator_opt *)(void *)tlv_hdr;

			return ext_hdr_len;
		} else if (tlv_hdr->type == SCION_E2E_OPTION_TYPE_PAD1) {
			offset += 1;
		} else {
			offset += 2 + tlv_hdr->data_len;
		}
	}

	/* No SPAO header detected */
	return 0;
}

/**
 * @param drkey_epoch_start_ns: in nanoseconds (CPU endian)
 * @param timestamp: current (unique) timestamp in nanoseconds (CPU endian)
 */
static inline int
set_spao_timestamp(uint64_t drkey_epoch_start_ns, uint64_t timestamp,
		struct scion_packet_authenticator_opt *spao_hdr)
{
	uint64_t relative_timestamp;

	if (unlikely(drkey_epoch_start_ns > timestamp)) {
		LF_WORKER_LOG_DP(NOTICE,
				"Path timestamp (%" PRIu64 "ms) is in the future (now: %" PRIu64
				").\n",
				drkey_epoch_start_ns, timestamp);
#if !LF_WORKER_IGNORE_PATH_TIMESTAMP_CHECK
		return -1;
#endif
	}

	relative_timestamp = timestamp - drkey_epoch_start_ns;

	/* ensure that timestamp fits into 6 bytes */
	if (unlikely(relative_timestamp >> 48)) {
		LF_WORKER_LOG_DP(NOTICE,
				"Path timestamp (%" PRIu64
				" ns) is too far in the past (relative_timestamp: %" PRIu64
				").\n",
				drkey_epoch_start_ns, relative_timestamp);
#if !LF_WORKER_IGNORE_PATH_TIMESTAMP_CHECK
		return -1;
#endif
	}

	/* Set header fields */
	scion_spao_set_timestamp(spao_hdr, relative_timestamp);
	return 0;
}

static inline int
hash_cmn_hdr(struct lf_crypto_hash_ctx *ctx,
		struct scion_cmn_hdr *scion_cmn_hdr)
{
	uint8_t ecn_old;

	ecn_old = scion_cmn_hdr->version_qos_flowid[1];
	scion_cmn_hdr->version_qos_flowid[1] &= 0xCF; // 0b11001111;
	lf_crypto_hash_update(ctx, (uint8_t *)scion_cmn_hdr, 4);
	lf_crypto_hash_update(ctx, (uint8_t *)scion_cmn_hdr + 8, 4);
	scion_cmn_hdr->version_qos_flowid[1] = ecn_old;
	return 0;
}

static inline int
hash_path_hdr(struct lf_worker_context *worker_context, void *path_hdr,
		uint8_t path_type, uint32_t path_header_len)
{
	switch (path_type) {
	case SCION_PATH_TYPE_EMPTY:
		/* nothing to do here */
		break;
	case SCION_PATH_TYPE_SCION: {
		if (unlikely(sizeof(struct scion_path_meta_hdr) > path_header_len)) {
			LF_WORKER_LOG_DP(NOTICE,
					"Invalid SCION packet: path header type "
					"inconsistent with expected path header length.\n");
			return -1;
		}

		struct scion_path_meta_hdr *scion_path_meta_hdr =
				(struct scion_path_meta_hdr *)path_hdr;

		uint32_t seg_len[3];
		seg_len[0] = ((scion_path_meta_hdr->seg_len[0] & 0x03) << 4) |
		             ((scion_path_meta_hdr->seg_len[1] & 0xF0) >> 4);
		seg_len[1] = ((scion_path_meta_hdr->seg_len[1] & 0x0F) << 2) |
		             ((scion_path_meta_hdr->seg_len[2] & 0xC0) >> 6);
		seg_len[2] = ((scion_path_meta_hdr->seg_len[2] & 0x3F));

		if (unlikely(seg_len[0] + seg_len[1] + seg_len[2] > 64)) {
			LF_WORKER_LOG_DP(NOTICE, "Invalid SCION packet: path header hop "
									 "field number exceeds 64.\n");
			return -1;
		}

		uint32_t actual_path_header_len =
				sizeof *scion_path_meta_hdr +
				(seg_len[0] ? SCION_PATH_INFOFIELD_SIZE +
										seg_len[0] * SCION_PATH_HOPFIELD_SIZE
							: 0) +
				(seg_len[1] ? SCION_PATH_INFOFIELD_SIZE +
										seg_len[1] * SCION_PATH_HOPFIELD_SIZE
							: 0) +
				(seg_len[2] ? SCION_PATH_INFOFIELD_SIZE +
										seg_len[2] * SCION_PATH_HOPFIELD_SIZE
							: 0);
		if (unlikely(actual_path_header_len != path_header_len)) {
			LF_WORKER_LOG_DP(NOTICE,
					"Invalid SCION packet: SCION path header length "
					"inconsistent with path header length.\n");
			return -1;
		}

		/* PathMeta Header (with CurrINF, CurrHF zeroed) */
		uint8_t curr_old = scion_path_meta_hdr->curr_inf_hf;
		scion_path_meta_hdr->curr_inf_hf = 0;

		/* InfoField Header (with SegID zeroed) */
		uint16_t seg_id_old[3];
		struct scion_path_info_hdr *info_field =
				(struct scion_path_info_hdr *)(scion_path_meta_hdr + 1);
		for (size_t i = 0; i < 3; ++i) {
			if (seg_len[i] != 0) {
				seg_id_old[i] = info_field->seg_id;
				info_field->seg_id = 0;
				info_field += 1;
			}
		}

		/* HopField Header (with router alerts zeroed) */
		struct scion_path_hop_hdr *hop_field =
				(struct scion_path_hop_hdr *)info_field;
		uint8_t router_alerts_old[64];
		for (size_t i = 0; i < seg_len[0] + seg_len[1] + seg_len[2]; ++i) {
			router_alerts_old[i] = hop_field->rie;
			hop_field->rie &= 0xFC; // 0b11111100;
			hop_field += 1;
		}

		lf_crypto_hash_update(&worker_context->crypto_hash_ctx,
				(uint8_t *)path_hdr, path_header_len);

		/* PathMeta Header reset */
		scion_path_meta_hdr->curr_inf_hf = curr_old;

		/* InfoField Header reset */
		info_field = (struct scion_path_info_hdr *)(scion_path_meta_hdr + 1);
		for (size_t i = 0; i < 3; ++i) {
			if (seg_len[i] != 0) {
				info_field->seg_id = seg_id_old[i];
				info_field += 1;
			}
		}

		/* HopField Header reset */
		hop_field = (struct scion_path_hop_hdr *)info_field;
		for (size_t i = 0; i < seg_len[0] + seg_len[1] + seg_len[2]; ++i) {
			hop_field->rie = router_alerts_old[i];
			hop_field += 1;
		}
		break;
	}
	case SCION_PATH_TYPE_ONEHOP: {
		if (unlikely(SCION_PATH_INFOFIELD_SIZE + 2 * SCION_PATH_HOPFIELD_SIZE >
					 path_header_len)) {
			LF_WORKER_LOG_DP(NOTICE, "Invalid SCION packet: path header type "
									 "inconsistent with header length.\n");
			return -1;
		}
		struct scion_path_info_hdr *scion_path_info_hdr =
				(struct scion_path_info_hdr *)path_hdr;

		/* add info field and first hop field (with router alert flags zeroed)
		 */
		struct scion_path_hop_hdr *hop_field_1 =
				(struct scion_path_hop_hdr *)(scion_path_info_hdr + 1);
		uint8_t router_alerts_old = hop_field_1->rie;
		hop_field_1->rie &= 0xFC; // 0b11111100;
		lf_crypto_hash_update(&worker_context->crypto_hash_ctx,
				(uint8_t *)path_hdr,
				SCION_PATH_INFOFIELD_SIZE + SCION_PATH_HOPFIELD_SIZE);
		hop_field_1->rie = router_alerts_old;

		/* add second hop field (with everything zeroed) */
		uint8_t hop_field_zeroed[SCION_PATH_HOPFIELD_SIZE] = { 0 };
		lf_crypto_hash_update(&worker_context->crypto_hash_ctx,
				hop_field_zeroed, SCION_PATH_HOPFIELD_SIZE);
		break;
	}
	default:
		LF_WORKER_LOG_DP(NOTICE, "Unknown SCION path type %u.\n", path_type);
		return -1;
		break;
	}

	return 0;
}

/**
 * Assume that the complete SCION header (limited through its size defined
 * in the cmn header) can be accessed in the same mbuf.
 * @return 0 if succeeds.
 */
static inline int
compute_pkt_hash(struct lf_worker_context *worker_context, struct rte_mbuf *m,
		struct parsed_pkt *parsed_pkt, struct parsed_spao *parsed_spao,
		uint8_t hash[LF_CRYPTO_HASH_LENGTH])
{
	int res;
	uint8_t *payload;

	/* hash common header */
	res = hash_cmn_hdr(&worker_context->crypto_hash_ctx,
			parsed_pkt->scion_cmn_hdr);
	if (unlikely(res != 0)) {
		return res;
	}

	/* hash path header */
	res = hash_path_hdr(worker_context, parsed_pkt->scion_path_hdr,
			parsed_pkt->scion_cmn_hdr->path_type,
			parsed_pkt->scion_path_hdr_len);
	if (unlikely(res != 0)) {
		return res;
	}

	/* hash payload */
	if (unlikely(parsed_spao->payload_offset + parsed_spao->payload_length >
				 m->data_len)) {
		LF_WORKER_LOG_DP(NOTICE,
				"Not yet implemented: SCION payload exceeds "
				"first buffer segment (offset = %d, length = %d, segment = "
				"%d).\n",
				parsed_spao->payload_offset, parsed_spao->payload_length,
				m->data_len);
		return -1;
	}
	payload =
			rte_pktmbuf_mtod_offset(m, uint8_t *, parsed_spao->payload_offset);
	(void)lf_crypto_hash_update(&worker_context->crypto_hash_ctx, payload,
			parsed_spao->payload_length);

	LF_WORKER_LOG_DP(DEBUG, "Finalize hash\n");
	(void)lf_crypto_hash_final(&worker_context->crypto_hash_ctx, hash);

	return 0;
}

/**
 * Perform packet hash check.
 * If this check is disable, the check is not performed and the function just
 * returns valid.
 * If this check is ignored, the check is performed but the function
 * always return valid.
 *
 * @return Returns 0 if the packet hash is valid.
 */
static int
check_pkt_hash(struct lf_worker_context *worker_context, struct rte_mbuf *m,
		struct parsed_pkt *parsed_pkt, struct parsed_spao *parsed_spao)
{
	int res;
	uint8_t hash[20];

#if (LF_WORKER_OMIT_HASH_CHECK)
	return 0;
#endif /* !(LF_WORKER_OMIT_HASH_CHECK) */

	res = compute_pkt_hash(worker_context, m, parsed_pkt, parsed_spao, hash);
	if (res != 0) {
		LF_WORKER_LOG_DP(ERR, "Failed to compute hash. res = %d\n", res);
		lf_statistics_worker_counter_inc(worker_context->statistics, error);
		return 1;
	}

	res = lf_crypto_hash_cmp(hash, parsed_spao->spao_hdr->hash);
	if (likely(res != 0)) {
		LF_WORKER_LOG_DP(DEBUG, "Packet hash check failed.\n");
		lf_statistics_worker_counter_inc(worker_context->statistics,
				invalid_hash);
	} else {
		LF_WORKER_LOG_DP(DEBUG, "Packet hash check passed.\n");
	}

#if (LF_WORKER_IGNORE_HASH_CHECK)
	res = 0;
#endif /* !(LF_WORKER_IGNORE_HASH_CHECK) */

	return res;
}

static void
preprocess_mac_input(const struct parsed_pkt *parsed_pkt,
		struct parsed_spao *parsed_spao)
{
	struct scion_mac_input *mac_input =
			SPAO_GET_MAC_INPUT(parsed_spao->spao_hdr);
	parsed_spao->hdr_len_old = mac_input->hdr_len;
	parsed_spao->upper_layer_protocol_old = mac_input->payload_protocol;
	parsed_spao->upper_layer_length_old = mac_input->payload_length;
	mac_input->hdr_len = parsed_pkt->scion_cmn_hdr->hdr_len;
	mac_input->payload_protocol = parsed_spao->payload_protocol;
	mac_input->payload_length = parsed_spao->payload_length;
}

static void
postprocess_mac_input(struct parsed_spao *parsed_spao)
{
	struct scion_mac_input *mac_input =
			SPAO_GET_MAC_INPUT(parsed_spao->spao_hdr);
	mac_input->hdr_len = parsed_spao->hdr_len_old;
	mac_input->payload_protocol = parsed_spao->upper_layer_protocol_old;
	mac_input->payload_length = parsed_spao->upper_layer_length_old;
}

/**
 * This function looks for a LF SPAO header.
 *
 * @param parsed_pkt The parsed packet.
 * @param parsed_spao Returns a parsed LF SPAO header if it the packet contains
 * one.
 * @param pkt_data Returns the packet data.
 * @return Returns 0 if the packet contains a LF SPAO header. Returns > 0 if the
 * packet does not contains a LF SPAO header. Returns < 0 if an error occurred.
 */
static int
get_lf_spao_hdr(struct rte_mbuf *m, struct parsed_pkt *parsed_pkt,
		struct parsed_spao *parsed_spao, struct lf_pkt_data *pkt_data)
{
	int scion_ext_hdr_len;

	/*
	 * Get SPAO header and check if it corresponds to the LightingFilter
	 * format.
	 */
	scion_ext_hdr_len =
			get_spao_hdr(m, parsed_pkt->offset, parsed_pkt->scion_cmn_hdr,
					&parsed_spao->spao_hdr, &parsed_spao->payload_protocol);
	if (unlikely(scion_ext_hdr_len == 0)) {
		/* no SPAO header found */
		return 1;
	} else if (unlikely(scion_ext_hdr_len < 0)) {
		LF_WORKER_LOG_DP(NOTICE, "Failed to get SPAO header.\n");
		return -1;
	}

	/* SPI must be in the DRKey format */
	if (unlikely(
				(parsed_spao->spao_hdr->spi &
						rte_cpu_to_be_32(
								SCION_PACKET_AUTHENTICATOR_OPT_SPI_DRKEY_MASK)) !=
						parsed_spao->spao_hdr->spi ||
				parsed_spao->spao_hdr->spi_drkey_rrr != 0 ||
				parsed_spao->spao_hdr->spi_drkey_t !=
						SCION_SPAO_SPI_DRKEY_TYPE_HH ||
				parsed_spao->spao_hdr->spi_drkey_d !=
						SCION_SPAO_SPI_DRKEY_DIRECTION_RECEIVER)) {
		LF_WORKER_LOG_DP(NOTICE, "Unexpected SPAO SPI DRKey information.\n");
		return -1;
	}

	/* Algorithm must be SHA and AES-CBC*/
	if (unlikely(parsed_spao->spao_hdr->algorithm !=
				 SCION_SPAO_ALGORITHM_TYPE_SHA_AES_CBC)) {
		LF_WORKER_LOG_DP(NOTICE,
				"Unexpected SPAO algorithm (%d), expected %d.\n",
				parsed_spao->spao_hdr->algorithm,
				SCION_SPAO_ALGORITHM_TYPE_SHA_AES_CBC);
		return -1;
	}

	if (unlikely(parsed_spao->spao_hdr->reserved != 0)) {
		LF_WORKER_LOG_DP(NOTICE,
				"Unexpected SPAO reserved field (%d), expected %d.\n",
				parsed_spao->spao_hdr, 0);
		return -1;
	}

	/*
	 * Set packet data
	 */
	pkt_data->src_as = parsed_pkt->scion_addr_ia_hdr->src_ia;
	pkt_data->dst_as = parsed_pkt->scion_addr_ia_hdr->dst_ia;

	pkt_data->src_addr = (struct lf_host_addr){
		.addr = scion_get_addr_host_src(parsed_pkt->scion_cmn_hdr),
		.type_length = parsed_pkt->scion_cmn_hdr->st_sl,
	};
	pkt_data->dst_addr = (struct lf_host_addr){
		.addr = scion_get_addr_host_dst(parsed_pkt->scion_cmn_hdr),
		.type_length = parsed_pkt->scion_cmn_hdr->dt_dl,
	};

	/* Obtain required SPAO fields before they are temporarily overwritten.
	 */
	pkt_data->timestamp = scion_spao_get_timestamp(parsed_spao->spao_hdr);
	pkt_data->drkey_protocol = parsed_spao->spao_hdr->spi_drkey_protocol_id;

	// TODO update since no longer explicitly defined in packet
	pkt_data->grace_period = 0;

	pkt_data->mac = parsed_spao->spao_hdr->mac;
	/* The MAC input starts at the after the type and length field of the
	 * SPAO extension header. */
	pkt_data->auth_data = (uint8_t *)parsed_spao->spao_hdr + 2;

	pkt_data->pkt_len =
			rte_be_to_cpu_16(parsed_pkt->scion_cmn_hdr->payload_len);

	/* Get Payload offset and length */
	parsed_spao->payload_offset = parsed_pkt->offset + scion_ext_hdr_len;
	parsed_spao->payload_length =
			rte_be_to_cpu_16(parsed_pkt->scion_cmn_hdr->payload_len) -
			scion_ext_hdr_len;

	return 0;
}

static enum lf_check_state
handle_inbound_pkt_without_lf_hdr(struct lf_worker_context *worker_context,
		struct rte_mbuf *m, struct parsed_pkt *parsed_pkt)
{
	(void)parsed_pkt;
	return lf_worker_check_best_effort_pkt(worker_context, m->pkt_len);
}

static enum lf_check_state
handle_inbound_pkt_with_lf_hdr(struct lf_worker_context *worker_context,
		struct rte_mbuf *m, struct parsed_pkt *parsed_pkt,
		struct parsed_spao *parsed_spao, struct lf_pkt_data *pkt_data)
{
	int res;
	enum lf_check_state check_state;

	preprocess_mac_input(parsed_pkt, parsed_spao);

	check_state = lf_worker_check_pkt(worker_context, pkt_data);

	postprocess_mac_input(parsed_spao);

	if (likely(check_state != LF_CHECK_VALID)) {
		/* Under attack, it is more likely that packets do not pass all checks.
		 */
		return check_state;
	}

	/* Only if all checks are passed, the packet hash is checked. */
	res = check_pkt_hash(worker_context, m, parsed_pkt, parsed_spao);
	if (res == 0) {
		return LF_CHECK_VALID;
	} else {
		return LF_CHECK_VALID_MAC_BUT_INVALID_HASH;
	}
}

/**
 * Handle inbound packets.
 *
 * @param worker_context Worker Context
 * @param m Packet buffer.
 * @param parsed_pkt Parsed packet headers.
 * @return enum lf_pkt_action
 */
static enum lf_pkt_action
handle_inbound_pkt(struct lf_worker_context *worker_context, struct rte_mbuf *m,
		struct parsed_pkt *parsed_pkt)
{
	int res;
	enum lf_check_state check_state;
	struct parsed_spao parsed_spao;
	struct lf_pkt_data pkt_data;

	res = get_lf_spao_hdr(m, parsed_pkt, &parsed_spao, &pkt_data);
	if (res == 0) {
		check_state = handle_inbound_pkt_with_lf_hdr(worker_context, m,
				parsed_pkt, &parsed_spao, &pkt_data);
	} else if (res > 0) {
		check_state = handle_inbound_pkt_without_lf_hdr(worker_context, m,
				parsed_pkt);
	} else {
		check_state = LF_CHECK_ERROR;
	}

	lf_worker_pkt_mod(m, parsed_pkt->ether_hdr, parsed_pkt->l3_hdr,
			lf_configmanager_worker_get_inbound_pkt_mod(
					worker_context->config));

	if (check_state == LF_CHECK_VALID || check_state == LF_CHECK_BE) {
		return LF_PKT_INBOUND_FORWARD;
	} else {
		return LF_PKT_INBOUND_DROP;
	}
}

/**
 * Add SPAO to SCION header
 * @param offset: Offset to SCION next header (header after address and path
 * header)
 * @param drkey_protocol: (network byte order).
 * @return Returns the length of the additional headers.
 * Returns -1 if failed.
 */
static inline int
add_spao(struct lf_worker_context *worker_context, struct rte_mbuf *m,
		struct parsed_pkt *parsed_pkt)
{
	int res;
	int add_hdr_len; /* added header length */
	struct scion_packet_authenticator_opt *spao_hdr;
	struct parsed_spao parsed_spao;

	uint64_t timestamp_now;

	struct lf_host_addr src_addr;
	struct lf_host_addr dst_addr;
	struct lf_crypto_drkey drkey;
	uint16_t drkey_protocol;
	int drkey_epoch_flag;

	uint8_t payload_protocol;
	unsigned int payload_offset;
	unsigned int payload_len;

	/* get current time */
	res = lf_time_worker_get_unique(&worker_context->time, &timestamp_now);
	if (unlikely(res != 0)) {
		LF_WORKER_LOG_DP(ERR, "Failed to get timestamp.\n");
		return -1;
	}

	/*
	 * Get DRKey for the dst address, src address, and drkey protocol.
	 * Querying for the DRKey also reveals if a key exists.
	 */
	dst_addr = (struct lf_host_addr){
		.addr = scion_get_addr_host_dst(parsed_pkt->scion_cmn_hdr),
		.type_length = parsed_pkt->scion_cmn_hdr->dt_dl,
	};
	src_addr = (struct lf_host_addr){
		.addr = scion_get_addr_host_src(parsed_pkt->scion_cmn_hdr),
		.type_length = parsed_pkt->scion_cmn_hdr->st_sl,
	};
	drkey_protocol = lf_configmanager_worker_get_outbound_drkey_protocol(
			worker_context->config);

	uint64_t drkey_epoch_start_ns;
	drkey_epoch_flag = lf_keymanager_worker_outbound_get_drkey(
			worker_context->key_manager, parsed_pkt->scion_addr_ia_hdr->dst_ia,
			&dst_addr, &src_addr, drkey_protocol, timestamp_now,
			&drkey_epoch_start_ns, &drkey);
	if (unlikely(drkey_epoch_flag < 0)) {
		LF_WORKER_LOG_DP(NOTICE,
				"Outbound DRKey not found for AS " PRIISDAS
				" and drkey_protocol %d (ns_now = %" PRIu64 ", res = %d)!\n",
				PRIISDAS_VAL(rte_be_to_cpu_64(
						parsed_pkt->scion_addr_ia_hdr->dst_ia)),
				rte_be_to_cpu_16(drkey_protocol), timestamp_now,
				drkey_epoch_flag);
		return -1;
	}

	LF_WORKER_LOG_DP(DEBUG,
			"Outbound DRKey [" PRIISDAS "]:" PRIIP " - [XX]:" PRIIP
			" and drkey_protocol %d is %x (ns_now = %" PRIu64 ", res = %d)\n",
			PRIISDAS_VAL(
					rte_be_to_cpu_64(parsed_pkt->scion_addr_ia_hdr->dst_ia)),
			PRIIP_VAL(*(uint32_t *)dst_addr.addr),
			PRIIP_VAL(*(uint32_t *)src_addr.addr),
			rte_be_to_cpu_16(drkey_protocol), drkey.key[0], timestamp_now,
			drkey_epoch_flag);

	/*
	 * Add SPAO Extension Header
	 * When adding the extension header, the preceding headers are moved.
	 * Hence, any pointer to these headers must be moved or should be
	 * invalidated afterwards.
	 */
	add_hdr_len = scion_add_spao_hdr(m, parsed_pkt->offset,
			parsed_pkt->scion_cmn_hdr, &spao_hdr);
	if (add_hdr_len < 0) {
		return -1;
	}
	/* adjust and invalidate pointers to moved memory */
	pkt_hdrs_move(parsed_pkt, -add_hdr_len);
	(void)src_addr;
	(void)dst_addr;

	/*
	 * Get payload offset, length, and protocol.
	 * The payload length can be computed by subtracting the SCION extension
	 * header length from the payload length provided in the SCION common
	 * header.
	 */
	payload_offset = scion_skip_extension_hdr(m, parsed_pkt->scion_cmn_hdr,
			parsed_pkt->offset, &payload_protocol);
	if (payload_offset == 0) {
		return -1;
	}
	payload_len = rte_be_to_cpu_16(parsed_pkt->scion_cmn_hdr->payload_len) -
	              (payload_offset - parsed_pkt->offset);

	/*
	 * Set SPAO header fields
	 */
	// TODO set correct fields once spao struct is updated
	spao_hdr->spi_drkey_zero0 = 0;
	spao_hdr->spi_drkey_zero1 = 0;
	spao_hdr->spi_drkey_rrr = 0;
	spao_hdr->spi_drkey_t = SCION_SPAO_SPI_DRKEY_TYPE_HH;
	spao_hdr->spi_drkey_d = SCION_SPAO_SPI_DRKEY_DIRECTION_RECEIVER;
	spao_hdr->spi_drkey_protocol_id = drkey_protocol;
	spao_hdr->algorithm = SCION_SPAO_ALGORITHM_TYPE_SHA_AES_CBC;
	spao_hdr->reserved = 0;

	/* Initialize parsed_spao struct. */
	parsed_spao.spao_hdr = spao_hdr;
	parsed_spao.payload_protocol = payload_protocol;
	parsed_spao.payload_offset = payload_offset;
	parsed_spao.payload_length = payload_len;

	/* packet hash */
	// TODO make sure hash is calculated over correct fields
	LF_WORKER_LOG_DP(DEBUG, "Compute packet hash.\n");
	res = compute_pkt_hash(worker_context, m, parsed_pkt, &parsed_spao,
			spao_hdr->hash);
	if (unlikely(res != 0)) {
		LF_WORKER_LOG_DP(ERR, "Failed to compute hash. res = %d\n", res);
		/* TODO: error handling */
		return -1;
	}

	/* set timestamp */
	res = set_spao_timestamp(drkey_epoch_start_ns, timestamp_now, spao_hdr);
	if (unlikely(res != 0)) {
		/* TODO: error handling */
		return -1;
	}

	/* Temporarily overwrite certain SPAO header fields */
	preprocess_mac_input(parsed_pkt, &parsed_spao);

	/* Compute MAC */
	// TODO calulate MAC over correct fields
	lf_crypto_drkey_compute_mac(&worker_context->crypto_drkey_ctx, &drkey,
			(uint8_t *)SPAO_GET_MAC_INPUT(spao_hdr), spao_hdr->mac);

	/* Revert overwrites */
	postprocess_mac_input(&parsed_spao);

	/* adjust header length fields */
#if LF_IPV6
	parsed_pkt->ipv6_hdr->payload_len = rte_cpu_to_be_16(
			rte_be_to_cpu_16(parsed_pkt->ipv6_hdr->payload_len) + add_hdr_len);
#else
	parsed_pkt->ipv4_hdr->total_length = rte_cpu_to_be_16(
			rte_be_to_cpu_16(parsed_pkt->ipv4_hdr->total_length) + add_hdr_len);
#endif
	parsed_pkt->udp_hdr->dgram_len = rte_cpu_to_be_16(
			rte_be_to_cpu_16(parsed_pkt->udp_hdr->dgram_len) + add_hdr_len);

	return add_hdr_len;
}

/**
 * Handle outbound packets.
 *
 * @param worker_context Worker Context
 * @param m Packet buffer.
 * @param parsed_pkt Parsed packet headers.
 * @return enum lf_pkt_action
 */
static enum lf_pkt_action
handle_outbound_pkt(struct lf_worker_context *worker_context,
		struct rte_mbuf *m, struct parsed_pkt *parsed_pkt)
{
	int add_len;

	add_len = add_spao(worker_context, m, parsed_pkt);
	if (unlikely(add_len < 0)) {
		LF_WORKER_LOG_DP(ERR, "Failed to add SPAO header.\n");
		return LF_PKT_OUTBOUND_DROP;
	}
	LF_WORKER_LOG_DP(DEBUG, "SPAO header added.\n");

	/*
	 * Apply outbound packet modifications, i.e., ethernet and IP address,
	 * and reset checksums.
	 */
	lf_worker_pkt_mod(m, parsed_pkt->ether_hdr, parsed_pkt->l3_hdr,
			lf_configmanager_worker_get_outbound_pkt_mod(
					worker_context->config));

	return LF_PKT_OUTBOUND_FORWARD;
}

/**
 * Parse packet according the expected format:
 * ETH/IPV4|IPV6/UDP/SCION_CMN/SCION_ADDR/SCION_PATH.
 *
 * From the SCION path, also the timestamp is parsed.
 *
 * @return Returns 0 on success.
 * Returns 1 if packet is a intra-AS packet.
 * Returns -1 on error.
 */
static int
parse_pkt(struct rte_mbuf *m, unsigned int offset,
		struct parsed_pkt *parsed_pkt)
{
	int res;

	if (unlikely(m->data_len != m->pkt_len)) {
		LF_WORKER_LOG_DP(NOTICE,
				"Not yet implemented: buffer with multiple segments "
				"received.\n");
		return -1;
	}

	offset = 0;
	offset = lf_get_eth_hdr(m, offset, &parsed_pkt->ether_hdr);
	if (unlikely(offset == 0)) {
		return -1;
	}

#if LF_IPV6
	if (unlikely(parsed_pkt->ether_hdr->ether_type !=
				 rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6))) {
		LF_WORKER_LOG_DP(NOTICE,
				"Unsupported packet type %#X: must be IPv6 (%#X).\n",
				rte_be_to_cpu_16(parsed_pkt->ether_hdr->ether_type),
				RTE_ETHER_TYPE_IPV6);
		return -1;
	}
	offset = lf_get_ipv6_hdr(m, offset, &parsed_pkt->ipv6_hdr);
	if (unlikely(offset == 0)) {
		return -1;
	}
	if (parsed_pkt->ipv6_hdr->proto != IP_PROTO_ID_UDP) {
		/* Probably intra AS traffic: forward without checks */
		LF_WORKER_LOG_DP(DEBUG,
				"IPv6 packet type is not UDP (%#X) but %#X. Probably intra "
				"AS traffic.\n",
				IP_PROTO_ID_UDP, parsed_pkt->ipv6_hdr->proto);
		return 1;
	}
#else
	if (unlikely(parsed_pkt->ether_hdr->ether_type !=
				 rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))) {
		LF_WORKER_LOG_DP(NOTICE,
				"Unsupported packet type %#X: must be IPv4 (%#X).\n",
				rte_be_to_cpu_16(parsed_pkt->ether_hdr->ether_type),
				RTE_ETHER_TYPE_IPV4);
		return -1;
	}

	offset = lf_get_ip_hdr(m, offset, &parsed_pkt->ipv4_hdr);
	if (unlikely(offset == 0)) {
		return -1;
	}
	if (parsed_pkt->ipv4_hdr->next_proto_id != IP_PROTO_ID_UDP) {
		/* Probably intra AS traffic: forward without checks */
		LF_WORKER_LOG_DP(DEBUG,
				"IPv4 packet type is not UDP (%#X) but %#X. Probably intra "
				"AS traffic.\n",
				IP_PROTO_ID_UDP, parsed_pkt->ipv4_hdr->next_proto_id);
		return 1;
	}
#endif /* LF_IPV6 */

	offset = lf_get_udp_hdr(m, offset, &parsed_pkt->udp_hdr);
	if (unlikely(offset == 0)) {
		return -1;
	}

	/*
	 * Get the full SCION header (Common, Address, Path):
	 * Validate that the full SCION header is inside the first mbuf
	 * segment.
	 */
	/* scion common header */
	offset = scion_get_cmn_hdr(m, offset, &parsed_pkt->scion_cmn_hdr);
	if (unlikely(offset == 0)) {
		return -1;
	}

	/* address header */
	parsed_pkt->scion_addr_hdr_len =
			SCION_ADDR_HDR_LEN(parsed_pkt->scion_cmn_hdr);
	if (parsed_pkt->scion_addr_hdr_len > m->data_len - offset) {
		LF_WORKER_LOG_DP(NOTICE, "Not yet implemented: SCION address header "
								 "exceeds first buffer segment.\n");
		return -1;
	}
	/* no need to check length again */
	(void)scion_get_addr_ia_hdr(m, offset, &parsed_pkt->scion_addr_ia_hdr);
	offset += parsed_pkt->scion_addr_hdr_len;

	/* path header */
	res = scion_path_hdr_length(m, offset,
			parsed_pkt->scion_cmn_hdr->path_type);
	if (res < 0) {
		LF_WORKER_LOG_DP(NOTICE,
				"Failed to calculate SCION path header length (res = %d)\n",
				res);
		return -1;
	}
	parsed_pkt->scion_path_hdr_len = res;
	parsed_pkt->scion_path_hdr = rte_pktmbuf_mtod_offset(m, void *, offset);
	offset += parsed_pkt->scion_path_hdr_len;

	/* validate header length provided in scion common header */
	if (sizeof(struct scion_cmn_hdr) + parsed_pkt->scion_addr_hdr_len +
					parsed_pkt->scion_path_hdr_len !=
			SCION_HDR_LEN(parsed_pkt->scion_cmn_hdr)) {
		LF_WORKER_LOG_DP(NOTICE,
				"Failed to parse SCION headers: header lengths mismatch "
				"(hdr_len = %d, cmn_hdr_len = %d, addr_hdr_len = %d, "
				"path_hdr_len = %d)\n",
				SCION_HDR_LEN(parsed_pkt->scion_cmn_hdr),
				sizeof(struct scion_cmn_hdr), parsed_pkt->scion_addr_hdr_len,
				parsed_pkt->scion_path_hdr_len);
		return -1;
	}

	/* obtain path timestamp */
	res = scion_get_path_timestamp(parsed_pkt->scion_cmn_hdr->path_type,
			parsed_pkt->scion_path_hdr, &parsed_pkt->path_timestamp);
	if (res == 1) {
		LF_WORKER_LOG_DP(DEBUG, "Path without path timestamp\n", res);
		return 1;
	} else if (res == -1) {
		LF_WORKER_LOG_DP(ERR, "Failed to obtain path timestamp\n", res);
		return -1;
	}

	parsed_pkt->offset = offset;
	return 0;
}

/**
 * Packet preprocessing results.
 * See function preprocess_pkt.
 */
enum preprocess_pkt_res {
	PKT_ERROR,
	PKT_INTRA_AS,
	PKT_OUTBOUND,
	PKT_INBOUND,
	PKT_UNEXPECTED,
};

/**
 * In the preprocessing of the packet, the packet is parsed and the forwarding
 * direction is determined.
 *
 * @param worker_context
 * @param m Packet to preprocessed.
 * @param parsed_pkt Returns the parsed packet struct.
 * @return enum preprocess_pkt_res
 * PKT_ERROR: an error occurred.
 * PKT_INTRA_AS: the packet is intra-AS.
 * PKT_OUTBOUND: the packet is an outbound packet.
 * PKT_INBOUND: the packet is an inbound packet.
 * PKT_UNEXPECTED: the packet direction can not be determined.
 */
static enum preprocess_pkt_res
preprocess_pkt(struct lf_worker_context *worker_context, struct rte_mbuf *m,
		struct parsed_pkt *parsed_pkt)
{
	int res;

	uint64_t dst_ia;
	uint64_t src_ia;

	const uint64_t local_isd_as =
			lf_configmanager_worker_get_local_as(worker_context->config);

	/*
	 * Parse packet and return if error occurred or packet is intra-AS.
	 */
	res = parse_pkt(m, 0, parsed_pkt);
	if (unlikely(res < 0)) {
		return PKT_ERROR;
	} else if (unlikely(res > 0) ||
			   parsed_pkt->scion_cmn_hdr->path_type == SCION_PATH_TYPE_EMPTY) {
		return PKT_INTRA_AS;
	}

	dst_ia = *scion_get_addr_ia_dst(parsed_pkt->scion_cmn_hdr);
	src_ia = *scion_get_addr_ia_src(parsed_pkt->scion_cmn_hdr);

	/*
	 * With the src/dst AS address, it is determined
	 * if the packet is an inbound or an outbound packet.
	 */
	if (dst_ia == local_isd_as) {
		LF_WORKER_LOG_DP(DEBUG, "Inbound packet\n");
		return PKT_INBOUND;
	}
	if (src_ia == local_isd_as) {
		LF_WORKER_LOG_DP(DEBUG, "Outbound packet\n");
		return PKT_OUTBOUND;
	}
	LF_WORKER_LOG_DP(DEBUG,
			"Neither source IA (" PRIISDAS ") nor destination IA (" PRIISDAS
			") correspond to local IA (" PRIISDAS ").\n",
			PRIISDAS_VAL(rte_be_to_cpu_64(src_ia)),
			PRIISDAS_VAL(rte_be_to_cpu_64(dst_ia)),
			PRIISDAS_VAL(rte_be_to_cpu_64(local_isd_as)));
	return PKT_UNEXPECTED;
}

static enum lf_pkt_action
handle_pkt(struct lf_worker_context *worker_context, struct rte_mbuf *m)
{
	enum preprocess_pkt_res preprocessing_res;
	struct parsed_pkt parsed_pkt;

	preprocessing_res = preprocess_pkt(worker_context, m, &parsed_pkt);

	switch (preprocessing_res) {
	case PKT_INBOUND:
		return handle_inbound_pkt(worker_context, m, &parsed_pkt);
	case PKT_OUTBOUND:
		return handle_outbound_pkt(worker_context, m, &parsed_pkt);
	case PKT_INTRA_AS:
		return LF_PKT_UNKNOWN_FORWARD;
	case PKT_ERROR:
	case PKT_UNEXPECTED:
	default:
		return LF_PKT_UNKNOWN_DROP;
	}
}

void
lf_worker_handle_pkt(struct lf_worker_context *worker_context,
		struct rte_mbuf **pkt_burst, uint16_t nb_pkts,
		enum lf_pkt_action *pkt_res)
{
	int i;

	for (i = 0; i < nb_pkts; i++) {
		if (pkt_res[i] != LF_PKT_UNKNOWN) {
			/* If packet action is already determined, do not process it */
			continue;
		}

		pkt_res[i] = handle_pkt(worker_context, pkt_burst[i]);
	}
}
