/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#ifndef SCION_UTILS_H
#define SCION_UTILS_H

#include <assert.h>
#include <stdint.h>

#include <rte_byteorder.h>
#include <rte_mbuf.h>

#include "../../worker.h"

#define SCION_ISD_SIZE 2
#define SCION_AS_SIZE  6

#define SCION_PATH_TYPE_EMPTY   0
#define SCION_PATH_TYPE_SCION   1
#define SCION_PATH_TYPE_ONEHOP  2
#define SCION_PATH_TYPE_EPIC    3
#define SCION_PATH_TYPE_COLIBRI 4

#define SCION_PATH_INFOFIELD_SIZE 8
#define SCION_PATH_HOPFIELD_SIZE  12

#define SCION_PROTOCOL_HBH 200
#define SCION_PROTOCOL_E2E 201

#define SCION_E2E_OPTION_TYPE_PAD1 0
#define SCION_E2E_OPTION_TYPE_PADN 1
#define SCION_E2E_OPTION_TYPE_SPAO 2

#define SCION_SPAO_SPI_DRKEY_TYPE_AH 0 // AS-to-host key
#define SCION_SPAO_SPI_DRKEY_TYPE_HH 1 // host-to-host key
// sender is derivation/fast side
#define SCION_SPAO_SPI_DRKEY_DIRECTION_SENDER 0
// receiver is derivation/fast side
#define SCION_SPAO_SPI_DRKEY_DIRECTION_RECEIVER 1
// DRKey for current epoch
#define SCION_SPAO_SPI_DRKEY_EPOCH_CURRENT 0
// DRKey for previous epoch (grace period)
#define SCION_SPAO_SPI_DRKEY_EPOCH_PREV 1

#define SCION_SPAO_ALGORITHM_TYPE_SHA_AES_CBC 1

#define SCION_ADDR_TL_IPV4 0x0 // 0b0000
#define SCION_ADDR_TL_IPV6 0x3 // 0b0011
#define SCION_ADDR_TL_SVC  0x4 // 0b0100

#define SCION_ADDR_HOST_LENGTH(t_l) ((((t_l) & 0x3) + 1) * 4)

struct scion_cmn_hdr {
	uint8_t version_qos_flowid[4];
	uint8_t next_hdr;
	uint8_t hdr_len;
	uint16_t payload_len;
	uint8_t path_type;
	/* Address type and length */
	union {
		uint8_t dt_dl_st_sl;
		struct {
#if RTE_BYTE_ORDER == RTE_BIG_ENDIAN
			uint8_t dt_dl: 4;
			uint8_t st_sl: 4;
#elif RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN
			uint8_t st_sl: 4;
			uint8_t dt_dl: 4;
#endif
		};
	};
	uint16_t rsv;
} __attribute__((__packed__));

struct scion_addr_ia_hdr {
	uint64_t dst_ia;
	uint64_t src_ia;
} __attribute__((__packed__));

struct scion_path_meta_hdr {
	uint8_t curr_inf_hf;
	uint8_t seg_len[3]; // first 6 bits are rsv
} __attribute__((__packed__));

struct scion_path_info_hdr {
	uint8_t rpc;
	uint8_t rsv;
	uint16_t seg_id;
	uint32_t timestamp;
} __attribute__((__packed__));

struct scion_path_hop_hdr {
	uint8_t rie;
	uint8_t exp_time;
	uint16_t cons_ingress;
	uint16_t cons_egress;
	uint8_t mac[6];
} __attribute__((__packed__));

struct scion_ext_hdr {
	uint8_t next_hdr;
	uint8_t ext_len;
} __attribute__((__packed__));

struct scion_ext_tlv_hdr {
	uint8_t type;
	uint8_t data_len;
} __attribute__((__packed__));

struct scion_pad1_opt {
	uint8_t opt_type;
} __attribute__((__packed__));

struct scion_packet_authenticator_opt {
	uint8_t type;
	uint8_t data_len;
	union {
		uint32_t spi;
		struct {
			uint8_t spi_drkey_zero0;
#if RTE_BYTE_ORDER == RTE_BIG_ENDIAN
			uint8_t spi_drkey_zero1: 3;
			uint8_t spi_drkey_rr: 2;
			uint8_t spi_drkey_t: 1;
			uint8_t spi_drkey_d: 1;
			uint8_t spi_drkey_e: 1;
#elif RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN
			uint8_t spi_drkey_e: 1;
			uint8_t spi_drkey_d: 1;
			uint8_t spi_drkey_t: 1;
			uint8_t spi_drkey_rr: 2;
			uint8_t spi_drkey_zero1: 3;
#endif
			uint16_t spi_drkey_protocol_id;
		};
	};
	union {
		uint64_t timestamp_unmasked;
		struct {
			uint8_t algorithm;
			uint8_t reserved;
			uint8_t timestamp[6];
		};
	};
	uint8_t hash[20];
	uint8_t mac[LF_CRYPTO_MAC_SIZE];
} __attribute__((__packed__));

#define SCION_PACKET_AUTHENTICATOR_OPT_SPI_DRKEY_MASK ((uint32_t)0x001FFFFF)
#define SCION_PACKET_AUTHENTICATOR_OPT_TIMESTAMP_MASK \
	((uint64_t)0xFFFFFFFFFFFF) /* 6 bytes */

struct scion_gateway_frame_hdr {
	uint8_t version;
	uint8_t session;
	uint16_t index;
	uint32_t reserved_stream;
	uint64_t sequence_numer;
} __attribute__((__packed__));

#define SCION_GATEWAY_FRAME_RSV_MASK    ((uint32_t)0xFFF00000)
#define SCION_GATEWAY_FRAME_STREAM_MASK ((uint32_t)0x000FFFFF)

/*
 * SCION Common Header Operations
 */

#define SCION_HDR_LEN(scion_cmn_hdr) ((scion_cmn_hdr)->hdr_len * 4)

static inline unsigned int
SCION_ADDR_HDR_LEN(const struct scion_cmn_hdr *scion_cmn_hdr)
{
	uint32_t src_addr_len = ((scion_cmn_hdr->dt_dl & 0x3) + 1) * 4;
	uint32_t dst_addr_len = ((scion_cmn_hdr->st_sl & 0x3) + 1) * 4;
	return src_addr_len + dst_addr_len + 2 * (SCION_ISD_SIZE + SCION_AS_SIZE);
}

#define SCION_EXT_HDR_LEN(ext_hdr) (((ext_hdr)->ext_len + 1) * 4)

static inline unsigned int
scion_get_cmn_hdr(const struct rte_mbuf *m, unsigned int offset,
		struct scion_cmn_hdr **scion_cmn_hdr)
{
	if (unlikely(sizeof(struct scion_cmn_hdr) > m->data_len - offset)) {
		LF_WORKER_LOG_DP(NOTICE,
				"Not yet implemented: SCION common header exceeds first buffer "
				"segment.\n");
		return 0;
	}

	*scion_cmn_hdr = rte_pktmbuf_mtod_offset(m, struct scion_cmn_hdr *, offset);
	return offset + sizeof(struct scion_cmn_hdr);
}

/*
 * SCION Address Header Operations
 */


static inline unsigned int
scion_get_addr_ia_hdr(const struct rte_mbuf *m, unsigned int offset,
		struct scion_addr_ia_hdr **scion_addr_ia_hdr)
{
	if (unlikely(sizeof(struct scion_addr_ia_hdr) > m->data_len - offset)) {
		LF_WORKER_LOG_DP(NOTICE, "Not yet implemented: SCION address IA header "
								 "exceeds first buffer segment.\n");
		return 0;
	}
	*scion_addr_ia_hdr =
			rte_pktmbuf_mtod_offset(m, struct scion_addr_ia_hdr *, offset);
	return offset + sizeof(struct scion_addr_ia_hdr);
}

/**
 * Obtain pointer to the the destination ISD-AS number.
 * The address header must directly follow the SCION common header in the
 * memory! Hence, the address header cannot be located in another buffer.
 *
 * @param scion_cmn_hdr: Pointer to the SCION common header.
 * @return Pointer to the destination ISD-AS number
 */
static inline uint64_t *
scion_get_addr_ia_dst(struct scion_cmn_hdr *scion_cmn_hdr)
{
	/*
	 * With the void cast, an alignment warning is avoided.
	 * This is not best-practice and should be changed.
	 */
	return (uint64_t *)(void *)(scion_cmn_hdr + 1);
}

/**
 *
 * Obtain pointer to the source ISD-AS number.
 * The address header must directly follow the SCION common header in the
 * memory! Hence, the address header cannot be located in another buffer.
 *
 * @param scion_cmn_hdr: Pointer to the SCION common header.
 * @return Pointer to the source ISD-AS number
 */
static inline uint64_t *
scion_get_addr_ia_src(struct scion_cmn_hdr *scion_cmn_hdr)
{
	/*
	 * With the void cast, an alignment warning is avoided.
	 * This is not best-practice and should be changed.
	 */
	return ((uint64_t *)(void *)(scion_cmn_hdr + 1) + 1);
}

/**
 * Obtain pointer to the destination host address.
 * The address header must directly follow the SCION common header in the
 * memory! Hence, the address header cannot be located in another buffer.
 *
 * @param scion_cmn_hdr: Pointer to the SCION common header.
 * @return Pointer to the destination host address.
 */
static inline void *
scion_get_addr_host_dst(struct scion_cmn_hdr *scion_cmn_hdr)
{
	return (uint8_t *)(scion_cmn_hdr + 1) + sizeof(struct scion_addr_ia_hdr);
}

/**
 * Obtain pointer to the source host address.
 * The address header must directly follow the SCION common header in the
 * memory! Hence, the address header cannot be located in another buffer.
 *
 * @param scion_cmn_hdr: Pointer to the SCION common header.
 * @return void*: Pointer to the source host address.
 */
static inline void *
scion_get_addr_host_src(struct scion_cmn_hdr *scion_cmn_hdr)
{
	return (uint8_t *)(scion_cmn_hdr + 1) + sizeof(struct scion_addr_ia_hdr) +
	       SCION_ADDR_HOST_LENGTH(scion_cmn_hdr->dt_dl);
}


/*
 * SCION Path Header Operations
 */

static inline unsigned int
scion_get_pathmeta_hdr(const struct rte_mbuf *m, unsigned int offset,
		struct scion_path_meta_hdr **scion_path_meta_hdr)
{
	if (unlikely(sizeof(struct scion_path_meta_hdr) > m->data_len - offset)) {
		LF_WORKER_LOG_DP(NOTICE, "Not yet implemented: SCION PathMeta header "
								 "exceeds first buffer segment.\n");
		return 0;
	}
	*scion_path_meta_hdr =
			rte_pktmbuf_mtod_offset(m, struct scion_path_meta_hdr *, offset);
	return offset + sizeof(struct scion_path_meta_hdr);
}

/**
 * Derives the SCION path header length from the PathMeta header.
 *
 * @param scion_path_meta_hdr PathMeta header.
 * @return Returns length of SCION path header.
 * Returns -1 if the number of hop fields exceeds 64, which is illegal.
 * Return -2 if an empty segment precedes a non-empty segment.
 */
static inline int
scion_path_meta_hdr_get_length(
		const struct scion_path_meta_hdr *scion_path_meta_hdr)
{
	uint32_t path_header_len;
	uint32_t seg0_len;
	uint32_t seg1_len;
	uint32_t seg2_len;

	seg0_len = ((scion_path_meta_hdr->seg_len[0] & 0x03) << 4) |
	           ((scion_path_meta_hdr->seg_len[1] & 0xF0) >> 4);
	seg1_len = ((scion_path_meta_hdr->seg_len[1] & 0x0F) << 2) |
	           ((scion_path_meta_hdr->seg_len[2] & 0xC0) >> 6);
	seg2_len = ((scion_path_meta_hdr->seg_len[2] & 0x3F));

	/* Number of hops cannot exceed 64 */
	if (unlikely(seg0_len + seg1_len + seg2_len > 64)) {
		LF_WORKER_LOG_DP(NOTICE, "SCION Path contains too many hops\n");
		return -1;
	}

	/* An empty segment cannot preced a non-empty segment */
	if (unlikely((seg2_len != 0 && seg1_len == 0) ||
				 (seg1_len != 0 && seg0_len == 0))) {
		LF_WORKER_LOG_DP(NOTICE, "SCION Path invalid\n");
		return -2;
	}

	path_header_len =
			sizeof(struct scion_path_meta_hdr) +
			(seg0_len ? SCION_PATH_INFOFIELD_SIZE +
									seg0_len * SCION_PATH_HOPFIELD_SIZE
					  : 0) +
			(seg1_len ? SCION_PATH_INFOFIELD_SIZE +
									seg1_len * SCION_PATH_HOPFIELD_SIZE
					  : 0) +
			(seg2_len ? SCION_PATH_INFOFIELD_SIZE +
									seg2_len * SCION_PATH_HOPFIELD_SIZE
					  : 0);

	assert(path_header_len <= INT_MAX);
	return (int)path_header_len;
}

/**
 * Derive path header length.
 *
 * @param m
 * @param offset Offset to the path header.
 * @param path_type SCION path type.
 * @return Returns length of path header, or a negative number if an error
 * occurred.
 */
static inline int
scion_path_hdr_length(const struct rte_mbuf *m, unsigned int offset,
		uint8_t path_type)
{
	int res;
	struct scion_path_meta_hdr *scion_path_meta_hdr;

	switch (path_type) {
	case SCION_PATH_TYPE_EMPTY:
		return 0;
	case SCION_PATH_TYPE_SCION:
		offset = scion_get_pathmeta_hdr(m, offset, &scion_path_meta_hdr);
		if (offset == 0) {
			return -2;
		}

		res = scion_path_meta_hdr_get_length(scion_path_meta_hdr);
		if (res < 0) {
			return -3;
		}

		return res;
	case SCION_PATH_TYPE_ONEHOP:
		return (int)(sizeof(struct scion_path_info_hdr) +
					 2 * sizeof(struct scion_path_hop_hdr));
	default:
		LF_WORKER_LOG_DP(NOTICE, "Failed to calculate SCION path header length "
								 "(unknown type)\n");
		return -1;
	}
}

/**
 * Obtain the timestamp in the path. This function assumes that the complete
 * SCION header is in the same buffer.
 * @return Returns 0 on success. Returns 1 if the header does not contain any
 * timestamp. Returns -1 if the header parsing failed.
 */
static inline int
scion_get_path_timestamp(uint8_t path_type, void *path_hdr,
		uint32_t *path_timestamp)
{
	uint32_t seg0_len;
	struct scion_path_meta_hdr *scion_path_meta_hdr;
	struct scion_path_info_hdr *scion_path_info_hdr;

	switch (path_type) {
	case SCION_PATH_TYPE_EMPTY:
		// nothing to do here
		return 1;
		break;
	case SCION_PATH_TYPE_SCION:
		scion_path_meta_hdr = (struct scion_path_meta_hdr *)path_hdr;
		seg0_len = ((scion_path_meta_hdr->seg_len[0] & 0x03) << 4) |
		           ((scion_path_meta_hdr->seg_len[1] & 0xF0) >> 4);
		if (seg0_len == 0) {
			/*
			 * Empty Path:
			 * Because the following segments are not allowed to have to contain
			 * any hop fields, the SCION path must be empty.
			 */
			return 1;
		}

		scion_path_info_hdr =
				(struct scion_path_info_hdr *)(scion_path_meta_hdr + 1);
		*path_timestamp = rte_be_to_cpu_32(scion_path_info_hdr->timestamp);
		return 0;
	case SCION_PATH_TYPE_ONEHOP:
		scion_path_info_hdr = (struct scion_path_info_hdr *)path_hdr;
		*path_timestamp = rte_be_to_cpu_32(scion_path_info_hdr->timestamp);
		return 0;
	default:
		return -1;
	}
}


/*
 * SCION Extension Header Operations
 */

static inline unsigned int
scion_get_ext_hdr(const struct rte_mbuf *m, unsigned int offset,
		struct scion_ext_hdr **scion_ext_hdr)
{
	if (unlikely(sizeof(struct scion_ext_hdr) > m->data_len - offset)) {
		LF_WORKER_LOG_DP(NOTICE, "Not yet implemented: SCION address header "
								 "exceeds first buffer segment.\n");
		return 0;
	}
	*scion_ext_hdr = rte_pktmbuf_mtod_offset(m, struct scion_ext_hdr *, offset);
	return offset + sizeof(struct scion_ext_hdr);
}

static inline unsigned int
scion_get_spao_hdr(const struct rte_mbuf *m, unsigned int offset,
		struct scion_packet_authenticator_opt **scion_packet_authenticator_opt)
{
	if (unlikely(sizeof(struct scion_packet_authenticator_opt) >
				 m->data_len - offset)) {
		LF_WORKER_LOG_DP(NOTICE, "Not yet implemented: SCION address header "
								 "exceeds first buffer segment.\n");
		return 0;
	}
	*scion_packet_authenticator_opt = rte_pktmbuf_mtod_offset(m,
			struct scion_packet_authenticator_opt *, offset);
	return offset + sizeof(struct scion_packet_authenticator_opt);
}

/**
 * Add SPAO extension header to SCION packet and adjust the SCION header
 * fields accordingly.
 * @param offset: Offset to SCION next header (header after address and path
 * header)
 * @return Returns the length of the additional headers, i.e., the number of
 * bytes the preceding memory has been moved. Returns -1 if failed.
 */
static inline int
scion_add_spao_hdr(struct rte_mbuf *m, unsigned int offset,
		struct scion_cmn_hdr *scion_cmn_hdr,
		struct scion_packet_authenticator_opt **spao_hdr_ptr)
{
	uint8_t *next_hdr;
	/* Protocol after the SCION header (inclusive extensions) */
	uint8_t payload_protocol;
	struct scion_ext_hdr *scion_hbh_ext_hdr, *scion_e2e_ext_hdr;
	struct scion_packet_authenticator_opt *spao_hdr;

	/* TODO: Assume that there is no E2E header yet
	 * and a new E2E header must be added */
	const size_t add_hdr_len = sizeof(struct scion_ext_hdr) +
	                           sizeof(struct scion_packet_authenticator_opt);

	next_hdr = &scion_cmn_hdr->next_hdr;

	/* skip HBH header and adjust next_hdr and offset*/
	if (scion_cmn_hdr->next_hdr == SCION_PROTOCOL_HBH) {
		if (scion_get_ext_hdr(m, offset, &scion_hbh_ext_hdr) == 0) {
			return -1;
		}

		offset += SCION_EXT_HDR_LEN(scion_hbh_ext_hdr);
		if (offset > m->data_len) {
			LF_WORKER_LOG_DP(NOTICE,
					"SCION extension header length (%u) larger than data "
					"len "
					"(%u).",
					SCION_EXT_HDR_LEN(scion_hbh_ext_hdr), m->data_len);
			return -1;
		}
		next_hdr = &scion_hbh_ext_hdr->next_hdr;
	}

	/* next_hdr points either to scion_cmn_hdr->next_hdr or
	 * to scion_ext_hdr->next_hdr of the HBH */
	if (*next_hdr == SCION_PROTOCOL_E2E) {
		LF_WORKER_LOG_DP(WARNING, "Not yet implemented: SCION packet already "
								  "contains E2E header.\n");
		return -1;
	}

	/*
	 * Add the SCION E2E extension header with the SPAO header
	 */

	/* Remember the upper layer protocol */
	payload_protocol = *next_hdr;
	/* Set the next header field of the header just in front of the new E2E
	 * header */
	*next_hdr = SCION_PROTOCOL_E2E;

	/* TODO: check that packet does not become too big */

	/* move everything before the new header entry */
	char *p = rte_pktmbuf_prepend(m, add_hdr_len);
	if (unlikely(p == NULL)) {
		LF_WORKER_LOG_DP(ERR, "Not enough headroom to add SPAO.\n");
		return -1;
	}
	(void)memmove(rte_pktmbuf_mtod(m, uint8_t *),
			rte_pktmbuf_mtod(m, uint8_t *) + add_hdr_len, offset);
	/* adjust pointers to moved memory */
	scion_cmn_hdr =
			(struct scion_cmn_hdr *)((uint8_t *)scion_cmn_hdr - add_hdr_len);
	/* invalidate pointers to moved memory */
	(void)next_hdr;

	/* adjust lengths */
	scion_cmn_hdr->payload_len = rte_cpu_to_be_16(
			rte_be_to_cpu_16(scion_cmn_hdr->payload_len) + add_hdr_len);

	/*
	 * add E2E extension header
	 */
	offset = scion_get_ext_hdr(m, offset, &scion_e2e_ext_hdr);
	if (unlikely(offset == 0)) {
		/* This should not happen! */
		LF_WORKER_LOG_DP(ERR, "Could not get SCION E2E extension header after "
							  "extending packet\n");
		return -1;
	}

	/* set E2E next header and previous header's next header field */
	scion_e2e_ext_hdr->next_hdr = payload_protocol;
/* add_hdr_len must be multiple of 4 */
#ifndef __clang__
	static_assert(add_hdr_len % 4 == 0,
			"scion_add_spao_hdr: add_hdr_len is not a multiple of 4");
#endif
	scion_e2e_ext_hdr->ext_len = (add_hdr_len / 4) - 1;

	/*
	 * add SPAO
	 */
	offset = scion_get_spao_hdr(m, offset, &spao_hdr);
	if (unlikely(offset == 0)) {
		/* This should not happen! */
		LF_WORKER_LOG_DP(ERR,
				"Could not get SAPO header after extending packet\n");
		return -1;
	}

	spao_hdr->type = SCION_E2E_OPTION_TYPE_SPAO;
	spao_hdr->data_len = sizeof *spao_hdr - sizeof spao_hdr->type -
	                     sizeof spao_hdr->data_len;

	*spao_hdr_ptr = spao_hdr;

	assert(add_hdr_len <= INT_MAX);
	return (int)add_hdr_len;
}

/**
 * Set timestamp in the SPAO header.
 * Note that only the 6 least significant bytes of the timestamp are written.
 *
 * @param spao_hdr SPAO header to write the timestamp to.
 * @param timestamp Timestamp that is written to the SPAO header.
 */
static inline void
scion_spao_set_timestamp(struct scion_packet_authenticator_opt *spao_hdr,
		uint64_t timestamp)
{
	/* set timestamp bits to zero */
	spao_hdr->timestamp_unmasked &=
			rte_cpu_to_be_64(~SCION_PACKET_AUTHENTICATOR_OPT_TIMESTAMP_MASK);
	/* add timestamp */
	spao_hdr->timestamp_unmasked |= rte_cpu_to_be_64(
			timestamp & SCION_PACKET_AUTHENTICATOR_OPT_TIMESTAMP_MASK);
}

/**
 * Get timestamp from the SPAO header.
 * Note that the timestamp exists of at most 6 bytes.
 *
 * @param spao_hdr SPAO header to read the timestamp from.
 */
static inline uint64_t
scion_spao_get_timestamp(struct scion_packet_authenticator_opt *spao_hdr)
{
	return rte_be_to_cpu_64(spao_hdr->timestamp_unmasked) &
	       SCION_PACKET_AUTHENTICATOR_OPT_TIMESTAMP_MASK;
}

/**
 * Parse extension headers (hop-by-hop and end-to-end option headers).
 *
 * @param offset Offset to the header after the SCION header (including
 * address and path header).
 * @param payload_protocol Returns next header value.
 * @return On success, offset to the header after the extension headers.
 * Otherwise, 0.
 */
static inline unsigned int
scion_skip_extension_hdr(const struct rte_mbuf *m,
		const struct scion_cmn_hdr *scion_cmn_hdr, unsigned int offset,
		uint8_t *payload_protocol)
{
	struct scion_ext_hdr *scion_ext_hdr;
	uint8_t next_hdr;

	next_hdr = scion_cmn_hdr->next_hdr;
	if (next_hdr == SCION_PROTOCOL_HBH) {
		if (unlikely(scion_get_ext_hdr(m, offset, &scion_ext_hdr) == 0)) {
			return 0;
		}
		next_hdr = scion_ext_hdr->next_hdr;
		offset += SCION_EXT_HDR_LEN(scion_ext_hdr);
		if (unlikely(offset > m->data_len)) {
			LF_WORKER_LOG_DP(NOTICE,
					"SCION HBH extension header length (%u) larger than "
					"data "
					"len (%u).\n",
					SCION_EXT_HDR_LEN(scion_ext_hdr), m->data_len);
			return 0;
		}
	}

	if (next_hdr == SCION_PROTOCOL_E2E) {
		if (unlikely(scion_get_ext_hdr(m, offset, &scion_ext_hdr) == 0)) {
			return 0;
		}
		next_hdr = scion_ext_hdr->next_hdr;
		offset += SCION_EXT_HDR_LEN(scion_ext_hdr);
		if (unlikely(offset > m->data_len)) {
			LF_WORKER_LOG_DP(NOTICE,
					"SCION E2E extension header length (%u) larger than "
					"data "
					"len (%u).\n",
					SCION_EXT_HDR_LEN(scion_ext_hdr), m->data_len);
			return 0;
		}
	}

	*payload_protocol = next_hdr;
	return offset;
}

/*
 * SCION Gateway Operations
 */

static inline unsigned int
scion_get_gateway_frame_hdr(const struct rte_mbuf *m, unsigned int offset,
		struct scion_gateway_frame_hdr **scion_gateway_frame_hdr)
{
	if (unlikely(sizeof(struct scion_gateway_frame_hdr) >
				 m->data_len - offset)) {
		LF_WORKER_LOG_DP(NOTICE,
				"Not yet implemented: SCION gateway frame header "
				"exceeds first buffer segment.\n");
		return 0;
	}
	*scion_gateway_frame_hdr = rte_pktmbuf_mtod_offset(m,
			struct scion_gateway_frame_hdr *, offset);
	return offset + sizeof(struct scion_gateway_frame_hdr);
}

/**
 * Parse the SCION IP gateway header.
 *
 * @param offset to the gateway frame header
 * @param enc_ipv4_hdr Return pointer to the encapsulated IP packet.
 * @return When successful, Offset to the header after the encapsulated IP
 * packet. Otherwise, 0 when the packet is not a SIG frame packet, and -1
 * when there was a error while parsing (including unsupported packets).
 */
unsigned int
scion_skip_gateway_frame_hdr(const struct rte_mbuf *m, unsigned int offset,
		uint16_t frame_len, struct rte_ipv4_hdr **enc_ipv4_hdr);

/**
 * Parse the complete ETH/IPv4/UDP/SCION/UDP(dport=sig_port)/SIG packet.
 *
 * @param sig_port UDP destination port used by the SIG (cpu byte order)
 * @param enc_ipv4_hdr Return pointer to the encapsulated IP packet.
 * @return When successful, Offset to the header after the encapsulated IP
 * packet. Otherwise, 0 when the packet is not a SIG frame packet, and -1
 * when there was a error while parsing (including unsupported packets).
 */
int
scion_skip_gateway(uint16_t sig_port, const struct rte_mbuf *m,
		struct rte_ipv4_hdr **enc_ipv4_hdr);

#endif /* SCION_UTILS_H */
