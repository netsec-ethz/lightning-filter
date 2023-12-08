/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#ifndef LF_CRYPT0_H
#define LF_CRYPT0_H

#include <inttypes.h>

#include <openssl/evp.h>

#define LF_CRYPTO_DRKEY_SIZE     16
#define LF_CRYPTO_MAC_SIZE       16
#define LF_CRYPTO_MAC_DATA_SIZE  32
#define LF_CRYPTO_CBC_IV_SIZE    16
#define LF_CRYPTO_CBC_BLOCK_SIZE 16

#define LF_CRYPTO_HASH_LENGTH 20

#define LF_CRYPTO_DRKEY_ROUNDKEY_SIZE (11 * LF_CRYPTO_DRKEY_SIZE)

/*
 * Cypher context for DRKey (CBC-MAC) computations, which allows to reuse data
 * structures to increase performance.
 */
struct lf_crypto_drkey_ctx {
#ifdef LF_CBCMAC_AESNI
	/* field to avoid empty struct */
	uint8_t dummy;
#else
	EVP_CIPHER_CTX *mdctx;
#endif
};

/*
 * DRKey wrapper containing the key and data of the CBC-MAC preprocessing.
 * This data structure should be used if the DRKey is used more than once.
 */
struct lf_crypto_drkey {
	uint8_t key[LF_CRYPTO_DRKEY_SIZE];
#ifdef LF_CBCMAC_AESNI
	uint8_t roundkey[LF_CRYPTO_DRKEY_ROUNDKEY_SIZE];
#endif
};

/**
 * Initialize the crypto DRKey context.
 * Before freeing, lf_crypto_drkey_ctx_close must be called.
 *
 * @param ctx Crypto DRKey context struct to be initialized.
 * @return int 0 on success.
 */
int
lf_crypto_drkey_ctx_init(struct lf_crypto_drkey_ctx *ctx);

void
lf_crypto_drkey_ctx_close(struct lf_crypto_drkey_ctx *ctx);

/**
 * Compute the CBC-MAC of the data with the given DRKey.
 *
 * @param ctx Crypto DRKey context for the CBC-MAC computation.
 * @param drkey The DRKey to be used.
 * @param data Data for the CBC-MAC computation.
 * @param data_len Length of the data in bytes. Must be a multiple of the
 * CBC-MAC block size (16)!
 * @param mac Returns the CBC-MAC
 */
void
lf_crypto_drkey_cbcmac(struct lf_crypto_drkey_ctx *ctx,
		const struct lf_crypto_drkey *drkey, const uint8_t *data,
		size_t data_len, uint8_t mac[LF_CRYPTO_MAC_SIZE]);

/**
 * Compute the CBC-MAC of some data with fixed length (LF_CRYPTO_MAC_DATA_SIZE
 * bytes) with the given DRKey.
 *
 * @param ctx Crypto DRKey context for the CBC-MAC computation.
 * @param drkey The DRKey to be used.
 * @param data Data for the CBC-MAC computation.
 * @param mac Returns the CBC-MAC
 */
void
lf_crypto_drkey_compute_mac(struct lf_crypto_drkey_ctx *ctx,
		const struct lf_crypto_drkey *drkey,
		const uint8_t data[LF_CRYPTO_MAC_DATA_SIZE],
		uint8_t mac[LF_CRYPTO_MAC_SIZE]);

/**
 * Computes MAC over data using the given DRKey and compares it to an expected
 * MAC.
 * @param ctx Crypto DRKey context for the CBC-MAC computation.
 * @param drkey The DRKey to be used.
 * @param data Data for the CBC-MAC computation of length
 * LF_CRYPTO_MAC_DATA_SIZE.
 * @param expected_mac Expected MAC.
 * @returns Returns 0 if the calculated MAC is equal to expected MAC. Otherwise
 * it returns -1.
 */
int
lf_crypto_drkey_check_mac(struct lf_crypto_drkey_ctx *ctx,
		const struct lf_crypto_drkey *drkey,
		const uint8_t data[LF_CRYPTO_MAC_DATA_SIZE],
		const uint8_t expected_mac[LF_CRYPTO_MAC_SIZE]);

/**
 * Perform a DRKey derivation step.
 *
 * @param ctx Crypto DRKey context for the CBC-MAC computation.
 * @param drkey The DRKey to be used.
 * @param data Data to be included in the derivation step.
 * @param data_len Length of data.
 * @param drkey_out Returns the derived key.
 */
void
lf_crypto_drkey_derivation_step(struct lf_crypto_drkey_ctx *ctx,
		const struct lf_crypto_drkey *drkey, uint8_t *data, int data_len,
		struct lf_crypto_drkey *drkey_out);

/**
 * Set DRKey context from DRKey stored in a buffer.
 * Copies buffer to the DRKey context and performs pre-computations to increase
 * performance for later use of the DRKey. E.g., if LF_CBCMAC_AESNI is defined,
 * also the expanded roundkey is stored in the context.
 *
 * @param ctx Crypto DRKey context for the CBC-MAC computation.
 * @param drkey Raw DRKey to be used.
 * @param drkey_ctx DRKey context to set.
 */
void
lf_crypto_drkey_from_buf(struct lf_crypto_drkey_ctx *ctx,
		const uint8_t buf[LF_CRYPTO_DRKEY_SIZE], struct lf_crypto_drkey *drkey);

/**
 * Context for hash calculations
 */
struct lf_crypto_hash_ctx {
	EVP_MD_CTX *mdctx;
};

/**
 * Initialize the crypto hash context.
 * Before freeing, lf_crypto_hash_ctx_close must be called.
 *
 * @param ctx Crypto hash context struct to be initialized.
 * @return int 0 on success.
 */
int
lf_crypto_hash_ctx_init(struct lf_crypto_hash_ctx *ctx);

void
lf_crypto_hash_ctx_close(struct lf_crypto_hash_ctx *ctx);

/**
 * Hashes data_len bytes at data into the hash context.
 * This function can be called several times.
 */
void
lf_crypto_hash_update(struct lf_crypto_hash_ctx *ctx, const uint8_t *data,
		size_t data_len);

/**
 * Retrieves the hash value from the context.
 */
void
lf_crypto_hash_final(struct lf_crypto_hash_ctx *ctx,
		uint8_t hash[LF_CRYPTO_HASH_LENGTH]);

/**
 * Compare two hash values.
 * This function is not performed in constant since hash values are not based
 * on private data.
 * @return 0 if equal.
 */
int
lf_crypto_hash_cmp(const uint8_t actual_hash[LF_CRYPTO_HASH_LENGTH],
		const uint8_t expected_hash[LF_CRYPTO_HASH_LENGTH]);

#endif /* LF_CRYPTO_H */