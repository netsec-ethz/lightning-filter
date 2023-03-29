/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021 ETH Zurich
 */

#include <assert.h>
#include <string.h>

#include <openssl/evp.h>

#include "crypto.h"

/**
 * Compare 16 bytes in constant time.
 * @return 0 if equal.
 */
inline static int
cmp_16(const void *x, const void *y)
{
	const unsigned char *a = x;
	const unsigned char *b = y;
	uint32_t d = 0;
	// NOLINTBEGIN(readability-magic-numbers)
	d |= a[0] ^ b[0];
	d |= a[1] ^ b[1];
	d |= a[2] ^ b[2];
	d |= a[3] ^ b[3];
	d |= a[4] ^ b[4];
	d |= a[5] ^ b[5];
	d |= a[6] ^ b[6];
	d |= a[7] ^ b[7];
	d |= a[8] ^ b[8];
	d |= a[9] ^ b[9];
	d |= a[10] ^ b[10];
	d |= a[11] ^ b[11];
	d |= a[12] ^ b[12];
	d |= a[13] ^ b[13];
	d |= a[14] ^ b[14];
	d |= a[15] ^ b[15];
	return (int)(1 & ((d - 1) >> 8)) - 1;
	// NOLINTEND(readability-magic-numbers)
}

int
lf_crypto_drkey_ctx_init(struct lf_crypto_drkey_ctx *ctx)
{
	int res;
	unsigned char iv[LF_CRYPTO_CBC_IV_SIZE];

	/* for CBC MAC, iv is always 0 */
	(void)memset(iv, 0, sizeof iv);

	ctx->mdctx = EVP_CIPHER_CTX_new();
	if (ctx->mdctx == NULL) {
		return -1;
	}
	res = EVP_EncryptInit_ex(ctx->mdctx, EVP_aes_128_cbc(), /* impl */ NULL,
			/* key */ NULL, iv);
	if (res != 1) {
		assert(res == 0);
		EVP_CIPHER_CTX_free(ctx->mdctx);
		return -1;
	}

	/* The data size is assumed to a multiple of the block size.
	 * Hence, no padding is required. */
	(void)EVP_CIPHER_CTX_set_padding(ctx->mdctx, 0);

	return 0;
}

void
lf_crypto_drkey_ctx_close(struct lf_crypto_drkey_ctx *ctx)
{
	EVP_CIPHER_CTX_free(ctx->mdctx);
}

void
lf_crypto_drkey_cbcmac(struct lf_crypto_drkey_ctx *ctx,
		const struct lf_crypto_drkey *drkey, const uint8_t *data,
		size_t data_len, uint8_t mac[LF_CRYPTO_MAC_SIZE])
{
	int res;
	size_t i;
	int n;
	static_assert(sizeof drkey->key == LF_CRYPTO_DRKEY_SIZE,
			"unexpected key size");
	res = EVP_EncryptInit_ex(ctx->mdctx, EVP_aes_128_cbc(), /* impl: */ NULL,
			drkey->key, /* iv: */ NULL);
	assert(res == 1);
	(void) res; // Unused variable in release

	assert(EVP_CIPHER_CTX_block_size(ctx->mdctx) == LF_CRYPTO_CBC_BLOCK_SIZE);
	assert(EVP_CIPHER_CTX_key_length(ctx->mdctx) == LF_CRYPTO_DRKEY_SIZE);
	assert(EVP_CIPHER_CTX_iv_length(ctx->mdctx) == LF_CRYPTO_CBC_IV_SIZE);

	/* CBC-MAC uses the CBC cipher of the last block */
	for (i = 0; i < data_len; i += LF_CRYPTO_CBC_BLOCK_SIZE) {
		res = EVP_EncryptUpdate(ctx->mdctx, mac, &n, data + i,
				LF_CRYPTO_CBC_BLOCK_SIZE);
		assert((res == 1) && (n == LF_CRYPTO_MAC_SIZE));
	(void) res; // Unused variable in release
	}
}

void
lf_crypto_drkey_from_buf(struct lf_crypto_drkey_ctx *ctx,
		const uint8_t buf[LF_CRYPTO_DRKEY_SIZE], struct lf_crypto_drkey *drkey)
{
	(void)ctx;
	static_assert(sizeof drkey->key == LF_CRYPTO_DRKEY_SIZE,
			"unexpected key size");
	memcpy(drkey->key, buf, LF_CRYPTO_DRKEY_SIZE);
}

void
lf_crypto_drkey_derivation_step(struct lf_crypto_drkey_ctx *ctx,
		const struct lf_crypto_drkey *drkey, uint8_t *data, int data_len,
		struct lf_crypto_drkey *drkey_out)
{
	assert(data_len % LF_CRYPTO_CBC_BLOCK_SIZE == 0);

	static_assert(sizeof drkey->key == LF_CRYPTO_MAC_SIZE,
			"unexpected key size");
	lf_crypto_drkey_cbcmac(ctx, drkey, data, data_len, drkey_out->key);
}

void
lf_crypto_drkey_compute_mac(struct lf_crypto_drkey_ctx *ctx,
		const struct lf_crypto_drkey *drkey,
		const uint8_t data[LF_CRYPTO_MAC_DATA_SIZE],
		uint8_t mac[LF_CRYPTO_MAC_SIZE])
{
	static_assert(LF_CRYPTO_MAC_DATA_SIZE % LF_CRYPTO_CBC_BLOCK_SIZE == 0,
			"unexpected data size");
	lf_crypto_drkey_cbcmac(ctx, drkey, data, LF_CRYPTO_MAC_DATA_SIZE, mac);
}

int
lf_crypto_drkey_check_mac(struct lf_crypto_drkey_ctx *ctx,
		const struct lf_crypto_drkey *drkey,
		const uint8_t data[LF_CRYPTO_MAC_DATA_SIZE],
		const uint8_t expected_mac[LF_CRYPTO_MAC_SIZE])
{
	uint8_t actual_mac[LF_CRYPTO_MAC_SIZE];
	lf_crypto_drkey_compute_mac(ctx, drkey, data, actual_mac);
	// NOLINTNEXTLINE(readability-magic-numbers)
	static_assert(LF_CRYPTO_MAC_SIZE == 16, "unexpected MAC size");
	return cmp_16(expected_mac, actual_mac);
}

int
lf_crypto_hash_ctx_init(struct lf_crypto_hash_ctx *ctx)
{
	int res;
	ctx->mdctx = EVP_MD_CTX_new();
	if (ctx->mdctx == NULL) {
		return -1;
	}
	res = EVP_DigestInit_ex(ctx->mdctx, EVP_sha1(), /* impl: */ NULL);
	if (res != 1) {
		assert(res == 0);
	(void) res; // Unused variable in release
		EVP_MD_CTX_free(ctx->mdctx);
		return -1;
	}
	return 0;
}

void
lf_crypto_hash_ctx_close(struct lf_crypto_hash_ctx *ctx)
{
	EVP_MD_CTX_free(ctx->mdctx);
}

void
lf_crypto_hash_update(struct lf_crypto_hash_ctx *ctx, const uint8_t *data,
		const size_t data_len)
{
	int res;
	res = EVP_DigestUpdate(ctx->mdctx, data, data_len);
	assert(res == 1);
	(void) res; // Unused variable in release
}

void
lf_crypto_hash_final(struct lf_crypto_hash_ctx *ctx,
		uint8_t hash[LF_CRYPTO_HASH_LENGTH])
{
	int res;
	unsigned int hash_length;
	res = EVP_DigestFinal_ex(ctx->mdctx, hash, &hash_length);
	assert(res == 1);
	(void) res; // Unused variable in release
	assert(hash_length == LF_CRYPTO_HASH_LENGTH);
	res = EVP_DigestInit_ex2(ctx->mdctx, /* type: */ NULL, /* impl: */ NULL);
	assert(res == 1);
	(void) res; // Unused variable in release
}

int
lf_crypto_hash_cmp(const uint8_t actual_hash[LF_CRYPTO_HASH_LENGTH],
		const uint8_t expected_hash[LF_CRYPTO_HASH_LENGTH])
{
	return memcmp(actual_hash, expected_hash, LF_CRYPTO_HASH_LENGTH);
}