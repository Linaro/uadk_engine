/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <openssl/engine.h>
#include "uadk.h"

struct cipher_priv_ctx {
	int enc;
};

static int cipher_nids[] = {
	NID_aes_128_cbc,
	NID_aes_192_cbc,
	NID_aes_256_cbc,
	NID_aes_128_ctr,
	NID_aes_192_ctr,
	NID_aes_256_ctr,
	NID_aes_128_xts,
	NID_aes_256_xts,
	0,
	};

static EVP_CIPHER *uadk_aes_128_cbc;
static EVP_CIPHER *uadk_aes_192_cbc;
static EVP_CIPHER *uadk_aes_256_cbc;
static EVP_CIPHER *uadk_aes_128_ctr;
static EVP_CIPHER *uadk_aes_192_ctr;
static EVP_CIPHER *uadk_aes_256_ctr;
static EVP_CIPHER *uadk_aes_128_xts;
static EVP_CIPHER *uadk_aes_256_xts;

static int uadk_engine_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
			       const int **nids, int nid)
{
	int ok = 1;

	if (!cipher) {
		*nids = cipher_nids;
		return (sizeof(cipher_nids) - 1) / sizeof(cipher_nids[0]);
	}

	switch (nid) {
	case NID_aes_128_cbc:
		*cipher = uadk_aes_128_cbc;
		break;
	case NID_aes_192_cbc:
		*cipher = uadk_aes_192_cbc;
		break;
	case NID_aes_256_cbc:
		*cipher = uadk_aes_256_cbc;
		break;
	case NID_aes_128_ctr:
		*cipher = uadk_aes_128_ctr;
		break;
	case NID_aes_192_ctr:
		*cipher = uadk_aes_192_ctr;
		break;
	case NID_aes_256_ctr:
		*cipher = uadk_aes_256_ctr;
		break;
	case NID_aes_128_xts:
		*cipher = uadk_aes_128_xts;
		break;
	case NID_aes_256_xts:
		*cipher = uadk_aes_256_xts;
		break;
	default:
		ok = 0;
		*cipher = NULL;
		break;
	}

	return ok;
}

static int uadk_cipher_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
			    const unsigned char *iv, int enc)
{
	return 1;
}

static int uadk_cipher_cleanup(EVP_CIPHER_CTX *ctx)
{
	return 1;
}

static int uadk_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
			  const unsigned char *in, size_t inlen)
{
	return 1;
}

#define UADK_CIPHER_DESCR(name, block_size, key_size, iv_len, flags, ctx_size,\
	init, cipher, cleanup, set_params, get_params)\
do { \
	uadk_##name = EVP_CIPHER_meth_new(NID_##name, block_size, key_size);\
	if (uadk_##name == 0 ||\
		!EVP_CIPHER_meth_set_iv_length(uadk_##name, iv_len) ||\
		!EVP_CIPHER_meth_set_flags(uadk_##name, flags) ||\
		!EVP_CIPHER_meth_set_impl_ctx_size(uadk_##name, ctx_size) ||\
		!EVP_CIPHER_meth_set_init(uadk_##name, init) ||\
		!EVP_CIPHER_meth_set_do_cipher(uadk_##name, cipher) ||\
		!EVP_CIPHER_meth_set_cleanup(uadk_##name, cleanup) ||\
		!EVP_CIPHER_meth_set_set_asn1_params(uadk_##name, set_params) ||\
		!EVP_CIPHER_meth_set_get_asn1_params(uadk_##name, get_params))\
		return 0;\
} while (0)

int uadk_bind_cipher(ENGINE *e)
{
	UADK_CIPHER_DESCR(aes_128_cbc, 16, 16, 16, EVP_CIPH_CBC_MODE,
			  sizeof(struct cipher_priv_ctx), uadk_cipher_init,
			  uadk_do_cipher, uadk_cipher_cleanup,
			  EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv);
	UADK_CIPHER_DESCR(aes_192_cbc, 16, 24, 16, EVP_CIPH_CBC_MODE,
			  sizeof(struct cipher_priv_ctx), uadk_cipher_init,
			  uadk_do_cipher, uadk_cipher_cleanup,
			  EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv);
	UADK_CIPHER_DESCR(aes_256_cbc, 16, 32, 16, EVP_CIPH_CBC_MODE,
			  sizeof(struct cipher_priv_ctx), uadk_cipher_init,
			  uadk_do_cipher, uadk_cipher_cleanup,
			  EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv);
	UADK_CIPHER_DESCR(aes_128_ctr, 1, 16, 16, EVP_CIPH_CTR_MODE,
			  sizeof(struct cipher_priv_ctx), uadk_cipher_init,
			  uadk_do_cipher, uadk_cipher_cleanup,
			  EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv);
	UADK_CIPHER_DESCR(aes_192_ctr, 1, 24, 16, EVP_CIPH_CTR_MODE,
			  sizeof(struct cipher_priv_ctx), uadk_cipher_init,
			  uadk_do_cipher, uadk_cipher_cleanup,
			  EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv);
	UADK_CIPHER_DESCR(aes_256_ctr, 1, 32, 16, EVP_CIPH_CTR_MODE,
			  sizeof(struct cipher_priv_ctx), uadk_cipher_init,
			  uadk_do_cipher, uadk_cipher_cleanup,
			  EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv);
	UADK_CIPHER_DESCR(aes_128_xts, 1, 32, 16, EVP_CIPH_XTS_MODE | EVP_CIPH_CUSTOM_IV,
			  sizeof(struct cipher_priv_ctx), uadk_cipher_init,
			  uadk_do_cipher, uadk_cipher_cleanup,
			  EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv);
	UADK_CIPHER_DESCR(aes_256_xts, 1, 64, 16, EVP_CIPH_XTS_MODE | EVP_CIPH_CUSTOM_IV,
			  sizeof(struct cipher_priv_ctx), uadk_cipher_init,
			  uadk_do_cipher, uadk_cipher_cleanup,
			  EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv);

	return ENGINE_set_ciphers(e, uadk_engine_ciphers);
}

void uadk_destroy_cipher(void)
{
	EVP_CIPHER_meth_free(uadk_aes_128_cbc);
	uadk_aes_128_cbc = 0;
	EVP_CIPHER_meth_free(uadk_aes_192_cbc);
	uadk_aes_192_cbc = 0;
	EVP_CIPHER_meth_free(uadk_aes_256_cbc);
	uadk_aes_256_cbc = 0;
	EVP_CIPHER_meth_free(uadk_aes_128_ctr);
	uadk_aes_128_ctr = 0;
	EVP_CIPHER_meth_free(uadk_aes_192_ctr);
	uadk_aes_192_ctr = 0;
	EVP_CIPHER_meth_free(uadk_aes_256_ctr);
	uadk_aes_256_ctr = 0;
	EVP_CIPHER_meth_free(uadk_aes_128_xts);
	uadk_aes_128_xts = 0;
	EVP_CIPHER_meth_free(uadk_aes_256_xts);
	uadk_aes_256_xts = 0;
}
