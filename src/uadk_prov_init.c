/*
 * Copyright 2023-2024 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2023-2024 Linaro ltd.
 *
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

#include <openssl/bio.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

#include "uadk_async.h"
#include "uadk_prov.h"
#include "uadk_prov_bio.h"
#include "uadk_prov_pkey.h"

static const char UADK_DEFAULT_PROPERTIES[] = "provider=uadk_provider";
static OSSL_PROVIDER *prov;

/* Functions provided by the core */
static OSSL_FUNC_core_gettable_params_fn *c_gettable_params;
static OSSL_FUNC_core_get_params_fn *c_get_params;
static OSSL_FUNC_core_get_libctx_fn *c_get_libctx;

/* Functions provided by the core */
static OSSL_FUNC_core_get_params_fn *c_get_params;
static OSSL_FUNC_core_get_libctx_fn *c_get_libctx;

struct uadk_provider_params {
	char *enable_sw_offload;
} uadk_params;

/* offload small packets to sw */
int enable_sw_offload;

const OSSL_ALGORITHM uadk_prov_digests[] = {
	{ OSSL_DIGEST_NAME_MD5, UADK_DEFAULT_PROPERTIES,
	  uadk_md5_functions, "uadk_provider md5" },
	{ OSSL_DIGEST_NAME_SM3, UADK_DEFAULT_PROPERTIES,
	  uadk_sm3_functions, "uadk_provider sm3" },
	{ OSSL_DIGEST_NAME_SHA1, UADK_DEFAULT_PROPERTIES,
	  uadk_sha1_functions, "uadk_provider sha1" },
	{ PROV_NAMES_SHA2_224, UADK_DEFAULT_PROPERTIES,
	  uadk_sha224_functions, "uadk_provider sha2-224" },
	{ PROV_NAMES_SHA2_256, UADK_DEFAULT_PROPERTIES,
	  uadk_sha256_functions, "uadk_provider sha2-256" },
	{ PROV_NAMES_SHA2_384, UADK_DEFAULT_PROPERTIES,
	  uadk_sha384_functions, "uadk_provider sha2-384" },
	{ PROV_NAMES_SHA2_512, UADK_DEFAULT_PROPERTIES,
	  uadk_sha512_functions, "uadk_provider sha2-512" },
	{ "SHA2-512/224:SHA-512/224:SHA512-224", UADK_DEFAULT_PROPERTIES,
	  uadk_sha512_224_functions, "uadk_provider sha2-512-224" },
	{ "SHA2-512/256:SHA-512/256:SHA512-256", UADK_DEFAULT_PROPERTIES,
	  uadk_sha512_256_functions, "uadk_provider sha2-512-256" },
	{ NULL, NULL, NULL }
};

const OSSL_ALGORITHM uadk_prov_ciphers[] = {
	{ "AES-128-CBC", UADK_DEFAULT_PROPERTIES,
	  uadk_aes_128_cbc_functions, "uadk_provider aes-128-cbc" },
	{ "AES-192-CBC", UADK_DEFAULT_PROPERTIES,
	  uadk_aes_192_cbc_functions, "uadk_provider aes-192-cbc" },
	{ "AES-256-CBC", UADK_DEFAULT_PROPERTIES,
	  uadk_aes_256_cbc_functions, "uadk_provider aes-256-cbc" },
	{ "AES-128-CBC-CTS", UADK_DEFAULT_PROPERTIES,
	  uadk_aes_128_cts_functions, "uadk_provider aes-128-cbc-cts" },
	{ "AES-192-CBC-CTS", UADK_DEFAULT_PROPERTIES,
	  uadk_aes_192_cts_functions, "uadk_provider aes-192-cbc-cts" },
	{ "AES-256-CBC-CTS", UADK_DEFAULT_PROPERTIES,
	  uadk_aes_256_cts_functions, "uadk_provider aes-256-cbc-cts" },
	{ "AES-128-ECB", UADK_DEFAULT_PROPERTIES,
	  uadk_aes_128_ecb_functions, "uadk_provider aes-128-ecb" },
	{ "AES-192-ECB", UADK_DEFAULT_PROPERTIES,
	  uadk_aes_192_ecb_functions, "uadk_provider aes-192-ecb" },
	{ "AES-256-ECB", UADK_DEFAULT_PROPERTIES,
	  uadk_aes_256_ecb_functions, "uadk_provider aes-256-ecb" },
	{ "AES-128-XTS", UADK_DEFAULT_PROPERTIES,
	  uadk_aes_128_xts_functions, "uadk_provider aes-128-xts" },
	{ "AES-256-XTS", UADK_DEFAULT_PROPERTIES,
	  uadk_aes_256_xts_functions, "uadk_provider aes-256-xts" },
	{ "AES-128-CTR", UADK_DEFAULT_PROPERTIES,
	  uadk_aes_128_ctr_functions, "uadk_provider aes-128-ctr" },
	{ "AES-192-CTR", UADK_DEFAULT_PROPERTIES,
	  uadk_aes_192_ctr_functions, "uadk_provider aes-192-ctr" },
	{ "AES-256-CTR", UADK_DEFAULT_PROPERTIES,
	  uadk_aes_256_ctr_functions, "uadk_provider aes-256-ctr" },
	{ "AES-128-OFB", UADK_DEFAULT_PROPERTIES,
	  uadk_aes_128_ofb128_functions, "uadk_provider aes-128-ofb" },
	{ "AES-192-OFB", UADK_DEFAULT_PROPERTIES,
	  uadk_aes_192_ofb128_functions, "uadk_provider aes-192-ofb" },
	{ "AES-256-OFB", UADK_DEFAULT_PROPERTIES,
	  uadk_aes_256_ofb128_functions, "uadk_provider aes-256-ofb" },
	{ "AES-128-CFB", UADK_DEFAULT_PROPERTIES,
	  uadk_aes_128_cfb128_functions, "uadk_provider aes-128-cfb" },
	{ "AES-192-CFB", UADK_DEFAULT_PROPERTIES,
	  uadk_aes_192_cfb128_functions, "uadk_provider aes-192-cfb" },
	{ "AES-256-CFB", UADK_DEFAULT_PROPERTIES,
	  uadk_aes_256_cfb128_functions, "uadk_provider aes-256-cfb" },
	{ "SM4-CBC", UADK_DEFAULT_PROPERTIES,
	  uadk_sm4_cbc_functions, "uadk_provider sm4-cbc" },
	{ "SM4-ECB", UADK_DEFAULT_PROPERTIES,
	  uadk_sm4_ecb_functions, "uadk_provider sm4-ecb" },
	{ "SM4-OFB", UADK_DEFAULT_PROPERTIES,
	  uadk_sm4_ofb128_functions, "uadk_provider sm4-ofb" },
	{ "SM4-CFB", UADK_DEFAULT_PROPERTIES,
	  uadk_sm4_cfb128_functions, "uadk_provider sm4-cfb" },
	{ "SM4-CTR", UADK_DEFAULT_PROPERTIES,
	  uadk_sm4_ctr_functions, "uadk_provider sm4-ctr" },
	{ "DES-EDE3-CBC", UADK_DEFAULT_PROPERTIES,
	  uadk_des_ede3_cbc_functions, "uadk_provider des-ede3-cbc" },
	{ "DES-EDE3-ECB", UADK_DEFAULT_PROPERTIES,
	  uadk_des_ede3_ecb_functions, "uadk_provider des-ede3-ecb" },
	{ NULL, NULL, NULL }
};

static const OSSL_ALGORITHM uadk_prov_signature[] = {
	{ "RSA", UADK_DEFAULT_PROPERTIES,
	  uadk_rsa_signature_functions, "uadk_provider rsa_signature" },
	{ "SM2", UADK_DEFAULT_PROPERTIES,
	  uadk_sm2_signature_functions, "uadk_provider sm2_signature" },
	{ NULL, NULL, NULL }
};

static const OSSL_ALGORITHM uadk_prov_keymgmt[] = {
	{ "RSA", UADK_DEFAULT_PROPERTIES,
	  uadk_rsa_keymgmt_functions, "uadk RSA Keymgmt implementation." },
	{ "DH", UADK_DEFAULT_PROPERTIES, uadk_dh_keymgmt_functions },
	{ "SM2", UADK_DEFAULT_PROPERTIES,
	  uadk_sm2_keymgmt_functions, "uadk SM2 Keymgmt implementation." },
	{ NULL, NULL, NULL }
};

static const OSSL_ALGORITHM uadk_prov_asym_cipher[] = {
	{ "RSA", UADK_DEFAULT_PROPERTIES,
	  uadk_rsa_asym_cipher_functions, "uadk RSA asym cipher implementation." },
	{ "SM2", UADK_DEFAULT_PROPERTIES,
	  uadk_sm2_asym_cipher_functions, "uadk SM2 asym cipher implementation." },
	{ NULL, NULL, NULL }
};

static const OSSL_ALGORITHM uadk_prov_keyexch[] = {
	{ "DH", UADK_DEFAULT_PROPERTIES,
	  uadk_dh_keyexch_functions, "UADK DH keyexch implementation"},
	{ NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *uadk_query(void *provctx, int operation_id,
					int *no_cache)
{
	static int prov_init;

	prov = OSSL_PROVIDER_load(NULL, "default");
	if (!prov_init) {
		prov_init = 1;
		/* uadk_provider takes the highest priority
		 * and overwrite the openssl.cnf property.
		 */
		EVP_set_default_properties(NULL, "?provider=uadk_provider");
	}

	*no_cache = 0;
	switch (operation_id) {
	case OSSL_OP_DIGEST:
		return uadk_prov_digests;
	case OSSL_OP_CIPHER:
		return uadk_prov_ciphers;
	case OSSL_OP_SIGNATURE:
		(void)uadk_prov_signature_alg();
		return uadk_prov_signature;
	case OSSL_OP_KEYMGMT:
		(void)uadk_prov_keymgmt_alg();
		return uadk_prov_keymgmt;
	case OSSL_OP_ASYM_CIPHER:
		(void)uadk_prov_asym_cipher_alg();
		return uadk_prov_asym_cipher;
	case OSSL_OP_KEYEXCH:
		return uadk_prov_keyexch;
	case OSSL_OP_STORE:
		return prov->query_operation(provctx, operation_id, no_cache);
	}
	return NULL;
}

static void uadk_teardown(void *provctx)
{
	struct uadk_prov_ctx *ctx = (struct uadk_prov_ctx *)provctx;

	uadk_prov_destroy_digest();
	uadk_prov_destroy_cipher();
	uadk_prov_destroy_rsa();
	uadk_prov_sm2_uninit();
	uadk_prov_dh_uninit();
	OPENSSL_free(ctx);
	OSSL_PROVIDER_unload(prov);
	async_poll_task_free();
}

static const OSSL_DISPATCH uadk_dispatch_table[] = {
	{ OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))uadk_query },
	{ OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))uadk_teardown },
	{ 0, NULL }
};

int uadk_get_params_from_core(const OSSL_CORE_HANDLE *handle)
{
	OSSL_PARAM core_params[2], *p = core_params;

	*p++ = OSSL_PARAM_construct_utf8_ptr(
			"enable_sw_offload",
			(char **)&uadk_params.enable_sw_offload,
			0);

	*p = OSSL_PARAM_construct_end();

	if (!c_get_params(handle, core_params)) {
		fprintf(stderr, "WARN: UADK get parameters from core is failed.\n");
		return 0;
	}

	if (uadk_params.enable_sw_offload)
		enable_sw_offload = atoi(uadk_params.enable_sw_offload);

	return 1;
}

static void provider_init_child_at_fork_handler(void)
{
	int ret;

	ret = async_module_init();
	if (!ret)
		fprintf(stderr, "async_module_init fail!\n");
}

static int uadk_prov_ctx_set_core_bio_method(struct uadk_prov_ctx *ctx)
{
	UADK_BIO_METHOD *core_bio;

	core_bio = ossl_bio_prov_init_bio_method();
	if (core_bio == NULL) {
		fprintf(stderr, "failed to set bio from dispatch\n");
		return 0;
	}

	ctx->corebiometh = core_bio;

	return 1;
}

static void ossl_prov_core_from_dispatch(const OSSL_DISPATCH *fns)
{
	while (fns && fns->function_id != 0) {
		switch (fns->function_id) {
		case OSSL_FUNC_CORE_GETTABLE_PARAMS:
			c_gettable_params = OSSL_FUNC_core_gettable_params(fns);
			break;
		case OSSL_FUNC_CORE_GET_PARAMS:
			c_get_params = OSSL_FUNC_core_get_params(fns);
			break;
		case OSSL_FUNC_CORE_GET_LIBCTX:
			c_get_libctx = OSSL_FUNC_core_get_libctx(fns);
			break;
		default:
			 /* Just ignore anything we don't understand */
			break;
		}
		fns++;
	}
}

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
		       const OSSL_DISPATCH *oin,
		       const OSSL_DISPATCH **out,
		       void **provctx)
{
	struct uadk_prov_ctx *ctx;
	int ret;

	if (oin == NULL) {
		fprintf(stderr, "failed to get dispatch in\n");
		return 0;
	}

	ossl_prov_bio_from_dispatch(oin);
	ossl_prov_core_from_dispatch(oin);

	/* get parameters from uadk_provider.cnf */
	if (!uadk_get_params_from_core(handle))
		return 0;

	ctx = OPENSSL_zalloc(sizeof(*ctx));
	if (ctx == NULL) {
		fprintf(stderr, "failed to alloc ctx\n");
		return 0;
	}

	/* Set handle from core to get core functions */
	ctx->handle = handle;
	ctx->libctx = (OSSL_LIB_CTX *)c_get_libctx(handle);

	ret = uadk_prov_ctx_set_core_bio_method(ctx);
	if (!ret)
		return 0;

	ret = async_module_init();
	if (!ret)
		fprintf(stderr, "async_module_init fail!\n");
	pthread_atfork(NULL, NULL, provider_init_child_at_fork_handler);

	*provctx = (void *)ctx;
	*out = uadk_dispatch_table;

	return 1;
}
