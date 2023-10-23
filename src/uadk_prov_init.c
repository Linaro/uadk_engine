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

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

#include "uadk_async.h"
#include "uadk_prov.h"

static const char UADK_DEFAULT_PROPERTIES[] = "provider=uadk_provider";
static OSSL_PROVIDER *prov;

const OSSL_ALGORITHM uadk_prov_digests[] = {
	{ OSSL_DIGEST_NAME_MD5, UADK_DEFAULT_PROPERTIES,
	  uadk_md5_functions, "uadk_provider md5" },
	{ OSSL_DIGEST_NAME_SM3, UADK_DEFAULT_PROPERTIES,
	  uadk_sm3_functions, "uadk_provider sm3" },
	{ OSSL_DIGEST_NAME_SHA1, UADK_DEFAULT_PROPERTIES,
	  uadk_sha1_functions, "uadk_provider sha1" },
	{ OSSL_DIGEST_NAME_SHA2_224, UADK_DEFAULT_PROPERTIES,
	  uadk_sha224_functions, "uadk_provider sha2-224" },
	{ OSSL_DIGEST_NAME_SHA2_256, UADK_DEFAULT_PROPERTIES,
	  uadk_sha256_functions, "uadk_provider sha2-256" },
	{ OSSL_DIGEST_NAME_SHA2_384, UADK_DEFAULT_PROPERTIES,
	  uadk_sha384_functions, "uadk_provider sha2-384" },
	{ OSSL_DIGEST_NAME_SHA2_512, UADK_DEFAULT_PROPERTIES,
	  uadk_sha512_functions, "uadk_provider sha2-512" },
	{ NULL, NULL, NULL }
};

const OSSL_ALGORITHM uadk_prov_ciphers[] = {
	{ "AES-128-CBC", UADK_DEFAULT_PROPERTIES,
	  uadk_aes_128_cbc_functions, "uadk_provider aes-128-cbc" },
	{ "AES-192-CBC", UADK_DEFAULT_PROPERTIES,
	  uadk_aes_192_cbc_functions, "uadk_provider aes-192-cbc" },
	{ "AES-256-CBC", UADK_DEFAULT_PROPERTIES,
	  uadk_aes_256_cbc_functions, "uadk_provider aes-256-cbc" },
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
	{ "SM4-CBC:SM4", UADK_DEFAULT_PROPERTIES,
	  uadk_sm4_cbc_functions, "uadk_provider sm4-cbc" },
	{ "SM4-ECB", UADK_DEFAULT_PROPERTIES,
	  uadk_sm4_ecb_functions, "uadk_provider sm4-ecb" },
	{ "DES-EDE3-CBC", UADK_DEFAULT_PROPERTIES,
	  uadk_des_ede3_cbc_functions, "uadk_provider des-ede3-cbc" },
	{ "DES-EDE3-ECB", UADK_DEFAULT_PROPERTIES,
	  uadk_des_ede3_ecb_functions, "uadk_provider des-ede3-ecb" },
	{ NULL, NULL, NULL }
};

static const OSSL_ALGORITHM uadk_prov_signature[] = {
	{ "RSA", UADK_DEFAULT_PROPERTIES,
	  uadk_rsa_signature_functions, "uadk_provider rsa_signature" },
	{ NULL, NULL, NULL }
};

static const OSSL_ALGORITHM uadk_prov_keymgmt[] = {
	{ "RSA", UADK_DEFAULT_PROPERTIES,
	  uadk_rsa_keymgmt_functions, "uadk RSA Keymgmt implementation." },
	{ "DH", UADK_DEFAULT_PROPERTIES, uadk_dh_keymgmt_functions },
	{ NULL, NULL, NULL }
};

static const OSSL_ALGORITHM uadk_prov_asym_cipher[] = {
	{ "RSA", UADK_DEFAULT_PROPERTIES, uadk_rsa_asym_cipher_functions },
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
		return uadk_prov_signature;
	case OSSL_OP_KEYMGMT:
		return uadk_prov_keymgmt;
	case OSSL_OP_ASYM_CIPHER:
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
	OPENSSL_free(ctx);
	OSSL_PROVIDER_unload(prov);
	async_poll_task_free();
}

static const OSSL_DISPATCH uadk_dispatch_table[] = {
	{ OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))uadk_query },
	{ OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))uadk_teardown },
	{ 0, NULL }
};

static void provider_init_child_at_fork_handler(void)
{
	int ret;

	ret = async_module_init();
	if (!ret)
		fprintf(stderr, "async_module_init fail!\n");
}

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
		       const OSSL_DISPATCH *oin,
		       const OSSL_DISPATCH **out,
		       void **provctx)
{
	struct uadk_prov_ctx *ctx;
	int ret;

	ctx = OPENSSL_zalloc(sizeof(*ctx));
	if (ctx == NULL)
		return 0;

	ctx->handle = handle;
	ret = async_module_init();
	if (!ret)
		fprintf(stderr, "async_module_init fail!\n");
	pthread_atfork(NULL, NULL, provider_init_child_at_fork_handler);

	*provctx = (void *)ctx;
	*out = uadk_dispatch_table;
	return 1;
}
