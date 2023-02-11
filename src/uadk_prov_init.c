/*
 * Copyright 2022-2023 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2022-2023 Linaro ltd.
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

#include "uadk.h"
#include "uadk_async.h"

struct p_uadk_ctx {
	const OSSL_CORE_HANDLE *handle;
	OSSL_LIB_CTX *libctx;
};

static const char UADK_DEFAULT_PROPERTIES[] = "provider=uadk";

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


static OSSL_FUNC_provider_query_operation_fn p_prov_query;
static OSSL_FUNC_provider_teardown_fn p_teardown;

static const OSSL_ALGORITHM *p_prov_query(void *provctx, int operation_id,
					  int *no_cache)
{
	*no_cache = 0;

	switch (operation_id) {
	case OSSL_OP_DIGEST:
		return uadk_prov_digests;
	}
	return NULL;
}

static const OSSL_DISPATCH p_test_table[] = {
	{ OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))p_prov_query },
	{ OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))p_teardown },
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
	struct p_uadk_ctx *ctx;
	int ret;

	ctx = OPENSSL_zalloc(sizeof(*ctx));
	if (ctx == NULL)
		return 0;

	ret = async_module_init();
	if (!ret)
		fprintf(stderr, "async_module_init fail!\n");
	pthread_atfork(NULL, NULL, provider_init_child_at_fork_handler);

	*provctx = (void *)ctx;
	*out = p_test_table;
	return 1;
}

static void p_teardown(void *provctx)
{
	struct p_uadk_ctx *ctx = (struct p_uadk_ctx *)provctx;

	OPENSSL_free(ctx);

}
