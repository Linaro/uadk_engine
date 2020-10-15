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
#include <openssl/md5.h>
#include "uadk.h"

static int digest_nids[] = {
	NID_md5,
	0,
	};

static EVP_MD *uadk_md5;

static int uadk_engine_digests(ENGINE *e, const EVP_MD **digest,
			       const int **nids, int nid)
{
	int ok = 1;

	if (!digest) {
		*nids = digest_nids;
		return (sizeof(digest_nids) - 1) / sizeof(digest_nids[0]);
	}

	switch (nid) {
	case NID_md5:
		*digest = uadk_md5;
		break;
	default:
		ok = 0;
		*digest = NULL;
		break;
	}

	return ok;
}

static int uadk_digest_init(EVP_MD_CTX *ctx)
{
	return 1;
}

static int uadk_digest_update(EVP_MD_CTX *ctx, const void *data, size_t data_len)
{
	return 1;
}

static int uadk_digest_final(EVP_MD_CTX *ctx, unsigned char *digest)
{
	return 1;
}

static int uadk_digest_cleanup(EVP_MD_CTX *ctx)
{
	return 1;
}

#define UADK_DIGEST_DESCR(name, pkey_type, md_size, flags,		\
	block_size, ctx_size, init, update, final, cleanup)		\
do { \
	uadk_##name = EVP_MD_meth_new(NID_##name, NID_##pkey_type);	\
	if (uadk_##name == 0 ||						\
	    !EVP_MD_meth_set_result_size(uadk_##name, md_size) ||	\
	    !EVP_MD_meth_set_input_blocksize(uadk_##name, block_size) || \
	    !EVP_MD_meth_set_app_datasize(uadk_##name, ctx_size) ||	\
	    !EVP_MD_meth_set_flags(uadk_##name, flags) ||		\
	    !EVP_MD_meth_set_init(uadk_##name, init) ||			\
	    !EVP_MD_meth_set_update(uadk_##name, update) ||		\
	    !EVP_MD_meth_set_final(uadk_##name, final) ||		\
	    !EVP_MD_meth_set_cleanup(uadk_##name, cleanup))		\
		return 0; \
} while (0)

int uadk_bind_digest(ENGINE *e)
{
	UADK_DIGEST_DESCR(md5, md5WithRSAEncryption, MD5_DIGEST_LENGTH, 0,
			  MD5_CBLOCK, sizeof(EVP_MD *) + sizeof(MD5_CTX),
			  uadk_digest_init, uadk_digest_update,
			  uadk_digest_final, uadk_digest_cleanup);

	return ENGINE_set_digests(e, uadk_engine_digests);
}

void uadk_destroy_digest(void)
{
	EVP_MD_meth_free(uadk_md5);
	uadk_md5 = 0;
}
