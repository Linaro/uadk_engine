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
#ifndef UADK_PROV_H
#define UADK_PROV_H

struct p_uadk_ctx {
	const OSSL_CORE_HANDLE *handle;
	OSSL_LIB_CTX *libctx;
};

static inline OSSL_LIB_CTX *prov_libctx_of(struct p_uadk_ctx *ctx)
{
	if (ctx == NULL)
		return NULL;
	return ctx->libctx;
}

extern const OSSL_DISPATCH uadk_md5_functions[];
extern const OSSL_DISPATCH uadk_sm3_functions[];
extern const OSSL_DISPATCH uadk_sha1_functions[];
extern const OSSL_DISPATCH uadk_sha224_functions[];
extern const OSSL_DISPATCH uadk_sha256_functions[];
extern const OSSL_DISPATCH uadk_sha384_functions[];
extern const OSSL_DISPATCH uadk_sha512_functions[];

extern const OSSL_DISPATCH uadk_aes_128_cbc_functions[];
extern const OSSL_DISPATCH uadk_aes_192_cbc_functions[];
extern const OSSL_DISPATCH uadk_aes_256_cbc_functions[];
extern const OSSL_DISPATCH uadk_aes_128_ecb_functions[];
extern const OSSL_DISPATCH uadk_aes_192_ecb_functions[];
extern const OSSL_DISPATCH uadk_aes_256_ecb_functions[];
extern const OSSL_DISPATCH uadk_aes_128_xts_functions[];
extern const OSSL_DISPATCH uadk_aes_256_xts_functions[];
extern const OSSL_DISPATCH uadk_sm4_cbc_functions[];
extern const OSSL_DISPATCH uadk_sm4_ecb_functions[];
extern const OSSL_DISPATCH uadk_des_ede3_cbc_functions[];
extern const OSSL_DISPATCH uadk_des_ede3_ecb_functions[];

extern const OSSL_DISPATCH uadk_rsa_signature_functions[];
extern const OSSL_DISPATCH uadk_rsa_keymgmt_functions[];
extern const OSSL_DISPATCH uadk_rsa_asym_cipher_functions[];

void uadk_prov_destroy_digest(void);
void uadk_prov_destroy_cipher(void);
void uadk_prov_destroy_rsa(void);
#endif
