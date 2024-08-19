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

#define FUNC_MAX_NUM	32

/* Copy openssl/providers/implementations/include/prov/names.h */
#define PROV_NAMES_SHA2_224 "SHA2-224:SHA-224:SHA224:2.16.840.1.101.3.4.2.4"
#define PROV_NAMES_SHA2_256 "SHA2-256:SHA-256:SHA256:2.16.840.1.101.3.4.2.1"
#define PROV_NAMES_SHA2_384 "SHA2-384:SHA-384:SHA384:2.16.840.1.101.3.4.2.2"
#define PROV_NAMES_SHA2_512 "SHA2-512:SHA-512:SHA512:2.16.840.1.101.3.4.2.3"

typedef int CRYPTO_REF_COUNT;

struct ossl_provider_st {
	/* Flag bits */
	unsigned int flag_initialized:1;
	unsigned int flag_activated:1;
	unsigned int flag_fallback:1; /* Can be used as fallback */

	/* Getting and setting the flags require synchronization */
	CRYPTO_RWLOCK *flag_lock;

	/* OpenSSL library side data */
	CRYPTO_REF_COUNT refcnt;
	CRYPTO_RWLOCK *refcnt_lock;  /* For the ref counter */
	int activatecnt;
	char *name;
	char *path;
	void *module;
	OSSL_provider_init_fn *init_function;

	STACK_OF(INFOPAIR) * parameters;
	OSSL_LIB_CTX *libctx; /* The library context this instance is in */
	struct provider_store_st *store; /* The store this instance belongs to */
#ifndef FIPS_MODULE
	/*
	 * In the FIPS module inner provider, this isn't needed, since the
	 * error upcalls are always direct calls to the outer provider.
	 */
	int error_lib;     /* ERR library number, one for each provider */
# ifndef OPENSSL_NO_ERR
	char *error_strings; /* Copy of what the provider gives us */
# endif
#endif

	/* Provider side functions */
	OSSL_FUNC_provider_teardown_fn * teardown;
	OSSL_FUNC_provider_gettable_params_fn *gettable_params;
	OSSL_FUNC_provider_get_params_fn *get_params;
	OSSL_FUNC_provider_get_capabilities_fn *get_capabilities;
	OSSL_FUNC_provider_self_test_fn *self_test;
	OSSL_FUNC_provider_query_operation_fn *query_operation;
	OSSL_FUNC_provider_unquery_operation_fn *unquery_operation;

	/*
	 * Cache of bit to indicate of query_operation() has been called on
	 * a specific operation or not.
	 */
	unsigned char *operation_bits;
	size_t operation_bits_sz;
	CRYPTO_RWLOCK *opbits_lock;

#ifndef FIPS_MODULE
	/* Whether this provider is the child of some other provider */
	const OSSL_CORE_HANDLE * handle;
	unsigned int ischild:1;
#endif

	/* Provider side data */
	void *provctx;
	const OSSL_DISPATCH *dispatch;
};

typedef struct bio_method_st {
	int type;
	char *name;
	int (*bwrite)(BIO *bio, const char *data, size_t datal, size_t *written);
	int (*bwrite_old)(BIO *bio, const char *data, int datal);
	int (*bread)(BIO *bio, char *data, size_t datal, size_t *read);
	int (*bread_old)(BIO *bio, char *data, int datal);
	int (*bputs)(BIO *bio, const char *buf);
	int (*bgets)(BIO *bio, char *buf, int size);
	long (*ctrl)(BIO *bio, int cmd, long larg, void *parg);
	int (*create)(BIO *bio);
	int (*destroy)(BIO *bio);
	long (*callback_ctrl)(BIO *bio, int cmd, BIO_info_cb *fp);
} UADK_BIO_METHOD;

typedef struct uadk_prov_ctx {
	const OSSL_CORE_HANDLE *handle;
	OSSL_LIB_CTX *libctx;
	UADK_BIO_METHOD *corebiometh;
} UADK_PROV_CTX;

static inline OSSL_LIB_CTX *prov_libctx_of(struct uadk_prov_ctx *ctx)
{
	if (ctx == NULL)
		return NULL;
	return ctx->libctx;
}

extern const OSSL_DISPATCH uadk_md5_functions[FUNC_MAX_NUM];
extern const OSSL_DISPATCH uadk_sm3_functions[FUNC_MAX_NUM];
extern const OSSL_DISPATCH uadk_sha1_functions[FUNC_MAX_NUM];
extern const OSSL_DISPATCH uadk_sha224_functions[FUNC_MAX_NUM];
extern const OSSL_DISPATCH uadk_sha256_functions[FUNC_MAX_NUM];
extern const OSSL_DISPATCH uadk_sha384_functions[FUNC_MAX_NUM];
extern const OSSL_DISPATCH uadk_sha512_functions[FUNC_MAX_NUM];
extern const OSSL_DISPATCH uadk_sha512_224_functions[FUNC_MAX_NUM];
extern const OSSL_DISPATCH uadk_sha512_256_functions[FUNC_MAX_NUM];


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

extern const OSSL_DISPATCH uadk_dh_keymgmt_functions[];
extern const OSSL_DISPATCH uadk_dh_keyexch_functions[];

void uadk_prov_destroy_digest(void);
void uadk_prov_destroy_cipher(void);
void uadk_prov_destroy_rsa(void);
void uadk_prov_destroy_dh(void);

/* offload small packets to sw */
extern int enable_sw_offload;
#endif
