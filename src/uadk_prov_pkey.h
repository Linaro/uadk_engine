/* SPDX-License-Identifier: Apache-2.0 */
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
#ifndef UADK_PROV_PKEY_H
#define UADK_PROV_PKEY_H
#include <openssl/asn1t.h>
#include <openssl/bn.h>
#include <openssl/buffer.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#include <openssl/proverr.h>
#include <openssl/types.h>
#include <uadk/wd_ecc.h>
#include <uadk/wd_sched.h>
#include "uadk_async.h"
#include "uadk_prov.h"

#define UADK_ECC_MAX_KEY_BITS		521
#define UADK_ECC_MAX_KEY_BYTES		66
#define UADK_ECC_CV_PARAM_NUM		6
#define UADK_P_INVALID			(-1)
#define PROV_KEYMGMT_ALG_NUM		7
#define ECC_POINT_SIZE(n)		((n) << 1)
#define UADK_OCTET_STRING		0x04
#define ECC128BITS			128
#define ECC192BITS			192
#define ECC224BITS			224
#define ECC256BITS			256
#define ECC320BITS			320
#define ECC384BITS			384
#define ECC521BITS			521
#define GET_RAND_MAX_CNT		100
#define OSSL_NELEM(x)			(sizeof(x)/sizeof((x)[0]))
#define UADK_ECC_PUBKEY_PARAM_NUM	2
#define OSSL_MAX_NAME_SIZE		50 /* Algorithm name */
#define OSSL_MAX_ALGORITHM_ID_SIZE	256 /* AlgorithmIdentifier DER */
#define TRANS_BITS_BYTES_SHIFT		3
#define GET_MS_BYTE(n)			((n) >> 8)
#define GET_LS_BYTE(n)			((n) & 0xFF)

enum HW_ASYM_ENC_DEV {
	HW_ASYM_ENC_INVALID = 0x0,
	HW_ASYM_ENC_V2 = 0x2,
	HW_ASYM_ENC_V3 = 0x3
};

enum {
	KEYMGMT_SM2 = 0x0,
	KEYMGMT_X448 = 0x1,
	KEYMGMT_ECDH = 0x2,
	KEYMGMT_X25519 = 0x3,
	KEYMGMT_MAX = 0x6
};

enum {
	SIGNATURE_SM2 = 0x0,
	SIGNATURE_ECDSA = 0x1,
	SIGNATURE_MAX = 0x3
};

enum {
	COFACTOR_MODE_USE_KEY = -1,
	COFACTOR_MODE_DISABLED = 0,
	COFACTOR_MODE_ENABLED = 1,
};

enum {
	KEYEXCH_X448 = 0x0,
	KEYEXCH_ECDH = 0x1,
	KEYEXCH_X25519 = 0x2,
};

struct curve_param {
	/* Prime */
	BIGNUM *p;
	/* ECC coefficient 'a' */
	BIGNUM *a;
	/* ECC coefficient 'b' */
	BIGNUM *b;
	/* Base point */
	const EC_POINT *g;
	/* Order of base point */
	const BIGNUM *order;
};

struct ec_gen_ctx {
	OSSL_LIB_CTX *libctx;
	char *group_name;
	char *encoding;
	char *pt_format;
	char *group_check;
	char *field_type;
	BIGNUM *p, *a, *b, *order, *cofactor;
	unsigned char *gen, *seed;
	size_t gen_len, seed_len;
	int selection;
	int ecdh_mode;
	EC_GROUP *gen_group;
	BIGNUM *priv_key;
};

typedef struct {
	/* libcrypto internal */
	int id;

	int name_id;
	char *type_name;
	const char *description;
	OSSL_PROVIDER *prov;
	int refcnt;
	void *lock;

	/* Constructor(s), destructor, information */
	OSSL_FUNC_keymgmt_new_fn *new_fun;
	OSSL_FUNC_keymgmt_free_fn *free;
	OSSL_FUNC_keymgmt_get_params_fn *get_params;
	OSSL_FUNC_keymgmt_gettable_params_fn *gettable_params;
	OSSL_FUNC_keymgmt_set_params_fn *set_params;
	OSSL_FUNC_keymgmt_settable_params_fn *settable_params;

	/* Generation, a complex constructor */
	OSSL_FUNC_keymgmt_gen_init_fn *gen_init;
	OSSL_FUNC_keymgmt_gen_set_template_fn *gen_set_template;
	OSSL_FUNC_keymgmt_gen_set_params_fn *gen_set_params;
	OSSL_FUNC_keymgmt_gen_settable_params_fn *gen_settable_params;
	OSSL_FUNC_keymgmt_gen_fn *gen;
	OSSL_FUNC_keymgmt_gen_cleanup_fn *gen_cleanup;
	OSSL_FUNC_keymgmt_load_fn *load;

	/* Key object checking */
	OSSL_FUNC_keymgmt_query_operation_name_fn *query_operation_name;
	OSSL_FUNC_keymgmt_has_fn *has;
	OSSL_FUNC_keymgmt_validate_fn *validate;
	OSSL_FUNC_keymgmt_match_fn *match;

	/* Import and export routines */
	OSSL_FUNC_keymgmt_import_fn *import;
	OSSL_FUNC_keymgmt_import_types_fn *import_types;
	OSSL_FUNC_keymgmt_export_fn *export_fun;
	OSSL_FUNC_keymgmt_export_types_fn *export_types;
	OSSL_FUNC_keymgmt_dup_fn *dup;
} UADK_PKEY_KEYMGMT;

#define UADK_PKEY_KEYMGMT_DESCR(nm, alg)	\
static OSSL_FUNC_keymgmt_new_fn uadk_keymgmt_##nm##_new;	\
static OSSL_FUNC_keymgmt_free_fn uadk_keymgmt_##nm##_free;	\
static OSSL_FUNC_keymgmt_get_params_fn uadk_keymgmt_##nm##_get_params;	\
static OSSL_FUNC_keymgmt_gettable_params_fn uadk_keymgmt_##nm##_gettable_params;	\
static OSSL_FUNC_keymgmt_set_params_fn uadk_keymgmt_##nm##_set_params;		\
static OSSL_FUNC_keymgmt_settable_params_fn uadk_keymgmt_##nm##_settable_params;	\
static OSSL_FUNC_keymgmt_gen_init_fn uadk_keymgmt_##nm##_gen_init;	\
static OSSL_FUNC_keymgmt_gen_set_template_fn uadk_keymgmt_##nm##_gen_set_template;	\
static OSSL_FUNC_keymgmt_gen_set_params_fn uadk_keymgmt_##nm##_gen_set_params;	\
static OSSL_FUNC_keymgmt_gen_settable_params_fn uadk_keymgmt_##nm##_gen_settable_params;	\
static OSSL_FUNC_keymgmt_gen_fn uadk_keymgmt_##nm##_gen;	\
static OSSL_FUNC_keymgmt_gen_cleanup_fn uadk_keymgmt_##nm##_gen_cleanup;	\
static OSSL_FUNC_keymgmt_load_fn uadk_keymgmt_##nm##_load;	\
static OSSL_FUNC_keymgmt_has_fn uadk_keymgmt_##nm##_has;	\
static OSSL_FUNC_keymgmt_validate_fn uadk_keymgmt_##nm##_validate;	\
static OSSL_FUNC_keymgmt_match_fn uadk_keymgmt_##nm##_match;	\
static OSSL_FUNC_keymgmt_import_fn uadk_keymgmt_##nm##_import;	\
static OSSL_FUNC_keymgmt_import_types_fn uadk_keymgmt_##nm##_import_types;	\
static OSSL_FUNC_keymgmt_export_fn uadk_keymgmt_##nm##_export;	\
static OSSL_FUNC_keymgmt_export_types_fn uadk_keymgmt_##nm##_export_types;	\
static OSSL_FUNC_keymgmt_dup_fn uadk_keymgmt_##nm##_dup;	\
static OSSL_FUNC_keymgmt_query_operation_name_fn uadk_keymgmt_##nm##_query_operation_name;	\
static UADK_PKEY_KEYMGMT get_default_##nm##_keymgmt(void)	\
{				\
	static UADK_PKEY_KEYMGMT s_keymgmt;	\
	static int initilazed;	\
				\
	if (!initilazed) {	\
		UADK_PKEY_KEYMGMT *keymgmt =	\
			(UADK_PKEY_KEYMGMT *)EVP_KEYMGMT_fetch(NULL, #alg, "provider=default");	\
				\
		if (keymgmt) {	\
			s_keymgmt = *keymgmt;	\
			EVP_KEYMGMT_free((EVP_KEYMGMT *)keymgmt);	\
			initilazed = 1;	\
		} else {	\
			fprintf(stderr, "failed to EVP_KEYMGMT_fetch default provider\n");	\
		}	\
	}	\
	return s_keymgmt;	\
}	\
const OSSL_DISPATCH uadk_##nm##_keymgmt_functions[] = {	\
	{ OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))uadk_keymgmt_##nm##_new },	\
	{ OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))uadk_keymgmt_##nm##_free },	\
	{ OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*) (void))uadk_keymgmt_##nm##_get_params },	\
	{ OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,	\
		(void (*) (void))uadk_keymgmt_##nm##_gettable_params },	\
	{ OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*) (void))uadk_keymgmt_##nm##_set_params },	\
	{ OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,	\
		(void (*) (void))uadk_keymgmt_##nm##_settable_params },	\
	{ OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))uadk_keymgmt_##nm##_gen_init },	\
	{ OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE, \
		(void (*)(void))uadk_keymgmt_##nm##_gen_set_template },	\
	{ OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,	\
		(void (*)(void))uadk_keymgmt_##nm##_gen_set_params },	\
	{ OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,	\
		(void (*)(void))uadk_keymgmt_##nm##_gen_settable_params },	\
	{ OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))uadk_keymgmt_##nm##_gen },	\
	{ OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))uadk_keymgmt_##nm##_gen_cleanup },	\
	{ OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))uadk_keymgmt_##nm##_load },	\
	{ OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))uadk_keymgmt_##nm##_has },	\
	{ OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))uadk_keymgmt_##nm##_validate },	\
	{ OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))uadk_keymgmt_##nm##_match },	\
	{ OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))uadk_keymgmt_##nm##_import },	\
	{ OSSL_FUNC_KEYMGMT_IMPORT_TYPES,	\
		(void (*)(void))uadk_keymgmt_##nm##_import_types },	\
	{ OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))uadk_keymgmt_##nm##_export },	\
	{ OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))uadk_keymgmt_##nm##_export_types },	\
	{ OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))uadk_keymgmt_##nm##_dup },	\
	{ OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,	\
		(void (*)(void))uadk_keymgmt_##nm##_query_operation_name },	\
	{ 0, NULL }	\
}	\

typedef struct {
	int name_id;
	char *type_name;
	const char *description;
	OSSL_PROVIDER *prov;
	int refcnt;
	void *lock;

	OSSL_FUNC_signature_newctx_fn *newctx;
	OSSL_FUNC_signature_sign_init_fn *sign_init;
	OSSL_FUNC_signature_sign_fn *sign;
	OSSL_FUNC_signature_verify_init_fn *verify_init;
	OSSL_FUNC_signature_verify_fn *verify;
	OSSL_FUNC_signature_verify_recover_init_fn *verify_recover_init;
	OSSL_FUNC_signature_verify_recover_fn *verify_recover;
	OSSL_FUNC_signature_digest_sign_init_fn *digest_sign_init;
	OSSL_FUNC_signature_digest_sign_update_fn *digest_sign_update;
	OSSL_FUNC_signature_digest_sign_final_fn *digest_sign_final;
	OSSL_FUNC_signature_digest_sign_fn *digest_sign;
	OSSL_FUNC_signature_digest_verify_init_fn *digest_verify_init;
	OSSL_FUNC_signature_digest_verify_update_fn *digest_verify_update;
	OSSL_FUNC_signature_digest_verify_final_fn *digest_verify_final;
	OSSL_FUNC_signature_digest_verify_fn *digest_verify;
	OSSL_FUNC_signature_freectx_fn *freectx;
	OSSL_FUNC_signature_dupctx_fn *dupctx;
	OSSL_FUNC_signature_get_ctx_params_fn *get_ctx_params;
	OSSL_FUNC_signature_gettable_ctx_params_fn *gettable_ctx_params;
	OSSL_FUNC_signature_set_ctx_params_fn *set_ctx_params;
	OSSL_FUNC_signature_settable_ctx_params_fn *settable_ctx_params;
	OSSL_FUNC_signature_get_ctx_md_params_fn *get_ctx_md_params;
	OSSL_FUNC_signature_gettable_ctx_md_params_fn *gettable_ctx_md_params;
	OSSL_FUNC_signature_set_ctx_md_params_fn *set_ctx_md_params;
	OSSL_FUNC_signature_settable_ctx_md_params_fn *settable_ctx_md_params;
} UADK_PKEY_SIGNATURE;

#define UADK_PKEY_SIGNATURE_DESCR(nm, alg)	\
static OSSL_FUNC_signature_newctx_fn uadk_signature_##nm##_newctx; \
static OSSL_FUNC_signature_sign_init_fn uadk_signature_##nm##_sign_init; \
static OSSL_FUNC_signature_verify_init_fn uadk_signature_##nm##_verify_init; \
static OSSL_FUNC_signature_sign_fn uadk_signature_##nm##_sign; \
static OSSL_FUNC_signature_verify_fn uadk_signature_##nm##_verify; \
static OSSL_FUNC_signature_verify_recover_init_fn uadk_signature_##nm##_verify_recover_init; \
static OSSL_FUNC_signature_verify_recover_fn uadk_signature_##nm##_verify_recover; \
static OSSL_FUNC_signature_digest_sign_init_fn uadk_signature_##nm##_digest_sign_init; \
static OSSL_FUNC_signature_digest_sign_update_fn uadk_signature_##nm##_digest_sign_update; \
static OSSL_FUNC_signature_digest_sign_final_fn uadk_signature_##nm##_digest_sign_final; \
static OSSL_FUNC_signature_digest_verify_init_fn uadk_signature_##nm##_digest_verify_init; \
static OSSL_FUNC_signature_digest_verify_update_fn uadk_signature_##nm##_digest_verify_update; \
static OSSL_FUNC_signature_digest_verify_final_fn uadk_signature_##nm##_digest_verify_final; \
static OSSL_FUNC_signature_freectx_fn uadk_signature_##nm##_freectx; \
static OSSL_FUNC_signature_dupctx_fn uadk_signature_##nm##_dupctx; \
static OSSL_FUNC_signature_get_ctx_params_fn uadk_signature_##nm##_get_ctx_params; \
static OSSL_FUNC_signature_gettable_ctx_params_fn uadk_signature_##nm##_gettable_ctx_params; \
static OSSL_FUNC_signature_set_ctx_params_fn uadk_signature_##nm##_set_ctx_params; \
static OSSL_FUNC_signature_settable_ctx_params_fn uadk_signature_##nm##_settable_ctx_params; \
static OSSL_FUNC_signature_get_ctx_md_params_fn uadk_signature_##nm##_get_ctx_md_params; \
static OSSL_FUNC_signature_gettable_ctx_md_params_fn uadk_signature_##nm##_gettable_ctx_md_params; \
static OSSL_FUNC_signature_set_ctx_md_params_fn uadk_signature_##nm##_set_ctx_md_params; \
static OSSL_FUNC_signature_settable_ctx_md_params_fn uadk_signature_##nm##_settable_ctx_md_params; \
const OSSL_DISPATCH uadk_##nm##_signature_functions[] = {	\
	{ OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))uadk_signature_##nm##_newctx },	\
	{ OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))uadk_signature_##nm##_sign_init }, \
	{ OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))uadk_signature_##nm##_sign }, \
	{ OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))uadk_signature_##nm##_verify_init }, \
	{ OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))uadk_signature_##nm##_verify }, \
	{ OSSL_FUNC_SIGNATURE_VERIFY_RECOVER_INIT, \
		(void (*)(void))uadk_signature_##nm##_verify_recover_init }, \
	{ OSSL_FUNC_SIGNATURE_VERIFY_RECOVER, \
		(void (*)(void))uadk_signature_##nm##_verify_recover }, \
	{ OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, \
		(void (*)(void))uadk_signature_##nm##_digest_sign_init }, \
	{ OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, \
		(void (*)(void))uadk_signature_##nm##_digest_sign_update }, \
	{ OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, \
		(void (*)(void))uadk_signature_##nm##_digest_sign_final }, \
	{ OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, \
		(void (*)(void))uadk_signature_##nm##_digest_verify_init }, \
	{ OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, \
		(void (*)(void))uadk_signature_##nm##_digest_verify_update }, \
	{ OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, \
		(void (*)(void))uadk_signature_##nm##_digest_verify_final }, \
	{ OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))uadk_signature_##nm##_freectx },	\
	{ OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))uadk_signature_##nm##_dupctx }, \
	{ OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, \
		(void (*)(void))uadk_signature_##nm##_get_ctx_params }, \
	{ OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, \
		(void (*)(void))uadk_signature_##nm##_gettable_ctx_params }, \
	{ OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, \
		(void (*)(void))uadk_signature_##nm##_set_ctx_params }, \
	{ OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, \
		(void (*)(void))uadk_signature_##nm##_settable_ctx_params }, \
	{ OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS, \
		(void (*)(void))uadk_signature_##nm##_get_ctx_md_params }, \
	{ OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS, \
		(void (*)(void))uadk_signature_##nm##_gettable_ctx_md_params }, \
	{ OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS, \
		(void (*)(void))uadk_signature_##nm##_set_ctx_md_params }, \
	{ OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS, \
		(void (*)(void))uadk_signature_##nm##_settable_ctx_md_params }, \
	{ 0, NULL } \
}	\

typedef struct {
	int name_id;
	char *type_name;
	const char *description;
	OSSL_PROVIDER *prov;
	int refcnt;
	void *lock;

	OSSL_FUNC_asym_cipher_newctx_fn *newctx;
	OSSL_FUNC_asym_cipher_encrypt_init_fn *encrypt_init;
	OSSL_FUNC_asym_cipher_encrypt_fn *encrypt;
	OSSL_FUNC_asym_cipher_decrypt_init_fn *decrypt_init;
	OSSL_FUNC_asym_cipher_decrypt_fn *decrypt;
	OSSL_FUNC_asym_cipher_freectx_fn *freectx;
	OSSL_FUNC_asym_cipher_dupctx_fn *dupctx;
	OSSL_FUNC_asym_cipher_get_ctx_params_fn *get_ctx_params;
	OSSL_FUNC_asym_cipher_gettable_ctx_params_fn *gettable_ctx_params;
	OSSL_FUNC_asym_cipher_set_ctx_params_fn *set_ctx_params;
	OSSL_FUNC_asym_cipher_settable_ctx_params_fn *settable_ctx_params;
} UADK_PKEY_ASYM_CIPHER;

#define UADK_PKEY_ASYM_CIPHER_DESCR(nm, alg)	\
static OSSL_FUNC_asym_cipher_newctx_fn uadk_asym_cipher_##nm##_newctx; \
static OSSL_FUNC_asym_cipher_encrypt_init_fn uadk_asym_cipher_##nm##_encrypt_init; \
static OSSL_FUNC_asym_cipher_encrypt_fn uadk_asym_cipher_##nm##_encrypt; \
static OSSL_FUNC_asym_cipher_decrypt_init_fn uadk_asym_cipher_##nm##_decrypt_init; \
static OSSL_FUNC_asym_cipher_decrypt_fn uadk_asym_cipher_##nm##_decrypt; \
static OSSL_FUNC_asym_cipher_freectx_fn uadk_asym_cipher_##nm##_freectx; \
static OSSL_FUNC_asym_cipher_dupctx_fn uadk_asym_cipher_##nm##_dupctx; \
static OSSL_FUNC_asym_cipher_get_ctx_params_fn uadk_asym_cipher_##nm##_get_ctx_params; \
static OSSL_FUNC_asym_cipher_gettable_ctx_params_fn uadk_asym_cipher_##nm##_gettable_ctx_params; \
static OSSL_FUNC_asym_cipher_set_ctx_params_fn uadk_asym_cipher_##nm##_set_ctx_params; \
static OSSL_FUNC_asym_cipher_settable_ctx_params_fn uadk_asym_cipher_##nm##_settable_ctx_params; \
const OSSL_DISPATCH uadk_##nm##_asym_cipher_functions[] = {	\
	{ OSSL_FUNC_ASYM_CIPHER_NEWCTX, (void (*)(void))uadk_asym_cipher_##nm##_newctx }, \
	{ OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT, \
		(void (*)(void))uadk_asym_cipher_##nm##_encrypt_init }, \
	{ OSSL_FUNC_ASYM_CIPHER_ENCRYPT, (void (*)(void))uadk_asym_cipher_##nm##_encrypt }, \
	{ OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT, \
		(void (*)(void))uadk_asym_cipher_##nm##_decrypt_init }, \
	{ OSSL_FUNC_ASYM_CIPHER_DECRYPT, (void (*)(void))uadk_asym_cipher_##nm##_decrypt }, \
	{ OSSL_FUNC_ASYM_CIPHER_FREECTX, (void (*)(void))uadk_asym_cipher_##nm##_freectx }, \
	{ OSSL_FUNC_ASYM_CIPHER_DUPCTX, (void (*)(void))uadk_asym_cipher_##nm##_dupctx }, \
	{ OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS, \
		(void (*)(void))uadk_asym_cipher_##nm##_get_ctx_params }, \
	{ OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS, \
		(void (*)(void))uadk_asym_cipher_##nm##_gettable_ctx_params }, \
	{ OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS, \
		(void (*)(void))uadk_asym_cipher_##nm##_set_ctx_params }, \
	{ OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS, \
			(void (*)(void))uadk_asym_cipher_##nm##_settable_ctx_params }, \
	{ 0, NULL } \
}	\

typedef struct {
	int name_id;
	char *type_name;
	const char *description;
	OSSL_PROVIDER *prov;
	int refcnt;
	void *lock;

	OSSL_FUNC_keyexch_newctx_fn *newctx;
	OSSL_FUNC_keyexch_init_fn *init;
	OSSL_FUNC_keyexch_set_peer_fn *set_peer;
	OSSL_FUNC_keyexch_derive_fn *derive;
	OSSL_FUNC_keyexch_freectx_fn *freectx;
	OSSL_FUNC_keyexch_dupctx_fn *dupctx;
	OSSL_FUNC_keyexch_set_ctx_params_fn *set_ctx_params;
	OSSL_FUNC_keyexch_settable_ctx_params_fn *settable_ctx_params;
	OSSL_FUNC_keyexch_get_ctx_params_fn *get_ctx_params;
	OSSL_FUNC_keyexch_gettable_ctx_params_fn *gettable_ctx_params;
} UADK_PKEY_KEYEXCH;

#define UADK_PKEY_KEYEXCH_DESCR(nm, alg)	\
	static OSSL_FUNC_keyexch_newctx_fn uadk_keyexch_##nm##_newctx;	\
	static OSSL_FUNC_keyexch_init_fn uadk_keyexch_##nm##_init;	\
	static OSSL_FUNC_keyexch_set_peer_fn uadk_keyexch_##nm##_set_peer;	\
	static OSSL_FUNC_keyexch_derive_fn uadk_keyexch_##nm##_derive;	\
	static OSSL_FUNC_keyexch_freectx_fn uadk_keyexch_##nm##_freectx;	\
	static OSSL_FUNC_keyexch_dupctx_fn uadk_keyexch_##nm##_dupctx;	\
	static OSSL_FUNC_keyexch_set_ctx_params_fn uadk_keyexch_##nm##_set_ctx_params;	\
	static OSSL_FUNC_keyexch_settable_ctx_params_fn uadk_keyexch_##nm##_settable_ctx_params; \
	static OSSL_FUNC_keyexch_get_ctx_params_fn uadk_keyexch_##nm##_get_ctx_params;	\
	static OSSL_FUNC_keyexch_gettable_ctx_params_fn uadk_keyexch_##nm##_gettable_ctx_params; \
const OSSL_DISPATCH uadk_##nm##_keyexch_functions[] = {	\
	{ OSSL_FUNC_KEYEXCH_NEWCTX, (void (*)(void))uadk_keyexch_##nm##_newctx },	\
	{ OSSL_FUNC_KEYEXCH_INIT, (void (*)(void))uadk_keyexch_##nm##_init },	\
	{ OSSL_FUNC_KEYEXCH_DERIVE, (void (*)(void))uadk_keyexch_##nm##_derive },	\
	{ OSSL_FUNC_KEYEXCH_SET_PEER, (void (*)(void))uadk_keyexch_##nm##_set_peer },	\
	{ OSSL_FUNC_KEYEXCH_FREECTX, (void (*)(void))uadk_keyexch_##nm##_freectx },	\
	{ OSSL_FUNC_KEYEXCH_DUPCTX, (void (*)(void))uadk_keyexch_##nm##_dupctx },	\
	{ OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS,	\
		(void (*)(void))uadk_keyexch_##nm##_set_ctx_params },	\
	{ OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS,	\
		(void (*)(void))uadk_keyexch_##nm##_settable_ctx_params },	\
	{OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS,	\
		(void (*)(void))uadk_keyexch_##nm##_get_ctx_params },	\
	{ OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS,	\
		(void (*)(void))uadk_keyexch_##nm##_gettable_ctx_params },	\
	{ 0, NULL }	\
}	\

handle_t uadk_prov_ecc_alloc_sess(const EC_KEY *eckey, const char *alg);
int uadk_prov_ecc_crypto(handle_t sess, struct wd_ecc_req *req, void *usr);
int uadk_prov_keymgmt_get_support_state(int alg_tag);
int uadk_prov_ecc_get_numa_id(void);
void uadk_prov_ecc_cb(void *req_t);
int uadk_prov_ecc_get_rand(char *out, size_t out_len, void *usr);
int uadk_prov_ecc_poll(void *ctx);
int uadk_prov_ecc_genctx_check(struct ec_gen_ctx *gctx, EC_KEY *ec);
void uadk_prov_keymgmt_alg(void);
void uadk_prov_ecc_fill_req(struct wd_ecc_req *req, unsigned int op, void *in, void *out);
int uadk_prov_signature_get_support_state(int alg_tag);
int uadk_prov_ecc_set_private_key(handle_t sess, const EC_KEY *eckey);
bool uadk_prov_is_all_zero(const unsigned char *data, size_t dlen);
int uadk_prov_ecc_set_public_key(handle_t sess, const EC_KEY *eckey);
void uadk_prov_signature_alg(void);
void uadk_prov_asym_cipher_alg(void);
int uadk_prov_asym_cipher_get_support_state(int alg_tag);
int uadk_prov_ecc_init(const char *alg_name);
void uadk_prov_keyexch_alg(void);
int uadk_prov_keyexch_get_support_state(int alg_tag);
int uadk_prov_ecc_bit_check(const EC_GROUP *group);
int uadk_prov_get_affine_coordinates(const EC_GROUP *group, const EC_POINT *p,
				     BIGNUM *x, BIGNUM *y, BN_CTX *ctx);
int uadk_prov_securitycheck_enabled(OSSL_LIB_CTX *ctx);
int uadk_prov_ecc_check_key(OSSL_LIB_CTX *ctx, const EC_KEY *ec, int protect);
int uadk_prov_pkey_version(void);

#endif
