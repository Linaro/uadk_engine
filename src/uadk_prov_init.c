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
#include <openssl/rand.h>

#include "uadk_async.h"
#include "uadk_prov.h"
#include "uadk_prov_bio.h"
#include "uadk_prov_pkey.h"
#include "uadk_utils.h"

#define ARRAY_SIZE(x)		(sizeof(x) / sizeof((x)[0]))
static const char UADK_DEFAULT_PROPERTIES[] = "provider=uadk_provider";
static OSSL_PROVIDER *default_prov;

/* Functions provided by the core */
static OSSL_FUNC_core_gettable_params_fn *c_gettable_params;
static OSSL_FUNC_core_get_params_fn *c_get_params;
static OSSL_FUNC_core_get_libctx_fn *c_get_libctx;

static struct uadk_provider_params {
	char *enable_sw_flag;
	char *sm2;
	char *rsa;
	char *ecdh;
	char *ecdsa;
	char *dh;
	char *x25519;
	char *x448;
	char *hmac;
	char *aes_ecb;
	char *aes_cbc;
	char *aes_xts;
	char *aes_ctr;
	char *aes_ofb128;
	char *aes_cfb128;
	char *sm4_cbc;
	char *sm4_ofb128;
	char *sm4_cfb128;
	char *sm4_ecb;
	char *sm4_ctr;
	char *des_ede3_cbc;
	char *des_ede3_ecb;
	char *md5;
	char *sm3;
	char *sha1;
	char *sha224;
	char *sha256;
	char *sha384;
	char *sha512;
	char *aes_gcm;
} uadk_params;

static struct uadk_prov_alg_en_info {
	int sm2_en;
	int rsa_en;
	int ecdh_en;
	int ecdsa_en;
	int dh_en;
	int x25519_en;
	int x448_en;
	int hmac_en;
	int aes_ecb_en;
	int aes_cbc_en;
	int aes_xts_en;
	int aes_ctr_en;
	int aes_ofb128_en;
	int aes_cfb128_en;
	int sm4_cbc_en;
	int sm4_ofb128_en;
	int sm4_cfb128_en;
	int sm4_ecb_en;
	int sm4_ctr_en;
	int des_ede3_cbc_en;
	int des_ede3_ecb_en;
	int md5_en;
	int sm3_en;
	int sha1_en;
	int sha224_en;
	int sha256_en;
	int sha384_en;
	int sha512_en;
	int aes_gcm_en;
} uadk_prov_alg_en;

/* offload small packets to sw */
int enable_sw_offload = 1;

struct uadk_prov_alg_cfg {
	const char *name;
	char **param;
	int *enable;
};

static struct uadk_prov_alg_cfg uadk_prov_alg_cfg_info[] = {
	{"sm2", &uadk_params.sm2, &uadk_prov_alg_en.sm2_en},
	{"rsa", &uadk_params.rsa, &uadk_prov_alg_en.rsa_en},
	{"ecdh", &uadk_params.ecdh, &uadk_prov_alg_en.ecdh_en},
	{"ecdsa", &uadk_params.ecdsa, &uadk_prov_alg_en.ecdsa_en},
	{"dh", &uadk_params.dh, &uadk_prov_alg_en.dh_en},
	{"x25519", &uadk_params.x25519, &uadk_prov_alg_en.x25519_en},
	{"x448", &uadk_params.x448, &uadk_prov_alg_en.x448_en},
	{"hmac", &uadk_params.hmac, &uadk_prov_alg_en.hmac_en},
	{"aes_ecb", &uadk_params.aes_ecb, &uadk_prov_alg_en.aes_ecb_en},
	{"aes_cbc", &uadk_params.aes_cbc, &uadk_prov_alg_en.aes_cbc_en},
	{"aes_xts", &uadk_params.aes_xts, &uadk_prov_alg_en.aes_xts_en},
	{"aes_ctr", &uadk_params.aes_ctr, &uadk_prov_alg_en.aes_ctr_en},
	{"aes_ofb128", &uadk_params.aes_ofb128, &uadk_prov_alg_en.aes_ofb128_en},
	{"aes_cfb128", &uadk_params.aes_cfb128, &uadk_prov_alg_en.aes_cfb128_en},
	{"sm4_cbc", &uadk_params.sm4_cbc, &uadk_prov_alg_en.sm4_cbc_en},
	{"sm4_ofb128", &uadk_params.sm4_ofb128, &uadk_prov_alg_en.sm4_ofb128_en},
	{"sm4_cfb128", &uadk_params.sm4_cfb128, &uadk_prov_alg_en.sm4_cfb128_en},
	{"sm4_ecb", &uadk_params.sm4_ecb, &uadk_prov_alg_en.sm4_ecb_en},
	{"sm4_ctr", &uadk_params.sm4_ctr, &uadk_prov_alg_en.sm4_ctr_en},
	{"des_ede3_cbc", &uadk_params.des_ede3_cbc,
	 &uadk_prov_alg_en.des_ede3_cbc_en},
	{"des_ede3_ecb", &uadk_params.des_ede3_ecb,
	 &uadk_prov_alg_en.des_ede3_ecb_en},
	{"md5", &uadk_params.md5, &uadk_prov_alg_en.md5_en},
	{"sm3", &uadk_params.sm3, &uadk_prov_alg_en.sm3_en},
	{"sha1", &uadk_params.sha1, &uadk_prov_alg_en.sha1_en},
	{"sha224", &uadk_params.sha224, &uadk_prov_alg_en.sha224_en},
	{"sha256", &uadk_params.sha256, &uadk_prov_alg_en.sha256_en},
	{"sha384", &uadk_params.sha384, &uadk_prov_alg_en.sha384_en},
	{"sha512", &uadk_params.sha512, &uadk_prov_alg_en.sha512_en},
	{"aes_gcm", &uadk_params.aes_gcm, &uadk_prov_alg_en.aes_gcm_en}
};

const OSSL_ALGORITHM uadk_prov_digests[] = {
	{ PROV_NAMES_MD5, UADK_DEFAULT_PROPERTIES,
	  uadk_md5_functions, "uadk_provider md5" },
	{ PROV_NAMES_SM3, UADK_DEFAULT_PROPERTIES,
	  uadk_sm3_functions, "uadk_provider sm3" },
	{ PROV_NAMES_SHA1, UADK_DEFAULT_PROPERTIES,
	  uadk_sha1_functions, "uadk_provider sha1" },
	{ PROV_NAMES_SHA2_224, UADK_DEFAULT_PROPERTIES,
	  uadk_sha224_functions, "uadk_provider sha2-224" },
	{ PROV_NAMES_SHA2_256, UADK_DEFAULT_PROPERTIES,
	  uadk_sha256_functions, "uadk_provider sha2-256" },
	{ PROV_NAMES_SHA2_384, UADK_DEFAULT_PROPERTIES,
	  uadk_sha384_functions, "uadk_provider sha2-384" },
	{ PROV_NAMES_SHA2_512, UADK_DEFAULT_PROPERTIES,
	  uadk_sha512_functions, "uadk_provider sha2-512" },
	{ PROV_NAMES_SHA2_512_224, UADK_DEFAULT_PROPERTIES,
	  uadk_sha512_224_functions, "uadk_provider sha2-512-224" },
	{ PROV_NAMES_SHA2_512_256, UADK_DEFAULT_PROPERTIES,
	  uadk_sha512_256_functions, "uadk_provider sha2-512-256" },
	{ NULL, NULL, NULL, NULL }
};

const OSSL_ALGORITHM uadk_prov_hmac[] = {
	{ "HMAC", UADK_DEFAULT_PROPERTIES,
	  uadk_hmac_functions, "uadk_provider hmac" },
	{ NULL, NULL, NULL, NULL }
};

const OSSL_ALGORITHM uadk_prov_ciphers_v2[] = {
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
	{ "SM4-CBC", UADK_DEFAULT_PROPERTIES,
	  uadk_sm4_cbc_functions, "uadk_provider sm4-cbc" },
	{ "SM4-ECB", UADK_DEFAULT_PROPERTIES,
	  uadk_sm4_ecb_functions, "uadk_provider sm4-ecb" },
	{ "DES-EDE3-CBC", UADK_DEFAULT_PROPERTIES,
	  uadk_des_ede3_cbc_functions, "uadk_provider des-ede3-cbc" },
	{ "DES-EDE3-ECB", UADK_DEFAULT_PROPERTIES,
	  uadk_des_ede3_ecb_functions, "uadk_provider des-ede3-ecb" },
	{ NULL, NULL, NULL, NULL }
};

const OSSL_ALGORITHM uadk_prov_ciphers_v3[] = {
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
	{ "AES-128-GCM", UADK_DEFAULT_PROPERTIES,
	  uadk_aes_128_gcm_functions, "uadk_provider aes-128-gcm" },
	{ "AES-192-GCM", UADK_DEFAULT_PROPERTIES,
	  uadk_aes_192_gcm_functions, "uadk_provider aes-192-gcm" },
	{ "AES-256-GCM", UADK_DEFAULT_PROPERTIES,
	  uadk_aes_256_gcm_functions, "uadk_provider aes-256-gcm" },
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
	{ NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM uadk_prov_signature_v2[] = {
	{ "RSA", UADK_DEFAULT_PROPERTIES,
	  uadk_rsa_signature_functions, "uadk_provider rsa_signature" },
	{ NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM uadk_prov_signature_v3[] = {
	{ "RSA", UADK_DEFAULT_PROPERTIES,
	  uadk_rsa_signature_functions, "uadk_provider rsa_signature" },
	{ "SM2", UADK_DEFAULT_PROPERTIES,
	  uadk_sm2_signature_functions, "uadk_provider sm2_signature" },
	{ "ECDSA", UADK_DEFAULT_PROPERTIES,
	  uadk_ecdsa_signature_functions, "uadk_provider ecdsa_signature" },
	{ NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM uadk_prov_keymgmt_v2[] = {
	{ "RSA", UADK_DEFAULT_PROPERTIES,
	  uadk_rsa_keymgmt_functions, "uadk RSA Keymgmt implementation." },
	{ "RSA-PSS", UADK_DEFAULT_PROPERTIES,
	  uadk_rsapss_keymgmt_functions, "uadk RSA-PSS Keymgmt implementation." },
	{ "DH", UADK_DEFAULT_PROPERTIES, uadk_dh_keymgmt_functions },
	{ NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM uadk_prov_keymgmt_v3[] = {
	{ "RSA", UADK_DEFAULT_PROPERTIES,
	  uadk_rsa_keymgmt_functions, "uadk RSA Keymgmt implementation." },
	{ "RSA-PSS", UADK_DEFAULT_PROPERTIES,
	  uadk_rsapss_keymgmt_functions, "uadk RSA-PSS Keymgmt implementation." },
	{ "DH", UADK_DEFAULT_PROPERTIES,
	  uadk_dh_keymgmt_functions, "uadk dh Keymgmt implementation." },
	{ "SM2", UADK_DEFAULT_PROPERTIES,
	  uadk_sm2_keymgmt_functions, "uadk SM2 Keymgmt implementation." },
	{ "EC", UADK_DEFAULT_PROPERTIES,
	  uadk_ec_keymgmt_functions, "uadk EC Keymgmt implementation."},
	{ "X448", UADK_DEFAULT_PROPERTIES,
	  uadk_x448_keymgmt_functions, "uadk X448 Keymgmt implementation."},
	{ "X25519", UADK_DEFAULT_PROPERTIES,
	  uadk_x25519_keymgmt_functions, "uadk X25519 Keymgmt implementation."},
	{ NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM uadk_prov_asym_cipher_v2[] = {
	{ "RSA", UADK_DEFAULT_PROPERTIES,
	  uadk_rsa_asym_cipher_functions, "uadk RSA asym cipher implementation." },
	{ NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM uadk_prov_asym_cipher_v3[] = {
	{ "RSA", UADK_DEFAULT_PROPERTIES,
	  uadk_rsa_asym_cipher_functions, "uadk RSA asym cipher implementation." },
	{ "SM2", UADK_DEFAULT_PROPERTIES,
	  uadk_sm2_asym_cipher_functions, "uadk SM2 asym cipher implementation." },
	{ NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM uadk_prov_keyexch_v2[] = {
	{ "DH", UADK_DEFAULT_PROPERTIES,
	  uadk_dh_keyexch_functions, "UADK DH keyexch implementation"},
	{ NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM uadk_prov_keyexch_v3[] = {
	{ "DH", UADK_DEFAULT_PROPERTIES,
	  uadk_dh_keyexch_functions, "UADK DH keyexch implementation"},
	{ "ECDH", UADK_DEFAULT_PROPERTIES,
	  uadk_ecdh_keyexch_functions, "uadk_provider ecdh_keyexch" },
	{ "X448", UADK_DEFAULT_PROPERTIES,
	  uadk_x448_keyexch_functions, "uadk X448 keyexch implementation."},
	{ "X25519", UADK_DEFAULT_PROPERTIES,
	  uadk_x25519_keyexch_functions, "uadk 25519 keyexch implementation."},
	{ NULL, NULL, NULL, NULL }
};

static OSSL_ALGORITHM *uadk_generate_digests_array(void)
{
	OSSL_ALGORITHM *digests_array;
	const char *name;
	int index = 0;
	int i, size;

	/* The algorithm will not exceed the size of a static array */
	size = ARRAY_SIZE(uadk_prov_digests);
	digests_array = OPENSSL_zalloc(size * sizeof(OSSL_ALGORITHM));
	if (!digests_array)
		return NULL;
	for (i = 0; i < size; i++) {
		name = uadk_prov_digests[i].algorithm_names;

		/* The last entry will be terminated by NULL. */
		if (name == NULL ||
		    (uadk_prov_alg_en.md5_en && strstr(name, "MD5")) ||
		    (uadk_prov_alg_en.sm3_en && strstr(name, "SM3")) ||
		    (uadk_prov_alg_en.sha1_en && strstr(name, "SHA1")) ||
		    (uadk_prov_alg_en.sha224_en && strstr(name, "SHA2-224")) ||
		    (uadk_prov_alg_en.sha256_en && strstr(name, "SHA2-256")) ||
		    (uadk_prov_alg_en.sha384_en && strstr(name, "SHA2-384")) ||
		    (uadk_prov_alg_en.sha512_en && strstr(name, "SHA2-512")))
			memcpy(&digests_array[index++],
			       &uadk_prov_digests[i], sizeof(OSSL_ALGORITHM));
	}

	return digests_array;
}

static OSSL_ALGORITHM *uadk_generate_hmac_array(void)
{
	OSSL_ALGORITHM *hmac_array;
	const char *name;
	int index = 0;
	int i, size;

	/* The algorithm will not exceed the size of a static array */
	size = ARRAY_SIZE(uadk_prov_hmac);
	hmac_array = OPENSSL_zalloc(size * sizeof(OSSL_ALGORITHM));
	if (!hmac_array)
		return NULL;
	for (i = 0; i < size; i++) {
		name = uadk_prov_hmac[i].algorithm_names;
		if (name == NULL ||
		    (uadk_prov_alg_en.hmac_en && strstr(name, "HMAC")))
			memcpy(&hmac_array[index++],
			       &uadk_prov_hmac[i], sizeof(OSSL_ALGORITHM));
	}

	return hmac_array;
}

static OSSL_ALGORITHM *uadk_generate_cipher_array_v2(void)
{
	OSSL_ALGORITHM *ciphers_array_v2;
	const char *name;
	int index = 0;
	int i, size;

	/* The algorithm will not exceed the size of a static array */
	size = ARRAY_SIZE(uadk_prov_ciphers_v2);
	ciphers_array_v2 = OPENSSL_zalloc(size * sizeof(OSSL_ALGORITHM));
	if (!ciphers_array_v2)
		return NULL;
	for (i = 0; i < size; i++) {
		name = uadk_prov_ciphers_v2[i].algorithm_names;

		if (name == NULL ||
		    (uadk_prov_alg_en.aes_cbc_en &&
		     strstr(name, "AES") && strstr(name, "CBC")) ||
		    (uadk_prov_alg_en.aes_ecb_en &&
		     strstr(name, "AES") && strstr(name, "ECB")) ||
		    (uadk_prov_alg_en.aes_xts_en && strstr(name, "XTS")) ||
		    (uadk_prov_alg_en.sm4_cbc_en && strstr(name, "SM4-CBC")) ||
		    (uadk_prov_alg_en.sm4_ecb_en && strstr(name, "SM4-ECB")) ||
		    (uadk_prov_alg_en.des_ede3_cbc_en && strstr(name, "EDE3-CBC")) ||
		    (uadk_prov_alg_en.des_ede3_ecb_en && strstr(name, "EDE3-ECB")))
			memcpy(&ciphers_array_v2[index++],
			       &uadk_prov_ciphers_v2[i], sizeof(OSSL_ALGORITHM));
	}

	return ciphers_array_v2;
}

static OSSL_ALGORITHM *uadk_generate_cipher_array_v3(void)
{
	OSSL_ALGORITHM *ciphers_array_v3;
	const char *name;
	int index = 0;
	int i, size;

	/* The algorithm will not exceed the size of a static array */
	size = ARRAY_SIZE(uadk_prov_ciphers_v3);
	ciphers_array_v3 = OPENSSL_zalloc(size * sizeof(OSSL_ALGORITHM));
	if (!ciphers_array_v3)
		return NULL;
	for (i = 0; i < size; i++) {
		name = uadk_prov_ciphers_v3[i].algorithm_names;

		if (name == NULL ||
		    (uadk_prov_alg_en.aes_cbc_en &&
		     strstr(name, "AES") && strstr(name, "CBC")) ||
		    (uadk_prov_alg_en.aes_ecb_en &&
		     strstr(name, "AES") && strstr(name, "ECB")) ||
		    (uadk_prov_alg_en.aes_ctr_en &&
		     strstr(name, "AES") && strstr(name, "CTR")) ||
		    (uadk_prov_alg_en.aes_xts_en && strstr(name, "XTS")) ||
		    (uadk_prov_alg_en.aes_ofb128_en &&
		     strstr(name, "AES") && strstr(name, "OFB")) ||
		    (uadk_prov_alg_en.aes_cfb128_en &&
		     strstr(name, "AES") && strstr(name, "CFB")) ||
		    (uadk_prov_alg_en.aes_gcm_en && strstr(name, "GCM")) ||
		    (uadk_prov_alg_en.sm4_cbc_en && strstr(name, "SM4-CBC")) ||
		    (uadk_prov_alg_en.sm4_ecb_en && strstr(name, "SM4-ECB")) ||
		    (uadk_prov_alg_en.sm4_ofb128_en && strstr(name, "SM4-OFB")) ||
		    (uadk_prov_alg_en.sm4_cfb128_en && strstr(name, "SM4-CFB")) ||
		    (uadk_prov_alg_en.sm4_ctr_en && strstr(name, "SM4-CTR")) ||
		    (uadk_prov_alg_en.des_ede3_cbc_en && strstr(name, "EDE3-CBC")) ||
		    (uadk_prov_alg_en.des_ede3_ecb_en && strstr(name, "EDE3-ECB")))
			memcpy(&ciphers_array_v3[index++],
			       &uadk_prov_ciphers_v3[i], sizeof(OSSL_ALGORITHM));
	}

	return ciphers_array_v3;
}

static OSSL_ALGORITHM *uadk_generate_signature_array_v2(void)
{
	OSSL_ALGORITHM *signature_array_v2;
	const char *name;
	int index = 0;
	int i, size;

	/* The algorithm will not exceed the size of a static array */
	size = ARRAY_SIZE(uadk_prov_signature_v2);
	signature_array_v2 = OPENSSL_zalloc(size * sizeof(OSSL_ALGORITHM));
	if (!signature_array_v2)
		return NULL;
	for (i = 0; i < size; i++) {
		name = uadk_prov_signature_v2[i].algorithm_names;
		if (name == NULL || (uadk_prov_alg_en.rsa_en && !strcmp(name, "RSA")))
			memcpy(&signature_array_v2[index++],
			       &uadk_prov_signature_v2[i], sizeof(OSSL_ALGORITHM));
	}

	return signature_array_v2;
}

static OSSL_ALGORITHM *uadk_generate_signature_array_v3(void)
{
	OSSL_ALGORITHM *signature_array_v3;
	const char *name;
	int index = 0;
	int i, size;

	/* The algorithm will not exceed the size of a static array */
	size = ARRAY_SIZE(uadk_prov_signature_v3);
	signature_array_v3 = OPENSSL_zalloc(size * sizeof(OSSL_ALGORITHM));
	if (!signature_array_v3)
		return NULL;
	for (i = 0; i < size; i++) {
		name = uadk_prov_signature_v3[i].algorithm_names;
		if (name == NULL ||
		    (uadk_prov_alg_en.rsa_en && !strcmp(name, "RSA")) ||
		    (uadk_prov_alg_en.sm2_en && !strcmp(name, "SM2")) ||
		    (uadk_prov_alg_en.ecdsa_en && !strcmp(name, "ECDSA")))
			memcpy(&signature_array_v3[index++],
			       &uadk_prov_signature_v3[i], sizeof(OSSL_ALGORITHM));
	}

	return signature_array_v3;
}

static OSSL_ALGORITHM *uadk_generate_keymgmt_array_v2(void)
{
	OSSL_ALGORITHM *keymgmt_array_v2;
	const char *name;
	int index = 0;
	int i, size;

	/* The algorithm will not exceed the size of a static array */
	size = ARRAY_SIZE(uadk_prov_keymgmt_v2);
	keymgmt_array_v2 = OPENSSL_zalloc(size * sizeof(OSSL_ALGORITHM));
	if (!keymgmt_array_v2)
		return NULL;

	for (i = 0; i < size; i++) {
		name = uadk_prov_keymgmt_v2[i].algorithm_names;
		if (name == NULL ||
		    (uadk_prov_alg_en.rsa_en && !strcmp(name, "RSA")) ||
		    /* RSA and RSA-PSS can utilize the same enable flag */
		    (uadk_prov_alg_en.rsa_en && !strcmp(name, "RSA-PSS")) ||
		    (uadk_prov_alg_en.dh_en && !strcmp(name, "DH")))
			memcpy(&keymgmt_array_v2[index++],
			       &uadk_prov_keymgmt_v2[i], sizeof(OSSL_ALGORITHM));
	}

	return keymgmt_array_v2;
}

static OSSL_ALGORITHM *uadk_generate_keymgmt_array_v3(void)
{
	OSSL_ALGORITHM *keymgmt_array_v3;
	const char *name;
	int index = 0;
	int i, size;

	/* The algorithm will not exceed the size of a static array */
	size = ARRAY_SIZE(uadk_prov_keymgmt_v3);
	keymgmt_array_v3 = OPENSSL_zalloc(size * sizeof(OSSL_ALGORITHM));
	if (!keymgmt_array_v3)
		return NULL;

	for (i = 0; i < size; i++) {
		name = uadk_prov_keymgmt_v3[i].algorithm_names;
		if (name == NULL ||
		    (uadk_prov_alg_en.rsa_en && !strcmp(name, "RSA")) ||
		    (uadk_prov_alg_en.rsa_en && !strcmp(name, "RSA-PSS")) ||
		    (uadk_prov_alg_en.dh_en && !strcmp(name, "DH")) ||
		    (uadk_prov_alg_en.sm2_en && !strcmp(name, "SM2")) ||
		    (uadk_prov_alg_en.ecdh_en && !strcmp(name, "EC")) ||
		    (uadk_prov_alg_en.x448_en && !strcmp(name, "X448")) ||
		    (uadk_prov_alg_en.x25519_en && !strcmp(name, "X25519")))
			memcpy(&keymgmt_array_v3[index++],
			       &uadk_prov_keymgmt_v3[i], sizeof(OSSL_ALGORITHM));
	}

	return keymgmt_array_v3;
}

static OSSL_ALGORITHM *uadk_generate_asym_cipher_array_v2(void)
{
	OSSL_ALGORITHM *asym_cipher_array_v2;
	const char *name;
	int index = 0;
	int i, size;

	/* The algorithm will not exceed the size of a static array */
	size = ARRAY_SIZE(uadk_prov_asym_cipher_v2);
	asym_cipher_array_v2 = OPENSSL_zalloc(size * sizeof(OSSL_ALGORITHM));
	if (!asym_cipher_array_v2)
		return NULL;

	for (i = 0; i < size; i++) {
		name = uadk_prov_asym_cipher_v2[i].algorithm_names;
		if (name == NULL || (uadk_prov_alg_en.rsa_en && !strcmp(name, "RSA")))
			memcpy(&asym_cipher_array_v2[index++],
			       &uadk_prov_asym_cipher_v2[i], sizeof(OSSL_ALGORITHM));
	}

	return asym_cipher_array_v2;
}

static OSSL_ALGORITHM *uadk_generate_asym_cipher_array_v3(void)
{
	OSSL_ALGORITHM *asym_cipher_array_v3;
	const char *name;
	int index = 0;
	int i, size;

	/* The algorithm will not exceed the size of a static array */
	size = ARRAY_SIZE(uadk_prov_asym_cipher_v3);
	asym_cipher_array_v3 = OPENSSL_zalloc(size * sizeof(OSSL_ALGORITHM));
	if (!asym_cipher_array_v3)
		return NULL;
	for (i = 0; i < size; i++) {
		name = uadk_prov_asym_cipher_v3[i].algorithm_names;
		if (name == NULL ||
		    (uadk_prov_alg_en.rsa_en && !strcmp(name, "RSA")) ||
		    (uadk_prov_alg_en.sm2_en && !strcmp(name, "SM2")))
			memcpy(&asym_cipher_array_v3[index++],
			       &uadk_prov_asym_cipher_v3[i], sizeof(OSSL_ALGORITHM));
	}

	return asym_cipher_array_v3;
}

static OSSL_ALGORITHM *uadk_generate_keyexch_array_v2(void)
{
	OSSL_ALGORITHM *keyexch_array_v2;
	const char *name;
	int index = 0;
	int i, size;

	/* The algorithm will not exceed the size of a static array */
	size = ARRAY_SIZE(uadk_prov_keyexch_v2);
	keyexch_array_v2 = OPENSSL_zalloc(size * sizeof(OSSL_ALGORITHM));
	if (!keyexch_array_v2)
		return NULL;

	for (i = 0; i < size; i++) {
		name = uadk_prov_keyexch_v2[i].algorithm_names;
		if (name == NULL || (uadk_prov_alg_en.dh_en && !strcmp(name, "DH")))
			memcpy(&keyexch_array_v2[index++],
			       &uadk_prov_keyexch_v2[i], sizeof(OSSL_ALGORITHM));
	}

	return keyexch_array_v2;
}

static OSSL_ALGORITHM *uadk_generate_keyexch_array_v3(void)
{
	OSSL_ALGORITHM *keyexch_array_v3;
	const char *name;
	int index = 0;
	int i, size;

	/* The algorithm will not exceed the size of a static array */
	size = ARRAY_SIZE(uadk_prov_keyexch_v3);
	keyexch_array_v3 = OPENSSL_zalloc(size * sizeof(OSSL_ALGORITHM));
	if (!keyexch_array_v3)
		return NULL;

	for (i = 0; i < size; i++) {
		name = uadk_prov_keyexch_v3[i].algorithm_names;
		if (name == NULL ||
		    (uadk_prov_alg_en.dh_en && !strcmp(name, "DH")) ||
		    (uadk_prov_alg_en.x448_en && !strcmp(name, "X448")) ||
		    (uadk_prov_alg_en.x25519_en && !strcmp(name, "X25519")) ||
		    (uadk_prov_alg_en.ecdh_en && !strcmp(name, "ECDH")))
			memcpy(&keyexch_array_v3[index++],
			       &uadk_prov_keyexch_v3[i], sizeof(OSSL_ALGORITHM));
	}

	return keyexch_array_v3;
}

static void uadk_set_default_alg(void)
{
	set_default_dh_keymgmt();
	set_default_dh_keyexch();
	set_default_ec_keymgmt();
	set_default_ecdh_keyexch();
	set_default_ecx_keymgmt();
	set_default_ecx_keyexch();
	set_default_rsa_keymgmt();
	set_default_rsapss_keymgmt();
	set_default_rsa_asym_cipher();
	set_default_rsa_signature();
	set_default_sm2_asym_cipher();
	set_default_sm2_keymgmt();
	set_default_sm2_signature();
}

static int uadk_set_default_prov(OSSL_LIB_CTX *libctx)
{
	if (default_prov)
		return UADK_P_SUCCESS;

	default_prov = OSSL_PROVIDER_load(libctx, "default");
	if (!default_prov) {
		printf("failed to load default provider\n");
		return UADK_P_FAIL;
	}
	/*
	 * uadk_provider takes the highest priority
	 * and overwrite the openssl.cnf property.
	 */
	EVP_set_default_properties(libctx, "?provider=uadk_provider");
	/*
	 * In asynchronous scenarios, if random numbers are obtained using
	 * uadk provider cipher, deadlocks may occur. Therefore, random numbers are
	 * obtained using default provider cipher.
	 */
	(void)RAND_set_DRBG_type(libctx, NULL, "provider=default", NULL, NULL);
	uadk_set_default_alg();

	return UADK_P_SUCCESS;
}

static const OSSL_ALGORITHM *uadk_query(void *provctx, int operation_id,
					int *no_cache)
{
	int ver;

	if (no_cache)
		*no_cache = 0;

	switch (operation_id) {
	case OSSL_OP_DIGEST:
		ver = uadk_prov_digest_version();
		if (!ver && uadk_get_sw_offload_state())
			break;
		return uadk_generate_digests_array();
	case OSSL_OP_MAC:
		return uadk_generate_hmac_array();
	case OSSL_OP_CIPHER:
		ver = uadk_prov_cipher_version();
		if (!ver && uadk_get_sw_offload_state())
			break;
		else if (ver == HW_SYMM_ENC_V2)
			return uadk_generate_cipher_array_v2();
		return uadk_generate_cipher_array_v3();
	case OSSL_OP_SIGNATURE:
		uadk_prov_signature_alg();
		ver = uadk_prov_pkey_version();
		if (!ver && uadk_get_sw_offload_state())
			break;
		else if (ver == HW_ASYM_ENC_V2)
			return uadk_generate_signature_array_v2();
		return uadk_generate_signature_array_v3();
	case OSSL_OP_KEYMGMT:
		uadk_prov_keymgmt_alg();
		ver = uadk_prov_pkey_version();
		if (!ver && uadk_get_sw_offload_state())
			break;
		else if (ver == HW_ASYM_ENC_V2)
			return uadk_generate_keymgmt_array_v2();
		return uadk_generate_keymgmt_array_v3();
	case OSSL_OP_ASYM_CIPHER:
		uadk_prov_asym_cipher_alg();
		ver = uadk_prov_pkey_version();
		if (!ver && uadk_get_sw_offload_state())
			break;
		else if (ver == HW_ASYM_ENC_V2)
			return uadk_generate_asym_cipher_array_v2();
		return uadk_generate_asym_cipher_array_v3();
	case OSSL_OP_KEYEXCH:
		uadk_prov_keyexch_alg();
		ver = uadk_prov_pkey_version();
		if (!ver && uadk_get_sw_offload_state())
			break;
		else if (ver == HW_ASYM_ENC_V2)
			return uadk_generate_keyexch_array_v2();
		return uadk_generate_keyexch_array_v3();
	default:
		break;
	}

	return OSSL_PROVIDER_query_operation(default_prov, operation_id, no_cache);
}

static void uadk_teardown(void *provctx)
{
	struct uadk_prov_ctx *ctx = (struct uadk_prov_ctx *)provctx;

	if (ctx) {
		BIO_meth_free(ctx->corebiometh);
		OPENSSL_free(ctx);
	}

	async_module_uninit();
	uadk_prov_destroy_digest();
	uadk_prov_destroy_hmac();
	uadk_prov_destroy_cipher();
	uadk_prov_destroy_aead();
	uadk_prov_destroy_rsa();
	uadk_prov_ecc_uninit();
	uadk_prov_dh_uninit();
	if (default_prov) {
		OSSL_PROVIDER_unload(default_prov);
		default_prov = NULL;
	}
}

static int uadk_get_params(OSSL_PARAM params[])
{
	return UADK_P_SUCCESS;
}

static void uadk_unquery(void *provctx, int operation_id,
			 const OSSL_ALGORITHM *algs)
{
	int needs_version_check = 0;
	int ver;

	switch (operation_id) {
	case OSSL_OP_DIGEST:
		ver = uadk_prov_digest_version();
		needs_version_check = 1;
		break;
	case OSSL_OP_CIPHER:
		ver = uadk_prov_cipher_version();
		needs_version_check = 1;
		break;
	case OSSL_OP_SIGNATURE:
	case OSSL_OP_KEYMGMT:
	case OSSL_OP_ASYM_CIPHER:
	case OSSL_OP_KEYEXCH:
		ver = uadk_prov_pkey_version();
		needs_version_check = 1;
		break;
	case OSSL_OP_MAC:
		if (algs)
			OPENSSL_free((void *)algs);
		return;
	default:
		break;
	}

	if (needs_version_check && (ver || !uadk_get_sw_offload_state())) {
		if (algs)
			OPENSSL_free((void *)algs);
		return;
	}

	if (default_prov)
		OSSL_PROVIDER_unquery_operation(default_prov, operation_id, algs);
}

static const OSSL_DISPATCH uadk_dispatch_table[] = {
	{ OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))uadk_query },
	{ OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))uadk_teardown },
	{ OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))uadk_get_params },
	{ OSSL_FUNC_PROVIDER_UNQUERY_OPERATION, (void (*)(void))uadk_unquery },
	{ OSSL_FUNC_PROVIDER_GET_CAPABILITIES, (void (*)(void))uadk_get_capabilities},
	{ 0, NULL }
};

int uadk_get_sw_offload_state(void)
{
	return enable_sw_offload;
}

static void uadk_set_alg_sel_state(void)
{
	int size, i;

	if (uadk_params.enable_sw_flag)
		uadk_set_sw_offload_state(atoi(uadk_params.enable_sw_flag));

	size = ARRAY_SIZE(uadk_prov_alg_cfg_info);
	for (i = 0; i < size; ++i) {
		if (*uadk_prov_alg_cfg_info[i].param == NULL) {
			*(uadk_prov_alg_cfg_info[i].enable) = 1;
			continue;
		}

		if (strcmp(*uadk_prov_alg_cfg_info[i].param, "1") == 0)
			*(uadk_prov_alg_cfg_info[i].enable) = 1;
		else if (strcmp(*uadk_prov_alg_cfg_info[i].param, "0") == 0)
			*(uadk_prov_alg_cfg_info[i].enable) = 0;
		else {
			*(uadk_prov_alg_cfg_info[i].enable) = 1;
			UADK_INFO("invalid: %s en param(%s) is error!, default to enabled\n",
				  uadk_prov_alg_cfg_info[i].name,
				  *uadk_prov_alg_cfg_info[i].param);
		}
	}
}

/* enable = 0 means disable sw offload, enable = 1 means enable sw offload */
void uadk_set_sw_offload_state(int enable)
{
	enable_sw_offload = enable;
}

static int uadk_get_params_from_core(const OSSL_CORE_HANDLE *handle)
{
	OSSL_PARAM core_params[31], *p = core_params;

	if (handle == NULL) {
		UADK_ERR("invalid: OSSL_CORE_HANDLE is NULL\n");
		return UADK_P_FAIL;
	}

	*p++ = OSSL_PARAM_construct_utf8_ptr("enable_sw_offload",
					     (char **)&uadk_params.enable_sw_flag, 0);
	*p++ = OSSL_PARAM_construct_utf8_ptr("SM2", (char **)&uadk_params.sm2, 0);
	*p++ = OSSL_PARAM_construct_utf8_ptr("RSA", (char **)&uadk_params.rsa, 0);
	*p++ = OSSL_PARAM_construct_utf8_ptr("ECDH", (char **)&uadk_params.ecdh, 0);
	*p++ = OSSL_PARAM_construct_utf8_ptr("ECDSA", (char **)&uadk_params.ecdsa, 0);
	*p++ = OSSL_PARAM_construct_utf8_ptr("DH", (char **)&uadk_params.dh, 0);
	*p++ = OSSL_PARAM_construct_utf8_ptr("X25519", (char **)&uadk_params.x25519, 0);
	*p++ = OSSL_PARAM_construct_utf8_ptr("X448", (char **)&uadk_params.x448, 0);
	*p++ = OSSL_PARAM_construct_utf8_ptr("HMAC", (char **)&uadk_params.hmac, 0);
	*p++ = OSSL_PARAM_construct_utf8_ptr("AES_ECB", (char **)&uadk_params.aes_ecb, 0);
	*p++ = OSSL_PARAM_construct_utf8_ptr("AES_CBC", (char **)&uadk_params.aes_cbc, 0);
	*p++ = OSSL_PARAM_construct_utf8_ptr("AES_XTS", (char **)&uadk_params.aes_xts, 0);
	*p++ = OSSL_PARAM_construct_utf8_ptr("AES_CTR", (char **)&uadk_params.aes_ctr, 0);
	*p++ = OSSL_PARAM_construct_utf8_ptr("AES_OFB128", (char **)&uadk_params.aes_ofb128, 0);
	*p++ = OSSL_PARAM_construct_utf8_ptr("AES_CFB128", (char **)&uadk_params.aes_cfb128, 0);
	*p++ = OSSL_PARAM_construct_utf8_ptr("SM4_CBC", (char **)&uadk_params.sm4_cbc, 0);
	*p++ = OSSL_PARAM_construct_utf8_ptr("SM4_OFB128", (char **)&uadk_params.sm4_ofb128, 0);
	*p++ = OSSL_PARAM_construct_utf8_ptr("SM4_CFB128", (char **)&uadk_params.sm4_cfb128, 0);
	*p++ = OSSL_PARAM_construct_utf8_ptr("SM4_ECB", (char **)&uadk_params.sm4_ecb, 0);
	*p++ = OSSL_PARAM_construct_utf8_ptr("SM4_CTR", (char **)&uadk_params.sm4_ctr, 0);
	*p++ = OSSL_PARAM_construct_utf8_ptr("MD5", (char **)&uadk_params.md5, 0);
	*p++ = OSSL_PARAM_construct_utf8_ptr("SM3", (char **)&uadk_params.sm3, 0);
	*p++ = OSSL_PARAM_construct_utf8_ptr("SHA1", (char **)&uadk_params.sha1, 0);
	*p++ = OSSL_PARAM_construct_utf8_ptr("SHA224", (char **)&uadk_params.sha224, 0);
	*p++ = OSSL_PARAM_construct_utf8_ptr("SHA256", (char **)&uadk_params.sha256, 0);
	*p++ = OSSL_PARAM_construct_utf8_ptr("SHA384", (char **)&uadk_params.sha384, 0);
	*p++ = OSSL_PARAM_construct_utf8_ptr("SHA512", (char **)&uadk_params.sha512, 0);
	*p++ = OSSL_PARAM_construct_utf8_ptr("AES_GCM", (char **)&uadk_params.aes_gcm, 0);
	*p++ = OSSL_PARAM_construct_utf8_ptr("DES_EDE3_CBC",
					     (char **)&uadk_params.des_ede3_cbc, 0);
	*p++ = OSSL_PARAM_construct_utf8_ptr("DES_EDE3_ECB",
					     (char **)&uadk_params.des_ede3_ecb, 0);
	*p = OSSL_PARAM_construct_end();

	if (!c_get_params(handle, core_params)) {
		UADK_ERR("WARN: UADK get parameters from core is failed.\n");
		return UADK_P_FAIL;
	}

	uadk_set_alg_sel_state();

	return UADK_P_SUCCESS;
}

static void provider_init_child_at_fork_handler(void)
{
	int ret;

	ret = async_module_init();
	if (!ret)
		UADK_ERR("async_module_init fail!\n");
}

static int uadk_prov_ctx_set_core_bio_method(struct uadk_prov_ctx *ctx)
{
	UADK_BIO_METHOD *core_bio;

	core_bio = ossl_bio_prov_init_bio_method();
	if (core_bio == NULL) {
		UADK_ERR("failed to set bio from dispatch\n");
		return UADK_P_FAIL;
	}

	ctx->corebiometh = core_bio;

	return UADK_P_SUCCESS;
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
		UADK_ERR("failed to get dispatch in\n");
		return UADK_P_FAIL;
	}

	ossl_prov_bio_from_dispatch(oin);
	ossl_prov_core_from_dispatch(oin);

	/* get parameters from uadk_provider.cnf */
	if (!uadk_get_params_from_core(handle))
		return UADK_P_FAIL;

	ctx = OPENSSL_zalloc(sizeof(*ctx));
	if (ctx == NULL) {
		UADK_ERR("failed to alloc ctx\n");
		return UADK_P_FAIL;
	}

	/* Set handle from core to get core functions */
	ctx->handle = handle;
	ctx->libctx = (OSSL_LIB_CTX *)c_get_libctx(handle);

	ret = uadk_prov_ctx_set_core_bio_method(ctx);
	if (!ret)
		goto free_ctx;

	ret = uadk_set_default_prov(ctx->libctx);
	if (!ret)
		goto free_corebiometh;

	ret = async_module_init();
	if (!ret)
		UADK_ERR("async_module_init fail!\n");
	pthread_atfork(NULL, NULL, provider_init_child_at_fork_handler);

	*provctx = (void *)ctx;
	*out = uadk_dispatch_table;

	return UADK_P_SUCCESS;

free_corebiometh:
	BIO_meth_free(ctx->corebiometh);
free_ctx:
	OPENSSL_free(ctx);
	return UADK_P_FAIL;
}
