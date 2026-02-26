// SPDX-License-Identifier: Apache-2.0
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
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/engine.h>
#include <uadk/wd_ecc.h>
#include <uadk/wd_sched.h>
#include "uadk_async.h"
#include "uadk_prov.h"
#include "uadk_prov_der_writer.h"
#include "uadk_prov_packet.h"
#include "uadk_prov_pkey.h"
#include "uadk_utils.h"

#define SM2_KEY_BYTES		32
#define SM2_GET_SIGNLEN		1
#define SM3_DIGEST_LENGTH	32
#define SM2_DEFAULT_USERID	"1234567812345678"
#define SM2_DEFAULT_USERID_LEN	16

UADK_PKEY_KEYMGMT_DESCR(sm2, SM2);
UADK_PKEY_SIGNATURE_DESCR(sm2, SM2);
UADK_PKEY_ASYM_CIPHER_DESCR(sm2, SM2);

static const OSSL_PARAM sm2_asym_cipher_known_settable_ctx_params[] = {
	OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_DIGEST, NULL, 0),
	OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_PROPERTIES, NULL, 0),
	OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_ENGINE, NULL, 0),
	OSSL_PARAM_END
};

static const OSSL_PARAM sm2_asym_cipher_known_gettable_ctx_params[] = {
	OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_DIGEST, NULL, 0),
	OSSL_PARAM_END
};

static const OSSL_PARAM sm2_sig_known_settable_ctx_params[] = {
	OSSL_PARAM_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE, NULL),
	OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
	OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_DIST_ID, NULL, 0),
	OSSL_PARAM_END
};

static const OSSL_PARAM sm2_sig_known_gettable_ctx_params[] = {
	OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
	OSSL_PARAM_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE, NULL),
	OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
	OSSL_PARAM_END
};

enum {
	CTX_INIT_FAIL = -1,
	CTX_UNINIT,
	CTX_INIT_SUCC
};

/* Structure for sm2 key related data */
typedef struct {
	BIGNUM *order;
	/* Key and paramgen group */
	EC_GROUP *gen_group;
	const BIGNUM *prikey;
	const EC_POINT *pubkey;
} SM2_PKEY_DATA;

/* Structure for sm2 digest method related data */
typedef struct {
	/* The nid of digest method */
	int md_nid;
	/* Legacy: update status of digest method, changed (1), unchanged (0) */
	int md_update_status;
	/*
	 * References to the underlying digest implementation.
	 * |md| caches the digest, always.
	 * |alloc_md| only holds a reference to an explicitly fetched digest.
	 */
	EVP_MD_CTX *mdctx;
	EVP_MD *md;
	EVP_MD *alloc_md;
	size_t mdsize;
} SM2_MD_DATA;

/* Structure for SM2 private context in uadk_provider, related to UADK */
typedef struct {
	int init_status;
	/* The session related to UADK */
	handle_t sess;
	SM2_PKEY_DATA *sm2_pd;
	SM2_MD_DATA *sm2_md;
} SM2_PROV_CTX;

/*
 * Provider sm2 signature algorithm context structure.
 * Upper application will use, such as, EVP_PKEY_CTX *ctx,
 * this structure will be called like: ctx->op.sig.algctx,
 * the 'algctx' can be defined by our uadk_provider, which is
 * the structure below.
 */
typedef struct {
	OSSL_LIB_CTX *libctx;
	char *propq;
	/* Use EC_KEY refer to keymgmt */
	EC_KEY *key;

	/*
	 * Flag to termine if the 'z' digest needs to be computed and fed to the
	 * hash function.
	 * This flag should be set on initialization and the compuation should
	 * be performed only once, on first update.
	 */
	unsigned int flag_compute_z_digest : 1;

	/* Will used by openssl, but not used by UADK, so put it outside SM2_PROV_CTX */
	char mdname[OSSL_MAX_NAME_SIZE];

	/* The Algorithm Identifier of the combined signature algorithm */
	unsigned char aid_buf[OSSL_MAX_ALGORITHM_ID_SIZE];
	unsigned char *aid;
	size_t  aid_len;

	/* main digest */
	EVP_MD *md;
	EVP_MD_CTX *mdctx;
	size_t mdsize;

	/*
	 * SM2 ID used for calculating the Z value,
	 * distinguishing Identifier, ISO/IEC 15946-3
	 */
	unsigned char *id;
	size_t id_len;
	/* Indicates if the 'id' field is set (1) or not (0) */
	int id_set;

	SM2_PROV_CTX *sm2_pctx;
} PROV_SM2_SIGN_CTX;

/*
 * To stay same structure with openssl sm2 cipher context,
 * add openssl PROV_DIGEST type to uadk provider.
 * It will not be used in uadk provider, so set it all zero.
 */
struct PROV_DIGEST {
	const EVP_MD *md;
	EVP_MD *alloc_md;

	ENGINE *engine;

	/* The resv is additional field, not in openssl structure.
	 * Add it to prevent possible field changes of openssl in future.
	 */
	char resv[OSSL_MAX_NAME_SIZE];
};

typedef struct {
	OSSL_LIB_CTX *libctx;
	/* Use EC_KEY refer to keymgmt */
	EC_KEY *key;
	/* The md will used by openssl, but not used by uadk provider */
	struct PROV_DIGEST md;

	SM2_PROV_CTX *sm2_pctx;
} PROV_SM2_ASYM_CTX;

struct sm2_param {
	/*
	 * p: BIGNUM with the prime number (GFp) or the polynomial
	 * defining the underlying field (GF2m)
	 */
	BIGNUM *p;
	/* a: BIGNUM for parameter a of the equation */
	BIGNUM *a;
	/* b: BIGNUM for parameter b of the equation */
	BIGNUM *b;
	/* xG: BIGNUM for the x-coordinate value of G point */
	BIGNUM *xG;
	/* yG: BIGNUM for the y-coordinate value of G point */
	BIGNUM *yG;
	/* xA: BIGNUM for the x-coordinate value of PA point */
	BIGNUM *xA;
	/* yA: BIGNUM for the y-coordinate value of PA point */
	BIGNUM *yA;
};

typedef struct sm2_ciphertext {
	BIGNUM *C1x;
	BIGNUM *C1y;
	ASN1_OCTET_STRING *C3;
	ASN1_OCTET_STRING *C2;
} SM2_Ciphertext;

DECLARE_ASN1_FUNCTIONS(SM2_Ciphertext)

ASN1_SEQUENCE(SM2_Ciphertext) = {
	ASN1_SIMPLE(SM2_Ciphertext, C1x, BIGNUM),
	ASN1_SIMPLE(SM2_Ciphertext, C1y, BIGNUM),
	ASN1_SIMPLE(SM2_Ciphertext, C3, ASN1_OCTET_STRING),
	ASN1_SIMPLE(SM2_Ciphertext, C2, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(SM2_Ciphertext)

IMPLEMENT_ASN1_FUNCTIONS(SM2_Ciphertext)

static UADK_PKEY_KEYMGMT s_keymgmt;
static UADK_PKEY_ASYM_CIPHER s_asym_cipher;
static UADK_PKEY_SIGNATURE s_signature;

static UADK_PKEY_KEYMGMT get_default_sm2_keymgmt(void)
{
	return s_keymgmt;
}

void set_default_sm2_keymgmt(void)
{
	UADK_PKEY_KEYMGMT *keymgmt;

	keymgmt = (UADK_PKEY_KEYMGMT *)EVP_KEYMGMT_fetch(NULL, "SM2", "provider=default");
	if (keymgmt) {
		s_keymgmt = *keymgmt;
		EVP_KEYMGMT_free((EVP_KEYMGMT *)keymgmt);
	} else {
		UADK_INFO("failed to EVP_KEYMGMT_fetch sm2 default provider\n");
	}
}

static const char *uadk_keymgmt_sm2_query_operation_name(int operation_id)
{
	if (!get_default_sm2_keymgmt().query_operation_name) {
		UADK_ERR("failed to get keymgmt query_operation_name function\n");
		return NULL;
	}

	return get_default_sm2_keymgmt().query_operation_name(operation_id);
}

/**
 * Create an uadk provider side sm2 key object.
 *
 * @param provctx The provider context.
 * @return Return created key object if success, return NULL if failed.
 */
static void *uadk_keymgmt_sm2_new(void *provctx)
{
	if (!get_default_sm2_keymgmt().new_fun) {
		UADK_ERR("failed to get keymgmt new function\n");
		return NULL;
	}

	return get_default_sm2_keymgmt().new_fun(provctx);
}

/**
 * Release an uadk provider side sm2 key object
 *
 * @param keydata Key object related data.
 */
static void uadk_keymgmt_sm2_free(void *keydata)
{
	if (!get_default_sm2_keymgmt().free) {
		UADK_ERR("failed to get keymgmt free function\n");
		return;
	}

	get_default_sm2_keymgmt().free(keydata);
}

static int uadk_keymgmt_sm2_get_params(void *key, OSSL_PARAM params[])
{
	if (!get_default_sm2_keymgmt().get_params) {
		UADK_ERR("failed to get keymgmt get_params function\n");
		return UADK_P_FAIL;
	}

	return get_default_sm2_keymgmt().get_params(key, params);
}

static const OSSL_PARAM *uadk_keymgmt_sm2_gettable_params(void *provctx)
{
	if (!get_default_sm2_keymgmt().gettable_params) {
		UADK_ERR("failed to get keymgmt gettable_params function\n");
		return NULL;
	}

	return get_default_sm2_keymgmt().gettable_params(provctx);
}

static int uadk_keymgmt_sm2_set_params(void *key, const OSSL_PARAM params[])
{
	if (!get_default_sm2_keymgmt().set_params) {
		UADK_ERR("failed to get keymgmt set_params function\n");
		return UADK_P_FAIL;
	}

	return get_default_sm2_keymgmt().set_params(key, params);
}

static int uadk_keymgmt_sm2_gen_set_template(void *genctx, void *templates)
{
	if (!get_default_sm2_keymgmt().gen_set_template) {
		UADK_ERR("failed to get keymgmt gen_set_template function\n");
		return UADK_P_FAIL;
	}

	return get_default_sm2_keymgmt().gen_set_template(genctx, templates);
}

static void uadk_keymgmt_sm2_gen_cleanup(void *genctx)
{
	if (!get_default_sm2_keymgmt().gen_cleanup) {
		UADK_ERR("failed to get keymgmt gen_cleanup function\n");
		return;
	}

	get_default_sm2_keymgmt().gen_cleanup(genctx);
}

static void *uadk_keymgmt_sm2_load(const void *reference, size_t reference_sz)
{
	if (!get_default_sm2_keymgmt().load) {
		UADK_ERR("failed to get keymgmt load function\n");
		return NULL;
	}

	return get_default_sm2_keymgmt().load(reference, reference_sz);
}

static int uadk_keymgmt_sm2_validate(const void *keydata, int selection, int checktype)
{
	if (!get_default_sm2_keymgmt().validate) {
		UADK_ERR("failed to get keymgmt validate function\n");
		return UADK_P_FAIL;
	}

	return get_default_sm2_keymgmt().validate(keydata, selection, checktype);
}

static int uadk_keymgmt_sm2_match(const void *keydata1, const void *keydata2, int selection)
{
	if (!get_default_sm2_keymgmt().match) {
		UADK_ERR("failed to get keymgmt validate function\n");
		return UADK_P_FAIL;
	}

	return get_default_sm2_keymgmt().match(keydata1, keydata2, selection);
}

/**
 * Check if a sm2 key object has specific options, such as public key,
 * private key, domain params etc.
 *
 * @param keydata The key object to check.
 * @param selection Check options, like public key, private key, domain params etc.
 * @return Return 1 if success, return 0 if failed.
 */
static int uadk_keymgmt_sm2_has(const void *keydata, int selection)
{
	if (!get_default_sm2_keymgmt().has) {
		UADK_ERR("failed to get keymgmt has function\n");
		return UADK_P_FAIL;
	}

	return get_default_sm2_keymgmt().has(keydata, selection);
}

/**
 * Import a sm2 key object with key related params.
 *
 * @param keydata The key object to import.
 * @param selection The key params to import.
 * @param params OSSL params.
 * @return Return 1 if success, return 0 if failed.
 */
static int uadk_keymgmt_sm2_import(void *keydata, int selection, const OSSL_PARAM params[])
{
	if (!get_default_sm2_keymgmt().import) {
		UADK_ERR("failed to get keymgmt import function\n");
		return UADK_P_FAIL;
	}

	return get_default_sm2_keymgmt().import(keydata, selection, params);
}

/**
 * Returns an array of argument types based on the type selected.
 *
 * @param selection Type of the selected key.
 * @return Return param type array.
 */
static const OSSL_PARAM *uadk_keymgmt_sm2_import_types(int selection)
{
	if (!get_default_sm2_keymgmt().import_types) {
		UADK_ERR("failed to get keymgmt import_types function\n");
		return NULL;
	}

	return get_default_sm2_keymgmt().import_types(selection);
}

static int uadk_keymgmt_sm2_export(void *keydata, int selection,
				   OSSL_CALLBACK *param_callback, void *cbarg)
{
	if (!get_default_sm2_keymgmt().export_fun) {
		UADK_ERR("failed to get keymgmt export function\n");
		return UADK_P_FAIL;
	}

	return get_default_sm2_keymgmt().export_fun(keydata, selection, param_callback, cbarg);
}

static const OSSL_PARAM *uadk_keymgmt_sm2_export_types(int selection)
{
	if (!get_default_sm2_keymgmt().export_types) {
		UADK_ERR("failed to get keymgmt export_types function\n");
		return NULL;
	}

	return get_default_sm2_keymgmt().export_types(selection);
}

static void *uadk_keymgmt_sm2_dup(const void *keydata_from, int selection)
{
	if (!get_default_sm2_keymgmt().dup) {
		UADK_ERR("failed to get keymgmt dup function\n");
		return NULL;
	}

	return get_default_sm2_keymgmt().dup(keydata_from, selection);
}

/**
 * Init sm2 key generation context.
 *
 * @param provctx The provider context.
 * @param selection The selected params related to the key.
 * @param params OSSL params.
 * @return Return inited key generation context if success, return NULL if failed.
 */
static void *uadk_keymgmt_sm2_gen_init(void *provctx, int selection,
				       const OSSL_PARAM params[])
{
	if (!get_default_sm2_keymgmt().gen_init) {
		UADK_ERR("failed to get keymgmt gen_init function\n");
		return NULL;
	}

	return get_default_sm2_keymgmt().gen_init(provctx, selection, params);
}

/**
 * Set sm2 key params
 *
 * @param genctx The pkey generation context.
 * @param params OSSL params array.
 * @return Return 1 if success, return 0 if failed.
 */
static int uadk_keymgmt_sm2_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
	if (!get_default_sm2_keymgmt().gen_set_params) {
		UADK_ERR("failed to get keymgmt gen_set_params function\n");
		return UADK_P_FAIL;
	}

	return get_default_sm2_keymgmt().gen_set_params(genctx, params);
}

static const OSSL_PARAM *uadk_keymgmt_sm2_settable_params(ossl_unused void *provctx)
{
	if (!get_default_sm2_keymgmt().settable_params) {
		UADK_ERR("failed to get keymgmt settable_params function\n");
		return NULL;
	}

	return get_default_sm2_keymgmt().settable_params(provctx);
}

/**
 * Get the settable params list.
 *
 * @param genctx key generation context.
 * @param provctx provider context.
 * @return Return params list if success, return NULL if failed.
 */
static const OSSL_PARAM *uadk_keymgmt_sm2_gen_settable_params(ossl_unused void *genctx,
							      ossl_unused void *provctx)
{
	if (!get_default_sm2_keymgmt().gen_settable_params) {
		UADK_ERR("failed to get keymgmt gen_settable_params function\n");
		return NULL;
	}

	return get_default_sm2_keymgmt().gen_settable_params(genctx, provctx);
}

static int uadk_prov_sm2_keygen_init_iot(handle_t sess, struct wd_ecc_req *req)
{
	struct wd_ecc_out *ecc_out = wd_sm2_new_kg_out(sess);

	if (ecc_out == NULL) {
		UADK_ERR("failed to new sign out\n");
		return UADK_P_FAIL;
	}

	uadk_prov_ecc_fill_req(req, WD_SM2_KG, NULL, ecc_out);

	return UADK_P_SUCCESS;
}

static int uadk_prov_sm2_set_key_to_ec_key(EC_KEY *ec, struct wd_ecc_req *req)
{
	unsigned char key_buff[ECC_POINT_SIZE(SM2_KEY_BYTES) + 1] = {0};
	struct wd_ecc_point *pubkey = NULL;
	struct wd_dtb *privkey = NULL;
	int x_offset, y_offset, ret;
	const EC_GROUP *group;
	EC_POINT *point, *ptr;
	BIGNUM *bn_key;

	wd_sm2_get_kg_out_params(req->dst, &privkey, &pubkey);
	if (privkey == NULL || pubkey == NULL) {
		UADK_ERR("failed to get privkey or pubkey\n");
		return UADK_P_FAIL;
	}

	if (pubkey->x.dsize > SM2_KEY_BYTES || pubkey->y.dsize > SM2_KEY_BYTES) {
		UADK_ERR("invalid pubkey size: %u, %u\n", pubkey->x.dsize, pubkey->y.dsize);
		return UADK_P_FAIL;
	}

	bn_key = BN_bin2bn((unsigned char *)privkey->data, privkey->dsize, NULL);
	ret = EC_KEY_set_private_key(ec, bn_key);
	BN_free(bn_key);
	if (ret == 0) {
		UADK_ERR("failed to EC KEY set private key\n");
		return UADK_P_FAIL;
	}

	group = EC_KEY_get0_group(ec);
	point = EC_POINT_new(group);
	if (point == NULL) {
		UADK_ERR("failed to EC POINT new\n");
		return UADK_P_FAIL;
	}

	key_buff[0] = UADK_OCTET_STRING;
	/* The component of sm2 pubkey need a SM2_KEY_BYTES align */
	x_offset = 1 + SM2_KEY_BYTES - pubkey->x.dsize;
	y_offset = 1 + ECC_POINT_SIZE(SM2_KEY_BYTES) - pubkey->y.dsize;
	memcpy(key_buff + x_offset, pubkey->x.data, pubkey->x.dsize);
	memcpy(key_buff + y_offset, pubkey->y.data, pubkey->y.dsize);
	bn_key = BN_bin2bn(key_buff, ECC_POINT_SIZE(SM2_KEY_BYTES) + 1, NULL);
	ptr = EC_POINT_bn2point(group, bn_key, point, NULL);
	BN_free(bn_key);
	if (ptr == NULL) {
		UADK_ERR("failed to EC_POINT_bn2point\n");
		EC_POINT_free(point);
		return UADK_P_FAIL;
	}

	ret = EC_KEY_set_public_key(ec, point);
	EC_POINT_free(point);
	if (ret == 0) {
		UADK_ERR("failed to EC_KEY_set_public_key\n");
		return UADK_P_FAIL;
	}

	return UADK_P_SUCCESS;
}

static int uadk_prov_sm2_check_priv_key(EC_KEY *eckey)
{
	BIGNUM *priv_key;
	int ret;

	priv_key = (BIGNUM *)EC_KEY_get0_private_key(eckey);
	if (priv_key)
		return UADK_P_SUCCESS;

	priv_key = BN_new();
	if (priv_key == NULL) {
		UADK_ERR("failed to BN_new priv_key\n");
		return UADK_P_FAIL;
	}

	ret = EC_KEY_set_private_key(eckey, priv_key);
	if (ret == 0)
		UADK_ERR("failed to set private key\n");

	BN_free(priv_key);

	return ret;
}

static int uadk_prov_sm2_keygen(EC_KEY *eckey)
{
	struct wd_ecc_req req = {0};
	handle_t sess;
	int ret;

	ret = uadk_prov_sm2_check_priv_key(eckey);
	if (ret == UADK_P_FAIL)
		goto error;

	sess = uadk_prov_ecc_alloc_sess(eckey, "sm2");
	if (sess == (handle_t)0)
		goto error;

	ret = uadk_prov_sm2_keygen_init_iot(sess, &req);
	if (ret == UADK_P_FAIL)
		goto free_sess;

	ret = uadk_prov_ecc_crypto(sess, &req, (void *)sess);
	if (ret == UADK_P_FAIL)
		goto uninit_iot;

	ret = uadk_prov_sm2_set_key_to_ec_key(eckey, &req);
	if (ret == UADK_P_FAIL)
		goto uninit_iot;

	wd_ecc_del_out(sess, req.dst);
	wd_ecc_free_sess(sess);

	return UADK_P_SUCCESS;

uninit_iot:
	wd_ecc_del_out(sess, req.dst);
free_sess:
	wd_ecc_free_sess(sess);
error:
	return UADK_P_FAIL;
}

static void *uadk_keymgmt_sm2_gen_sw(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
	if (!uadk_get_sw_offload_state())
		return NULL;

	if (!get_default_sm2_keymgmt().gen) {
		UADK_ERR("failed to get keymgmt gen function\n");
		return NULL;
	}

	UADK_INFO("switch to software sm2 keygen.\n");
	return get_default_sm2_keymgmt().gen(genctx, osslcb, cbarg);
}

/**
 * @brief Generate SM2 key pair.
 *
 * @param genctx Key generation context.
 * @param osslcb Callback function.
 * @param cbarg The param of callback function.
 *
 * @return Return generated key pair if success, return NULL if failed.
 */
static void *uadk_keymgmt_sm2_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
	struct ec_gen_ctx *gctx = genctx;
	EC_KEY *ec;
	int ret;

	if (gctx == NULL) {
		UADK_ERR("invalid: the generation context is NULL\n");
		return NULL;
	}

	ec = EC_KEY_new_ex(gctx->libctx, NULL);
	if (ec == NULL) {
		UADK_ERR("failed to EC_KEY_new_ex\n");
		return NULL;
	}

	ret = uadk_prov_ecc_genctx_check(genctx, ec);
	if (ret == UADK_P_FAIL) {
		UADK_ERR("failed to check genctx\n");
		goto free_ec_key;
	}

	ret = uadk_prov_keymgmt_get_support_state(KEYMGMT_SM2);
	if (ret == UADK_P_FAIL) {
		UADK_ERR("failed to get hardware sm2 keygen support\n");
		goto do_soft;
	}

	/* SM2 hardware init */
	ret = uadk_prov_ecc_init("sm2");
	if (ret == UADK_P_FAIL) {
		UADK_ERR("failed to init sm2\n");
		goto do_soft;
	}

	/* Do sm2 keygen with hardware */
	if ((gctx->selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0) {
		UADK_ERR("invalid keymgmt keypair selection\n");
		goto free_ec_key;
	}

	ret = uadk_prov_sm2_keygen(ec);
	if (ret == UADK_P_FAIL) {
		UADK_ERR("failed to generate sm2 key\n");
		goto do_soft;
	}

	return ec;

do_soft:
	EC_KEY_free(ec);
	return uadk_keymgmt_sm2_gen_sw(genctx, osslcb, cbarg);
free_ec_key:
	/* Something went wrong, throw the key away */
	EC_KEY_free(ec);
	return NULL;
}

static UADK_PKEY_SIGNATURE get_default_sm2_signature(void)
{
	return s_signature;
}

void set_default_sm2_signature(void)
{
	UADK_PKEY_SIGNATURE *signature;

	signature = (UADK_PKEY_SIGNATURE *)EVP_SIGNATURE_fetch(NULL, "SM2", "provider=default");
	if (signature) {
		s_signature = *signature;
		EVP_SIGNATURE_free((EVP_SIGNATURE *)signature);
	} else {
		UADK_INFO("failed to EVP_SIGNATURE_fetch sm2 default provider\n");
	}
}

static void *uadk_signature_sm2_newctx(void *provctx, const char *propq)
{
	PROV_SM2_SIGN_CTX *psm2ctx = OPENSSL_zalloc(sizeof(PROV_SM2_SIGN_CTX));
	SM2_PROV_CTX *smctx;

	if (psm2ctx == NULL) {
		UADK_ERR("failed to alloc sm2 signature ctx\n");
		return NULL;
	}
	/* The libctx maybe NULL, if libctx is NULL, will use default ctx. */
	psm2ctx->libctx = prov_libctx_of(provctx);

	smctx = OPENSSL_zalloc(sizeof(SM2_PROV_CTX));
	if (smctx == NULL) {
		UADK_ERR("failed to alloc sm2 prov ctx\n");
		goto free_ctx;
	}

	smctx->sm2_pd = OPENSSL_zalloc(sizeof(SM2_PKEY_DATA));
	if (smctx->sm2_pd == NULL) {
		UADK_ERR("failed to alloc sm2 pkey data\n");
		goto free_smctx;
	}

	smctx->sm2_md = OPENSSL_zalloc(sizeof(SM2_MD_DATA));
	if (smctx->sm2_md == NULL) {
		UADK_ERR("failed to alloc sm2 md data\n");
		goto free_pd;
	}

	/*
	 * Use SM3 for digest method in default, other digest algs
	 * can be set with set_ctx_params API.
	 */
	smctx->sm2_md->mdsize = SM3_DIGEST_LENGTH;
	psm2ctx->mdsize = SM3_DIGEST_LENGTH;
	smctx->sm2_md->md_nid = NID_sm3;
	strcpy(psm2ctx->mdname, OSSL_DIGEST_NAME_SM3);
	smctx->sm2_md->mdctx = EVP_MD_CTX_new();
	if (smctx->sm2_md->mdctx == NULL) {
		UADK_ERR("failed to alloc sm2 mdctx\n");
		goto free_md;
	}

	psm2ctx->sm2_pctx = smctx;

	if (propq) {
		psm2ctx->propq = OPENSSL_strdup(propq);
		if (psm2ctx->propq == NULL) {
			UADK_ERR("failed to dup propq\n");
			goto free_mdctx;
		}
	}

	return psm2ctx;

free_mdctx:
	EVP_MD_CTX_free(smctx->sm2_md->mdctx);
free_md:
	OPENSSL_free(smctx->sm2_md);
free_pd:
	OPENSSL_free(smctx->sm2_pd);
free_smctx:
	OPENSSL_free(smctx);
free_ctx:
	OPENSSL_free(psm2ctx);
	return NULL;
}

static void uadk_signature_sm2_freectx(void *vpsm2ctx)
{
	PROV_SM2_SIGN_CTX *psm2ctx = (PROV_SM2_SIGN_CTX *)vpsm2ctx;
	SM2_PROV_CTX *smctx;

	if (psm2ctx == NULL)
		return;

	smctx = psm2ctx->sm2_pctx;
	if (smctx) {
		if (smctx->sess)
			wd_ecc_free_sess(smctx->sess);

		if (smctx->sm2_md) {
			EVP_MD_free(smctx->sm2_md->md);
			EVP_MD_CTX_free(smctx->sm2_md->mdctx);
			OPENSSL_free(smctx->sm2_md);
		}

		if (smctx->sm2_pd) {
			if (smctx->sm2_pd->order)
				BN_free(smctx->sm2_pd->order);
			OPENSSL_free(smctx->sm2_pd);
		}

		OPENSSL_free(smctx);
	}

	if (psm2ctx->propq)
		OPENSSL_free(psm2ctx->propq);
	if (psm2ctx->key)
		EC_KEY_free(psm2ctx->key);
	if (psm2ctx->id)
		OPENSSL_free(psm2ctx->id);

	OPENSSL_free(psm2ctx);
}

static int uadk_prov_sm2_check_md_params(SM2_PROV_CTX *smctx)
{
	if (smctx->sm2_md == NULL) {
		UADK_ERR("invalid: sm2_md is NULL\n");
		return UADK_P_FAIL;
	}

	if (smctx->sm2_md->md == NULL) {
		UADK_ERR("invalid: md is NULL\n");
		return UADK_P_FAIL;
	}

	if (smctx->sm2_md->mdctx == NULL) {
		UADK_ERR("invalid: mdctx is NULL\n");
		return UADK_P_FAIL;
	}

	return UADK_P_SUCCESS;
}

static int uadk_prov_sm2_sig_set_mdname(PROV_SM2_SIGN_CTX *psm2ctx, const char *mdname)
{
	SM2_PROV_CTX *smctx;

	/* If mdname is NULL, no need to set, just return */
	if (mdname == NULL)
		return UADK_P_SUCCESS;

	/* 'psm2ctx' has already been checked when call this function, no need to check again */
	smctx = psm2ctx->sm2_pctx;
	if (smctx == NULL) {
		UADK_ERR("invalid: smctx is NULL\n");
		return UADK_P_FAIL;
	}

	if (smctx->sm2_md == NULL) {
		UADK_ERR("invalid: smctx->sm2_md is NULL\n");
		return UADK_P_FAIL;
	}

	if (smctx->sm2_md->md == NULL) {
		smctx->sm2_md->md = EVP_MD_fetch(psm2ctx->libctx,
						 psm2ctx->mdname, psm2ctx->propq);
		if (smctx->sm2_md->md == NULL) {
			UADK_ERR("failed to fetch digest method\n");
			return UADK_P_FAIL;
		}
	}

	if (strlen(mdname) >= sizeof(psm2ctx->mdname) ||
	    !EVP_MD_is_a(smctx->sm2_md->md, mdname)) {
		UADK_ERR("failed to check mdname, digest=%s\n", mdname);
		return UADK_P_FAIL;
	}

	OPENSSL_strlcpy(psm2ctx->mdname, mdname, sizeof(psm2ctx->mdname));

	return UADK_P_SUCCESS;
}

static int uadk_prov_compute_hash(const char *in, size_t in_len,
				  char *out, size_t out_len, void *usr)
{
	const EVP_MD *digest = (const EVP_MD *)usr;
	int ret = WD_SUCCESS;
	EVP_MD_CTX *hash;

	hash = EVP_MD_CTX_new();
	if (hash == NULL)
		return -WD_EINVAL;

	if (EVP_DigestInit(hash, digest) == 0 ||
	    EVP_DigestUpdate(hash, in, in_len) == 0 ||
	    EVP_DigestFinal(hash, (void *)out, NULL) == 0) {
		UADK_ERR("compute hash failed\n");
		ret = -WD_EINVAL;
	}

	EVP_MD_CTX_free(hash);

	return ret;
}

static int uadk_prov_get_hash_type(int nid_hash)
{
	switch (nid_hash) {
	case NID_sha1:
		return WD_HASH_SHA1;
	case NID_sha224:
		return WD_HASH_SHA224;
	case NID_sha256:
		return WD_HASH_SHA256;
	case NID_sha384:
		return WD_HASH_SHA384;
	case NID_sha512:
		return WD_HASH_SHA512;
	case NID_md4:
		return WD_HASH_MD4;
	case NID_md5:
		return WD_HASH_MD5;
	case NID_sm3:
		return WD_HASH_SM3;
	default:
		return -WD_EINVAL;
	}
}

static int uadk_prov_sm2_update_sess(SM2_PROV_CTX *smctx)
{
	const unsigned char sm2_order[] = {
		0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x72, 0x03, 0xdf, 0x6b, 0x21, 0xc6, 0x05, 0x2b,
		0x53, 0xbb, 0xf4, 0x09, 0x39, 0xd5, 0x41, 0x23
	};
	struct wd_ecc_sess_setup setup = {0};
	struct sched_params params = {0};
	handle_t sess;
	int type;

	if (smctx->sm2_pd == NULL) {
		UADK_ERR("invalid: sm2 pd is NULL\n");
		return UADK_P_FAIL;
	}

	/* order is free in freectx */
	if (smctx->sm2_pd->order == NULL) {
		smctx->sm2_pd->order = BN_bin2bn((void *)sm2_order, sizeof(sm2_order), NULL);
		if (smctx->sm2_pd->order == NULL) {
			UADK_ERR("failed to BN_bin2bn order\n");
			return UADK_P_FAIL;
		}
	}
	setup.rand.usr = (void *)smctx->sm2_pd->order;

	if (smctx->sm2_md->md) {
		/* Set hash method */
		setup.hash.cb = uadk_prov_compute_hash;
		setup.hash.usr = (void *)smctx->sm2_md->md;
		type = uadk_prov_get_hash_type(smctx->sm2_md->md_nid);
		if (type < 0) {
			UADK_ERR("uadk not support hash nid %d\n", smctx->sm2_md->md_nid);
			return UADK_P_FAIL;
		}
		setup.hash.type = type;
	}
	setup.alg = "sm2";

	/* Use the default numa parameters */
	params.numa_id = -1;
	setup.sched_param = &params;
	setup.rand.cb = uadk_prov_ecc_get_rand;
	sess = wd_ecc_alloc_sess(&setup);
	if (sess == (handle_t)0) {
		UADK_ERR("failed to alloc sess\n");
		smctx->init_status = CTX_INIT_FAIL;
		return UADK_P_FAIL;
	}

	/* Free old session before setting new session */
	if (smctx->sess)
		wd_ecc_free_sess(smctx->sess);
	smctx->sess = sess;

	smctx->sm2_pd->prikey = NULL;
	smctx->sm2_pd->pubkey = NULL;

	return UADK_P_SUCCESS;
}

static int uadk_signature_sm2_sign_init_sw(void *vpsm2ctx, void *ec,
					   const OSSL_PARAM params[])
{
	if (uadk_get_sw_offload_state() && get_default_sm2_signature().sign_init) {
		UADK_INFO("switch to software sm2 sign_init.\n");
		return get_default_sm2_signature().sign_init(vpsm2ctx, ec, params);
	}

	return UADK_P_FAIL;
}

static int uadk_signature_sm2_sign_init(void *vpsm2ctx, void *ec,
					const OSSL_PARAM params[])
{
	PROV_SM2_SIGN_CTX *psm2ctx = (PROV_SM2_SIGN_CTX *)vpsm2ctx;
	int ret;

	if (psm2ctx == NULL) {
		UADK_ERR("invalid: vpsm2ctx is NULL\n");
		return UADK_P_FAIL;
	}

	if (ec == NULL && psm2ctx->key == NULL) {
		UADK_ERR("invalid: sm2 key is NULL\n");
		return UADK_P_FAIL;
	}

	if (ec) {
		if (!EC_KEY_up_ref(ec)) {
			UADK_ERR("failed to EC_KEY_up_ref\n");
			return UADK_P_FAIL;
		}
		EC_KEY_free(psm2ctx->key);
		psm2ctx->key = (EC_KEY *)ec;
	}

	if (psm2ctx->sm2_pctx == NULL) {
		UADK_ERR("failed to get smctx\n");
		return UADK_P_FAIL;
	}

	/* openssl dgst tool will call sign_init twice, avoid repeated initialization */
	if (psm2ctx->sm2_pctx->init_status == CTX_INIT_SUCC)
		return UADK_P_SUCCESS;

	ret = uadk_signature_sm2_set_ctx_params((void *)psm2ctx, params);
	if (ret == UADK_P_FAIL) {
		UADK_ERR("failed to set sm2 sig ctx params\n");
		goto do_soft;
	}

	ret = uadk_prov_signature_get_support_state(SIGNATURE_SM2);
	if (ret == UADK_P_FAIL) {
		UADK_ERR("failed to get hardware sm2 signature support\n");
		goto do_soft;
	}

	/* Init with UADK */
	ret = uadk_prov_ecc_init("sm2");
	if (ret == UADK_P_FAIL) {
		UADK_ERR("failed to init sm2\n");
		goto do_soft;
	}

	psm2ctx->sm2_pctx->init_status = CTX_INIT_SUCC;

	return UADK_P_SUCCESS;

do_soft:
	return uadk_signature_sm2_sign_init_sw(vpsm2ctx, ec, params);
}

static int uadk_signature_sm2_verify_init(void *vpsm2ctx, void *ec,
					  const OSSL_PARAM params[])
{
	return uadk_signature_sm2_sign_init(vpsm2ctx, ec, params);
}

static int uadk_prov_sm2_check_tbs_params(PROV_SM2_SIGN_CTX *psm2ctx,
					  const unsigned char *tbs, size_t tbslen)
{
	SM2_PROV_CTX *smctx = psm2ctx->sm2_pctx;

	if (smctx == NULL) {
		UADK_ERR("invalid: ctx is NULL\n");
		return UADK_P_FAIL;
	}

	if (smctx->init_status != CTX_INIT_SUCC) {
		UADK_ERR("sm2 ctx init did not init\n");
		return UADK_P_FAIL;
	}

	if (smctx->sm2_md == NULL) {
		UADK_ERR("invalid: sm2_md is NULL\n");
		return UADK_P_FAIL;
	}

	if (smctx->sm2_md->mdsize != 0 && tbslen != smctx->sm2_md->mdsize) {
		UADK_ERR("invalid: tbslen(%zu) != mdsize(%zu)\n",
			 tbslen, smctx->sm2_md->mdsize);
		return UADK_P_FAIL;
	}

	if (tbslen > SM2_KEY_BYTES) {
		UADK_ERR("invalid: tbslen(%zu) > SM2_KEY_BYTES(32)\n", tbslen);
		return UADK_P_FAIL;
	}

	if (uadk_prov_is_all_zero(tbs, tbslen)) {
		UADK_ERR("invalid: tbs all zero\n");
		return UADK_P_FAIL;
	}

	return UADK_P_SUCCESS;
}

static int uadk_prov_sm2_sign_init_iot(handle_t sess, struct wd_ecc_req *req,
				       unsigned char *digest, size_t digest_len)
{
	struct wd_ecc_out *ecc_out;
	struct wd_ecc_in *ecc_in;
	struct wd_dtb e = {0};

	ecc_out = wd_sm2_new_sign_out(sess);
	if (ecc_out == NULL) {
		UADK_ERR("failed to new sign out\n");
		return UADK_P_FAIL;
	}

	e.data = (void *)digest;
	e.dsize = digest_len;
	ecc_in = wd_sm2_new_sign_in(sess, &e, NULL, NULL, 1);
	if (ecc_in == NULL) {
		UADK_ERR("failed to new sign in\n");
		wd_ecc_del_out(sess, ecc_out);
		return UADK_P_FAIL;
	}

	uadk_prov_ecc_fill_req(req, WD_SM2_SIGN, ecc_in, ecc_out);

	return UADK_P_SUCCESS;
}

static int uadk_prov_sm2_update_private_key(SM2_PROV_CTX *smctx, EC_KEY *eckey)
{
	const BIGNUM *d;
	int ret;

	d = EC_KEY_get0_private_key(eckey);
	if (d == NULL) {
		UADK_ERR("failed to set private key\n");
		return UADK_P_FAIL;
	}

	if (smctx->sm2_pd == NULL) {
		UADK_ERR("invalid: sm2_pd is NULL\n");
		return UADK_P_FAIL;
	}

	if (smctx->sm2_pd->prikey && !BN_cmp(d, smctx->sm2_pd->prikey)) {
		UADK_ERR("invalid: private key mismatch\n");
		return UADK_P_FAIL;
	}

	ret = uadk_prov_ecc_set_private_key(smctx->sess, eckey);
	if (ret == UADK_P_FAIL)
		return ret;

	smctx->sm2_pd->prikey = d;

	return UADK_P_SUCCESS;
}

static int uadk_prov_sm2_sign_bin_to_ber(struct wd_dtb *r, struct wd_dtb *s,
					 unsigned char *sig, size_t *siglen)
{
	BIGNUM *bn_r, *bn_s;
	ECDSA_SIG *e_sig;
	int sltmp, ret;

	e_sig = ECDSA_SIG_new();
	if (e_sig == NULL) {
		UADK_ERR("failed to ECDSA_SIG_new\n");
		return UADK_P_FAIL;
	}

	bn_r = BN_bin2bn((void *)r->data, r->dsize, NULL);
	if (bn_r == NULL) {
		UADK_ERR("failed to BN_bin2bn r\n");
		goto free_sig;
	}

	bn_s = BN_bin2bn((void *)s->data, s->dsize, NULL);
	if (bn_s == NULL) {
		UADK_ERR("failed to BN_bin2bn s\n");
		goto free_r;
	}

	ret = ECDSA_SIG_set0(e_sig, bn_r, bn_s);
	if (ret == 0) {
		UADK_ERR("failed to ECDSA_SIG_set0\n");
		goto free_s;
	}

	sltmp = i2d_ECDSA_SIG(e_sig, &sig);
	if (sltmp < 0) {
		UADK_ERR("failed to i2d_ECDSA_SIG\n");
		/* bs and br set to e_sig, use unified interface to prevent double release. */
		goto free_sig;
	}
	*siglen = (size_t)sltmp;
	ECDSA_SIG_free(e_sig);

	return UADK_P_SUCCESS;

free_s:
	BN_free(bn_s);
free_r:
	BN_free(bn_r);
free_sig:
	ECDSA_SIG_free(e_sig);

	return UADK_P_FAIL;
}

static int uadk_prov_sm2_sign_ber_to_bin(unsigned char *sig, size_t sig_len,
					 struct wd_dtb *r, struct wd_dtb *s)
{
	const unsigned char *p = sig;
	unsigned char *der = NULL;
	BIGNUM *bn_r, *bn_s;
	ECDSA_SIG *e_sig;
	int len1, len2;

	e_sig = ECDSA_SIG_new();
	if (e_sig == NULL) {
		UADK_ERR("failed to ECDSA_SIG_new\n");
		return UADK_P_FAIL;
	}

	if (d2i_ECDSA_SIG(&e_sig, &p, sig_len) == NULL) {
		UADK_ERR("d2i_ECDSA_SIG error\n");
		goto free_sig;
	}

	/* Ensure signature uses DER and doesn't have trailing garbage */
	len1 = i2d_ECDSA_SIG(e_sig, &der);
	if (len1 != sig_len || memcmp(sig, der, len1) != 0) {
		UADK_ERR("sig data error, der_len(%d), sig_len(%zu)\n",
			 len1, sig_len);
		goto free_der;
	}

	bn_r = (void *)ECDSA_SIG_get0_r((const ECDSA_SIG *)e_sig);
	if (bn_r == NULL) {
		UADK_ERR("failed to get r\n");
		goto free_der;
	}

	bn_s = (void *)ECDSA_SIG_get0_s((const ECDSA_SIG *)e_sig);
	if (bn_s == NULL) {
		UADK_ERR("failed to get s\n");
		goto free_der;
	}

	len1 = BN_num_bytes(bn_r);
	len2 = BN_num_bytes(bn_s);
	if (len1 > UADK_ECC_MAX_KEY_BYTES || len2 > UADK_ECC_MAX_KEY_BYTES) {
		UADK_ERR("r or s bytes = (%d, %d) error\n", len1, len2);
		goto free_der;
	}
	r->dsize = BN_bn2bin(bn_r, (void *)r->data);
	s->dsize = BN_bn2bin(bn_s, (void *)s->data);

	OPENSSL_free(der);
	ECDSA_SIG_free(e_sig);

	return UADK_P_SUCCESS;

free_der:
	OPENSSL_free(der);
free_sig:
	ECDSA_SIG_free(e_sig);

	return UADK_P_FAIL;
}

static int uadk_prov_sm2_sign(PROV_SM2_SIGN_CTX *psm2ctx,
			      unsigned char *sig, size_t *siglen,
			      const unsigned char *tbs, size_t tbslen)
{
	SM2_PROV_CTX *smctx = psm2ctx->sm2_pctx;
	struct wd_ecc_req req = {0};
	struct wd_dtb *r = NULL;
	struct wd_dtb *s = NULL;
	int ret;

	/* sess is free in uadk_signature_sm2_freectx() */
	if (smctx->sess == (handle_t)0) {
		ret = uadk_prov_sm2_update_sess(smctx);
		if (ret == UADK_P_FAIL) {
			UADK_ERR("failed to alloc sess in sign\n");
			return ret;
		}
	}

	ret = uadk_prov_sm2_sign_init_iot(smctx->sess, &req, (void *)tbs, tbslen);
	if (ret == UADK_P_FAIL)
		return ret;

	ret = uadk_prov_sm2_update_private_key(smctx, psm2ctx->key);
	if (ret == UADK_P_FAIL)
		goto uninit_iot;

	ret = uadk_prov_ecc_crypto(smctx->sess, &req, smctx);
	if (ret == UADK_P_FAIL) {
		UADK_ERR("failed to uadk_ecc_crypto, ret = %d\n", ret);
		goto uninit_iot;
	}

	wd_sm2_get_sign_out_params(req.dst, &r, &s);
	if (r == NULL || s == NULL) {
		UADK_ERR("failed to get sign result\n");
		ret = UADK_P_FAIL;
		goto uninit_iot;
	}

	ret = uadk_prov_sm2_sign_bin_to_ber(r, s, sig, siglen);

uninit_iot:
	wd_ecc_del_in(smctx->sess, req.src);
	wd_ecc_del_out(smctx->sess, req.dst);

	return ret;
}

static int uadk_signature_sm2_sign_sw(void *vpsm2ctx, unsigned char *sig, size_t *siglen,
				      size_t sigsize, const unsigned char *tbs, size_t tbslen)
{
	if (uadk_get_sw_offload_state() && get_default_sm2_signature().sign) {
		UADK_INFO("switch to soft sm2 sign\n");
		return get_default_sm2_signature().sign(vpsm2ctx, sig, siglen, sigsize,
							tbs, tbslen);
	}

	return UADK_P_FAIL;
}

static int uadk_signature_sm2_sign(void *vpsm2ctx, unsigned char *sig, size_t *siglen,
				   size_t sigsize, const unsigned char *tbs, size_t tbslen)
{
	PROV_SM2_SIGN_CTX *psm2ctx = (PROV_SM2_SIGN_CTX *)vpsm2ctx;
	int ret, ecsize;
	size_t sltmp;

	if (psm2ctx == NULL) {
		UADK_ERR("invalid: psm2ctx is NULL\n");
		return UADK_P_FAIL;
	}

	if (psm2ctx->key == NULL) {
		UADK_ERR("invalid: sm2 ec is NULL\n");
		return UADK_P_FAIL;
	}

	ecsize = ECDSA_size(psm2ctx->key);
	if (ecsize <= 0) {
		UADK_ERR("ecsize error %d\n", ecsize);
		return UADK_P_FAIL;
	}

	/*
	 * If 'sig' is NULL, users can use sm2_decrypt API to obtain the valid 'siglen' first,
	 * then users use the value of 'signlen' to alloc the memory of 'sig' and call the
	 * sm2_decrypt API a second time to do the decryption task.
	 */
	if (sig == NULL) {
		*siglen = (size_t)ecsize;
		return SM2_GET_SIGNLEN;
	}

	if (sigsize < (size_t)ecsize) {
		UADK_ERR("sigsize(%zu) < ecsize(%d)\n", sigsize, ecsize);
		return UADK_P_FAIL;
	}

	ret = uadk_prov_sm2_check_tbs_params(psm2ctx, tbs, tbslen);
	if (ret == UADK_P_FAIL) {
		UADK_ERR("failed to check sm2 signature params\n");
		goto do_soft;
	}

	ret = uadk_prov_sm2_sign(psm2ctx, sig, &sltmp, tbs, tbslen);
	if (ret == UADK_P_FAIL) {
		UADK_ERR("failed to do sm2 sign\n");
		goto do_soft;
	}

	*siglen = sltmp;

	return UADK_P_SUCCESS;

do_soft:
	return uadk_signature_sm2_sign_sw(vpsm2ctx, sig, siglen, sigsize, tbs, tbslen);
}

static int uadk_prov_sm2_verify_init_iot(handle_t sess, struct wd_ecc_req *req,
					struct wd_dtb *e, struct wd_dtb *r,
					struct wd_dtb *s)
{
	struct wd_ecc_in *ecc_in;

	ecc_in = wd_sm2_new_verf_in(sess, e, r, s, NULL, 1);
	if (ecc_in == NULL) {
		UADK_ERR("failed to new verf in\n");
		return UADK_E_FAIL;
	}

	uadk_prov_ecc_fill_req(req, WD_SM2_VERIFY, ecc_in, NULL);

	return UADK_E_SUCCESS;
}

static int uadk_prov_sm2_update_public_key(SM2_PROV_CTX *smctx, EC_KEY *eckey)
{
	SM2_PKEY_DATA *spd = smctx->sm2_pd;
	const EC_GROUP *group;
	const EC_POINT *point;
	int ret;

	point = EC_KEY_get0_public_key(eckey);
	if (point == NULL) {
		UADK_ERR("pubkey not set!\n");
		return UADK_E_FAIL;
	}

	if (spd == NULL) {
		UADK_ERR("invalid: sm2_pd is NULL\n");
		return UADK_P_FAIL;
	}

	if (spd->pubkey) {
		group = EC_KEY_get0_group(eckey);
		if (group == NULL) {
			UADK_ERR("failed to get group\n");
			return UADK_E_FAIL;
		}

		ret = EC_POINT_cmp(group, (void *)spd->pubkey, point, NULL);
		if (ret == UADK_E_FAIL) {
			UADK_ERR("failed to do EC_POINT_cmp\n");
			return ret;
		}
	}

	ret = uadk_prov_ecc_set_public_key(smctx->sess, eckey);
	if (ret == UADK_E_FAIL)
		return ret;

	spd->pubkey = point;

	return UADK_E_SUCCESS;
}

static int uadk_prov_sm2_verify(PROV_SM2_SIGN_CTX *psm2ctx,
				const unsigned char *sig, size_t siglen,
				const unsigned char *tbs, size_t tbslen)
{
	unsigned char buf_r[UADK_ECC_MAX_KEY_BYTES] = {0};
	unsigned char buf_s[UADK_ECC_MAX_KEY_BYTES] = {0};
	SM2_PROV_CTX *smctx = psm2ctx->sm2_pctx;
	struct wd_ecc_req req = {0};
	EC_KEY *ec = psm2ctx->key;
	struct wd_dtb e = {0};
	struct wd_dtb r = {0};
	struct wd_dtb s = {0};
	int ret;

	/* sess is free in uadk_signature_sm2_freectx() */
	if (smctx->sess == (handle_t)0) {
		ret = uadk_prov_sm2_update_sess(smctx);
		if (ret == UADK_P_FAIL) {
			UADK_ERR("failed to alloc sess in verify\n");
			return ret;
		}
	}

	r.data = (void *)buf_r;
	s.data = (void *)buf_s;
	r.bsize = UADK_ECC_MAX_KEY_BYTES;
	s.bsize = UADK_ECC_MAX_KEY_BYTES;
	ret = uadk_prov_sm2_sign_ber_to_bin((void *)sig, siglen, &r, &s);
	if (ret == UADK_P_FAIL) {
		UADK_ERR("failed to uadk_prov_sm2_sign_ber_to_bin\n");
		return ret;
	}

	e.data = (void *)tbs;
	e.dsize = tbslen;
	ret = uadk_prov_sm2_verify_init_iot(smctx->sess, &req, &e, &r, &s);
	if (ret == UADK_P_FAIL) {
		UADK_ERR("failed to uadk_prov_sm2_verify_init_iot\n");
		return ret;
	}

	ret = uadk_prov_sm2_update_public_key(smctx, ec);
	if (ret == UADK_P_FAIL) {
		UADK_ERR("failed to uadk_prov_sm2_update_public_key\n");
		goto uninit_iot;
	}

	ret = uadk_prov_ecc_crypto(smctx->sess, &req, smctx);
	if (ret == UADK_P_FAIL) {
		UADK_ERR("failed to uadk_ecc_crypto, ret = %d\n", ret);
		goto uninit_iot;
	}

	wd_ecc_del_in(smctx->sess, req.src);

	return UADK_P_SUCCESS;

uninit_iot:
	wd_ecc_del_in(smctx->sess, req.src);

	return UADK_P_FAIL;
}

static int uadk_signature_sm2_verify_sw(void *vpsm2ctx, const unsigned char *sig, size_t siglen,
					const unsigned char *tbs, size_t tbslen)
{
	if (uadk_get_sw_offload_state() && get_default_sm2_signature().verify) {
		UADK_INFO("switch to soft sm2 verify\n");
		return get_default_sm2_signature().verify(vpsm2ctx, sig, siglen, tbs, tbslen);
	}

	return UADK_P_FAIL;
}

static int uadk_signature_sm2_verify(void *vpsm2ctx, const unsigned char *sig, size_t siglen,
				     const unsigned char *tbs, size_t tbslen)
{
	PROV_SM2_SIGN_CTX *psm2ctx = (PROV_SM2_SIGN_CTX *)vpsm2ctx;
	int ret;

	if (psm2ctx == NULL) {
		UADK_ERR("invalid: psm2ctx is NULL\n");
		return UADK_P_FAIL;
	}

	ret = uadk_prov_sm2_check_tbs_params(psm2ctx, tbs, tbslen);
	if (ret == UADK_P_FAIL) {
		UADK_ERR("failed to check sm2 verify params\n");
		goto do_soft;
	}

	ret = uadk_prov_sm2_verify(psm2ctx, sig, siglen, tbs, tbslen);
	if (ret == UADK_P_FAIL) {
		UADK_ERR("failed to do sm2 verify\n");
		goto do_soft;
	}

	return UADK_P_SUCCESS;

do_soft:
	return uadk_signature_sm2_verify_sw(vpsm2ctx, sig, siglen, tbs, tbslen);
}

static int uadk_signature_sm2_digest_sign_init(void *vpsm2ctx, const char *mdname,
					       void *ec, const OSSL_PARAM params[])
{
	PROV_SM2_SIGN_CTX *psm2ctx = (PROV_SM2_SIGN_CTX *)vpsm2ctx;
	SM2_PROV_CTX *smctx;
	int md_nid;
	WPACKET pkt;

	if (!uadk_signature_sm2_sign_init(vpsm2ctx, ec, params) ||
	    !uadk_prov_sm2_sig_set_mdname(psm2ctx, mdname))
		return UADK_P_FAIL;

	smctx = psm2ctx->sm2_pctx;

	if (smctx->sm2_md->mdctx == NULL) {
		smctx->sm2_md->mdctx = EVP_MD_CTX_new();
		if (unlikely(smctx->sm2_md->mdctx == NULL)) {
			UADK_ERR("failed to EVP_MD_CTX_new\n");
			return UADK_P_FAIL;
		}
	}

	/*
	 * We do not care about DER writing errors.
	 * All it really means is that for some reason, there's no
	 * AlgorithmIdentifier to be had, but the operation itself is
	 * still valid, just as long as it's not used to construct
	 * anything that needs an AlgorithmIdentifier.
	 */
	md_nid = EVP_MD_get_type(smctx->sm2_md->md);
	smctx->sm2_md->md_nid = md_nid;
	psm2ctx->aid_len = 0;
	if (WPACKET_init_der(&pkt, psm2ctx->aid_buf, sizeof(psm2ctx->aid_buf)) &&
	    ossl_DER_w_algorithmIdentifier_SM2_with_MD(&pkt, -1, psm2ctx->key, md_nid) &&
	    WPACKET_finish(&pkt)) {
		WPACKET_get_total_written(&pkt, &psm2ctx->aid_len);
		psm2ctx->aid = WPACKET_get_curr(&pkt);
	}
	WPACKET_cleanup(&pkt);

	if (!EVP_DigestInit_ex2(smctx->sm2_md->mdctx, smctx->sm2_md->md, params)) {
		UADK_ERR("failed to do digest init\n");
		EVP_MD_CTX_free(smctx->sm2_md->mdctx);
		return UADK_P_FAIL;
	}

	psm2ctx->flag_compute_z_digest = 1;

	return UADK_P_SUCCESS;
}

static int uadk_prov_check_equation_param(struct sm2_param *param, EVP_MD_CTX *hash,
					  uint8_t *buf, int p_bytes)
{
	if (BN_bn2binpad(param->a, buf, p_bytes) < 0 ||
	    !EVP_DigestUpdate(hash, buf, p_bytes) ||
	    BN_bn2binpad(param->b, buf, p_bytes) < 0 ||
	    !EVP_DigestUpdate(hash, buf, p_bytes)) {
		UADK_ERR("failed to check equation param\n");
		return UADK_P_FAIL;
	}

	return UADK_P_SUCCESS;
}

static int uadk_prov_check_base_point_group_param(struct sm2_param *param, BN_CTX *ctx,
						  const EC_KEY *key)
{
	const EC_GROUP *group = EC_KEY_get0_group(key);

	if (!EC_POINT_get_affine_coordinates(group,
					     EC_GROUP_get0_generator(group),
					     param->xG, param->yG, ctx)) {
		UADK_ERR("failed to check base point group param\n");
		return UADK_P_FAIL;
	}

	return UADK_P_SUCCESS;
}

static int uadk_prov_check_base_point_param(struct sm2_param *param, EVP_MD_CTX *hash,
					    uint8_t *buf, int p_bytes)
{
	if (BN_bn2binpad(param->xG, buf, p_bytes) < 0 ||
	    !EVP_DigestUpdate(hash, buf, p_bytes) ||
	    BN_bn2binpad(param->yG, buf, p_bytes) < 0 ||
	    !EVP_DigestUpdate(hash, buf, p_bytes)) {
		UADK_ERR("failed to check base point param\n");
		return UADK_P_FAIL;
	}

	return UADK_P_SUCCESS;
}

static int uadk_prov_check_pkey_point_group_param(struct sm2_param *param, BN_CTX *ctx,
						  const EC_KEY *key)
{
	const EC_GROUP *group = EC_KEY_get0_group(key);

	if (!EC_POINT_get_affine_coordinates(group,
					     EC_KEY_get0_public_key(key),
					     param->xA, param->yA, ctx)) {
		UADK_ERR("failed to check pkey point group param\n");
		return UADK_P_FAIL;
	}
	return UADK_P_SUCCESS;
}

static int uadk_prov_check_pkey_point_param(struct sm2_param *param, EVP_MD_CTX *hash,
					    uint8_t *buf, int p_bytes, uint8_t *out)
{
	if (BN_bn2binpad(param->xA, buf, p_bytes) < 0 ||
	    !EVP_DigestUpdate(hash, buf, p_bytes) ||
	    BN_bn2binpad(param->yA, buf, p_bytes) < 0 ||
	    !EVP_DigestUpdate(hash, buf, p_bytes) ||
	    !EVP_DigestFinal(hash, out, NULL)) {
		UADK_ERR("failed to check pkey point param\n");
		return UADK_P_FAIL;
	}

	return UADK_P_SUCCESS;
}

static int uadk_prov_get_sm2_param(struct sm2_param *params, BN_CTX *ctx)
{
	params->p = BN_CTX_get(ctx);
	if (params->p == NULL)
		goto end;

	params->a = BN_CTX_get(ctx);
	if (params->a == NULL)
		goto end;

	params->b = BN_CTX_get(ctx);
	if (params->b == NULL)
		goto end;

	params->xG = BN_CTX_get(ctx);
	if (params->xG == NULL)
		goto end;

	params->yG = BN_CTX_get(ctx);
	if (params->yG == NULL)
		goto end;

	params->xA = BN_CTX_get(ctx);
	if (params->xA == NULL)
		goto end;

	params->yA = BN_CTX_get(ctx);
	if (params->yA == NULL)
		goto end;

	return UADK_P_SUCCESS;

end:
	UADK_ERR("failed to get bn ctx for sm2 params\n");
	return UADK_P_FAIL;
}

static int uadk_prov_check_digest_evp_lib(const EVP_MD *digest, EVP_MD_CTX *hash,
					  const size_t id_len, const uint8_t *id)
{
	uint8_t e_byte;
	uint16_t entl;

	if (!EVP_DigestInit(hash, digest)) {
		UADK_ERR("error evp lib\n");
		return UADK_P_FAIL;
	}

	/* Z = h(ENTL || ID || a || b || xG || yG || xA || yA) */
	if (id_len >= (UINT16_MAX >> TRANS_BITS_BYTES_SHIFT)) {
		UADK_ERR("invalid: id too large\n");
		return UADK_P_FAIL;
	}

	entl = (uint16_t)(id_len << TRANS_BITS_BYTES_SHIFT);

	/* Update the most significant (first) byte of 'entl' */
	e_byte = GET_MS_BYTE(entl);
	if (!EVP_DigestUpdate(hash, &e_byte, 1)) {
		UADK_ERR("failed to do EVP_DigestUpdate for e_byte's first byte\n");
		return UADK_P_FAIL;
	}

	/* Update the least significant (second) byte of 'entl' */
	e_byte = GET_LS_BYTE(entl);
	if (!EVP_DigestUpdate(hash, &e_byte, 1)) {
		UADK_ERR("failed to do EVP_DigestUpdate for e_byte's second byte\n");
		return UADK_P_FAIL;
	}

	if (id_len > 0 && !EVP_DigestUpdate(hash, id, id_len)) {
		UADK_ERR("failed to do EVP_DigestUpdate for id\n");
		return UADK_P_FAIL;
	}

	return UADK_P_SUCCESS;
}

static int uadk_prov_sm2_compute_z_digest(uint8_t *out, const EVP_MD *digest,
					  const uint8_t *id, const size_t id_len,
					  const EC_KEY *key)
{
	const EC_GROUP *group = EC_KEY_get0_group(key);
	struct sm2_param *params;
	int ret = UADK_P_FAIL;
	EVP_MD_CTX *hash;
	uint8_t *buf;
	BN_CTX *ctx;
	int p_bytes;

	hash = EVP_MD_CTX_new();
	if (hash == NULL)
		return ret;

	ctx = BN_CTX_new_ex(key->libctx);
	if (ctx == NULL)
		goto free_hash;

	params = OPENSSL_zalloc(sizeof(struct sm2_param));
	if (params == NULL) {
		UADK_ERR("failed to malloc sm2 param\n");
		goto free_ctx;
	}

	if (uadk_prov_get_sm2_param(params, ctx) == UADK_P_FAIL)
		goto free_params;

	if (uadk_prov_check_digest_evp_lib(digest, hash, id_len, id) == UADK_P_FAIL)
		goto free_params;

	if (EC_GROUP_get_curve(group, params->p, params->a, params->b, ctx) == 0) {
		UADK_ERR("failed to EC_GROUP_get_curve\n");
		goto free_params;
	}

	p_bytes = BN_num_bytes(params->p);
	buf = OPENSSL_zalloc(p_bytes);
	if (buf == NULL) {
		UADK_ERR("failed to alloc buffer\n");
		goto free_params;
	}

	if (!uadk_prov_check_equation_param(params, hash, buf, p_bytes) ||
	    !uadk_prov_check_base_point_group_param(params, ctx, key) ||
	    !uadk_prov_check_base_point_param(params, hash, buf, p_bytes) ||
	    !uadk_prov_check_pkey_point_group_param(params, ctx, key) ||
	    !uadk_prov_check_pkey_point_param(params, hash, buf, p_bytes, out))
		goto free_buf;

	ret = UADK_P_SUCCESS;

free_buf:
	OPENSSL_free(buf);
free_params:
	OPENSSL_free(params);
free_ctx:
	BN_CTX_free(ctx);
free_hash:
	EVP_MD_CTX_free(hash);
	return ret;
}

static int sm2_sig_compute_z_digest(PROV_SM2_SIGN_CTX *psm2ctx)
{
	SM2_PROV_CTX *smctx = psm2ctx->sm2_pctx;
	uint8_t *z;
	int ret;

	if (psm2ctx->flag_compute_z_digest) {
		/* Only do this once */
		psm2ctx->flag_compute_z_digest = 0;

		z = OPENSSL_zalloc(smctx->sm2_md->mdsize);
		if (z == NULL) {
			UADK_ERR("failed to alloc z\n");
			return UADK_P_FAIL;
		}

		/* if id is not set, use default id */
		if (psm2ctx->id == NULL) {
			/* psm2ctx id will be freed in uadk_signature_sm2_freectx, not here */
			psm2ctx->id = OPENSSL_memdup(SM2_DEFAULT_USERID, SM2_DEFAULT_USERID_LEN);
			if (psm2ctx->id == NULL) {
				UADK_ERR("failed to memdup psm2ctx id\n");
				goto free_z;
			}
			psm2ctx->id_len = SM2_DEFAULT_USERID_LEN;
		}

		/* get hashed prefix 'z' of tbs message */
		ret = uadk_prov_sm2_compute_z_digest(z, smctx->sm2_md->md, psm2ctx->id,
			psm2ctx->id_len, psm2ctx->key);
		if (ret == UADK_P_FAIL) {
			UADK_ERR("failed to uadk_prov_sm2_compute_z_digest\n");
			goto free_z;
		}

		ret = EVP_DigestUpdate(smctx->sm2_md->mdctx, z, smctx->sm2_md->mdsize);
		if (ret == UADK_P_FAIL) {
			UADK_ERR("failed to EVP_DigestUpdate\n");
			goto free_z;
		}
		OPENSSL_free(z);
	}

	return UADK_P_SUCCESS;

free_z:
	OPENSSL_free(z);
	return UADK_P_FAIL;
}

static int uadk_signature_sm2_digest_sign_update(void *vpsm2ctx, const unsigned char *data,
						 size_t datalen)
{
	PROV_SM2_SIGN_CTX *psm2ctx = (PROV_SM2_SIGN_CTX *)vpsm2ctx;
	SM2_PROV_CTX *smctx;
	int ret;

	if (psm2ctx == NULL) {
		UADK_ERR("invalid: psm2ctx is NULL in digest sign update\n");
		return UADK_P_FAIL;
	}

	smctx = psm2ctx->sm2_pctx;
	if (smctx == NULL) {
		UADK_ERR("invalid: smctx is NULL in compute z digest\n");
		return UADK_P_FAIL;
	}

	ret = uadk_prov_sm2_check_md_params(smctx);
	if (ret == UADK_P_FAIL)
		return ret;

	ret = sm2_sig_compute_z_digest(psm2ctx);
	if (ret == UADK_P_FAIL) {
		UADK_ERR("failed to compute z digest\n");
		return ret;
	}

	ret = EVP_DigestUpdate(smctx->sm2_md->mdctx, data, datalen);
	if (ret == UADK_P_FAIL) {
		UADK_ERR("failed to EVP_DigestUpdate\n");
		return ret;
	}

	return UADK_P_SUCCESS;
}

static int uadk_signature_sm2_digest_sign_final(void *vpsm2ctx,
						unsigned char *sig, size_t *siglen,
						size_t sigsize)
{
	PROV_SM2_SIGN_CTX *psm2ctx = (PROV_SM2_SIGN_CTX *)vpsm2ctx;
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int dlen = 0;
	SM2_PROV_CTX *smctx;
	int ret;

	if (psm2ctx == NULL) {
		UADK_ERR("invalid: psm2ctx is NULL\n");
		return UADK_P_FAIL;
	}

	smctx = psm2ctx->sm2_pctx;
	if (smctx == NULL) {
		UADK_ERR("invalid: smctx is NULL\n");
		return UADK_P_FAIL;
	}

	ret = uadk_prov_sm2_check_md_params(smctx);
	if (ret == UADK_P_FAIL)
		return ret;

	/*
	 * If sig is NULL then we're just finding out the sig size. Other fields
	 * are ignored. Defer to sm2sig_sign.
	 */
	if (sig != NULL) {
		ret = sm2_sig_compute_z_digest(psm2ctx);
		if (ret == UADK_P_FAIL)
			return ret;

		ret = EVP_DigestFinal_ex(smctx->sm2_md->mdctx, digest, &dlen);
		if (ret == UADK_P_FAIL) {
			UADK_ERR("failed to do EVP_DigestFinal_ex\n");
			return ret;
		}
	}

	return uadk_signature_sm2_sign(vpsm2ctx, sig, siglen, sigsize, digest, (size_t)dlen);
}

static int uadk_signature_sm2_digest_verify_init(void *vpsm2ctx, const char *mdname,
						 void *ec, const OSSL_PARAM params[])
{
	return uadk_signature_sm2_digest_sign_init(vpsm2ctx, mdname, ec, params);
}

static int uadk_signature_sm2_digest_verify_update(void *vpsm2ctx, const unsigned char *data,
						   size_t datalen)
{
	return uadk_signature_sm2_digest_sign_update(vpsm2ctx, data, datalen);
}

static int uadk_signature_sm2_digest_verify_final(void *vpsm2ctx, const unsigned char *sig,
						  size_t siglen)
{
	PROV_SM2_SIGN_CTX *psm2ctx = (PROV_SM2_SIGN_CTX *)vpsm2ctx;
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int dlen = 0;
	SM2_PROV_CTX *smctx;
	int ret, size;

	if (psm2ctx == NULL) {
		UADK_ERR("invalid: psm2ctx is NULL\n");
		return UADK_P_FAIL;
	}

	smctx = psm2ctx->sm2_pctx;
	if (smctx == NULL) {
		UADK_ERR("invalid: smctx is NULL\n");
		return UADK_P_FAIL;
	}

	ret = uadk_prov_sm2_check_md_params(smctx);
	if (ret == UADK_P_FAIL)
		return ret;

	size = EVP_MD_get_size(smctx->sm2_md->md);
	if (size > EVP_MAX_MD_SIZE) {
		UADK_ERR("invalid: md size(%d) > %d\n", size, EVP_MAX_MD_SIZE);
		return UADK_P_FAIL;
	}

	ret = sm2_sig_compute_z_digest(psm2ctx);
	if (ret == UADK_P_FAIL) {
		UADK_ERR("failed to do sm2_sig_compute_z_digest\n");
		return ret;
	}

	ret = EVP_DigestFinal_ex(smctx->sm2_md->mdctx, digest, &dlen);
	if (ret == UADK_P_FAIL) {
		UADK_ERR("failed to do EVP_DigestFinal_ex, dlen = %u\n", dlen);
		return ret;
	}

	return uadk_signature_sm2_verify(vpsm2ctx, sig, siglen, digest, (size_t)dlen);
}

static SM2_PROV_CTX *sm2_copy_src_smctx(SM2_PROV_CTX *src_smctx)
{
	SM2_PROV_CTX *dst_smctx;
	int ret;

	if (src_smctx == NULL || src_smctx->sm2_md == NULL || src_smctx->sm2_pd == NULL) {
		UADK_ERR("invalid: src_smctx is NULL to dupctx\n");
		return NULL;
	}

	dst_smctx = OPENSSL_zalloc(sizeof(SM2_PROV_CTX));
	if (dst_smctx == NULL) {
		UADK_ERR("failed to alloc dst_smctx\n");
		return NULL;
	}
	dst_smctx->init_status = src_smctx->init_status;

	dst_smctx->sm2_md = OPENSSL_zalloc(sizeof(SM2_MD_DATA));
	if (dst_smctx->sm2_md == NULL) {
		UADK_ERR("failed to alloc dst_smctx->sm2_md\n");
		goto free_dst_smctx;
	}

	if (src_smctx->sm2_md->md != NULL && !EVP_MD_up_ref(src_smctx->sm2_md->md)) {
		UADK_ERR("failed to check srcctx md reference\n");
		goto free_sm2_md;
	}
	dst_smctx->sm2_md->md = src_smctx->sm2_md->md;
	dst_smctx->sm2_md->mdsize = src_smctx->sm2_md->mdsize;
	dst_smctx->sm2_md->md_nid = src_smctx->sm2_md->md_nid;

	if (src_smctx->sm2_md->mdctx != NULL) {
		dst_smctx->sm2_md->mdctx = EVP_MD_CTX_new();
		if (dst_smctx->sm2_md->mdctx == NULL ||
		    EVP_MD_CTX_copy_ex(dst_smctx->sm2_md->mdctx, src_smctx->sm2_md->mdctx) == 0) {
			UADK_ERR("failed to new dst mdctx or copy src mdctx\n");
			goto free_mdctx;
		}
	}

	dst_smctx->sm2_pd = OPENSSL_zalloc(sizeof(SM2_PKEY_DATA));
	if (dst_smctx->sm2_pd == NULL) {
		UADK_ERR("failed to alloc sm2_pd\n");
		goto free_mdctx;
	}

	if (src_smctx->sess) {
		ret = uadk_prov_sm2_update_sess(dst_smctx);
		if (!ret)
			goto free_sm2_pd;
	}

	return dst_smctx;

free_sm2_pd:
	OPENSSL_free(dst_smctx->sm2_pd);
free_mdctx:
	if (dst_smctx->sm2_md->mdctx != NULL)
		EVP_MD_CTX_free(dst_smctx->sm2_md->mdctx);
	EVP_MD_free(dst_smctx->sm2_md->md);
free_sm2_md:
	OPENSSL_free(dst_smctx->sm2_md);
free_dst_smctx:
	OPENSSL_free(dst_smctx);
	return NULL;
}

static void *uadk_signature_sm2_dupctx(void *vpsm2ctx)
{
	PROV_SM2_SIGN_CTX *srcctx = (PROV_SM2_SIGN_CTX *)vpsm2ctx;
	PROV_SM2_SIGN_CTX *dstctx;

	if (srcctx == NULL) {
		UADK_ERR("invalid: src ctx is NULL to dupctx!\n");
		return NULL;
	}

	dstctx = OPENSSL_zalloc(sizeof(PROV_SM2_SIGN_CTX));
	if (dstctx == NULL) {
		UADK_ERR("failed to alloc dst ctx\n");
		return NULL;
	}
	*dstctx = *srcctx;
	dstctx->key = NULL;
	dstctx->id = NULL;
	dstctx->sm2_pctx = NULL;
	dstctx->propq = NULL;

	if (srcctx->key != NULL && !EC_KEY_up_ref(srcctx->key)) {
		UADK_ERR("failed to check srcctx key reference\n");
		goto free_ctx;
	}
	dstctx->key = srcctx->key;

	if (srcctx->propq) {
		dstctx->propq = OPENSSL_strdup(srcctx->propq);
		if (dstctx->propq == NULL)
			goto free_ctx;
	}

	dstctx->sm2_pctx = sm2_copy_src_smctx(srcctx->sm2_pctx);
	if (dstctx->sm2_pctx == NULL)
		goto free_ctx;

	if (srcctx->id != NULL) {
		dstctx->id = OPENSSL_malloc(srcctx->id_len);
		if (dstctx->id == NULL) {
			UADK_ERR("failed to alloc id\n");
			goto free_ctx;
		}
		memcpy(dstctx->id, srcctx->id, srcctx->id_len);
	}

	return dstctx;

free_ctx:
	uadk_signature_sm2_freectx(dstctx);
	return NULL;
}

static int uadk_prov_sm2_locate_id_digest(PROV_SM2_SIGN_CTX *psm2ctx,  const OSSL_PARAM params[])
{
	size_t tmp_idlen = 0;
	const OSSL_PARAM *p;
	void *tmp_id = NULL;
	char *mdname = NULL;
	size_t mdsize;

	p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_DIST_ID);
	if (p) {
		/*If the 'z' digest has already been computed, the ID is set too late */
		if (psm2ctx->flag_compute_z_digest == 0) {
			UADK_ERR("invalid: should set ID param before z digest\n");
			return UADK_P_FAIL;
		}

		if (p->data_size != 0 &&
		    !OSSL_PARAM_get_octet_string(p, &tmp_id, 0, &tmp_idlen)) {
			UADK_ERR("failed to OSSL_PARAM_get_octet_string\n");
			return UADK_P_FAIL;
		}
		if (psm2ctx->id != NULL)
			OPENSSL_free(psm2ctx->id);
		psm2ctx->id = tmp_id;
		psm2ctx->id_len = tmp_idlen;
	}

	/*
	 * The following code checks that the size is the same as the SM3 digest
	 * size returning an error otherwise.
	 * If there is ever any different digest algorithm allowed with SM2
	 * this needs to be adjusted accordingly.
	 */
	p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST_SIZE);
	if (p != NULL && (!OSSL_PARAM_get_size_t(p, &mdsize) ||
			  mdsize != psm2ctx->sm2_pctx->sm2_md->mdsize)) {
		UADK_ERR("failed to locate digest size\n");
		return UADK_P_FAIL;
	}

	p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
	if (p) {
		if (!OSSL_PARAM_get_utf8_string(p, &mdname, 0)) {
			UADK_ERR("failed to OSSL_PARAM_get_utf8_string\n");
			return UADK_P_FAIL;
		}

		if (!uadk_prov_sm2_sig_set_mdname(psm2ctx, mdname)) {
			OPENSSL_free(mdname);
			UADK_ERR("failed to OSSL_PARAM_get_utf8_string\n");
			return UADK_P_FAIL;
		}

		if (mdname != NULL)
			OPENSSL_free(mdname);
	}

	return UADK_P_SUCCESS;
}

static int uadk_signature_sm2_set_ctx_params(void *vpsm2ctx, const OSSL_PARAM params[])
{
	PROV_SM2_SIGN_CTX *psm2ctx = (PROV_SM2_SIGN_CTX *)vpsm2ctx;
	SM2_PROV_CTX *smctx;

	/*
	 * 'set_ctx_param' function can be called independently,
	 * so check 'psm2ctx' again here.
	 */
	if (psm2ctx == NULL) {
		UADK_ERR("invalid: sm2 ctx is NULL\n");
		return UADK_P_FAIL;
	}

	/* If params is NULL, no need to set ctx params, just return */
	if (params == NULL)
		return UADK_P_SUCCESS;

	smctx = psm2ctx->sm2_pctx;
	if (smctx == NULL) {
		UADK_ERR("invalid: smctx is NULL\n");
		return UADK_P_FAIL;
	}

	return uadk_prov_sm2_locate_id_digest(psm2ctx, params);
}

static int uadk_signature_sm2_get_ctx_params(void *vpsm2ctx, OSSL_PARAM *params)
{
	PROV_SM2_SIGN_CTX *psm2ctx = (PROV_SM2_SIGN_CTX *)vpsm2ctx;
	OSSL_PARAM *p;

	if (psm2ctx == NULL) {
		UADK_ERR("invalid: psm2ctx is NULL\n");
		return UADK_P_FAIL;
	}

	p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
	if (p != NULL && !OSSL_PARAM_set_octet_string(p, psm2ctx->aid, psm2ctx->aid_len)) {
		UADK_ERR("failed to locate algorithm id\n");
		return UADK_P_FAIL;
	}

	p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST_SIZE);
	if (p != NULL && !OSSL_PARAM_set_size_t(p, psm2ctx->sm2_pctx->sm2_md->mdsize)) {
		UADK_ERR("failed to locate digest size\n");
		return UADK_P_FAIL;
	}

	p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
	if (p != NULL && !OSSL_PARAM_set_utf8_string(p, psm2ctx->sm2_pctx->sm2_md->md == NULL
		? psm2ctx->mdname : EVP_MD_get0_name(psm2ctx->sm2_pctx->sm2_md->md))) {
		UADK_ERR("failed to locate digest\n");
		return UADK_P_FAIL;
	}

	return UADK_P_SUCCESS;
}

static const OSSL_PARAM *uadk_signature_sm2_settable_ctx_params(ossl_unused void *vpsm2ctx,
								ossl_unused void *provctx)
{
	return sm2_sig_known_settable_ctx_params;
}

static const OSSL_PARAM *uadk_signature_sm2_gettable_ctx_params(ossl_unused void *vpsm2ctx,
								ossl_unused void *provctx)
{
	return sm2_sig_known_gettable_ctx_params;
}

static int uadk_signature_sm2_set_ctx_md_params(void *vpsm2ctx, const OSSL_PARAM params[])
{
	PROV_SM2_SIGN_CTX *psm2ctx = (PROV_SM2_SIGN_CTX *)vpsm2ctx;
	SM2_PROV_CTX *smctx;

	smctx = psm2ctx->sm2_pctx;
	if (smctx == NULL) {
		UADK_ERR("invalid: smctx is NULL\n");
		return UADK_P_FAIL;
	}

	if (smctx->sm2_md->mdctx == NULL) {
		UADK_ERR("invalid: mdctx is NULL\n");
		return UADK_P_FAIL;
	}

	return EVP_MD_CTX_set_params(smctx->sm2_md->mdctx, params);
}

static int uadk_signature_sm2_get_ctx_md_params(void *vpsm2ctx, OSSL_PARAM *params)
{
	PROV_SM2_SIGN_CTX *psm2ctx = (PROV_SM2_SIGN_CTX *)vpsm2ctx;
	SM2_PROV_CTX *smctx;

	smctx = psm2ctx->sm2_pctx;
	if (smctx == NULL) {
		UADK_ERR("invalid: smctx is NULL\n");
		return UADK_P_FAIL;
	}

	if (smctx->sm2_md->mdctx == NULL) {
		UADK_ERR("invalid: mdctx is NULL\n");
		return UADK_P_FAIL;
	}

	return EVP_MD_CTX_get_params(smctx->sm2_md->mdctx, params);
}

static const OSSL_PARAM *uadk_signature_sm2_settable_ctx_md_params(void *vpsm2ctx)
{
	PROV_SM2_SIGN_CTX *psm2ctx = (PROV_SM2_SIGN_CTX *)vpsm2ctx;
	SM2_PROV_CTX *smctx;

	smctx = psm2ctx->sm2_pctx;
	if (smctx == NULL) {
		UADK_ERR("invalid: smctx is NULL\n");
		return UADK_P_FAIL;
	}

	if (smctx->sm2_md->md == NULL) {
		UADK_ERR("invalid: md is NULL\n");
		return UADK_P_FAIL;
	}

	return EVP_MD_settable_ctx_params(smctx->sm2_md->md);
}

static const OSSL_PARAM *uadk_signature_sm2_gettable_ctx_md_params(void *vpsm2ctx)
{
	PROV_SM2_SIGN_CTX *psm2ctx = (PROV_SM2_SIGN_CTX *)vpsm2ctx;
	SM2_PROV_CTX *smctx;

	smctx = psm2ctx->sm2_pctx;
	if (smctx == NULL) {
		UADK_ERR("invalid: smctx is NULL\n");
		return UADK_P_FAIL;
	}

	if (smctx->sm2_md->md == NULL) {
		UADK_ERR("invalid: md is NULL\n");
		return UADK_P_FAIL;
	}

	return EVP_MD_gettable_ctx_params(smctx->sm2_md->md);
}

static int uadk_signature_sm2_verify_recover_init(void *vpsm2ctx, void *vsm2,
						  const OSSL_PARAM params[])
{
	return UADK_P_SUCCESS;
}

static int uadk_signature_sm2_verify_recover(void *vpsm2ctx, unsigned char *rout,
					     size_t *routlen, size_t routsize,
					     const unsigned char *sig, size_t siglen)
{
	return UADK_P_SUCCESS;
}

static UADK_PKEY_ASYM_CIPHER get_default_sm2_asym_cipher(void)
{
	return s_asym_cipher;
}

void set_default_sm2_asym_cipher(void)
{
	UADK_PKEY_ASYM_CIPHER *asym_cipher;

	asym_cipher = (UADK_PKEY_ASYM_CIPHER *)EVP_ASYM_CIPHER_fetch(NULL,
						"SM2", "provider=default");
	if (asym_cipher) {
		s_asym_cipher = *asym_cipher;
		EVP_ASYM_CIPHER_free((EVP_ASYM_CIPHER *)asym_cipher);
	} else {
		UADK_INFO("failed to EVP_ASYM_CIPHER_fetch sm2 default provider\n");
	}
}

static void *uadk_asym_cipher_sm2_newctx(void *provctx)
{
	PROV_SM2_ASYM_CTX *psm2ctx = OPENSSL_zalloc(sizeof(PROV_SM2_ASYM_CTX));
	SM2_PROV_CTX *smctx;

	if (psm2ctx == NULL) {
		UADK_ERR("failed to alloc PROV_SM2_ASYM_CTX\n");
		return NULL;
	}

	psm2ctx->libctx = prov_libctx_of(provctx);

	smctx = OPENSSL_zalloc(sizeof(SM2_PROV_CTX));
	if (smctx == NULL) {
		UADK_ERR("failed to alloc sm2 prov ctx\n");
		goto free_psm2ctx;
	}

	smctx->sm2_md = OPENSSL_zalloc(sizeof(SM2_MD_DATA));
	if (smctx->sm2_md == NULL) {
		UADK_ERR("failed to alloc sm2 md data\n");
		goto free_smctx;
	}
	/* Use SM3 in default, other digest can be set with set_ctx_params API. */
	smctx->sm2_md->mdsize = SM3_DIGEST_LENGTH;

	smctx->sm2_pd = OPENSSL_zalloc(sizeof(SM2_PKEY_DATA));
	if (smctx->sm2_pd == NULL) {
		UADK_ERR("failed to alloc sm2 pkey data\n");
		goto free_sm2_md;
	}

	psm2ctx->sm2_pctx = smctx;

	return psm2ctx;

free_sm2_md:
	OPENSSL_free(smctx->sm2_md);
free_smctx:
	OPENSSL_free(smctx);
free_psm2ctx:
	OPENSSL_free(psm2ctx);

	return NULL;
}

static void ossl_prov_digest_reset(struct PROV_DIGEST *pd)
{
	EVP_MD_free(pd->alloc_md);

#if !defined(FIPS_MODULE) && !defined(OPENSSL_NO_ENGINE)
	ENGINE_finish(pd->engine);
#endif
}

static void uadk_asym_cipher_sm2_freectx(void *vpsm2ctx)
{
	PROV_SM2_ASYM_CTX *psm2ctx = (PROV_SM2_ASYM_CTX *)vpsm2ctx;
	SM2_PROV_CTX *smctx;

	if (psm2ctx == NULL)
		return;

	smctx = psm2ctx->sm2_pctx;
	if (smctx) {
		if (smctx->sm2_md) {
			EVP_MD_free(smctx->sm2_md->md);
			OPENSSL_free(smctx->sm2_md);
		}

		if (smctx->sm2_pd) {
			if (smctx->sm2_pd->order)
				BN_free(smctx->sm2_pd->order);
			OPENSSL_free(smctx->sm2_pd);
		}

		if (smctx->sess)
			wd_ecc_free_sess(smctx->sess);
		OPENSSL_free(smctx);
	}

	if (psm2ctx->key)
		EC_KEY_free(psm2ctx->key);

	ossl_prov_digest_reset(&psm2ctx->md);
	OPENSSL_free(psm2ctx);
}

static void uadk_prov_sm2_set_default_md(PROV_SM2_ASYM_CTX *psm2ctx)
{
	SM2_PROV_CTX *smctx = psm2ctx->sm2_pctx;
	SM2_MD_DATA *smd = smctx->sm2_md;

	/* Set SM3 as default digest method */
	if (smd->alloc_md)
		EVP_MD_free(smd->alloc_md);
	smd->md = smd->alloc_md = EVP_MD_fetch(psm2ctx->libctx, "SM3", NULL);
	smd->md_nid = NID_sm3;
}

static int uadk_asym_cipher_sm2_encrypt_init_sw(void *vpsm2ctx, void *vkey,
						const OSSL_PARAM params[])
{
	if (uadk_get_sw_offload_state() && get_default_sm2_asym_cipher().encrypt_init) {
		UADK_INFO("switch to software sm2 encrypt init\n");
		return get_default_sm2_asym_cipher().encrypt_init(vpsm2ctx, vkey, params);
	}

	return UADK_P_FAIL;
}

static int uadk_asym_cipher_sm2_encrypt_init(void *vpsm2ctx, void *vkey,
					     const OSSL_PARAM params[])
{
	PROV_SM2_ASYM_CTX *psm2ctx = (PROV_SM2_ASYM_CTX *)vpsm2ctx;
	SM2_PROV_CTX *smctx;
	int ret;

	if (psm2ctx == NULL) {
		UADK_ERR("invalid: psm2ctx is NULL\n");
		return UADK_P_FAIL;
	}

	smctx = psm2ctx->sm2_pctx;
	if (smctx == NULL) {
		UADK_ERR("invalid: smctx is NULL\n");
		return UADK_P_FAIL;
	}

	if (vkey == NULL || !EC_KEY_up_ref(vkey)) {
		UADK_ERR("invalid: vkey is NULL\n");
		return UADK_P_FAIL;
	}
	EC_KEY_free(psm2ctx->key);
	psm2ctx->key = vkey;

	/* Set default digest method as SM3 */
	uadk_prov_sm2_set_default_md(psm2ctx);

	ret = uadk_asym_cipher_sm2_set_ctx_params(psm2ctx, params);
	if (ret == UADK_P_FAIL) {
		UADK_ERR("failed to set_ctx_params\n");
		goto do_soft;
	}

	ret = uadk_prov_asym_cipher_get_support_state(SIGNATURE_SM2);
	if (ret == UADK_P_FAIL) {
		UADK_ERR("failed to get hardware sm2 signature support\n");
		goto do_soft;
	}

	/* Init with UADK */
	ret = uadk_prov_ecc_init("sm2");
	if (ret == UADK_P_FAIL) {
		UADK_ERR("failed to init sm2\n");
		goto do_soft;
	}

	smctx->init_status = CTX_INIT_SUCC;

	ret = uadk_prov_sm2_update_sess(smctx);
	if (ret == UADK_P_FAIL) {
		UADK_ERR("failed to update sess\n");
		goto do_soft;
	}

	return UADK_P_SUCCESS;

do_soft:
	return uadk_asym_cipher_sm2_encrypt_init_sw(vpsm2ctx, vkey, params);
}

static int uadk_prov_sm2_encrypt_check(PROV_SM2_ASYM_CTX *psm2ctx,
				       unsigned char *out, size_t *outlen,
				       const unsigned char *in, size_t inlen)
{
	SM2_PROV_CTX *smctx = psm2ctx->sm2_pctx;
	const EVP_MD *md;
	int c3_size;

	if (smctx == NULL || smctx->sess == (handle_t)0) {
		UADK_ERR("smctx or sess NULL\n");
		return UADK_P_FAIL;
	}

	if (smctx->init_status != CTX_INIT_SUCC) {
		UADK_ERR("sm2 ctx init failed\n");
		return UADK_P_FAIL;
	}

	/*
	 * As we have already set md method in init, if not set, will use default digest.
	 * The md is unlikey to be NULL here, so if the md is still NULL when encrypt start,
	 * just return fail.
	 */
	md = smctx->sm2_md->md;
	if (md == NULL) {
		UADK_ERR("failed to get md method\n");
		return UADK_P_FAIL;
	}

	c3_size = EVP_MD_size(md);
	if (c3_size <= 0) {
		UADK_ERR("c3 size error\n");
		return UADK_P_FAIL;
	}

	if (inlen > UINT_MAX) {
		UADK_ERR("invalid: inlen is out of range\n");
		return UADK_P_FAIL;
	}

	return UADK_P_SUCCESS;
}

static int uadk_prov_sm2_encrypt_init_iot(handle_t sess, struct wd_ecc_req *req,
					  unsigned char *in, size_t inlen)
{
	struct wd_ecc_out *ecc_out;
	struct wd_ecc_in *ecc_in;
	struct wd_dtb e = {0};

	ecc_out = wd_sm2_new_enc_out(sess, inlen);
	if (ecc_out == NULL) {
		UADK_ERR("failed to new enc out\n");
		return UADK_P_FAIL;
	}

	e.data = (void *)in;
	e.dsize = inlen;
	ecc_in = wd_sm2_new_enc_in(sess, NULL, &e);
	if (ecc_in == NULL) {
		UADK_ERR("failed to new enc in\n");
		wd_ecc_del_out(sess, ecc_out);
		return UADK_P_FAIL;
	}

	uadk_prov_ecc_fill_req(req, WD_SM2_ENCRYPT, ecc_in, ecc_out);

	return UADK_P_SUCCESS;
}

static int uadk_prov_sm2_asym_bin_to_ber(struct wd_ecc_point *c1,
					 struct wd_dtb *c2, struct wd_dtb *c3,
					 unsigned char *ber, size_t *ber_len)
{
	struct sm2_ciphertext ctext;
	int ctext_leni, ret;
	BIGNUM *x1, *y1;

	x1 = BN_bin2bn((void *)c1->x.data, c1->x.dsize, NULL);
	if (x1 == NULL) {
		UADK_ERR("failed to BN_bin2bn x1\n");
		return UADK_P_FAIL;
	}

	y1 = BN_bin2bn((void *)c1->y.data, c1->y.dsize, NULL);
	if (y1 == NULL) {
		UADK_ERR("failed to BN_bin2bn y1\n");
		ret = UADK_P_FAIL;
		goto free_x1;
	}

	ctext.C1x = x1;
	ctext.C1y = y1;
	ctext.C3 = ASN1_OCTET_STRING_new();
	if (ctext.C3 == NULL) {
		ret = UADK_P_FAIL;
		goto free_y1;
	}

	ret = ASN1_OCTET_STRING_set(ctext.C3, (void *)c3->data, c3->dsize);
	if (ret == 0)
		goto free_c3;

	ctext.C2 = ASN1_OCTET_STRING_new();
	if (ctext.C2 == NULL) {
		ret = UADK_P_FAIL;
		goto free_c3;
	}

	ret = ASN1_OCTET_STRING_set(ctext.C2, (void *)c2->data, c2->dsize);
	if (ret == 0)
		goto free_c2;

	ctext_leni = i2d_SM2_Ciphertext(&ctext, &ber);
	/* Ensure cast to size_t is safe */
	if (ctext_leni < 0) {
		ret = UADK_P_FAIL;
		goto free_c2;
	}
	*ber_len = (size_t)ctext_leni;
	ret = UADK_P_SUCCESS;

free_c2:
	ASN1_OCTET_STRING_free(ctext.C2);
free_c3:
	ASN1_OCTET_STRING_free(ctext.C3);
free_y1:
	BN_free(y1);
free_x1:
	BN_free(x1);

	return ret;
}

static int uadk_prov_sm2_encrypt_sw(PROV_SM2_ASYM_CTX *vpsm2ctx,
				    unsigned char *out, size_t *outlen,
				    const unsigned char *in, size_t inlen)
{
	if (uadk_get_sw_offload_state() && get_default_sm2_asym_cipher().encrypt) {
		UADK_INFO("switch to software sm2 encrypt\n");
		return get_default_sm2_asym_cipher().encrypt(vpsm2ctx, out, outlen, 0, in, inlen);
	}

	return UADK_P_FAIL;
}

static int uadk_prov_sm2_encrypt(PROV_SM2_ASYM_CTX *vpsm2ctx,
				 unsigned char *out, size_t *outlen,
				 const unsigned char *in, size_t inlen)
{
	SM2_PROV_CTX *smctx = vpsm2ctx->sm2_pctx;
	struct wd_ecc_point *c1 = NULL;
	struct wd_ecc_req req = {0};
	struct wd_dtb *c2 = NULL;
	struct wd_dtb *c3 = NULL;
	const EVP_MD *md;
	int md_size, ret;

	ret = uadk_prov_sm2_encrypt_init_iot(smctx->sess, &req, (void *)in, inlen);
	if (ret == UADK_P_FAIL)
		goto do_soft;

	ret = uadk_prov_sm2_update_public_key(smctx, vpsm2ctx->key);
	if (ret == UADK_P_FAIL)
		goto uninit_iot;

	ret = uadk_prov_ecc_crypto(smctx->sess, &req, smctx);
	if (ret == UADK_P_FAIL) {
		UADK_ERR("failed to uadk_ecc_crypto, ret = %d\n", ret);
		goto uninit_iot;
	}

	wd_sm2_get_enc_out_params(req.dst, &c1, &c2, &c3);
	if (c1 == NULL || c2 == NULL || c3 == NULL) {
		ret = UADK_P_FAIL;
		goto uninit_iot;
	}

	ret = uadk_prov_sm2_asym_bin_to_ber(c1, c2, c3, out, outlen);
	if (ret == UADK_P_FAIL)
		goto uninit_iot;

	md = (smctx->sm2_md->md == NULL) ? EVP_sm3() : smctx->sm2_md->md;
	md_size = EVP_MD_size(md);
	if (c3->dsize != md_size) {
		UADK_ERR("invalid: c3 dsize(%u) != hash_size(%d)\n", c3->dsize, md_size);
		ret = UADK_P_FAIL;
		goto uninit_iot;
	}

	wd_ecc_del_in(smctx->sess, req.src);
	wd_ecc_del_out(smctx->sess, req.dst);

	return UADK_P_SUCCESS;

uninit_iot:
	wd_ecc_del_in(smctx->sess, req.src);
	wd_ecc_del_out(smctx->sess, req.dst);
do_soft:
	return uadk_prov_sm2_encrypt_sw(vpsm2ctx, out, outlen, in, inlen);
}

static size_t uadk_prov_ec_field_size(const EC_GROUP *group)
{
	BIGNUM *p = BN_new();
	BIGNUM *a = BN_new();
	BIGNUM *b = BN_new();
	size_t field_size = 0;
	size_t p_bits;

	if (p == NULL || a == NULL || b == NULL) {
		UADK_ERR("failed to new bignumber\n");
		goto done;
	}

	if (!EC_GROUP_get_curve(group, p, a, b, NULL)) {
		UADK_ERR("failed to get curve from group\n");
		goto done;
	}

	p_bits = BN_num_bits(p);
	field_size = BITS_TO_BYTES(p_bits);

done:
	BN_free(p);
	BN_free(a);
	BN_free(b);

	return field_size;
}

static int uadk_prov_sm2_ciphertext_size(const EC_KEY *key,
					 const EVP_MD *digest, size_t msg_len,
					 size_t *ct_size)
{
	const size_t field_size = uadk_prov_ec_field_size(EC_KEY_get0_group(key));
	const int md_size = EVP_MD_size(digest);
	size_t sz;

	if (field_size == 0)
		return UADK_P_FAIL;

	if (md_size < 0) {
		UADK_ERR("invalid md_size: %d\n", md_size);
		return UADK_P_FAIL;
	}

	/*
	 * Integer and string are simple type; set constructed = 0, means
	 * primitive and definite length encoding.
	 */
	sz = ECC_POINT_SIZE(ASN1_object_size(0, field_size + 1, V_ASN1_INTEGER)) +
	     ASN1_object_size(0, md_size, V_ASN1_OCTET_STRING) +
	     ASN1_object_size(0, msg_len, V_ASN1_OCTET_STRING);
	*ct_size = ASN1_object_size(1, sz, V_ASN1_SEQUENCE);

	return UADK_P_SUCCESS;
}

static int uadk_asym_cipher_sm2_encrypt(void *vpsm2ctx, unsigned char *out, size_t *outlen,
					size_t outsize, const unsigned char *in,
					size_t inlen)
{
	PROV_SM2_ASYM_CTX *psm2ctx = (PROV_SM2_ASYM_CTX *)vpsm2ctx;
	SM2_PROV_CTX *smctx;
	SM2_MD_DATA *smd;
	const EVP_MD *md;
	int ret;

	if (psm2ctx == NULL) {
		UADK_ERR("invalid: psm2ctx is NULL\n");
		return UADK_P_FAIL;
	}

	ret = uadk_prov_sm2_encrypt_check(psm2ctx, out, outlen, in, inlen);
	if (ret == UADK_P_FAIL)
		return uadk_prov_sm2_encrypt_sw(vpsm2ctx, out, outlen, in, inlen);

	/* If out is NULL, compute outlen size and return */
	if (out == NULL) {
		smctx = psm2ctx->sm2_pctx;
		smd = smctx->sm2_md;
		md = (const EVP_MD *)smd->md;
		if (!uadk_prov_sm2_ciphertext_size(psm2ctx->key, md, inlen, outlen))
			return UADK_P_FAIL;
		else
			return UADK_P_SUCCESS;
	}

	return uadk_prov_sm2_encrypt(psm2ctx, out, outlen, in, inlen);
}

static int uadk_asym_cipher_sm2_decrypt_init(void *vpsm2ctx, void *vkey,
					     const OSSL_PARAM params[])
{
	return uadk_asym_cipher_sm2_encrypt_init(vpsm2ctx, vkey, params);
}

static int uadk_prov_sm2_decrypt_check(SM2_PROV_CTX *smctx,
				       unsigned char *out, size_t *outlen,
				       const unsigned char *in, size_t inlen)
{
	const EVP_MD *md;
	int hash_size;

	if (smctx == NULL || smctx->sess == (handle_t)0) {
		UADK_ERR("smctx or sess NULL\n");
		return UADK_P_FAIL;
	}

	if (smctx->init_status != CTX_INIT_SUCC) {
		UADK_ERR("sm2 ctx init failed\n");
		return UADK_P_FAIL;
	}

	/*
	 * As we have already set md method in init, if not set, will use default digest.
	 * The md is unlikey to be NULL here, so if the md is still NULL when encrypt start,
	 * just return fail.
	 */
	md = smctx->sm2_md->md;
	if (md == NULL) {
		UADK_ERR("failed to get md method\n");
		return UADK_P_FAIL;
	}

	hash_size = EVP_MD_size(md);
	if (hash_size <= 0) {
		UADK_ERR("hash size = %d error\n", hash_size);
		return UADK_P_FAIL;
	}

	return UADK_P_SUCCESS;
}

static int uadk_prov_sm2_asym_ber_to_bin(const EVP_MD *md, struct sm2_ciphertext *ctext,
					 struct wd_ecc_point *c1, struct wd_dtb *c2,
					 struct wd_dtb *c3)
{
	int c1x_len, c1y_len, md_size;

	if (md == NULL) {
		UADK_ERR("invalid: md is NULL\n");
		return UADK_P_FAIL;
	}

	c1x_len = BN_num_bytes(ctext->C1x);
	c1y_len = BN_num_bytes(ctext->C1y);
	c1->x.data = malloc(c1x_len + c1y_len + ctext->C2->length + ctext->C3->length);
	if (c1->x.data == NULL)
		return UADK_P_FAIL;

	c1->y.data = c1->x.data + c1x_len;
	c3->data = c1->y.data + c1y_len;
	c2->data = c3->data + ctext->C3->length;
	memcpy(c2->data, ctext->C2->data, ctext->C2->length);
	memcpy(c3->data, ctext->C3->data, ctext->C3->length);
	c2->dsize = ctext->C2->length;
	c3->dsize = ctext->C3->length;
	md_size = EVP_MD_size(md);
	if (c3->dsize != md_size) {
		UADK_ERR("invalid: c3 dsize(%u) != hash_size(%d)\n", c3->dsize, md_size);
		free(c1->x.data);
		return UADK_P_FAIL;
	}

	c1->x.dsize = BN_bn2bin(ctext->C1x, (void *)c1->x.data);
	c1->y.dsize = BN_bn2bin(ctext->C1y, (void *)c1->y.data);

	return UADK_P_SUCCESS;
}

static int uadk_prov_sm2_decrypt_init_iot(handle_t sess, struct wd_ecc_req *req,
					  struct wd_ecc_point *c1,
					  struct wd_dtb *c2, struct wd_dtb *c3)
{
	struct wd_ecc_out *ecc_out;
	struct wd_ecc_in *ecc_in;

	ecc_out = wd_sm2_new_dec_out(sess, c2->dsize);
	if (ecc_out == NULL) {
		UADK_ERR("failed to new dec out\n");
		return UADK_P_FAIL;
	}

	ecc_in = wd_sm2_new_dec_in(sess, c1, c2, c3);
	if (ecc_in == NULL) {
		UADK_ERR("failed to new dec in\n");
		wd_ecc_del_out(sess, ecc_out);
		return UADK_P_FAIL;
	}

	uadk_prov_ecc_fill_req(req, WD_SM2_DECRYPT, ecc_in, ecc_out);

	return UADK_P_SUCCESS;
}

static int uadk_prov_sm2_get_plaintext(struct wd_ecc_req *req,
				       unsigned char *out, size_t *outlen)
{
	struct wd_dtb *ptext = NULL;

	wd_sm2_get_dec_out_params(req->dst, &ptext);
	if (ptext == NULL) {
		UADK_ERR("failed to get ptext\n");
		return UADK_P_FAIL;
	}

	if (*outlen < ptext->dsize) {
		UADK_ERR("outlen(%zu) < (%u)\n", *outlen, ptext->dsize);
		return UADK_P_FAIL;
	}

	memcpy(out, ptext->data, ptext->dsize);
	*outlen = ptext->dsize;

	return UADK_P_SUCCESS;
}

static int uadk_prov_sm2_decrypt_sw(PROV_SM2_ASYM_CTX *ctx,
				    unsigned char *out, size_t *outlen,
				    const unsigned char *in, size_t inlen)
{
	if (uadk_get_sw_offload_state() && get_default_sm2_asym_cipher().decrypt) {
		UADK_INFO("switch to software sm2 decrypt\n");
		return get_default_sm2_asym_cipher().decrypt(ctx, out, outlen, 0, in, inlen);
	}

	return UADK_P_FAIL;
}

static int uadk_prov_sm2_decrypt(PROV_SM2_ASYM_CTX *ctx,
				 unsigned char *out, size_t *outlen,
				 const unsigned char *in, size_t inlen)
{
	const unsigned char *original_in = in;
	SM2_PROV_CTX *smctx = ctx->sm2_pctx;
	struct sm2_ciphertext *ctext;
	struct wd_ecc_req req = {0};
	struct wd_ecc_point c1;
	struct wd_dtb c2, c3;
	const EVP_MD *md;
	int ret;

	ret = uadk_prov_sm2_decrypt_check(smctx, out, outlen, in, inlen);
	if (ret == UADK_P_FAIL)
		goto do_soft;

	ctext = d2i_SM2_Ciphertext(NULL, &in, inlen);
	if (ctext == NULL)
		goto do_soft;

	md = (smctx->sm2_md->md == NULL) ? EVP_sm3() : smctx->sm2_md->md;
	ret = uadk_prov_sm2_asym_ber_to_bin(md, ctext, &c1, &c2, &c3);
	if (ret == UADK_P_FAIL)
		goto free_ctext;

	ret = uadk_prov_sm2_decrypt_init_iot(smctx->sess, &req, &c1, &c2, &c3);
	if (ret == UADK_P_FAIL)
		goto free_c1;

	ret = uadk_prov_sm2_update_private_key(smctx, ctx->key);
	if (ret == UADK_P_FAIL)
		goto uninit_iot;

	ret = uadk_prov_ecc_crypto(smctx->sess, &req, smctx);
	if (ret == UADK_P_FAIL) {
		UADK_ERR("failed to uadk_ecc_crypto, ret = %d\n", ret);
		goto uninit_iot;
	}

	ret = uadk_prov_sm2_get_plaintext(&req, out, outlen);
	if (ret == UADK_P_FAIL)
		goto uninit_iot;

	wd_ecc_del_in(smctx->sess, req.src);
	wd_ecc_del_out(smctx->sess, req.dst);
	free(c1.x.data);
	SM2_Ciphertext_free(ctext);

	return UADK_P_SUCCESS;

uninit_iot:
	wd_ecc_del_in(smctx->sess, req.src);
	wd_ecc_del_out(smctx->sess, req.dst);
free_c1:
	free(c1.x.data);
free_ctext:
	SM2_Ciphertext_free(ctext);
do_soft:
	return uadk_prov_sm2_decrypt_sw(ctx, out, outlen, original_in, inlen);
}

static int uadk_prov_sm2_plaintext_size(const unsigned char *ct, size_t ct_size, size_t *pt_size)
{
	struct sm2_ciphertext *sm2_ctext;

	sm2_ctext = d2i_SM2_Ciphertext(NULL, &ct, ct_size);
	if (sm2_ctext == NULL) {
		UADK_ERR("invalid sm2 encoding\n");
		return UADK_P_FAIL;
	}

	*pt_size = sm2_ctext->C2->length;
	SM2_Ciphertext_free(sm2_ctext);

	return UADK_P_SUCCESS;
}

static int uadk_asym_cipher_sm2_decrypt(void *vpsm2ctx, unsigned char *out, size_t *outlen,
					size_t outsize, const unsigned char *in,
					size_t inlen)
{
	PROV_SM2_ASYM_CTX *psm2ctx = (PROV_SM2_ASYM_CTX *)vpsm2ctx;
	SM2_PROV_CTX *smctx;
	int ret;

	if (psm2ctx == NULL) {
		UADK_ERR("invalid: psm2ctx is NULL\n");
		return UADK_P_FAIL;
	}

	smctx = psm2ctx->sm2_pctx;
	ret = uadk_prov_sm2_decrypt_check(smctx, out, outlen, in, inlen);
	if (ret == UADK_P_FAIL)
		return uadk_prov_sm2_decrypt_sw(vpsm2ctx, out, outlen, in, inlen);

	if (out == NULL) {
		if (!uadk_prov_sm2_plaintext_size(in, inlen, outlen))
			return UADK_P_FAIL;
		else
			return UADK_P_SUCCESS;
	}

	return uadk_prov_sm2_decrypt(psm2ctx, out, outlen, in, inlen);
}

static int ossl_prov_digest_copy(struct PROV_DIGEST *dst, const struct PROV_DIGEST *src)
{
	if (src->alloc_md != NULL && !EVP_MD_up_ref(src->alloc_md))
		return UADK_P_FAIL;

#if !defined(FIPS_MODULE) && !defined(OPENSSL_NO_ENGINE)
	if (src->engine != NULL && !ENGINE_init(src->engine)) {
		EVP_MD_free(src->alloc_md);
		return UADK_P_FAIL;
	}
#endif
	dst->engine = src->engine;
	dst->md = src->md;
	dst->alloc_md = src->alloc_md;

	return UADK_P_SUCCESS;
}

static void *uadk_asym_cipher_sm2_dupctx(void *vpsm2ctx)
{
	PROV_SM2_ASYM_CTX *srcctx = (PROV_SM2_ASYM_CTX *)vpsm2ctx;
	PROV_SM2_ASYM_CTX *dstctx;
	int ret;

	if (srcctx == NULL) {
		UADK_ERR("src ctx is NULL\n");
		return NULL;
	}

	dstctx = OPENSSL_zalloc(sizeof(PROV_SM2_ASYM_CTX));
	if (dstctx == NULL) {
		UADK_ERR("failed to alloc dst ctx\n");
		return NULL;
	}
	*dstctx = *srcctx;
	dstctx->key = NULL;
	dstctx->sm2_pctx = NULL;
	memset(&dstctx->md, 0, sizeof(dstctx->md));

	ret = ossl_prov_digest_copy(&dstctx->md, &srcctx->md);
	if (!ret)
		goto free_ctx;

	if (srcctx->key != NULL && !EC_KEY_up_ref(srcctx->key)) {
		UADK_ERR("failed to check dstctx key reference\n");
		goto free_ctx;
	}
	dstctx->key = srcctx->key;

	dstctx->sm2_pctx = sm2_copy_src_smctx(srcctx->sm2_pctx);
	if (dstctx->sm2_pctx == NULL)
		goto free_ctx;

	return dstctx;

free_ctx:
	uadk_asym_cipher_sm2_freectx(dstctx);
	return NULL;
}

static int uadk_asym_cipher_sm2_get_ctx_params(void *vpsm2ctx, OSSL_PARAM *params)
{
	PROV_SM2_ASYM_CTX *psm2ctx = (PROV_SM2_ASYM_CTX *)vpsm2ctx;
	SM2_PROV_CTX *smctx;
	SM2_MD_DATA *smd;
	OSSL_PARAM *p;
	EVP_MD *md;

	if (psm2ctx == NULL) {
		UADK_ERR("failed to get psm2ctx\n");
		return UADK_P_FAIL;
	}

	smctx = psm2ctx->sm2_pctx;
	if (smctx == NULL) {
		UADK_ERR("failed to get smctx\n");
		return UADK_P_FAIL;
	}

	smd = smctx->sm2_md;
	if (smd == NULL) {
		UADK_ERR("failed to get sm2 md\n");
		return UADK_P_FAIL;
	}

	if (params == NULL) {
		UADK_ERR("params is NULL\n");
		return UADK_P_FAIL;
	}

	p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_DIGEST);
	if (p != NULL) {
		md = smd->md;
		if (!OSSL_PARAM_set_utf8_string(p, md == NULL ? "" : EVP_MD_get0_name(md))) {
			UADK_ERR("failed to set utf8 string\n");
			return UADK_P_FAIL;
		}
		smd->md_nid = EVP_MD_type(md);
	} else {
		return UADK_P_FAIL;
	}

	return UADK_P_SUCCESS;
}

static EVP_MD *uadk_prov_load_digest_from_params(SM2_MD_DATA *smd, const OSSL_PARAM params[],
						 OSSL_LIB_CTX *ctx)
{
	const char *propquery = NULL;
	const OSSL_PARAM *p;

	/* Load common param properties, p can be NULL */
	p = OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_PROPERTIES);
	if (p) {
		if (p->data_type != OSSL_PARAM_UTF8_STRING) {
			UADK_ERR("data_type != OSSL_PARAM_UTF8_STRING\n");
			return NULL;
		}
		propquery = p->data;
	}

	/* Load digest related params */
	p = OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_DIGEST);
	if (p) {
		if (p->data_type != OSSL_PARAM_UTF8_STRING) {
			UADK_ERR("data_type != OSSL_PARAM_UTF8_STRING\n");
			return NULL;
		}
	} else {
		/* If digest related params is NULL, no need to set digest */
		return NULL;
	}

	/* Fetch digest */
	EVP_MD_free(smd->alloc_md);
	smd->md = smd->alloc_md = EVP_MD_fetch(ctx, p->data, propquery);
	if (smd->md == NULL) {
		UADK_ERR("failed to fetch MD method\n");
		return NULL;
	}

	return smd->md;
}

static int uadk_asym_cipher_sm2_set_ctx_params_sw(void *vpsm2ctx, const OSSL_PARAM params[])
{
	if (uadk_get_sw_offload_state() && get_default_sm2_asym_cipher().set_ctx_params) {
		UADK_INFO("switch to software sm2 set ctx params\n");
		return get_default_sm2_asym_cipher().set_ctx_params(vpsm2ctx, params);
	}

	return UADK_P_FAIL;
}

static int uadk_asym_cipher_sm2_set_ctx_params(void *vpsm2ctx, const OSSL_PARAM params[])
{
	PROV_SM2_ASYM_CTX *psm2ctx = (PROV_SM2_ASYM_CTX *)vpsm2ctx;
	SM2_PROV_CTX *smctx;
	SM2_MD_DATA *smd;
	int ret;

	if (psm2ctx == NULL) {
		UADK_ERR("invalid: sm2 ctx is NULL\n");
		return UADK_P_FAIL;
	}

	/* No need to set */
	if (params == NULL)
		return UADK_P_SUCCESS;

	smctx = psm2ctx->sm2_pctx;
	if (smctx == NULL) {
		UADK_ERR("invalid: smctx is NULL\n");
		return UADK_P_FAIL;
	}

	/* Set digest method */
	smd = smctx->sm2_md;
	if (smd == NULL) {
		UADK_ERR("invalid: sm2 md is NULL\n");
		return UADK_P_FAIL;
	}

	smd->md = uadk_prov_load_digest_from_params(smctx->sm2_md, params, psm2ctx->libctx);
	if (smd->md == NULL) {
		UADK_ERR("failed to set digest with set_ctx_params\n");
		return UADK_P_FAIL;
	}
	smd->md_nid = EVP_MD_type(smd->md);

	/* If not init, do not need to update session, just set the data before */
	if (smctx->init_status == CTX_INIT_SUCC) {
		ret = uadk_prov_sm2_update_sess(smctx);
		if (ret == UADK_P_FAIL) {
			UADK_ERR("failed to update sess\n");
			goto do_soft;
		}
	}

	return UADK_P_SUCCESS;

do_soft:
	return uadk_asym_cipher_sm2_set_ctx_params_sw(vpsm2ctx, params);
}

static const OSSL_PARAM *uadk_asym_cipher_sm2_gettable_ctx_params(ossl_unused void *vpsm2ctx,
								  ossl_unused void *provctx)
{
	return sm2_asym_cipher_known_gettable_ctx_params;
}

static const OSSL_PARAM *uadk_asym_cipher_sm2_settable_ctx_params(ossl_unused void *vpsm2ctx,
								  ossl_unused void *provctx)
{
	return sm2_asym_cipher_known_settable_ctx_params;
}
