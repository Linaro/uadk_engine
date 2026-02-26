// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2024 Huawei Technologies Co.,Ltd. All rights reserved.
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
#include <openssl/kdf.h>
#include <uadk/wd_ecc.h>
#include "uadk_async.h"
#include "uadk_prov.h"
#include "uadk_prov_der_writer.h"
#include "uadk_prov_pkey.h"
#include "uadk_utils.h"

#define UADK_PROV_MAX_PARAM_LEN		80

enum kdf_type {
	PROV_ECDH_KDF_NONE = 0,
	PROV_ECDH_KDF_X9_63
};

/*
 * What's passed as an actual key is defined by the KEYMGMT interface.
 * We happen to know that our KEYMGMT simply passes EC_KEY structures, so
 * we use that here too.
 */
struct ecdh_ctx {
	OSSL_LIB_CTX *libctx;

	EC_KEY *k;
	EC_KEY *peerk;

	/*
	 * ECDH cofactor mode:
	 *
	 * . 0  disabled
	 * . 1  enabled
	 * . -1 use cofactor mode set for k
	 */
	int cofactor_mode;
	/* KDF (if any) to use for ECDH */
	enum kdf_type kdf_type;
	/* Message digest to use for key derivation */
	EVP_MD *kdf_md;
	/* User key material */
	unsigned char *kdf_ukm;
	size_t kdf_ukmlen;
	/* KDF output length */
	size_t kdf_outlen;
};

struct ecdh_sess_ctx {
	EC_KEY *privk;
	const EC_POINT *pub_key;
	const BIGNUM *cofactor;
	const EC_GROUP *group;
};

UADK_PKEY_KEYEXCH_DESCR(ecdh, ECDH);
static UADK_PKEY_KEYEXCH s_keyexch;

static UADK_PKEY_KEYEXCH get_default_ecdh_keyexch(void)
{
	return s_keyexch;
}

void set_default_ecdh_keyexch(void)
{
	UADK_PKEY_KEYEXCH *keyexch;

	keyexch = (UADK_PKEY_KEYEXCH *)EVP_KEYEXCH_fetch(NULL, "ecdh", "provider=default");
	if (keyexch) {
		s_keyexch = *keyexch;
		EVP_KEYEXCH_free((EVP_KEYEXCH *)keyexch);
	} else {
		UADK_INFO("failed to EVP_KEYEXCH_fetch default ecdh provider\n");
	}
}

static size_t ecdh_get_ec_size(const EC_GROUP *group)
{
	size_t degree;

	degree = EC_GROUP_get_degree(group);

	return BITS_TO_BYTES(degree);
}

static int ecdh_param_check(struct ecdh_ctx *pecdhctx, struct ecdh_sess_ctx *sess_ctx)
{
	const EC_GROUP *group;
	int type;

	if (!pecdhctx->k || !pecdhctx->peerk) {
		UADK_ERR("invalid: k or peerk is NULL.\n");
		return UADK_P_FAIL;
	}

	sess_ctx->pub_key = EC_KEY_get0_public_key(pecdhctx->peerk);
	if (!sess_ctx->pub_key) {
		UADK_ERR("invalid: public key is NULL.\n");
		return UADK_P_FAIL;
	}

	group = EC_KEY_get0_group(pecdhctx->k);
	if (!group) {
		UADK_ERR("invalid: group is 0.\n");
		return UADK_P_FAIL;
	}

	sess_ctx->cofactor = EC_GROUP_get0_cofactor(group);
	if (!sess_ctx->cofactor) {
		UADK_ERR("invalid: cofactor is NULL!\n");
		return UADK_P_FAIL;
	}

	/* Field GF(2m) is not supported by uadk */
	type = EC_METHOD_get_field_type(EC_GROUP_method_of(group));
	if (type != NID_X9_62_prime_field) {
		UADK_ERR("invalid: uadk unsupport Field GF(2m)!\n");
		return UADK_DO_SOFT;
	}

	sess_ctx->group = group;

	if (uadk_prov_ecc_bit_check(group) != UADK_P_SUCCESS)
		return UADK_DO_SOFT;

	return UADK_P_SUCCESS;
}

static int ecdh_set_privk(struct ecdh_ctx *pecdhctx,
			  struct ecdh_sess_ctx *sess_ctx)
{
	int key_cofactor_mode;

	/*
	 * The ctx->cofactor_mode flag has precedence over the
	 * cofactor_mode flag set on ctx->k.
	 *
	 * - if ctx->cofactor_mode == -1, use ctx->k directly
	 * - if ctx->cofactor_mode == key_cofactor_mode, use ctx->k directly
	 * - if ctx->cofactor_mode != key_cofactor_mode:
	 *     - if ctx->k->cofactor == 1, the cofactor_mode flag is irrelevant, use
	 *          ctx->k directly
	 *     - if ctx->k->cofactor != 1, use a duplicate of ctx->k with the flag
	 *          set to ctx->cofactor_mode
	 */
	key_cofactor_mode = (EC_KEY_get_flags(pecdhctx->k) & EC_FLAG_COFACTOR_ECDH) ?
			    COFACTOR_MODE_ENABLED : COFACTOR_MODE_DISABLED;
	if (pecdhctx->cofactor_mode != COFACTOR_MODE_USE_KEY &&
	    pecdhctx->cofactor_mode != key_cofactor_mode &&
	    !BN_is_one(sess_ctx->cofactor)) {
		sess_ctx->privk = EC_KEY_dup(pecdhctx->k);
		if (!sess_ctx->privk)
			return UADK_P_FAIL;

		if (pecdhctx->cofactor_mode == COFACTOR_MODE_ENABLED)
			EC_KEY_set_flags(sess_ctx->privk, EC_FLAG_COFACTOR_ECDH);
		else
			EC_KEY_clear_flags(sess_ctx->privk, EC_FLAG_COFACTOR_ECDH);
	} else {
		sess_ctx->privk = pecdhctx->k;
	}

	return UADK_P_SUCCESS;
}

static handle_t ecdh_alloc_sess(EC_KEY *privk)
{
	int ret;

	ret = uadk_prov_keyexch_get_support_state(KEYEXCH_ECDH);
	if (!ret) {
		UADK_ERR("invalid: hardware not support ecdh!\n");
		return UADK_P_FAIL;
	}

	ret = uadk_prov_ecc_init("ecdh");
	if (!ret) {
		UADK_ERR("failed to init ecdh to compute key!\n");
		return UADK_P_FAIL;
	}

	return uadk_prov_ecc_alloc_sess(privk, "ecdh");
}

static void ecdh_free_sess(handle_t sess)
{
	wd_ecc_free_sess(sess);
}

static int ecdh_init_req(struct ecdh_sess_ctx *sess_ctx,
			 struct wd_ecc_req *req, handle_t sess)
{
	char buf_x[UADK_ECC_MAX_KEY_BYTES];
	char buf_y[UADK_ECC_MAX_KEY_BYTES];
	struct wd_ecc_point in_pkey;
	struct wd_ecc_out *ecdh_out;
	struct wd_ecc_in *ecdh_in;
	BIGNUM *pkey_x, *pkey_y;
	int ret = UADK_P_FAIL;
	BN_CTX *ctx;

	ctx = BN_CTX_new();
	if (!ctx)
		return -ENOMEM;

	BN_CTX_start(ctx);
	pkey_x = BN_CTX_get(ctx);
	if (!pkey_x)
		goto free_ctx;

	pkey_y = BN_CTX_get(ctx);
	if (!pkey_y)
		goto free_ctx;

	uadk_prov_get_affine_coordinates(sess_ctx->group, sess_ctx->pub_key, pkey_x, pkey_y, ctx);
	in_pkey.x.data = buf_x;
	in_pkey.y.data = buf_y;
	in_pkey.x.dsize = BN_bn2bin(pkey_x, (unsigned char *)in_pkey.x.data);
	in_pkey.y.dsize = BN_bn2bin(pkey_y, (unsigned char *)in_pkey.y.data);

	/* Set public key */
	ecdh_in = wd_ecxdh_new_in(sess, &in_pkey);
	if (!ecdh_in) {
		UADK_ERR("failed to new ecxdh in\n");
		goto free_ctx;
	}

	ecdh_out = wd_ecxdh_new_out(sess);
	if (!ecdh_out) {
		UADK_ERR("failed to new ecxdh out\n");
		wd_ecc_del_in(sess, ecdh_in);
		goto free_ctx;
	}

	uadk_prov_ecc_fill_req(req, WD_ECXDH_COMPUTE_KEY, ecdh_in, ecdh_out);

	ret = UADK_P_SUCCESS;

free_ctx:
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	return ret;
}

static void ecdh_uninit_req(struct wd_ecc_req *req, handle_t sess)
{
	wd_ecc_del_in(sess, req->src);
	wd_ecc_del_out(sess, req->dst);
}

static int ecdh_get_shared_key(unsigned char *secret,
			       size_t size, size_t *psecretlen,
			       struct wd_ecc_req *req)
{
	struct wd_ecc_point *shared_key = NULL;
	size_t len;

	wd_ecxdh_get_out_params(req->dst, &shared_key);
	if (!shared_key) {
		UADK_ERR("failed to get ecdh shared key\n");
		return UADK_P_FAIL;
	}

	len = size < shared_key->x.dsize ? size : shared_key->x.dsize;

	memset(secret, 0, size - len);
	memcpy(secret + size - len, (unsigned char *)shared_key->x.data, len);

	*psecretlen = size;

	return UADK_P_SUCCESS;
}

static int ecdh_compute_key(struct ecdh_sess_ctx *sess_ctx,
			    unsigned char *secret,
			    size_t *psecretlen, size_t size)
{
	struct wd_ecc_req req = {0};
	handle_t sess;
	int ret;

	sess = ecdh_alloc_sess(sess_ctx->privk);
	if (!sess) {
		UADK_ERR("failed to alloc sess to compute key!\n");
		return UADK_DO_SOFT;
	}

	ret = uadk_prov_ecc_set_private_key(sess, sess_ctx->privk);
	if (!ret) {
		UADK_ERR("failed to set private key!\n");
		goto free_sess;
	}

	ret = ecdh_init_req(sess_ctx, &req, sess);
	if (!ret) {
		UADK_ERR("failed to init req!\n");
		goto free_sess;
	}

	ret = uadk_prov_ecc_crypto(sess, &req, (void *)sess);
	if (ret != UADK_P_SUCCESS) {
		UADK_ERR("failed to calculate shared key!\n");
		ret = UADK_DO_SOFT;
		goto uninit_req;
	}

	ret = ecdh_get_shared_key(secret, size, psecretlen, &req);

uninit_req:
	ecdh_uninit_req(&req, sess);
free_sess:
	ecdh_free_sess(sess);
	return ret;
}

static int ecdh_plain_derive(struct ecdh_ctx *pecdhctx,
			     unsigned char *secret,
			     size_t *psecretlen, size_t outlen)
{
	struct ecdh_sess_ctx sess_ctx = {0};
	size_t size, ec_size;
	int ret;

	ret = ecdh_param_check(pecdhctx, &sess_ctx);
	if (ret != UADK_P_SUCCESS)
		return ret;

	ec_size = ecdh_get_ec_size(sess_ctx.group);
	if (!secret) {
		*psecretlen = ec_size;
		return UADK_P_SUCCESS;
	}

	ret = ecdh_set_privk(pecdhctx, &sess_ctx);
	if (!ret) {
		UADK_ERR("failed to set private key!\n");
		return ret;
	}

	size = outlen < ec_size ? outlen : ec_size;
	ret = ecdh_compute_key(&sess_ctx, secret, psecretlen, size);
	if (sess_ctx.privk != pecdhctx->k)
		EC_KEY_free(sess_ctx.privk);

	return ret;
}

/* Key derivation function from X9.63/SECG */
static int ecdh_kdf_X9_63(unsigned char *out, struct ecdh_ctx *pecdhctx,
			  unsigned char *stmp, size_t stmplen)
{
	OSSL_PARAM params[4], *p = params;
	int ret = UADK_P_FAIL;
	const char *mdname;
	EVP_KDF_CTX *kctx;
	EVP_KDF *kdf;

	kdf = EVP_KDF_fetch(pecdhctx->libctx, OSSL_KDF_NAME_X963KDF, NULL);
	if (!kdf) {
		UADK_ERR("failed to fetch kdf!\n");
		return ret;
	}

	mdname = EVP_MD_get0_name(pecdhctx->kdf_md);
	kctx = EVP_KDF_CTX_new(kdf);
	if (!kctx) {
		UADK_ERR("failed to new kctx!\n");
		goto free_kdf;
	}

	*p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char *)mdname, 0);
	*p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)stmp, stmplen);
	*p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
						(void *)pecdhctx->kdf_ukm, pecdhctx->kdf_ukmlen);
	*p = OSSL_PARAM_construct_end();

	ret = EVP_KDF_derive(kctx, out, pecdhctx->kdf_outlen, params);
	if (ret <= 0)
		ret = UADK_P_FAIL;
	else
		ret = UADK_P_SUCCESS;

	EVP_KDF_CTX_free(kctx);

free_kdf:
	EVP_KDF_free(kdf);

	return ret;
}

static int ecdh_X9_63_kdf_derive(struct ecdh_ctx *pecdhctx, unsigned char *secret,
				 size_t *psecretlen, size_t outlen)
{
	unsigned char *stmp;
	size_t stmplen = 0;
	int ret;

	if (!secret) {
		*psecretlen = pecdhctx->kdf_outlen;
		return UADK_P_SUCCESS;
	}

	if (outlen < pecdhctx->kdf_outlen) {
		UADK_ERR("invalid: outlen %zu is less than kdf_outlen %zu!\n",
			 outlen, pecdhctx->kdf_outlen);
		return UADK_P_FAIL;
	}

	ret = ecdh_plain_derive(pecdhctx, NULL, &stmplen, 0);
	if (ret != UADK_P_SUCCESS)
		return ret;

	stmp = OPENSSL_secure_malloc(stmplen);
	if (!stmp) {
		UADK_ERR("failed to alloc stmp!\n");
		return UADK_P_FAIL;
	}

	ret = ecdh_plain_derive(pecdhctx, stmp, &stmplen, stmplen);
	if (!ret)
		goto free_stmp;

	ret = ecdh_kdf_X9_63(secret, pecdhctx, stmp, stmplen);
	if (!ret)
		goto free_stmp;

	*psecretlen = pecdhctx->kdf_outlen;

 free_stmp:
	OPENSSL_secure_clear_free(stmp, stmplen);
	return ret;
}

static int uadk_ecdh_sw_derive(void *vpecdhctx, unsigned char *secret,
			       size_t *psecretlen, size_t outlen)
{
	if (!enable_sw_offload || !get_default_ecdh_keyexch().derive)
		return UADK_P_FAIL;

	UADK_INFO("switch to openssl software calculation in ecdh derivation.\n");

	return get_default_ecdh_keyexch().derive(vpecdhctx, secret, psecretlen, outlen);
}

static int uadk_keyexch_ecdh_derive(void *vpecdhctx, unsigned char *secret,
				    size_t *psecretlen, size_t outlen)
{
	struct ecdh_ctx *pecdhctx = vpecdhctx;
	int ret = UADK_P_FAIL;

	if (!pecdhctx) {
		UADK_ERR("invalid: vpecdhctx is NULL to derive!\n");
		return UADK_P_FAIL;
	}

	switch (pecdhctx->kdf_type) {
	case PROV_ECDH_KDF_NONE:
		ret = ecdh_plain_derive(pecdhctx, secret, psecretlen, outlen);
		break;
	case PROV_ECDH_KDF_X9_63:
		ret = ecdh_X9_63_kdf_derive(pecdhctx, secret, psecretlen, outlen);
		break;
	default:
		break;
	}

	if (ret == UADK_P_SUCCESS)
		return UADK_P_SUCCESS;
	if (ret == UADK_DO_SOFT)
		return uadk_ecdh_sw_derive(vpecdhctx, secret, psecretlen, outlen);

	return UADK_P_FAIL;
}

static void *uadk_keyexch_ecdh_newctx(void *provctx)
{
	struct ecdh_ctx *pectx;

	pectx = OPENSSL_zalloc(sizeof(*pectx));
	if (!pectx)
		return NULL;

	pectx->libctx = prov_libctx_of(provctx);
	pectx->cofactor_mode = COFACTOR_MODE_USE_KEY;
	pectx->kdf_type = PROV_ECDH_KDF_NONE;

	return pectx;
}

static void uadk_keyexch_ecdh_freectx(void *vpecdhctx)
{
	struct ecdh_ctx *pecdhctx = vpecdhctx;

	if (!pecdhctx)
		return;

	EC_KEY_free(pecdhctx->k);
	EC_KEY_free(pecdhctx->peerk);
	EVP_MD_free(pecdhctx->kdf_md);
	OPENSSL_clear_free(pecdhctx->kdf_ukm, pecdhctx->kdf_ukmlen);
	OPENSSL_free(pecdhctx);
}

static int uadk_keyexch_ecdh_init(void *vpecdhctx, void *vecdh, const OSSL_PARAM params[])
{
	struct ecdh_ctx *pecdhctx = vpecdhctx;
	int ret;

	if (!pecdhctx || !vecdh) {
		UADK_ERR("invalid: pecdhctx or vecdh is to init!\n");
		return UADK_P_FAIL;
	}

	if (!EC_KEY_up_ref(vecdh))
		return UADK_P_FAIL;

	EC_KEY_free(pecdhctx->k);
	pecdhctx->k = vecdh;
	pecdhctx->cofactor_mode = COFACTOR_MODE_USE_KEY;
	pecdhctx->kdf_type = PROV_ECDH_KDF_NONE;

	ret = uadk_keyexch_ecdh_set_ctx_params(pecdhctx, params);
	if (!ret) {
		UADK_ERR("failed to set_ctx_params!\n");
		return ret;
	}

	return uadk_prov_ecc_check_key(pecdhctx->libctx, vecdh, 1);
}

static int ecdh_match_params(const EC_KEY *privk, const EC_KEY *pubk)
{
	const EC_GROUP *group_privk = EC_KEY_get0_group(privk);
	const EC_GROUP *group_pubk = EC_KEY_get0_group(pubk);
	int ret = UADK_P_SUCCESS;
	BN_CTX *ctx;

	ctx = BN_CTX_new_ex(privk->libctx);
	if (!ctx) {
		UADK_ERR("failed to new ctx!\n");
		return UADK_P_FAIL;
	}

	if (group_privk && group_pubk) {
		if (EC_GROUP_cmp(group_privk, group_pubk, ctx)) {
			UADK_ERR("invalid: privk is not match pubk!\n");
			ret = UADK_P_FAIL;
		}
	}

	BN_CTX_free(ctx);

	return ret;
}

static int uadk_keyexch_ecdh_set_peer(void *vpecdhctx, void *vecdh)
{
	struct ecdh_ctx *pecdhctx = vpecdhctx;
	int ret;

	if (!pecdhctx || !vecdh) {
		UADK_ERR("invalid: vpecdhctx or vecdh is NULL to set_peer!\n");
		return UADK_P_FAIL;
	}

	ret = ecdh_match_params(pecdhctx->k, vecdh);
	if (!ret)
		return ret;

	ret = uadk_prov_ecc_check_key(pecdhctx->libctx, vecdh, 1);
	if (!ret)
		return ret;

	if (!EC_KEY_up_ref(vecdh))
		return UADK_P_FAIL;

	EC_KEY_free(pecdhctx->peerk);
	pecdhctx->peerk = vecdh;

	return UADK_P_SUCCESS;
}

static void *uadk_keyexch_ecdh_dupctx(void *vpecdhctx)
{
	struct ecdh_ctx *srcctx = vpecdhctx;
	struct ecdh_ctx *dstctx;

	if (!srcctx) {
		UADK_ERR("invalid: source ecdh ctx is NULL!\n");
		return NULL;
	}

	dstctx = OPENSSL_zalloc(sizeof(*srcctx));
	if (!dstctx) {
		UADK_ERR("failed to alloc dst ctx!\n");
		return NULL;
	}

	memcpy(dstctx, srcctx, sizeof(*dstctx));

	dstctx->k = NULL;
	dstctx->peerk = NULL;
	dstctx->kdf_md = NULL;
	dstctx->kdf_ukm = NULL;

	/* up-ref all ref-counted objects referenced in dstctx */
	if (srcctx->k && !EC_KEY_up_ref(srcctx->k))
		goto err;
	else
		dstctx->k = srcctx->k;

	if (srcctx->peerk && !EC_KEY_up_ref(srcctx->peerk))
		goto err;
	else
		dstctx->peerk = srcctx->peerk;

	if (srcctx->kdf_md && !EVP_MD_up_ref(srcctx->kdf_md))
		goto err;
	else
		dstctx->kdf_md = srcctx->kdf_md;

	/* Duplicate UKM data if present */
	if (srcctx->kdf_ukm && srcctx->kdf_ukmlen > 0) {
		dstctx->kdf_ukm = OPENSSL_memdup(srcctx->kdf_ukm,
						 srcctx->kdf_ukmlen);
		if (!dstctx->kdf_ukm)
			goto err;
	}

	return dstctx;

err:
	uadk_keyexch_ecdh_freectx(dstctx);
	return NULL;
}

static int ecdh_set_cofactor_mode(struct ecdh_ctx *pectx, const OSSL_PARAM params[])
{
	const OSSL_PARAM *p;
	int mode, ret;

	p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE);
	if (!p)
		return UADK_P_SUCCESS;

	ret = OSSL_PARAM_get_int(p, &mode);
	if (!ret)
		return UADK_P_FAIL;

	if (mode < COFACTOR_MODE_USE_KEY || mode > COFACTOR_MODE_ENABLED)
		return UADK_P_FAIL;

	pectx->cofactor_mode = mode;

	return UADK_P_SUCCESS;
}

static int ecdh_get_cofactor_mode(struct ecdh_ctx *pectx, OSSL_PARAM params[])
{
	int mode = pectx->cofactor_mode;
	OSSL_PARAM *p;

	p = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE);
	if (!p)
		return UADK_P_SUCCESS;

	if (mode == COFACTOR_MODE_USE_KEY)
		/* Check what is the default for pecdhctx->k */
		mode = (EC_KEY_get_flags(pectx->k) & EC_FLAG_COFACTOR_ECDH) ?
		       COFACTOR_MODE_ENABLED : COFACTOR_MODE_DISABLED;

	return OSSL_PARAM_set_int(p, mode);
}

static int ecdh_set_kdf_type(struct ecdh_ctx *pectx, const OSSL_PARAM params[])
{
	char name[UADK_PROV_MAX_PARAM_LEN] = {'\0'};
	const OSSL_PARAM *p;
	char *str = name;
	int ret;

	p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_TYPE);
	if (!p)
		return UADK_P_SUCCESS;

	ret = OSSL_PARAM_get_utf8_string(p, &str, sizeof(name));
	if (!ret)
		return UADK_P_FAIL;

	if (name[0] == '\0')
		pectx->kdf_type = PROV_ECDH_KDF_NONE;
	else if (!strcmp(name, OSSL_KDF_NAME_X963KDF))
		pectx->kdf_type = PROV_ECDH_KDF_X9_63;
	else
		return UADK_P_FAIL;

	return UADK_P_SUCCESS;
}

static int ecdh_get_kdf_type(struct ecdh_ctx *pectx, OSSL_PARAM params[])
{
	const char *kdf_type;
	OSSL_PARAM *p;

	p = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_KDF_TYPE);
	if (!p)
		return UADK_P_SUCCESS;

	switch (pectx->kdf_type) {
	case PROV_ECDH_KDF_NONE:
		kdf_type = "";
		break;
	case PROV_ECDH_KDF_X9_63:
		kdf_type = OSSL_KDF_NAME_X963KDF;
		break;
	default:
		return UADK_P_FAIL;
	}

	return OSSL_PARAM_set_utf8_string(p, kdf_type);
}

static int ecdh_set_kdf_digest(struct ecdh_ctx *pectx, const OSSL_PARAM params[])
{
	char mdprops[UADK_PROV_MAX_PARAM_LEN] = {'\0'};
	char name[UADK_PROV_MAX_PARAM_LEN] = {'\0'};
	const OSSL_PARAM *p;
	char *str = name;
	int ret;

	p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_DIGEST);
	if (!p)
		return UADK_P_SUCCESS;

	ret = OSSL_PARAM_get_utf8_string(p, &str, sizeof(name));
	if (!ret)
		return UADK_P_FAIL;

	p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS);
	if (p) {
		str = mdprops;
		ret = OSSL_PARAM_get_utf8_string(p, &str, sizeof(mdprops));
		if (!ret)
			return UADK_P_FAIL;
	}

	EVP_MD_free(pectx->kdf_md);
	pectx->kdf_md = EVP_MD_fetch(pectx->libctx, name, mdprops);
	if (!pectx->kdf_md)
		return UADK_P_FAIL;

	return UADK_P_SUCCESS;
}

static int ecdh_get_kdf_digest(struct ecdh_ctx *pectx, OSSL_PARAM params[])
{
	OSSL_PARAM *p;

	p = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_KDF_DIGEST);
	if (!p)
		return UADK_P_SUCCESS;

	if (!pectx->kdf_md)
		return OSSL_PARAM_set_utf8_string(p, "");

	return OSSL_PARAM_set_utf8_string(p, EVP_MD_get0_name(pectx->kdf_md));
}

static int ecdh_set_kdf_outlen(struct ecdh_ctx *pectx, const OSSL_PARAM params[])
{
	const OSSL_PARAM *p;

	p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_OUTLEN);
	if (!p)
		return UADK_P_SUCCESS;

	return OSSL_PARAM_get_size_t(p, &pectx->kdf_outlen);
}

static int ecdh_get_kdf_outlen(struct ecdh_ctx *pectx, OSSL_PARAM params[])
{
	OSSL_PARAM *p;

	p = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_KDF_OUTLEN);
	if (!p)
		return UADK_P_SUCCESS;

	return OSSL_PARAM_set_size_t(p, pectx->kdf_outlen);
}

static int ecdh_set_kdf_ukm(struct ecdh_ctx *pectx, const OSSL_PARAM params[])
{
	const OSSL_PARAM *p;
	void *tmp_ukm = NULL;
	size_t tmp_ukmlen;
	int ret;

	p = OSSL_PARAM_locate_const(params, OSSL_EXCHANGE_PARAM_KDF_UKM);
	if (!p)
		return UADK_P_SUCCESS;

	ret = OSSL_PARAM_get_octet_string(p, &tmp_ukm, 0, &tmp_ukmlen);
	if (!ret)
		return ret;

	OPENSSL_free(pectx->kdf_ukm);
	pectx->kdf_ukm = tmp_ukm;
	pectx->kdf_ukmlen = tmp_ukmlen;

	return UADK_P_SUCCESS;
}

static int ecdh_get_kdf_ukm(struct ecdh_ctx *pectx, OSSL_PARAM params[])
{
	OSSL_PARAM *p;

	p = OSSL_PARAM_locate(params, OSSL_EXCHANGE_PARAM_KDF_UKM);
	if (!p)
		return UADK_P_SUCCESS;

	return OSSL_PARAM_set_octet_ptr(p, pectx->kdf_ukm, pectx->kdf_ukmlen);
}

static int uadk_keyexch_ecdh_set_ctx_params(void *vpecdhctx, const OSSL_PARAM params[])
{
	struct ecdh_ctx *pectx = (struct ecdh_ctx *)vpecdhctx;
	int ret;

	if (!pectx) {
		UADK_ERR("invalid: pectx is NULL to set_ctx_params!\n");
		return UADK_P_FAIL;
	}

	if (!params)
		return UADK_P_SUCCESS;

	ret = ecdh_set_cofactor_mode(pectx, params);
	if (!ret)
		return ret;

	ret = ecdh_set_kdf_type(pectx, params);
	if (!ret)
		return ret;

	ret = ecdh_set_kdf_digest(pectx, params);
	if (!ret)
		return ret;

	ret = ecdh_set_kdf_outlen(pectx, params);
	if (!ret)
		return ret;

	return ecdh_set_kdf_ukm(pectx, params);
}

static int uadk_keyexch_ecdh_get_ctx_params(void *vpecdhctx, OSSL_PARAM params[])
{
	struct ecdh_ctx *pectx = vpecdhctx;
	int ret;

	if (!pectx) {
		UADK_ERR("invalid: pectx is NULL to get_ctx_params!\n");
		return UADK_P_FAIL;
	}

	ret = ecdh_get_cofactor_mode(pectx, params);
	if (!ret)
		return ret;

	ret = ecdh_get_kdf_type(pectx, params);
	if (!ret)
		return ret;

	ret = ecdh_get_kdf_digest(pectx, params);
	if (!ret)
		return ret;

	ret = ecdh_get_kdf_outlen(pectx, params);
	if (!ret)
		return ret;

	return ecdh_get_kdf_ukm(pectx, params);
}

static const OSSL_PARAM *uadk_keyexch_ecdh_settable_ctx_params(ossl_unused void *vpecdhctx,
							       ossl_unused void *provctx)
{
	static const OSSL_PARAM known_settable_ctx_params[] = {
		OSSL_PARAM_int(OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE, NULL),
		OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE, NULL, 0),
		OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST, NULL, 0),
		OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS, NULL, 0),
		OSSL_PARAM_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN, NULL),
		OSSL_PARAM_octet_string(OSSL_EXCHANGE_PARAM_KDF_UKM, NULL, 0),
		OSSL_PARAM_END
	};

	return known_settable_ctx_params;
}

static const OSSL_PARAM *uadk_keyexch_ecdh_gettable_ctx_params(ossl_unused void *vpecdhctx,
							       ossl_unused void *provctx)
{
	static const OSSL_PARAM known_gettable_ctx_params[] = {
		OSSL_PARAM_int(OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE, NULL),
		OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE, NULL, 0),
		OSSL_PARAM_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST, NULL, 0),
		OSSL_PARAM_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN, NULL),
		OSSL_PARAM_DEFN(OSSL_EXCHANGE_PARAM_KDF_UKM, OSSL_PARAM_OCTET_PTR,
				NULL, 0),
		OSSL_PARAM_END
	};

	return known_gettable_ctx_params;
}
