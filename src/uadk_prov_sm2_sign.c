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
#include "uadk_prov_pkey.h"
#include "uadk_utils.h"

#define SM2_GET_SIGNLEN		1
#define SM2_DEFAULT_USERID	"1234567812345678"
#define SM2_DEFAULT_USERID_LEN	16
#define SM3_DIGEST_LENGTH	32

UADK_PKEY_SIGNATURE_DESCR(sm2, SM2);

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
} PROV_SM2_SIGN_CTX;

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

static UADK_PKEY_SIGNATURE s_signature;

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
	PROV_SM2_SIGN_CTX *psm2ctx;

	psm2ctx = OPENSSL_zalloc(sizeof(PROV_SM2_SIGN_CTX));
	if (!psm2ctx) {
		UADK_ERR("failed to alloc sm2 signature ctx\n");
		return NULL;
	}

	if (propq) {
		psm2ctx->propq = OPENSSL_strdup(propq);
		if (!psm2ctx->propq) {
			UADK_ERR("failed to dup propq\n");
			OPENSSL_free(psm2ctx);
			return NULL;
		}
	}

	/*
	 * Use SM3 for digest method in default, other digest algs
	 * can be set with set_ctx_params API.
	 */
	psm2ctx->mdsize = SM3_DIGEST_LENGTH;
	strcpy(psm2ctx->mdname, OSSL_DIGEST_NAME_SM3);

	/* The libctx maybe NULL, if libctx is NULL, will use default ctx. */
	psm2ctx->libctx = prov_libctx_of(provctx);

	return psm2ctx;
}

static void uadk_signature_sm2_freectx(void *vpsm2ctx)
{
	PROV_SM2_SIGN_CTX *psm2ctx = (PROV_SM2_SIGN_CTX *)vpsm2ctx;

	if (!psm2ctx)
		return;

	EVP_MD_CTX_free(psm2ctx->mdctx);
	EVP_MD_free(psm2ctx->md);
	OPENSSL_free(psm2ctx->propq);
	EC_KEY_free(psm2ctx->key);
	OPENSSL_free(psm2ctx->id);
	OPENSSL_free(psm2ctx);
}

static int sm2_sig_set_mdname(PROV_SM2_SIGN_CTX *psm2ctx, const char *mdname)
{
	if (!psm2ctx->md) {
		psm2ctx->md = EVP_MD_fetch(psm2ctx->libctx,
					   psm2ctx->mdname, psm2ctx->propq);
		if (!psm2ctx->md) {
			UADK_ERR("failed to fetch digest method\n");
			return UADK_P_FAIL;
		}
	}

	/* If mdname is NULL, no need to set, just return */
	if (!mdname)
		return UADK_P_SUCCESS;

	/* psm2ctx->md is free in freectx */
	if (strlen(mdname) >= sizeof(psm2ctx->mdname) ||
	    !EVP_MD_is_a(psm2ctx->md, mdname)) {
		UADK_ERR("failed to check mdname, digest=%s\n", mdname);
		return UADK_P_FAIL;
	}

	OPENSSL_strlcpy(psm2ctx->mdname, mdname, sizeof(psm2ctx->mdname));

	return UADK_P_SUCCESS;
}

static handle_t sm2_alloc_sess(const EC_KEY *key)
{
	const EC_GROUP *group = EC_KEY_get0_group(key);
	const BIGNUM *order = EC_GROUP_get0_order(group);
	struct wd_ecc_sess_setup setup = {0};
	struct sched_params params = {0};
	handle_t sess;

	setup.alg = "sm2";
	setup.rand.cb = uadk_prov_ecc_get_rand;
	setup.rand.usr = (void *)order;
	if (!setup.rand.usr) {
		UADK_ERR("failed to BN_bin2bn order\n");
		return (handle_t)0;
	}

	/* Use the default numa parameters */
	params.numa_id = -1;
	setup.sched_param = &params;
	sess = wd_ecc_alloc_sess(&setup);
	if (sess == (handle_t)0)
		UADK_ERR("failed to alloc sess\n");

	return sess;
}

static void sm2_free_sess(handle_t sess)
{
	wd_ecc_free_sess(sess);
}

static int sm2_locate_id_digest(PROV_SM2_SIGN_CTX *psm2ctx, const OSSL_PARAM params[])
{
	size_t tmp_idlen = 0;
	const OSSL_PARAM *p;
	void *tmp_id = NULL;
	char *mdname = NULL;
	size_t mdsize;

	p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_DIST_ID);
	if (p) {
		if (!psm2ctx->flag_compute_z_digest) {
			UADK_ERR("invalid: should set ID param before z digest\n");
			return UADK_P_FAIL;
		}

		if (p->data_size &&
		    !OSSL_PARAM_get_octet_string(p, &tmp_id, 0, &tmp_idlen)) {
			UADK_ERR("failed to get sm2 sign id and len\n");
			return UADK_P_FAIL;
		}

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
	if (p && (!OSSL_PARAM_get_size_t(p, &mdsize) || mdsize != psm2ctx->mdsize)) {
		UADK_ERR("failed to locate digest size\n");
		return UADK_P_FAIL;
	}

	p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
	if (p) {
		if (!OSSL_PARAM_get_utf8_string(p, &mdname, 0)) {
			UADK_ERR("failed to get sm2 sign mdname\n");
			return UADK_P_FAIL;
		}

		if (!sm2_sig_set_mdname(psm2ctx, mdname)) {
			OPENSSL_free(mdname);
			UADK_ERR("failed to set sm2 mdname\n");
			return UADK_P_FAIL;
		}

		OPENSSL_free(mdname);
	}

	return UADK_P_SUCCESS;
}

static int uadk_signature_sm2_set_ctx_params(void *vpsm2ctx, const OSSL_PARAM params[])
{
	PROV_SM2_SIGN_CTX *psm2ctx = (PROV_SM2_SIGN_CTX *)vpsm2ctx;

	/*
	 * 'set_ctx_param' function can be called independently,
	 * so check 'psm2ctx' again here.
	 */
	if (!psm2ctx) {
		UADK_ERR("invalid: sm2 ctx is NULL for set_ctx_params\n");
		return UADK_P_FAIL;
	}

	/* If params is NULL, no need to set ctx params, just return */
	if (!params)
		return UADK_P_SUCCESS;

	return sm2_locate_id_digest(psm2ctx, params);
}

static int sm2_signverify_init(void *vpsm2ctx, void *ec, const OSSL_PARAM params[])
{
	PROV_SM2_SIGN_CTX *psm2ctx = (PROV_SM2_SIGN_CTX *)vpsm2ctx;

	if (!psm2ctx) {
		UADK_ERR("invalid: vpsm2ctx is NULL\n");
		return UADK_P_FAIL;
	}

	if (!ec && !psm2ctx->key) {
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

	return uadk_signature_sm2_set_ctx_params(vpsm2ctx, params);
}

static int uadk_signature_sm2_sign_init(void *vpsm2ctx, void *ec,
					const OSSL_PARAM params[])
{
	return sm2_signverify_init(vpsm2ctx, ec, params);
}

static int uadk_signature_sm2_verify_init(void *vpsm2ctx, void *ec,
					  const OSSL_PARAM params[])
{
	return sm2_signverify_init(vpsm2ctx, ec, params);
}

static int sm2_check_tbs_params(PROV_SM2_SIGN_CTX *psm2ctx,
				const unsigned char *tbs, size_t tbslen)
{
	if (psm2ctx->mdsize && tbslen != psm2ctx->mdsize) {
		UADK_ERR("invalid: tbslen(%zu) != mdsize(%zu)\n",
			 tbslen, psm2ctx->mdsize);
		return UADK_P_FAIL;
	}

	if (uadk_prov_is_all_zero(tbs, tbslen)) {
		UADK_ERR("invalid: tbs all zero\n");
		return UADK_P_FAIL;
	}

	return UADK_P_SUCCESS;
}

static int sm2_sign_init_iot(handle_t sess, struct wd_ecc_req *req,
			     void *digest, size_t digest_len)
{
	struct wd_ecc_out *ecc_out;
	struct wd_ecc_in *ecc_in;
	struct wd_dtb e = {0};

	ecc_out = wd_sm2_new_sign_out(sess);
	if (!ecc_out) {
		UADK_ERR("failed to new sign out\n");
		return UADK_P_FAIL;
	}

	e.data = digest;
	e.dsize = digest_len;
	e.bsize = digest_len;
	ecc_in = wd_sm2_new_sign_in(sess, &e, NULL, NULL, 1);
	if (!ecc_in) {
		UADK_ERR("failed to new sign in\n");
		wd_ecc_del_out(sess, ecc_out);
		return UADK_P_FAIL;
	}

	uadk_prov_ecc_fill_req(req, WD_SM2_SIGN, ecc_in, ecc_out);

	return UADK_P_SUCCESS;
}

static void sm2_sign_uninit_iot(handle_t sess, struct wd_ecc_req *req)
{
	wd_ecc_del_in(sess, req->src);
	wd_ecc_del_out(sess, req->dst);
}

static int sm2_sign_bin_to_ber(struct wd_ecc_req *req,
			       unsigned char *sig, size_t *siglen)
{
	struct wd_dtb *r = NULL;
	struct wd_dtb *s = NULL;
	BIGNUM *bn_r, *bn_s;
	ECDSA_SIG *e_sig;
	int sltmp, ret;

	wd_sm2_get_sign_out_params(req->dst, &r, &s);
	if (!r || !s) {
		UADK_ERR("failed to get sign result\n");
		return UADK_P_FAIL;
	}

	e_sig = ECDSA_SIG_new();
	if (!e_sig) {
		UADK_ERR("failed to ECDSA_SIG_new\n");
		return UADK_P_FAIL;
	}

	bn_r = BN_bin2bn((const unsigned char *)r->data, r->dsize, NULL);
	if (!bn_r) {
		UADK_ERR("failed to BN_bin2bn r\n");
		goto free_sig;
	}

	bn_s = BN_bin2bn((const unsigned char *)s->data, s->dsize, NULL);
	if (!bn_s) {
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

static int sm2_sign_ber_to_bin(unsigned char *sig, size_t sig_len,
			       struct wd_dtb *r, struct wd_dtb *s)
{
	const unsigned char *p = sig;
	unsigned char *der = NULL;
	const BIGNUM *bn_r, *bn_s;
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

	ECDSA_SIG_get0(e_sig, &bn_r, &bn_s);
	if (!bn_r || !bn_s) {
		UADK_ERR("failed to get r or s\n");
		goto free_der;
	}

	len1 = BN_num_bytes(bn_r);
	len2 = BN_num_bytes(bn_s);
	if (len1 > UADK_ECC_MAX_KEY_BYTES || len2 > UADK_ECC_MAX_KEY_BYTES) {
		UADK_ERR("r or s bytes = (%d, %d) error\n", len1, len2);
		goto free_der;
	}
	r->dsize = BN_bn2bin(bn_r, (unsigned char *)r->data);
	s->dsize = BN_bn2bin(bn_s, (unsigned char *)s->data);

	OPENSSL_free(der);
	ECDSA_SIG_free(e_sig);

	return UADK_P_SUCCESS;

free_der:
	OPENSSL_free(der);
free_sig:
	ECDSA_SIG_free(e_sig);

	return UADK_P_FAIL;
}

static int sm2_sign_hw(PROV_SM2_SIGN_CTX *psm2ctx,
		       unsigned char *sig, size_t *siglen,
		       const unsigned char *tbs, size_t tbslen)
{
	struct wd_ecc_req req = {0};
	handle_t sess;
	int ret;

	/* Init with UADK */
	ret = uadk_prov_ecc_init("sm2");
	if (ret == UADK_P_FAIL) {
		UADK_ERR("failed to init sm2\n");
		return UADK_DO_SOFT;
	}

	sess = sm2_alloc_sess(psm2ctx->key);
	if (sess == (handle_t)0) {
		UADK_ERR("failed to alloc sess in sign\n");
		return UADK_P_FAIL;
	}

	ret = sm2_sign_init_iot(sess, &req, (void *)tbs, tbslen);
	if (ret == UADK_P_FAIL)
		goto free_sess;

	ret = uadk_prov_ecc_set_private_key(sess, psm2ctx->key);
	if (ret == UADK_P_FAIL)
		goto uninit_iot;

	ret = uadk_prov_ecc_crypto(sess, &req, (void *)sess);
	if (ret == UADK_P_FAIL) {
		UADK_ERR("failed to do sm2 sign\n");
		ret = UADK_DO_SOFT;
		goto uninit_iot;
	}

	ret = sm2_sign_bin_to_ber(&req, sig, siglen);

uninit_iot:
	sm2_sign_uninit_iot(sess, &req);
free_sess:
	sm2_free_sess(sess);
	return ret;
}

static int sm2_sign_sw(void *vpsm2ctx, unsigned char *sig, size_t *siglen,
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
	size_t sltmp = 0;
	int ret, ecsize;

	if (!psm2ctx || !psm2ctx->key) {
		UADK_ERR("invalid: psm2ctx or key is NULL\n");
		return UADK_P_FAIL;
	}

	ecsize = ECDSA_size(psm2ctx->key);
	if (ecsize <= 0) {
		UADK_ERR("ecsize error %d\n", ecsize);
		return UADK_P_FAIL;
	}

	if (!sig) {
		*siglen = (size_t)ecsize;
		return SM2_GET_SIGNLEN;
	}

	if (sigsize < (size_t)ecsize) {
		UADK_ERR("sigsize(%zu) < ecsize(%d)\n", sigsize, ecsize);
		return UADK_P_FAIL;
	}

	ret = sm2_check_tbs_params(psm2ctx, tbs, tbslen);
	if (ret == UADK_P_FAIL) {
		UADK_ERR("failed to check sm2 signature params\n");
		return UADK_P_FAIL;
	}

	ret = sm2_sign_hw(psm2ctx, sig, &sltmp, tbs, tbslen);
	if (ret != UADK_P_SUCCESS) {
		UADK_ERR("failed to do sm2 sign\n");
		goto do_soft;
	}

	*siglen = sltmp;

	return UADK_P_SUCCESS;

do_soft:
	if (ret == UADK_DO_SOFT)
		return sm2_sign_sw(vpsm2ctx, sig, siglen, sigsize, tbs, tbslen);

	return UADK_P_FAIL;
}

static int sm2_verify_init_iot(handle_t sess, struct wd_ecc_req *req,
			       const unsigned char *sig, size_t siglen,
			       const unsigned char *tbs, size_t tbslen)
{
	unsigned char buf_r[UADK_ECC_MAX_KEY_BYTES] = {0};
	unsigned char buf_s[UADK_ECC_MAX_KEY_BYTES] = {0};
	struct wd_ecc_in *ecc_in;
	struct wd_dtb e = {0};
	struct wd_dtb r = {0};
	struct wd_dtb s = {0};
	int ret;

	r.data = (void *)buf_r;
	s.data = (void *)buf_s;
	r.bsize = UADK_ECC_MAX_KEY_BYTES;
	s.bsize = UADK_ECC_MAX_KEY_BYTES;
	ret = sm2_sign_ber_to_bin((void *)sig, siglen, &r, &s);
	if (ret == UADK_P_FAIL) {
		UADK_ERR("failed to sm2_sign_ber_to_bin\n");
		return ret;
	}

	e.data = (void *)tbs;
	e.dsize = tbslen;
	e.bsize = tbslen;
	ecc_in = wd_sm2_new_verf_in(sess, &e, &r, &s, NULL, 1);
	if (!ecc_in) {
		UADK_ERR("failed to new verf in\n");
		return UADK_P_FAIL;
	}

	uadk_prov_ecc_fill_req(req, WD_SM2_VERIFY, ecc_in, NULL);

	return UADK_P_SUCCESS;
}

static void sm2_verify_uninit_iot(handle_t sess, struct wd_ecc_req *req)
{
	wd_ecc_del_in(sess, req->src);
}

static int sm2_verify_hw(PROV_SM2_SIGN_CTX *psm2ctx,
			 const unsigned char *sig, size_t siglen,
			 const unsigned char *tbs, size_t tbslen)
{
	struct wd_ecc_req req = {0};
	handle_t sess;
	int ret;

	/* Init with UADK */
	ret = uadk_prov_ecc_init("sm2");
	if (ret == UADK_P_FAIL) {
		UADK_ERR("failed to init sm2\n");
		return UADK_DO_SOFT;
	}

	sess = sm2_alloc_sess(psm2ctx->key);
	if (sess == (handle_t)0) {
		UADK_ERR("failed to alloc sess in verify\n");
		return UADK_P_FAIL;
	}

	ret = sm2_verify_init_iot(sess, &req, sig, siglen, tbs, tbslen);
	if (ret == UADK_P_FAIL) {
		UADK_ERR("failed to sm2_verify_init_iot\n");
		goto free_sess;
	}

	ret = uadk_prov_ecc_set_public_key(sess, psm2ctx->key);
	if (ret == UADK_P_FAIL) {
		UADK_ERR("failed to uadk_prov_ecc_set_public_key\n");
		goto uninit_iot;
	}

	ret = uadk_prov_ecc_crypto(sess, &req, (void *)sess);
	if (req.status == WD_VERIFY_ERR) {
		ret = UADK_P_FAIL;
	} else if (ret == UADK_P_FAIL) {
		ret = UADK_DO_SOFT;
		UADK_ERR("failed to do sm2 verify\n");
	}

uninit_iot:
	sm2_verify_uninit_iot(sess, &req);
free_sess:
	sm2_free_sess(sess);

	return ret;
}

static int sm2_verify_sw(void *vpsm2ctx, const unsigned char *sig, size_t siglen,
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

	if (!psm2ctx) {
		UADK_ERR("invalid: psm2ctx is NULL\n");
		return UADK_P_FAIL;
	}

	ret = sm2_check_tbs_params(psm2ctx, tbs, tbslen);
	if (ret == UADK_P_FAIL) {
		UADK_ERR("failed to check sm2 verify params\n");
		return UADK_P_FAIL;
	}

	ret = sm2_verify_hw(psm2ctx, sig, siglen, tbs, tbslen);
	if (ret == UADK_DO_SOFT)
		return sm2_verify_sw(vpsm2ctx, sig, siglen, tbs, tbslen);

	return ret;
}

static int sm2_digest_signverify_init(void *vpsm2ctx, const char *mdname,
				      void *ec, const OSSL_PARAM params[])
{
	PROV_SM2_SIGN_CTX *psm2ctx = (PROV_SM2_SIGN_CTX *)vpsm2ctx;
	int md_nid;
	WPACKET pkt;

	if (!sm2_signverify_init(vpsm2ctx, ec, params) ||
	    !sm2_sig_set_mdname(psm2ctx, mdname))
		return UADK_P_FAIL;

	/* psm2ctx->mdctx free in freectx */
	if (!psm2ctx->mdctx) {
		psm2ctx->mdctx = EVP_MD_CTX_new();
		if (unlikely(!psm2ctx->mdctx)) {
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
	md_nid = EVP_MD_get_type(psm2ctx->md);
	psm2ctx->aid_len = 0;
	if (WPACKET_init_der(&pkt, psm2ctx->aid_buf, sizeof(psm2ctx->aid_buf)) &&
	    ossl_DER_w_algorithmIdentifier_SM2_with_MD(&pkt, -1, psm2ctx->key, md_nid) &&
	    WPACKET_finish(&pkt)) {
		WPACKET_get_total_written(&pkt, &psm2ctx->aid_len);
		psm2ctx->aid = WPACKET_get_curr(&pkt);
	}
	WPACKET_cleanup(&pkt);

	if (!EVP_DigestInit_ex2(psm2ctx->mdctx, psm2ctx->md, params)) {
		UADK_ERR("failed to do digest init\n");
		return UADK_P_FAIL;
	}

	psm2ctx->flag_compute_z_digest = 1;

	return UADK_P_SUCCESS;
}

static int uadk_signature_sm2_digest_sign_init(void *vpsm2ctx, const char *mdname,
					       void *ec, const OSSL_PARAM params[])
{
	return sm2_digest_signverify_init(vpsm2ctx, mdname, ec, params);
}

static int sm2_get_params(struct sm2_param *params, BN_CTX *ctx)
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

static int sm2_check_digest_evp_lib(const EVP_MD *digest, EVP_MD_CTX *hash,
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

static int sm2_check_equation_param(struct sm2_param *param, EVP_MD_CTX *hash,
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

static int sm2_check_base_point_group_param(struct sm2_param *param,
					    BN_CTX *ctx, const EC_KEY *key)
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

static int sm2_check_base_point_param(struct sm2_param *param, EVP_MD_CTX *hash,
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

static int sm2_check_pkey_point_group_param(struct sm2_param *param,
					    BN_CTX *ctx, const EC_KEY *key)
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

static int sm2_check_pkey_point_param(struct sm2_param *param, EVP_MD_CTX *hash,
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

static int sm2_compute_z_digest(uint8_t *out, const EVP_MD *digest,
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
	if (!hash)
		return UADK_P_FAIL;

	ctx = BN_CTX_new_ex(key->libctx);
	if (!ctx)
		goto free_hash;

	params = OPENSSL_zalloc(sizeof(struct sm2_param));
	if (!params) {
		UADK_ERR("failed to malloc sm2 param\n");
		goto free_ctx;
	}

	if (!sm2_get_params(params, ctx))
		goto free_params;

	if (!sm2_check_digest_evp_lib(digest, hash, id_len, id))
		goto free_params;

	if (!EC_GROUP_get_curve(group, params->p, params->a, params->b, ctx)) {
		UADK_ERR("failed to EC_GROUP_get_curve\n");
		goto free_params;
	}

	p_bytes = BN_num_bytes(params->p);
	buf = OPENSSL_zalloc(p_bytes);
	if (!buf) {
		UADK_ERR("failed to alloc buffer\n");
		goto free_params;
	}

	if (!sm2_check_equation_param(params, hash, buf, p_bytes) ||
	    !sm2_check_base_point_group_param(params, ctx, key) ||
	    !sm2_check_base_point_param(params, hash, buf, p_bytes) ||
	    !sm2_check_pkey_point_group_param(params, ctx, key) ||
	    !sm2_check_pkey_point_param(params, hash, buf, p_bytes, out))
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
	uint8_t *z;
	int ret;

	if (psm2ctx->flag_compute_z_digest) {
		/* Only do this once */
		psm2ctx->flag_compute_z_digest = 0;

		z = OPENSSL_zalloc(psm2ctx->mdsize);
		if (!z) {
			UADK_ERR("failed to alloc z\n");
			return UADK_P_FAIL;
		}

		/* if id is not set, use default id */
		if (!psm2ctx->id) {
			/* psm2ctx id will be freed in uadk_signature_sm2_freectx, not here */
			psm2ctx->id = OPENSSL_memdup(SM2_DEFAULT_USERID, SM2_DEFAULT_USERID_LEN);
			if (!psm2ctx->id) {
				UADK_ERR("failed to memdup psm2ctx id\n");
				goto free_z;
			}
			psm2ctx->id_len = SM2_DEFAULT_USERID_LEN;
		}

		/* get hashed prefix 'z' of tbs message */
		ret = sm2_compute_z_digest(z, psm2ctx->md, psm2ctx->id,
					   psm2ctx->id_len, psm2ctx->key);
		if (ret == UADK_P_FAIL) {
			UADK_ERR("failed to sm2_compute_z_digest\n");
			goto free_z;
		}

		ret = EVP_DigestUpdate(psm2ctx->mdctx, z, psm2ctx->mdsize);
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

static int sm2_digest_signverify_update(void *vpsm2ctx, const unsigned char *data, size_t datalen)
{
	PROV_SM2_SIGN_CTX *psm2ctx = (PROV_SM2_SIGN_CTX *)vpsm2ctx;
	int ret;

	if (!psm2ctx || !psm2ctx->mdctx) {
		UADK_ERR("invalid: psm2ctx or mdctx is NULL in digest sign update\n");
		return UADK_P_FAIL;
	}

	ret = sm2_sig_compute_z_digest(psm2ctx);
	if (ret == UADK_P_FAIL) {
		UADK_ERR("failed to compute z digest\n");
		return UADK_P_FAIL;
	}

	ret = EVP_DigestUpdate(psm2ctx->mdctx, data, datalen);
	if (ret == UADK_P_FAIL) {
		UADK_ERR("failed to EVP_DigestUpdate\n");
		return UADK_P_FAIL;
	}

	return UADK_P_SUCCESS;
}

static int uadk_signature_sm2_digest_sign_update(void *vpsm2ctx,
						 const unsigned char *data,
						 size_t datalen)
{
	return sm2_digest_signverify_update(vpsm2ctx, data, datalen);
}

static int uadk_signature_sm2_digest_sign_final(void *vpsm2ctx, unsigned char *sig,
						size_t *siglen, size_t sigsize)
{
	PROV_SM2_SIGN_CTX *psm2ctx = (PROV_SM2_SIGN_CTX *)vpsm2ctx;
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int dlen = 0;
	int ret;

	if (!psm2ctx || !psm2ctx->mdctx) {
		UADK_ERR("invalid: psm2ctx or mdctx is NULL\n");
		return UADK_P_FAIL;
	}

	/*
	 * If sig is NULL then we're just finding out the sig size. Other fields
	 * are ignored. Defer to sm2sig_sign.
	 */
	if (sig) {
		ret = sm2_sig_compute_z_digest(psm2ctx);
		if (ret == UADK_P_FAIL)
			return ret;

		ret = EVP_DigestFinal_ex(psm2ctx->mdctx, digest, &dlen);
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
	return sm2_digest_signverify_init(vpsm2ctx, mdname, ec, params);
}

static int uadk_signature_sm2_digest_verify_update(void *vpsm2ctx, const unsigned char *data,
						   size_t datalen)
{
	return sm2_digest_signverify_update(vpsm2ctx, data, datalen);
}

static int uadk_signature_sm2_digest_verify_final(void *vpsm2ctx, const unsigned char *sig,
						  size_t siglen)
{
	PROV_SM2_SIGN_CTX *psm2ctx = (PROV_SM2_SIGN_CTX *)vpsm2ctx;
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int dlen = 0;
	int ret, size;

	if (!psm2ctx || !psm2ctx->mdctx || !psm2ctx->md) {
		UADK_ERR("invalid: psm2ctx or mdctx is NULL\n");
		return UADK_P_FAIL;
	}

	size = EVP_MD_get_size(psm2ctx->md);
	if (size > EVP_MAX_MD_SIZE) {
		UADK_ERR("invalid: md size(%d) > %d\n", size, EVP_MAX_MD_SIZE);
		return UADK_P_FAIL;
	}

	ret = sm2_sig_compute_z_digest(psm2ctx);
	if (ret == UADK_P_FAIL) {
		UADK_ERR("failed to do sm2_sig_compute_z_digest\n");
		return ret;
	}

	ret = EVP_DigestFinal_ex(psm2ctx->mdctx, digest, &dlen);
	if (ret == UADK_P_FAIL) {
		UADK_ERR("failed to do EVP_DigestFinal_ex, dlen = %u\n", dlen);
		return ret;
	}

	return uadk_signature_sm2_verify(vpsm2ctx, sig, siglen, digest, (size_t)dlen);
}

static const OSSL_PARAM *uadk_signature_sm2_settable_ctx_md_params(void *vpsm2ctx)
{
	PROV_SM2_SIGN_CTX *psm2ctx = (PROV_SM2_SIGN_CTX *)vpsm2ctx;

	if (!psm2ctx || !psm2ctx->md) {
		UADK_ERR("invalid: psm2ctx or md is NULL\n");
		return NULL;
	}

	return EVP_MD_settable_ctx_params(psm2ctx->md);
}

static int uadk_signature_sm2_set_ctx_md_params(void *vpsm2ctx, const OSSL_PARAM params[])
{
	PROV_SM2_SIGN_CTX *psm2ctx = (PROV_SM2_SIGN_CTX *)vpsm2ctx;

	if (!psm2ctx || !psm2ctx->mdctx) {
		UADK_ERR("invalid: psm2ctx or mdctx is NULL\n");
		return UADK_P_FAIL;
	}

	return EVP_MD_CTX_set_params(psm2ctx->mdctx, params);
}

static const OSSL_PARAM *uadk_signature_sm2_gettable_ctx_md_params(void *vpsm2ctx)
{
	PROV_SM2_SIGN_CTX *psm2ctx = (PROV_SM2_SIGN_CTX *)vpsm2ctx;

	if (!psm2ctx || !psm2ctx->md) {
		UADK_ERR("invalid: psm2ctx or md is NULL for gettable_ctx_md_params\n");
		return NULL;
	}

	return EVP_MD_gettable_ctx_params(psm2ctx->md);
}

static int uadk_signature_sm2_get_ctx_md_params(void *vpsm2ctx, OSSL_PARAM *params)
{
	PROV_SM2_SIGN_CTX *psm2ctx = (PROV_SM2_SIGN_CTX *)vpsm2ctx;

	if (!psm2ctx || !psm2ctx->mdctx) {
		UADK_ERR("invalid: psm2ctx or mdctx is NULL for get_ctx_md_params\n");
		return UADK_P_FAIL;
	}

	return EVP_MD_CTX_get_params(psm2ctx->mdctx, params);
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

static int uadk_signature_sm2_get_ctx_params(void *vpsm2ctx, OSSL_PARAM *params)
{
	PROV_SM2_SIGN_CTX *psm2ctx = (PROV_SM2_SIGN_CTX *)vpsm2ctx;
	OSSL_PARAM *p;

	if (!psm2ctx) {
		UADK_ERR("invalid: psm2ctx is NULL for get_ctx_params\n");
		return UADK_P_FAIL;
	}

	p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
	if (p && !OSSL_PARAM_set_octet_string(p, psm2ctx->aid, psm2ctx->aid_len)) {
		UADK_ERR("failed to locate algorithm id\n");
		return UADK_P_FAIL;
	}

	p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST_SIZE);
	if (p && !OSSL_PARAM_set_size_t(p, psm2ctx->mdsize)) {
		UADK_ERR("failed to locate digest size\n");
		return UADK_P_FAIL;
	}

	p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
	if (p && !OSSL_PARAM_set_utf8_string(p, !psm2ctx->md ?
						 psm2ctx->mdname :
						 EVP_MD_get0_name(psm2ctx->md))) {
		UADK_ERR("failed to locate digest\n");
		return UADK_P_FAIL;
	}

	return UADK_P_SUCCESS;
}

static void *uadk_signature_sm2_dupctx(void *vpsm2ctx)
{
	PROV_SM2_SIGN_CTX *srcctx = (PROV_SM2_SIGN_CTX *)vpsm2ctx;
	PROV_SM2_SIGN_CTX *dstctx;

	if (!srcctx) {
		UADK_ERR("invalid: src ctx is NULL to dupctx!\n");
		return NULL;
	}

	dstctx = OPENSSL_zalloc(sizeof(PROV_SM2_SIGN_CTX));
	if (!dstctx) {
		UADK_ERR("failed to alloc dst ctx\n");
		return NULL;
	}
	memcpy(dstctx, srcctx, sizeof(*dstctx));
	dstctx->key = NULL;
	dstctx->propq = NULL;
	dstctx->md = NULL;
	dstctx->mdctx = NULL;
	dstctx->id = NULL;

	if (srcctx->key && !EC_KEY_up_ref(srcctx->key)) {
		UADK_ERR("failed to check srcctx key reference\n");
		goto free_ctx;
	}
	dstctx->key = srcctx->key;

	if (srcctx->propq) {
		dstctx->propq = OPENSSL_strdup(srcctx->propq);
		if (!dstctx->propq)
			goto free_ctx;
	}

	if (srcctx->md && !EVP_MD_up_ref(srcctx->md))
		goto free_ctx;
	dstctx->md = srcctx->md;

	if (srcctx->mdctx) {
		dstctx->mdctx = EVP_MD_CTX_new();
		if (!dstctx->mdctx ||
		!EVP_MD_CTX_copy_ex(dstctx->mdctx, srcctx->mdctx))
			goto free_ctx;
	}

	if (srcctx->id) {
		dstctx->id = OPENSSL_memdup(srcctx->id, srcctx->id_len);
		if (!dstctx->id)
			goto free_ctx;
	}

	return dstctx;

free_ctx:
	uadk_signature_sm2_freectx(dstctx);
	return NULL;
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
