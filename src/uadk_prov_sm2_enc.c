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
#include "uadk_prov_pkey.h"
#include "uadk_utils.h"

typedef struct {
	/*
	 * References to the underlying digest implementation. |md| caches
	 * the digest, always. |alloc_md| only holds a reference to an explicitly
	 * fetched digest.
	 */
	const EVP_MD *md;
	/* fetched digest */
	EVP_MD *alloc_md;

	/* Conditions for legacy EVP_MD uses, digest engine */
	ENGINE *engine;
} PROV_DIGEST;

typedef struct {
	OSSL_LIB_CTX *libctx;
	/* Use EC_KEY refer to keymgmt */
	EC_KEY *key;
	/* The md will used by openssl, but not used by uadk provider */
	PROV_DIGEST md;
} PROV_SM2_ASYM_CTX;

typedef struct sm2_ciphertext {
	BIGNUM *C1x;
	BIGNUM *C1y;
	ASN1_OCTET_STRING *C3;
	ASN1_OCTET_STRING *C2;
} SM2_Ciphertext;

static const OSSL_PARAM sm2_asym_cipher_known_gettable_ctx_params[] = {
	OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_DIGEST, NULL, 0),
	OSSL_PARAM_END
};

static const OSSL_PARAM sm2_asym_cipher_known_settable_ctx_params[] = {
	OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_DIGEST, NULL, 0),
	OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_PROPERTIES, NULL, 0),
	OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_ENGINE, NULL, 0),
	OSSL_PARAM_END
};

DECLARE_ASN1_FUNCTIONS(SM2_Ciphertext)

ASN1_SEQUENCE(SM2_Ciphertext) = {
	ASN1_SIMPLE(SM2_Ciphertext, C1x, BIGNUM),
	ASN1_SIMPLE(SM2_Ciphertext, C1y, BIGNUM),
	ASN1_SIMPLE(SM2_Ciphertext, C3, ASN1_OCTET_STRING),
	ASN1_SIMPLE(SM2_Ciphertext, C2, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(SM2_Ciphertext)

IMPLEMENT_ASN1_FUNCTIONS(SM2_Ciphertext)
UADK_PKEY_ASYM_CIPHER_DESCR(sm2, SM2);

static UADK_PKEY_ASYM_CIPHER s_asym_cipher;

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
	PROV_SM2_ASYM_CTX *psm2ctx;

	psm2ctx = OPENSSL_zalloc(sizeof(PROV_SM2_ASYM_CTX));
	if (!psm2ctx) {
		UADK_ERR("failed to alloc PROV_SM2_ASYM_CTX\n");
		return NULL;
	}

	psm2ctx->libctx = prov_libctx_of(provctx);

	return psm2ctx;
}

static void sm2_prov_digest_reset(PROV_DIGEST *pd)
{
	EVP_MD_free(pd->alloc_md);
}

static void uadk_asym_cipher_sm2_freectx(void *vpsm2ctx)
{
	PROV_SM2_ASYM_CTX *psm2ctx = (PROV_SM2_ASYM_CTX *)vpsm2ctx;

	if (!psm2ctx)
		return;

	EC_KEY_free(psm2ctx->key);
	sm2_prov_digest_reset(&psm2ctx->md);
	OPENSSL_free(psm2ctx);
}

static int sm2_prov_load_common(const OSSL_PARAM params[], const char **propquery, ENGINE **engine)
{
	const OSSL_PARAM *p;

	*propquery = NULL;
	p = OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_PROPERTIES);
	if (p) {
		if (p->data_type != OSSL_PARAM_UTF8_STRING)
			return UADK_P_FAIL;
		*propquery = p->data;
	}

	*engine = NULL;

	return UADK_P_SUCCESS;
}

static const EVP_MD *sm2_prov_digest_fetch(PROV_DIGEST *pd, OSSL_LIB_CTX *libctx,
					   const char *mdname, const char *propquery)
{
	EVP_MD_free(pd->alloc_md);
	pd->md = pd->alloc_md = EVP_MD_fetch(libctx, mdname, propquery);

	return pd->md;
}

static int sm2_load_digest_from_params(PROV_DIGEST *pd, const OSSL_PARAM params[],
				       OSSL_LIB_CTX *ctx)
{
	const char *propquery;
	const OSSL_PARAM *p;

	if (!sm2_prov_load_common(params, &propquery, &pd->engine))
		return UADK_P_FAIL;

	p = OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_DIGEST);
	if (!p)
		return UADK_P_SUCCESS;

	if (p->data_type != OSSL_PARAM_UTF8_STRING)
		return UADK_P_FAIL;

	pd->md = sm2_prov_digest_fetch(pd, ctx, p->data, propquery);
	if (!pd->md)
		return UADK_P_FAIL;

	return UADK_P_SUCCESS;
}

static int uadk_asym_cipher_sm2_set_ctx_params(void *vpsm2ctx, const OSSL_PARAM params[])
{
	PROV_SM2_ASYM_CTX *psm2ctx = (PROV_SM2_ASYM_CTX *)vpsm2ctx;
	int ret;

	if (!psm2ctx) {
		UADK_ERR("invalid: sm2 ctx is NULL\n");
		return UADK_P_FAIL;
	}

	/* No need to set */
	if (!params)
		return UADK_P_SUCCESS;

	ret = sm2_load_digest_from_params(&psm2ctx->md, params, psm2ctx->libctx);
	if (ret == UADK_P_FAIL) {
		UADK_ERR("failed to set digest with set_ctx_params\n");
		return UADK_P_FAIL;
	}

	return UADK_P_SUCCESS;
}

static int uadk_asym_cipher_sm2_encrypt_init(void *vpsm2ctx, void *vkey,
					     const OSSL_PARAM params[])
{
	PROV_SM2_ASYM_CTX *psm2ctx = (PROV_SM2_ASYM_CTX *)vpsm2ctx;

	if (!psm2ctx || !vkey) {
		UADK_ERR("invalid: psm2ctx or vkey is NULL\n");
		return UADK_P_FAIL;
	}

	if (!EC_KEY_up_ref(vkey)) {
		UADK_ERR("failed to EC_KEY_up_ref vkey\n");
		return UADK_P_FAIL;
	}
	EC_KEY_free(psm2ctx->key);
	psm2ctx->key = vkey;

	return uadk_asym_cipher_sm2_set_ctx_params(psm2ctx, params);
}

static int uadk_asym_cipher_sm2_decrypt_init(void *vpsm2ctx, void *vkey,
					     const OSSL_PARAM params[])
{
	return uadk_asym_cipher_sm2_encrypt_init(vpsm2ctx, vkey, params);
}

static const EVP_MD *sm2_prov_digest_md(const PROV_DIGEST *pd)
{
	return pd->md;
}

static const EVP_MD *sm2_prov_get_md(PROV_SM2_ASYM_CTX *psm2ctx)
{
	const EVP_MD *md = sm2_prov_digest_md(&psm2ctx->md);

	if (!md)
		md = sm2_prov_digest_fetch(&psm2ctx->md, psm2ctx->libctx, "SM3", NULL);

	return md;
}

static size_t sm2_prov_ec_field_size(const EC_GROUP *group)
{
	size_t field_size = 0;
	size_t p_bits;
	BIGNUM *p;

	p = BN_new();
	if (!p) {
		UADK_ERR("failed to new bignumber\n");
		return field_size;
	}

	if (!EC_GROUP_get_curve(group, p, NULL, NULL, NULL)) {
		UADK_ERR("failed to get curve p from group\n");
		goto out;
	}

	p_bits = BN_num_bits(p);
	field_size = BITS_TO_BYTES(p_bits);

out:
	BN_free(p);
	return field_size;
}

static int sm2_prov_compute_hash(const char *in, size_t in_len,
				 char *out, size_t out_len, void *usr)
{
	const EVP_MD *digest = (const EVP_MD *)usr;
	int ret = WD_SUCCESS;
	EVP_MD_CTX *hash;

	hash = EVP_MD_CTX_new();
	if (!hash)
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

static int sm2_prov_get_hash_type(int nid_hash)
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

static int sm2_prov_alloc_sess(PROV_SM2_ASYM_CTX *vpsm2ctx, handle_t *sess)
{
	const EC_GROUP *group = EC_KEY_get0_group(vpsm2ctx->key);
	const EVP_MD *md = sm2_prov_digest_md(&vpsm2ctx->md);
	const BIGNUM *order = EC_GROUP_get0_order(group);
	struct wd_ecc_sess_setup setup = {0};
	struct sched_params params = {0};
	int md_nid = EVP_MD_get_type(md);
	int type;

	type = sm2_prov_get_hash_type(md_nid);
	if (type < 0) {
		UADK_ERR("uadk not support hash nid %d\n", md_nid);
		return UADK_DO_SOFT;
	}
	setup.hash.type = type;
	setup.hash.cb = sm2_prov_compute_hash;
	setup.hash.usr = (void *)md;

	setup.rand.cb = uadk_prov_ecc_get_rand;
	setup.rand.usr = (void *)order;
	setup.alg = "sm2";

	/* Use the default numa parameters */
	params.numa_id = -1;
	setup.sched_param = &params;
	*sess = wd_ecc_alloc_sess(&setup);
	if (*sess == (handle_t)0) {
		UADK_ERR("failed to alloc sess\n");
		return UADK_P_FAIL;
	}

	return UADK_P_SUCCESS;
}

static void sm2_prov_free_sess(handle_t sess)
{
	wd_ecc_free_sess(sess);
}

static int sm2_prov_encrypt_init_iot(handle_t sess, struct wd_ecc_req *req,
				     void *in, size_t inlen)
{
	struct wd_ecc_out *ecc_out;
	struct wd_ecc_in *ecc_in;
	struct wd_dtb e = {0};

	ecc_out = wd_sm2_new_enc_out(sess, inlen);
	if (!ecc_out) {
		UADK_ERR("failed to new enc out\n");
		return UADK_P_FAIL;
	}

	e.data = in;
	e.dsize = inlen;
	e.bsize = inlen;
	ecc_in = wd_sm2_new_enc_in(sess, NULL, &e);
	if (!ecc_in) {
		UADK_ERR("failed to new enc in\n");
		wd_ecc_del_out(sess, ecc_out);
		return UADK_P_FAIL;
	}

	uadk_prov_ecc_fill_req(req, WD_SM2_ENCRYPT, ecc_in, ecc_out);

	return UADK_P_SUCCESS;
}

static void sm2_prov_uninit_iot(handle_t sess, struct wd_ecc_req *req)
{
	wd_ecc_del_in(sess, req->src);
	wd_ecc_del_out(sess, req->dst);
}

static int sm2_prov_asym_bin_to_ber(struct wd_ecc_point *c1,
				    struct wd_dtb *c2, struct wd_dtb *c3,
				    unsigned char *ber, size_t *ber_len)
{
	struct sm2_ciphertext ctext;
	int ret = UADK_P_FAIL;
	BIGNUM *x1, *y1;
	int ctext_leni;

	x1 = BN_bin2bn((const unsigned char *)c1->x.data, c1->x.dsize, NULL);
	if (!x1) {
		UADK_ERR("failed to BN_bin2bn x1\n");
		return UADK_P_FAIL;
	}

	y1 = BN_bin2bn((const unsigned char *)c1->y.data, c1->y.dsize, NULL);
	if (!y1) {
		UADK_ERR("failed to BN_bin2bn y1\n");
		goto free_x1;
	}

	ctext.C1x = x1;
	ctext.C1y = y1;
	ctext.C3 = ASN1_OCTET_STRING_new();
	if (!ctext.C3)
		goto free_y1;

	ret = ASN1_OCTET_STRING_set(ctext.C3, (const unsigned char *)c3->data, c3->dsize);
	if (ret == UADK_P_FAIL)
		goto free_c3;

	ctext.C2 = ASN1_OCTET_STRING_new();
	if (!ctext.C2) {
		ret = UADK_P_FAIL;
		goto free_c3;
	}

	ret = ASN1_OCTET_STRING_set(ctext.C2, (const unsigned char *)c2->data, c2->dsize);
	if (ret == UADK_P_FAIL)
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

static int sm2_prov_encrypt_sw(PROV_SM2_ASYM_CTX *vpsm2ctx,
			       unsigned char *out, size_t *outlen,
			       const unsigned char *in, size_t inlen)
{
	if (uadk_get_sw_offload_state() && get_default_sm2_asym_cipher().encrypt) {
		UADK_INFO("switch to software sm2 encrypt\n");
		return get_default_sm2_asym_cipher().encrypt(vpsm2ctx, out, outlen, 0, in, inlen);
	}

	return UADK_P_FAIL;
}

static int sm2_prov_encrypt(PROV_SM2_ASYM_CTX *vpsm2ctx,
			    unsigned char *out, size_t *outlen,
			    const unsigned char *in, size_t inlen)
{
	struct wd_ecc_point *c1 = NULL;
	struct wd_ecc_req req = {0};
	struct wd_dtb *c2 = NULL;
	struct wd_dtb *c3 = NULL;
	handle_t sess;
	int ret;

	if (inlen > UINT_MAX) {
		ret = UADK_DO_SOFT;
		goto do_soft;
	}

	ret = uadk_prov_ecc_init("sm2");
	if (ret == UADK_P_FAIL) {
		UADK_ERR("failed to init sm2\n");
		ret = UADK_DO_SOFT;
		goto do_soft;
	}

	ret = sm2_prov_alloc_sess(vpsm2ctx, &sess);
	if (ret != UADK_P_SUCCESS) {
		UADK_ERR("failed to alloc sess in encrypt\n");
		goto do_soft;
	}

	ret = sm2_prov_encrypt_init_iot(sess, &req, (void *)in, inlen);
	if (ret == UADK_P_FAIL)
		goto free_sess;

	ret = uadk_prov_ecc_set_public_key(sess, vpsm2ctx->key);
	if (ret == UADK_P_FAIL)
		goto uninit_iot;

	ret = uadk_prov_ecc_crypto(sess, &req, (void *)sess);
	if (ret == UADK_P_FAIL) {
		UADK_ERR("failed to do sm2 encrypt\n");
		ret = UADK_DO_SOFT;
		goto uninit_iot;
	}

	wd_sm2_get_enc_out_params(req.dst, &c1, &c2, &c3);
	if (!c1 || !c2 || !c3) {
		ret = UADK_P_FAIL;
		goto uninit_iot;
	}

	ret = sm2_prov_asym_bin_to_ber(c1, c2, c3, out, outlen);

uninit_iot:
	sm2_prov_uninit_iot(sess, &req);
free_sess:
	sm2_prov_free_sess(sess);
do_soft:
	if (ret == UADK_DO_SOFT)
		return sm2_prov_encrypt_sw(vpsm2ctx, out, outlen, in, inlen);
	return ret;
}

static int sm2_prov_ciphertext_size(const EC_KEY *key, const EVP_MD *digest,
				    size_t msg_len, size_t *ct_size)
{
	const size_t field_size = sm2_prov_ec_field_size(EC_KEY_get0_group(key));
	const int md_size = EVP_MD_get_size(digest);
	size_t sz;

	if (!field_size || md_size < 0) {
		UADK_ERR("invalid field_size or md_size: %d\n", md_size);
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
					size_t outsize, const unsigned char *in, size_t inlen)
{
	PROV_SM2_ASYM_CTX *psm2ctx = (PROV_SM2_ASYM_CTX *)vpsm2ctx;
	const EVP_MD *md;

	if (!psm2ctx) {
		UADK_ERR("invalid: psm2ctx is NULL\n");
		return UADK_P_FAIL;
	}

	md = sm2_prov_get_md(psm2ctx);
	if (!md) {
		UADK_ERR("failed to get md method\n");
		return UADK_P_FAIL;
	}

	/* If out is NULL, compute outlen size and return */
	if (!out)
		return sm2_prov_ciphertext_size(psm2ctx->key, md, inlen, outlen);

	return sm2_prov_encrypt(psm2ctx, out, outlen, in, inlen);
}

static int sm2_prov_get_plaintext(struct wd_ecc_req *req,
				  unsigned char *out, size_t *outlen)
{
	struct wd_dtb *ptext = NULL;

	wd_sm2_get_dec_out_params(req->dst, &ptext);
	if (!ptext) {
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

static int sm2_prov_decrypt_init_iot(handle_t sess, struct wd_ecc_req *req,
				     int md_size, const unsigned char *in, size_t inlen)
{
	char buf_x[SM2_KEY_BYTES] = {0};
	char buf_y[SM2_KEY_BYTES] = {0};
	struct sm2_ciphertext **a = NULL;
	struct sm2_ciphertext *ctext;
	struct wd_ecc_out *ecc_out;
	struct wd_ecc_in *ecc_in;
	struct wd_ecc_point c1;
	struct wd_dtb c2, c3;
	int ret = UADK_P_FAIL;
	int c1x_len, c1y_len;

	ctext = d2i_SM2_Ciphertext(a, &in, inlen);
	if (!ctext)
		return UADK_P_FAIL;

	if (ctext->C3->length != md_size) {
		UADK_ERR("invalid: c3 dsize(%d) != md_size(%d)\n", ctext->C3->length, md_size);
		goto free_ctext;
	}

	c1x_len = BN_num_bytes(ctext->C1x);
	c1y_len = BN_num_bytes(ctext->C1y);
	if (c1x_len > SM2_KEY_BYTES || c1y_len > SM2_KEY_BYTES) {
		UADK_ERR("invalid: x size %d or y size %d is error\n", c1x_len, c1y_len);
		goto free_ctext;
	}

	c1.x.dsize = BN_bn2bin(ctext->C1x, (void *)buf_x);
	c1.y.dsize = BN_bn2bin(ctext->C1y, (void *)buf_y);
	c1.x.bsize = SM2_KEY_BYTES;
	c1.y.bsize = SM2_KEY_BYTES;
	c1.x.data = buf_x;
	c1.y.data = buf_y;

	c2.data = (char *)ctext->C2->data;
	c2.dsize = ctext->C2->length;
	c2.bsize = ctext->C2->length;

	c3.data = (char *)ctext->C3->data;
	c3.dsize = ctext->C3->length;
	c3.bsize = ctext->C3->length;

	ecc_out = wd_sm2_new_dec_out(sess, c2.dsize);
	if (!ecc_out) {
		UADK_ERR("failed to new dec out\n");
		goto free_ctext;
	}

	ecc_in = wd_sm2_new_dec_in(sess, &c1, &c2, &c3);
	if (!ecc_in) {
		UADK_ERR("failed to new dec in\n");
		wd_ecc_del_out(sess, ecc_out);
		goto free_ctext;
	}

	uadk_prov_ecc_fill_req(req, WD_SM2_DECRYPT, ecc_in, ecc_out);
	ret = UADK_P_SUCCESS;

free_ctext:
	SM2_Ciphertext_free(ctext);
	return ret;
}

static int sm2_prov_decrypt_sw(PROV_SM2_ASYM_CTX *ctx,
			       unsigned char *out, size_t *outlen,
			       const unsigned char *in, size_t inlen)
{
	if (uadk_get_sw_offload_state() && get_default_sm2_asym_cipher().decrypt) {
		UADK_INFO("switch to software sm2 decrypt\n");
		return get_default_sm2_asym_cipher().decrypt(ctx, out, outlen, 0, in, inlen);
	}

	return UADK_P_FAIL;
}

static int sm2_prov_decrypt(PROV_SM2_ASYM_CTX *psm2ctx, unsigned char *out,
			    size_t *outlen, const unsigned char *in, size_t inlen)
{
	const EVP_MD *md = sm2_prov_digest_md(&psm2ctx->md);
	int md_size = EVP_MD_get_size(md);
	struct wd_ecc_req req = {0};
	handle_t sess;
	int ret;

	if (inlen > UINT_MAX) {
		ret = UADK_DO_SOFT;
		goto do_soft;
	}

	ret = uadk_prov_ecc_init("sm2");
	if (ret == UADK_P_FAIL) {
		UADK_ERR("failed to init sm2\n");
		ret = UADK_DO_SOFT;
		goto do_soft;
	}

	ret = sm2_prov_alloc_sess(psm2ctx, &sess);
	if (ret != UADK_P_SUCCESS) {
		UADK_ERR("failed to alloc sess in encrypt\n");
		goto do_soft;
	}

	ret = sm2_prov_decrypt_init_iot(sess, &req, md_size, in, inlen);
	if (ret == UADK_P_FAIL)
		goto free_sess;

	ret = uadk_prov_ecc_set_private_key(sess, psm2ctx->key);
	if (ret == UADK_P_FAIL)
		goto uninit_iot;

	ret = uadk_prov_ecc_crypto(sess, &req, (void *)sess);
	if (ret == UADK_P_FAIL) {
		UADK_ERR("failed to do sm2 decrypt\n");
		ret = UADK_DO_SOFT;
		goto uninit_iot;
	}

	ret = sm2_prov_get_plaintext(&req, out, outlen);

uninit_iot:
	sm2_prov_uninit_iot(sess, &req);
free_sess:
	sm2_prov_free_sess(sess);
do_soft:
	if (ret == UADK_DO_SOFT)
		return sm2_prov_decrypt_sw(psm2ctx, out, outlen, in, inlen);

	return ret;
}

static int sm2_prov_plaintext_size(const unsigned char *ct, size_t ct_size, size_t *pt_size)
{
	struct sm2_ciphertext *sm2_ctext;

	sm2_ctext = d2i_SM2_Ciphertext(NULL, &ct, ct_size);
	if (!sm2_ctext) {
		UADK_ERR("invalid sm2 encoding\n");
		return UADK_P_FAIL;
	}

	*pt_size = sm2_ctext->C2->length;
	SM2_Ciphertext_free(sm2_ctext);

	return UADK_P_SUCCESS;
}

static int uadk_asym_cipher_sm2_decrypt(void *vpsm2ctx, unsigned char *out, size_t *outlen,
					size_t outsize, const unsigned char *in, size_t inlen)
{
	PROV_SM2_ASYM_CTX *psm2ctx = (PROV_SM2_ASYM_CTX *)vpsm2ctx;
	const EVP_MD *md;

	if (!psm2ctx) {
		UADK_ERR("invalid: psm2ctx is NULL\n");
		return UADK_P_FAIL;
	}

	md = sm2_prov_get_md(psm2ctx);
	if (!md) {
		UADK_ERR("invalid: md is NULL\n");
		return UADK_P_FAIL;
	}

	if (!out)
		return sm2_prov_plaintext_size(in, inlen, outlen);

	return sm2_prov_decrypt(psm2ctx, out, outlen, in, inlen);
}

static int sm2_prov_digest_copy(PROV_DIGEST *dst, const PROV_DIGEST *src)
{
	if (src->alloc_md && !EVP_MD_up_ref(src->alloc_md))
		return UADK_P_FAIL;

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

	if (!srcctx) {
		UADK_ERR("src ctx is NULL\n");
		return NULL;
	}

	dstctx = OPENSSL_zalloc(sizeof(PROV_SM2_ASYM_CTX));
	if (!dstctx) {
		UADK_ERR("failed to alloc dst ctx\n");
		return NULL;
	}
	memcpy(dstctx, srcctx, sizeof(*dstctx));
	memset(&dstctx->md, 0, sizeof(dstctx->md));

	if (srcctx->key && !EC_KEY_up_ref(srcctx->key)) {
		OPENSSL_free(dstctx);
		return NULL;
	}
	dstctx->key = srcctx->key;

	ret = sm2_prov_digest_copy(&dstctx->md, &srcctx->md);
	if (ret == UADK_P_FAIL) {
		uadk_asym_cipher_sm2_freectx(dstctx);
		return NULL;
	}

	return dstctx;
}

static int uadk_asym_cipher_sm2_get_ctx_params(void *vpsm2ctx, OSSL_PARAM *params)
{
	PROV_SM2_ASYM_CTX *psm2ctx = (PROV_SM2_ASYM_CTX *)vpsm2ctx;
	const char *mdname;
	const EVP_MD *md;
	OSSL_PARAM *p;

	if (!psm2ctx) {
		UADK_ERR("failed to get psm2ctx\n");
		return UADK_P_FAIL;
	}

	if (!params) {
		UADK_ERR("params is NULL\n");
		return UADK_P_FAIL;
	}

	p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_DIGEST);
	if (p) {
		md = sm2_prov_digest_md(&psm2ctx->md);
		mdname = md ? EVP_MD_get0_name(md) : "";
		if (!OSSL_PARAM_set_utf8_string(p, mdname)) {
			UADK_ERR("failed to set utf8 string\n");
			return UADK_P_FAIL;
		}
	}

	return UADK_P_SUCCESS;
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
