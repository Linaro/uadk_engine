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
#include <openssl/kdf.h>
#include "uadk_async.h"
#include "uadk_prov.h"
#include "uadk_prov_der_writer.h"
#include "uadk_prov_pkey.h"

#define DIGEST_MAX_NAME_SIZE		50
#define MAX_ALGORITHM_ID_SIZE		256
#define MAX_PROPQUERY_SIZE		256
#define UADK_SIGN_SIG_NULL		2
#define DGST_SHIFT_NUM(n)		(8 - ((n) & 0x7))
#define UADK_PROV_ECDSA			"ecdsa"

/*
 * What's passed as an actual key is defined by the KEYMGMT interface.
 * We happen to know that our KEYMGMT simply passes DSA structures, so
 * we use that here too.
 */
struct ecdsa_ctx {
	OSSL_LIB_CTX *libctx;
	char *propq;
	EC_KEY *ec;
	char mdname[DIGEST_MAX_NAME_SIZE];

	/*
	 * Flag to determine if the hash function can be changed (true) or not (false)
	 * Because it's dangerous to change during a DigestSign or DigestVerify
	 * operation, this flag is cleared by their Init function, and set again
	 * by their Final function.
	 */
	bool flag_allow_md;

	/* The Algorithm Identifier of the combined signature algorithm */
	unsigned char aid_buf[MAX_ALGORITHM_ID_SIZE];
	unsigned char *aid;
	size_t aid_len;
	size_t mdsize;
	int operation;

	EVP_MD *md;
	EVP_MD_CTX *mdctx;
	/*
	 * Internally used to cache the results of calling the EC group
	 * sign_setup() methods which are then passed to the sign operation.
	 * This is used by CAVS failure tests to terminate a loop if the signature
	 * is not valid.
	 * This could of also been done with a simple flag.
	 */
	BIGNUM *kinv;
	BIGNUM *r;
};

struct ecdsa_opdata {
	const unsigned char *tbs;
	size_t tbslen;
	ECDSA_SIG *sig;
	EC_KEY *ec;
};

UADK_PKEY_SIGNATURE_DESCR(ecdsa, ECDSA);

static void *uadk_signature_ecdsa_newctx(void *provctx, const char *propq)
{
	struct ecdsa_ctx *ctx;

	ctx = OPENSSL_zalloc(sizeof(*ctx));
	if (!ctx)
		return NULL;

	ctx->flag_allow_md = true;
	ctx->libctx = prov_libctx_of(provctx);

	if (propq) {
		ctx->propq = OPENSSL_strdup(propq);
		if (!ctx->propq) {
			fprintf(stderr, "failed to strdup propq!\n");
			OPENSSL_free(ctx);
			ctx = NULL;
		}
	}

	return ctx;
}

static void uadk_signature_ecdsa_freectx(void *vctx)
{
	struct ecdsa_ctx *ctx = (struct ecdsa_ctx *)vctx;

	if (!ctx)
		return;

	OPENSSL_free(ctx->propq);
	EVP_MD_CTX_free(ctx->mdctx);
	EVP_MD_free(ctx->md);
	EC_KEY_free(ctx->ec);
	BN_clear_free(ctx->kinv);
	BN_clear_free(ctx->r);
	OPENSSL_clear_free(ctx, sizeof(*ctx));
}

static void *uadk_signature_ecdsa_dupctx(void *vctx)
{
	struct ecdsa_ctx *src_ctx = (struct ecdsa_ctx *)vctx;
	struct ecdsa_ctx *dst_ctx;

	if (!src_ctx) {
		fprintf(stderr, "invalid: src ctx is NULL to dupctx!\n");
		return NULL;
	}

	/* Test KATS should not need to be supported */
	if (src_ctx->kinv || src_ctx->r) {
		fprintf(stderr, "invalid: src ctx kinv or r is not NULL!\n");
		return NULL;
	}

	dst_ctx = OPENSSL_zalloc(sizeof(*dst_ctx));
	if (!dst_ctx)
		return NULL;

	*dst_ctx = *src_ctx;
	dst_ctx->ec = NULL;
	dst_ctx->md = NULL;
	dst_ctx->mdctx = NULL;
	dst_ctx->propq = NULL;

	if (src_ctx->ec && !EC_KEY_up_ref(src_ctx->ec))
		goto err;
	dst_ctx->ec = src_ctx->ec;

	if (src_ctx->md && !EVP_MD_up_ref(src_ctx->md))
		goto err;
	dst_ctx->md = src_ctx->md;

	if (src_ctx->mdctx) {
		dst_ctx->mdctx = EVP_MD_CTX_new();
		if (!dst_ctx->mdctx || !EVP_MD_CTX_copy_ex(dst_ctx->mdctx, src_ctx->mdctx))
			goto err;
	}

	if (src_ctx->propq) {
		dst_ctx->propq = OPENSSL_strdup(src_ctx->propq);
		if (!dst_ctx->propq)
			goto err;
	}

	return dst_ctx;

err:
	uadk_signature_ecdsa_freectx(dst_ctx);
	return NULL;
}

static void ecdsa_set_aid(struct ecdsa_ctx *ctx, int md_nid)
{
	WPACKET pkt;

	ctx->aid_len = 0;
	if (WPACKET_init_der(&pkt, ctx->aid_buf, sizeof(ctx->aid_buf)) &&
	    ossl_DER_w_algorithmIdentifier_ECDSA_with_MD(&pkt, -1, ctx->ec, md_nid) &&
	    WPACKET_finish(&pkt)) {
		WPACKET_get_total_written(&pkt, &ctx->aid_len);
		ctx->aid = WPACKET_get_curr(&pkt);
	}
	WPACKET_cleanup(&pkt);
}

/*
 * Internal library code deals with NIDs, so we need to translate from a name.
 * We do so using EVP_MD_is_a(), and therefore need a name to NID map.
 */
static int ecdsa_digest_md_to_nid(const EVP_MD *md, const OSSL_ITEM *it, size_t it_len)
{
	size_t i;

	if (!md)
		return NID_undef;

	for (i = 0; i < it_len; i++)
		if (EVP_MD_is_a(md, it[i].ptr))
			return (int)it[i].id;

	return NID_undef;
}

/*
 * Retrieve one of the FIPS approved hash algorithms by nid.
 * See FIPS 180-4 "Secure Hash Standard" and FIPS 202 - SHA-3.
 */
static int ecdsa_digest_get_nid(const EVP_MD *md)
{
	static const OSSL_ITEM name_to_nid[] = {
		{NID_sha1, OSSL_DIGEST_NAME_SHA1},
		{NID_sha224, OSSL_DIGEST_NAME_SHA2_224},
		{NID_sha256, OSSL_DIGEST_NAME_SHA2_256},
		{NID_sha384, OSSL_DIGEST_NAME_SHA2_384},
		{NID_sha512, OSSL_DIGEST_NAME_SHA2_512},
		{NID_sha512_224, OSSL_DIGEST_NAME_SHA2_512_224},
		{NID_sha512_256, OSSL_DIGEST_NAME_SHA2_512_256},
		{NID_sha3_224, OSSL_DIGEST_NAME_SHA3_224},
		{NID_sha3_256, OSSL_DIGEST_NAME_SHA3_256},
		{NID_sha3_384, OSSL_DIGEST_NAME_SHA3_384},
		{NID_sha3_512, OSSL_DIGEST_NAME_SHA3_512},
	};

	return ecdsa_digest_md_to_nid(md, name_to_nid, OSSL_NELEM(name_to_nid));
}

static int ecdsa_digest_get_approved_nid(struct ecdsa_ctx *ctx, const EVP_MD *md)
{
	int mdnid = ecdsa_digest_get_nid(md);

#ifndef OPENSSL_NO_FIPS_SECURITYCHECKS
	int sha1_allowed = (ctx->operation != EVP_PKEY_OP_SIGN);

	if (uadk_prov_securitycheck_enabled(ctx->libctx)) {
		if (mdnid == NID_undef || (mdnid == NID_sha1 && !sha1_allowed))
			mdnid = -1; /* disallowed by security checks */
	}
# endif /* OPENSSL_NO_FIPS_SECURITYCHECKS */

	return mdnid;
}

static int ecdsa_setup_md(struct ecdsa_ctx *ctx, const char *mdname, const char *mdprops)
{
	size_t mdname_len;
	EVP_MD *md = NULL;
	int md_nid;

	if (!mdname)
		return UADK_P_SUCCESS;

	mdname_len = strlen(mdname);
	if (mdname_len >= DIGEST_MAX_NAME_SIZE) {
		fprintf(stderr, "invalid: %s size %zu exceeds name buffer length %d!\n",
			mdname, mdname_len, DIGEST_MAX_NAME_SIZE);
		return UADK_P_FAIL;
	}

	if (!mdprops)
		mdprops = ctx->propq;

	md = EVP_MD_fetch(ctx->libctx, mdname, mdprops);
	if (!md) {
		fprintf(stderr, "failed to fetch %s!\n", mdname);
		return UADK_P_FAIL;
	}

	md_nid = ecdsa_digest_get_approved_nid(ctx, md);
	if (md_nid < 0) {
		fprintf(stderr, "digest %s not allowed!\n", mdname);
		goto err;
	}

	if (!ctx->flag_allow_md) {
		if (ctx->mdname[0] != '\0' && !EVP_MD_is_a(md, ctx->mdname)) {
			fprintf(stderr, "digest %s is not same ctx digest %s!\n",
				mdname, ctx->mdname);
			goto err;
		}
		EVP_MD_free(md);
		return UADK_P_SUCCESS;
	}

	EVP_MD_CTX_free(ctx->mdctx);
	ctx->mdctx = NULL;

	EVP_MD_free(ctx->md);
	ctx->md = md;
	ctx->mdsize = EVP_MD_get_size(ctx->md);
	OPENSSL_strlcpy(ctx->mdname, mdname, DIGEST_MAX_NAME_SIZE);

	ecdsa_set_aid(ctx, md_nid);

	return UADK_P_SUCCESS;

err:
	EVP_MD_free(md);
	return UADK_P_FAIL;
}

static int ecdsa_signverify_init(void *vctx, void *ec,
				 const OSSL_PARAM params[],
				 int operation)
{
	struct ecdsa_ctx *ctx = (struct ecdsa_ctx *)vctx;
	const EC_KEY *eckey = (const EC_KEY *)ec;
	int ret;

	if (!ctx || (!ec && !ctx->ec)) {
		fprintf(stderr, "invalid: ctx or ec is NULL to digest init!\n");
		return UADK_P_FAIL;
	}

	ret = uadk_signature_ecdsa_set_ctx_params(ctx, params);
	if (!ret)
		return ret;

	if (eckey) {
		if (!uadk_prov_ecc_check_key(ctx->libctx, eckey,
					     operation == EVP_PKEY_OP_SIGN))
			return UADK_P_FAIL;

		if (!EC_KEY_up_ref(ec))
			return UADK_P_FAIL;
		EC_KEY_free(ctx->ec);
		ctx->ec = ec;
	}

	ctx->operation = operation;

	return UADK_P_SUCCESS;
}

static int uadk_signature_ecdsa_sign_init(void *vctx, void *ec, const OSSL_PARAM params[])
{
	return ecdsa_signverify_init(vctx, ec, params, EVP_PKEY_OP_SIGN);
}

static int uadk_signature_ecdsa_verify_init(void *vctx, void *ec, const OSSL_PARAM params[])
{
	return ecdsa_signverify_init(vctx, ec, params, EVP_PKEY_OP_VERIFY);
}

static int ecdsa_soft_sign(struct ecdsa_ctx *ctx, unsigned char *sig, size_t *siglen,
			   size_t sigsize, const unsigned char *tbs, size_t tbslen)
{
	unsigned int tmplen;
	int ret;

	if (!enable_sw_offload)
		return UADK_P_FAIL;

	fprintf(stderr, "switch to openssl software calculation in ecdsa signature.\n");

	ret = ECDSA_sign_ex(0, tbs, tbslen, sig, &tmplen, ctx->kinv, ctx->r, ctx->ec);
	if (ret <= 0)
		return UADK_P_FAIL;

	*siglen = (size_t)tmplen;

	return UADK_P_SUCCESS;
}

static int ecdsa_soft_verify(struct ecdsa_ctx *ctx, const unsigned char *sig, size_t siglen,
			     const unsigned char *tbs, size_t tbslen)
{
	if (!enable_sw_offload)
		return UADK_P_FAIL;

	fprintf(stderr, "switch to openssl software calculation in ecdsa verification.\n");

	return ECDSA_verify(0, tbs, tbslen, sig, siglen, ctx->ec);
}

static int ecdsa_common_params_check(struct ecdsa_ctx *ctx,
				     struct ecdsa_opdata *opdata)
{
	const EC_GROUP *group;
	int type;

	if (unlikely(!opdata->tbs || !opdata->tbslen)) {
		fprintf(stderr, "invalid: tbs is NULL or tbslen %zu error!\n", opdata->tbslen);
		return UADK_P_FAIL;
	}

	if (ctx->mdsize && opdata->tbslen != ctx->mdsize) {
		fprintf(stderr, "invalid: ctx->mdsize %zu not equal tbslen %zu!\n",
			ctx->mdsize, opdata->tbslen);
		return UADK_P_FAIL;
	}

	group = EC_KEY_get0_group(ctx->ec);
	if (unlikely(!group)) {
		fprintf(stderr, "invalid: group is NULL!\n");
		return UADK_P_FAIL;
	}

	/* Field GF(2m) is not supported by uadk */
	type = EC_METHOD_get_field_type(EC_GROUP_method_of(group));
	if (type != NID_X9_62_prime_field) {
		fprintf(stderr, "invalid: uadk unsupport Field GF(2m)!\n");
		return UADK_DO_SOFT;
	}

	opdata->ec = ctx->ec;

	return uadk_prov_ecc_bit_check(group);
}

static handle_t ecdsa_alloc_sess(EC_KEY *ec)
{
	int ret;

	ret = uadk_prov_signature_get_support_state(SIGNATURE_ECDSA);
	if (!ret) {
		fprintf(stderr, "failed to get hardware ecdsa support!\n");
		return ret;
	}

	ret = uadk_prov_ecc_init(UADK_PROV_ECDSA);
	if (!ret) {
		fprintf(stderr, "failed to init ecdsa!\n");
		return ret;
	}

	return uadk_prov_ecc_alloc_sess(ec, UADK_PROV_ECDSA);
}

static void ecdsa_free_sess(handle_t sess)
{
	wd_ecc_free_sess(sess);
}

static bool ecdsa_data_is_all_zero(struct wd_dtb *e)
{
	__u32 i;

	for (i = 0; i < e->dsize; i++) {
		if (e->data[i])
			return false;
	}

	return true;
}

static int ecdsa_set_digest(struct ecdsa_opdata *opdata, struct wd_dtb *e)
{
	const EC_GROUP *group = EC_KEY_get0_group(opdata->ec);
	size_t order_bits = EC_GROUP_order_bits(group);
	size_t data_len = opdata->tbslen;
	BIGNUM *m;

	if (BYTES_TO_BITS(data_len) > order_bits) {
		m = BN_new();
		if (!m) {
			fprintf(stderr, "failed to BN_new m!\n");
			return UADK_P_FAIL;
		}

		/*
		 * Need to truncate digest if it is too long: first truncate
		 * whole bytes
		 */
		data_len = BITS_TO_BYTES(order_bits);
		if (!BN_bin2bn(opdata->tbs, data_len, m)) {
			fprintf(stderr, "failed to BN_bin2bn tbs!\n");
			BN_free(m);
			return UADK_P_FAIL;
		}

		/*
		 * If the length of digest is still longer than the length
		 * of the base point order, truncate remaining bits with a
		 * shift to that length.
		 */
		if (BYTES_TO_BITS(data_len) > order_bits &&
		    !BN_rshift(m, m, DGST_SHIFT_NUM(order_bits))) {
			fprintf(stderr, "failed to truncate input tbs!\n");
			BN_free(m);
			return UADK_P_FAIL;
		}
		e->dsize = BN_bn2bin(m, (void *)e->data);
		e->bsize = UADK_ECC_MAX_KEY_BYTES;
		BN_free(m);
	} else {
		e->data = (char *)opdata->tbs;
		e->dsize = data_len;
		e->bsize = data_len;
	}

	if (ecdsa_data_is_all_zero(e))
		return UADK_P_FAIL;

	return UADK_P_SUCCESS;
}

static int ecdsa_sign_init_iot(handle_t sess, struct wd_ecc_req *req,
			       struct ecdsa_opdata *opdata)
{
	char buff[UADK_ECC_MAX_KEY_BYTES] = {0};
	struct wd_ecc_out *ecc_out;
	struct wd_ecc_in *ecc_in;
	struct wd_dtb e = {0};
	int ret;

	e.data = buff;
	ret = ecdsa_set_digest(opdata, &e);
	if (!ret)
		return ret;

	ecc_in = wd_ecdsa_new_sign_in(sess, &e, NULL);
	if (unlikely(!ecc_in)) {
		fprintf(stderr, "failed to new ecdsa sign in!\n");
		return UADK_P_FAIL;
	}

	ecc_out = wd_ecdsa_new_sign_out(sess);
	if (unlikely(!ecc_out)) {
		fprintf(stderr, "failed to new ecdsa sign out!\n");
		wd_ecc_del_in(sess, ecc_in);
		return UADK_P_FAIL;
	}

	uadk_prov_ecc_fill_req(req, WD_ECDSA_SIGN, ecc_in, ecc_out);

	return UADK_P_SUCCESS;
}

static void ecdsa_uninit_req_iot(handle_t sess, struct wd_ecc_req *req)
{
	if (req->src)
		wd_ecc_del_in(sess, req->src);
	if (req->dst)
		wd_ecc_del_out(sess, req->dst);
}

static ECDSA_SIG *ecdsa_get_sign_data(struct wd_ecc_req *req)
{
	struct wd_dtb *r = NULL;
	struct wd_dtb *s = NULL;
	BIGNUM *br, *bs;
	ECDSA_SIG *sig;
	int ret;

	br = BN_new();
	bs = BN_new();
	if (unlikely(!br || !bs)) {
		fprintf(stderr, "failed to new br or bs!\n");
		goto free_bn;
	}

	wd_ecdsa_get_sign_out_params(req->dst, &r, &s);
	if (unlikely(!r || !s)) {
		fprintf(stderr, "failed to get r or s\n");
		goto free_bn;
	}

	if (!BN_bin2bn((void *)r->data, r->dsize, br) ||
	    !BN_bin2bn((void *)s->data, s->dsize, bs)) {
		fprintf(stderr, "failed to BN_bin2bn r or s\n");
		goto free_bn;
	}

	sig = ECDSA_SIG_new();
	if (unlikely(!sig)) {
		fprintf(stderr, "failed to new sig!\n");
		goto free_bn;
	}

	ret = ECDSA_SIG_set0(sig, br, bs);
	if (unlikely(!ret)) {
		fprintf(stderr, "failed to set br or bs to sig!\n");
		goto free_sig;
	}

	return sig;
free_sig:
	ECDSA_SIG_free(sig);
free_bn:
	BN_clear_free(br);
	BN_clear_free(bs);
	return NULL;
}

static int ecdsa_hw_sign(struct ecdsa_opdata *opdata)
{
	struct wd_ecc_req req = {0};
	handle_t sess;
	int ret;

	sess = ecdsa_alloc_sess(opdata->ec);
	if (unlikely(!sess)) {
		fprintf(stderr, "failed to alloc ecdsa sess!\n");
		return UADK_DO_SOFT;
	}

	ret = ecdsa_sign_init_iot(sess, &req, opdata);
	if (unlikely(!ret)) {
		fprintf(stderr, "failed to ecdsa_sign_init_iot!\n");
		goto free_sess;
	}

	ret = uadk_prov_ecc_set_private_key(sess, opdata->ec);
	if (unlikely(!ret)) {
		fprintf(stderr, "failed to set private key!\n");
		goto free_iot;
	}

	ret = uadk_prov_ecc_crypto(sess, &req, (void *)sess);
	if (unlikely(!ret || req.status)) {
		fprintf(stderr, "failed to hardware sign!\n");
		ret = UADK_DO_SOFT;
		goto free_iot;
	}

	opdata->sig = ecdsa_get_sign_data(&req);
	if (!opdata->sig)
		ret = UADK_P_FAIL;

free_iot:
	ecdsa_uninit_req_iot(sess, &req);
free_sess:
	ecdsa_free_sess(sess);
	return ret;
}

static int ecdsa_sign_params_check(struct ecdsa_ctx *ctx,
				   struct ecdsa_opdata *opdata,
				   unsigned char *sig, size_t *siglen,
				   size_t sigsize)
{
	size_t ecsize;

	if (unlikely(!siglen)) {
		fprintf(stderr, "invalid: siglen is NULL to sign!\n");
		return UADK_P_FAIL;
	}

	if (unlikely(!ctx || !ctx->ec)) {
		fprintf(stderr, "invalid: ctx or ec is NULL to sign!\n");
		return UADK_P_FAIL;
	}

	ecsize = ECDSA_size(ctx->ec);
	if (unlikely(!sig)) {
		*siglen = ecsize;
		return UADK_SIGN_SIG_NULL;
	}

	if (unlikely(sigsize < ecsize)) {
		fprintf(stderr, "invalid: sigsize %zu is less than ecsize %zu!\n",
			sigsize, ecsize);
		return UADK_P_FAIL;
	}

	return ecdsa_common_params_check(ctx, opdata);
}

static int uadk_signature_ecdsa_sign(void *vctx, unsigned char *sig, size_t *siglen,
				     size_t sigsize, const unsigned char *tbs, size_t tbslen)
{
	struct ecdsa_ctx *ctx = (struct ecdsa_ctx *)vctx;
	struct ecdsa_opdata opdata = {0};
	int ret;

	opdata.tbs = tbs;
	opdata.tbslen = tbslen;
	ret = ecdsa_sign_params_check(ctx, &opdata, sig, siglen, sigsize);
	if (ret == UADK_SIGN_SIG_NULL) {
		return UADK_P_SUCCESS;
	} else if (unlikely(ret != UADK_P_SUCCESS)) {
		fprintf(stderr, "failed to check params to sign!\n");
		goto err;
	}

	ret = ecdsa_hw_sign(&opdata);
	if (unlikely(ret != UADK_P_SUCCESS))
		goto err;
	ret = i2d_ECDSA_SIG(opdata.sig, &sig);
	/* ECDSA_SIG_free will free br and bs applied for in ecdsa_get_sign_data() */
	ECDSA_SIG_free(opdata.sig);
	if (ret < 0)
		goto err;

	*siglen = (size_t)ret;

	return UADK_P_SUCCESS;
err:
	if (siglen)
		*siglen = 0;

	if (ret == UADK_DO_SOFT)
		return ecdsa_soft_sign(ctx, sig, siglen, sigsize, tbs, tbslen);

	return UADK_P_FAIL;
}

static int ecdsa_verify_init_iot(handle_t sess, struct wd_ecc_req *req,
				 struct ecdsa_opdata *opdata)
{
	char buf_r[UADK_ECC_MAX_KEY_BYTES] = {0};
	char buf_s[UADK_ECC_MAX_KEY_BYTES] = {0};
	char buf_e[UADK_ECC_MAX_KEY_BYTES] = {0};
	const BIGNUM *sig_r = NULL;
	const BIGNUM *sig_s = NULL;
	struct wd_ecc_in *ecc_in;
	struct wd_dtb e = {0};
	struct wd_dtb r = {0};
	struct wd_dtb s = {0};
	int ret;

	e.data = buf_e;
	ret = ecdsa_set_digest(opdata, &e);
	if (!ret)
		return ret;

	r.data = buf_r;
	s.data = buf_s;
	r.bsize = UADK_ECC_MAX_KEY_BYTES;
	s.bsize = UADK_ECC_MAX_KEY_BYTES;
	ECDSA_SIG_get0(opdata->sig, &sig_r, &sig_s);
	r.dsize = BN_bn2bin(sig_r, (void *)r.data);
	s.dsize = BN_bn2bin(sig_s, (void *)s.data);
	ecc_in = wd_ecdsa_new_verf_in(sess, &e, &r, &s);
	if (unlikely(!ecc_in)) {
		fprintf(stderr, "failed to new ecdsa verf in\n");
		return UADK_P_FAIL;
	}

	uadk_prov_ecc_fill_req(req, WD_ECDSA_VERIFY, ecc_in, NULL);

	return UADK_P_SUCCESS;
}

static int ecdsa_hw_verify(struct ecdsa_opdata *opdata)
{
	struct wd_ecc_req req = {0};
	handle_t sess;
	int ret;

	sess = ecdsa_alloc_sess(opdata->ec);
	if (unlikely(!sess)) {
		fprintf(stderr, "failed to alloc ecdsa sess!\n");
		return UADK_DO_SOFT;
	}

	ret = ecdsa_verify_init_iot(sess, &req, opdata);
	if (unlikely(!ret))
		goto free_sess;

	ret = uadk_prov_ecc_set_public_key(sess, opdata->ec);
	if (unlikely(!ret))
		goto free_iot;

	ret = uadk_prov_ecc_crypto(sess, &req, (void *)sess);
	if (unlikely(ret != UADK_P_SUCCESS || req.status)) {
		fprintf(stderr, "failed to hardware verify!\n");
		ret = UADK_DO_SOFT;
	}

free_iot:
	ecdsa_uninit_req_iot(sess, &req);
free_sess:
	ecdsa_free_sess(sess);
	return ret;
}

static int ecdsa_verify_params_check(struct ecdsa_ctx *ctx, struct ecdsa_opdata *opdata,
				     const unsigned char *sig, size_t siglen)
{
	if (!ctx || !ctx->ec) {
		fprintf(stderr, "invalid: ctx or ec is NULL to verify!\n");
		return UADK_P_FAIL;
	}

	if (!sig || !siglen) {
		fprintf(stderr, "invalid: sig is NULL or siglen %zu error!\n", siglen);
		return UADK_P_FAIL;
	}

	return ecdsa_common_params_check(ctx, opdata);
}

static ECDSA_SIG *ecdsa_create_sig(const unsigned char *sig, size_t siglen)
{
	const unsigned char *p = sig;
	unsigned char *der = NULL;
	ECDSA_SIG *s;
	int derlen;

	s = ECDSA_SIG_new();
	if (!s) {
		fprintf(stderr, "failed to new s to verify!\n");
		return NULL;
	}

	if (!d2i_ECDSA_SIG(&s, &p, siglen)) {
		fprintf(stderr, "failed to d2i_ECDSA_SIG: siglen = %zu!\n",
			siglen);
		goto err;
	}

	/* Ensure signature uses DER and doesn't have trailing garbage */
	derlen = i2d_ECDSA_SIG(s, &der);
	if (derlen != siglen || memcmp(sig, der, derlen) != 0) {
		fprintf(stderr, "sig have trailing garbage, derlen %d!\n", derlen);
		OPENSSL_free(der);
		goto err;
	}

	OPENSSL_free(der);

	return s;

err:
	ECDSA_SIG_free(s);
	return NULL;
}

static int uadk_signature_ecdsa_verify(void *vctx, const unsigned char *sig,
				       size_t siglen, const unsigned char *tbs,
				       size_t tbslen)
{
	struct ecdsa_ctx *ctx = (struct ecdsa_ctx *)vctx;
	struct ecdsa_opdata opdata = {0};
	int ret;

	opdata.tbs = tbs;
	opdata.tbslen = tbslen;
	ret = ecdsa_verify_params_check(ctx, &opdata, sig, siglen);
	if (ret != UADK_P_SUCCESS) {
		fprintf(stderr, "failed to check params to sign!\n");
		goto err;
	}

	opdata.sig = ecdsa_create_sig(sig, siglen);
	if (!opdata.sig) {
		fprintf(stderr, "failed to create s to verify!\n");
		return UADK_P_FAIL;
	}

	ret = ecdsa_hw_verify(&opdata);

	ECDSA_SIG_free(opdata.sig);

err:
	if (ret == UADK_DO_SOFT)
		return ecdsa_soft_verify(ctx, sig, siglen, tbs, tbslen);

	return ret;
}

static int ecdsa_digest_singverify_init(void *vctx, const char *mdname, void *ec,
					const OSSL_PARAM params[], int operation)
{
	struct ecdsa_ctx *ctx = (struct ecdsa_ctx *)vctx;
	int ret;

	ret = ecdsa_signverify_init(vctx, ec, params, operation);
	if (!ret)
		return ret;

	ret = ecdsa_setup_md(ctx, mdname, NULL);
	if (!ret)
		return ret;

	ctx->flag_allow_md = false;
	if (!ctx->mdctx) {
		ctx->mdctx = EVP_MD_CTX_new();
		if (!ctx->mdctx)
			return UADK_P_FAIL;
	}

	ret = EVP_DigestInit_ex2(ctx->mdctx, ctx->md, params);
	if (!ret)
		goto err;

	return UADK_P_SUCCESS;

err:
	EVP_MD_CTX_free(ctx->mdctx);
	ctx->mdctx = NULL;
	return UADK_P_FAIL;
}

static int uadk_signature_ecdsa_digest_sign_init(void *vctx, const char *mdname,
						 void *ec, const OSSL_PARAM params[])
{
	return ecdsa_digest_singverify_init(vctx, mdname, ec, params, EVP_PKEY_OP_SIGN);
}

static int ecdsa_digest_signverify_update(void *vctx, const unsigned char *data,
					  size_t datalen)
{
	struct ecdsa_ctx *ctx = (struct ecdsa_ctx *)vctx;

	if (!ctx || !ctx->mdctx) {
		fprintf(stderr, "invalid: ctx or mdctx is NULL to digest update!\n");
		return UADK_P_FAIL;
	}

	return EVP_DigestUpdate(ctx->mdctx, data, datalen);
}

static int uadk_signature_ecdsa_digest_sign_update(void *vctx, const unsigned char *data,
						   size_t datalen)
{
	return ecdsa_digest_signverify_update(vctx, data, datalen);
}

static int uadk_signature_ecdsa_digest_sign_final(void *vctx, unsigned char *sig,
						  size_t *siglen, size_t sigsize)
{
	struct ecdsa_ctx *ctx = (struct ecdsa_ctx *)vctx;
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int dlen = 0;

	if (!ctx || !ctx->mdctx) {
		fprintf(stderr, "invalid: ctx or mdctx is NULL to sign digest final!\n");
		return UADK_P_FAIL;
	}

	/*
	 * If sig is NULL then we're just finding out the sig size. Other fields
	 * are ignored. Defer to uadk_signature_ecdsa_sign.
	 */
	if (sig && !EVP_DigestFinal_ex(ctx->mdctx, digest, &dlen))
		return UADK_P_FAIL;

	ctx->flag_allow_md = true;

	return uadk_signature_ecdsa_sign(vctx, sig, siglen, sigsize, digest, (size_t)dlen);
}

static int uadk_signature_ecdsa_digest_verify_init(void *vctx, const char *mdname,
						   void *ec, const OSSL_PARAM params[])
{
	return ecdsa_digest_singverify_init(vctx, mdname, ec, params, EVP_PKEY_OP_VERIFY);
}

static int uadk_signature_ecdsa_digest_verify_update(void *vctx, const unsigned char *data,
						     size_t datalen)
{
	return ecdsa_digest_signverify_update(vctx, data, datalen);
}

static int uadk_signature_ecdsa_digest_verify_final(void *vctx, const unsigned char *sig,
						    size_t siglen)
{
	struct ecdsa_ctx *ctx = (struct ecdsa_ctx *)vctx;
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int dlen = 0;

	if (!ctx || !ctx->mdctx) {
		fprintf(stderr, "invalid: ctx or mdctx is NULL to verify digest final!\n");
		return UADK_P_FAIL;
	}

	if (!EVP_DigestFinal_ex(ctx->mdctx, digest, &dlen))
		return UADK_P_FAIL;

	ctx->flag_allow_md = true;

	return uadk_signature_ecdsa_verify(vctx, sig, siglen, digest, (size_t)dlen);
}

static int ecdsa_get_ctx_aid(struct ecdsa_ctx *ctx, OSSL_PARAM *params)
{
	OSSL_PARAM *p;

	p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
	if (!p)
		return UADK_P_SUCCESS;

	return OSSL_PARAM_set_octet_string(p, ctx->aid, ctx->aid_len);
}

static int ecdsa_get_ctx_digest_size(struct ecdsa_ctx *ctx, OSSL_PARAM *params)
{
	OSSL_PARAM *p;

	p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST_SIZE);
	if (!p)
		return UADK_P_SUCCESS;

	return OSSL_PARAM_set_size_t(p, ctx->mdsize);
}

static int ecdsa_get_ctx_digest(struct ecdsa_ctx *ctx, OSSL_PARAM *params)
{
	const char *mdname;
	OSSL_PARAM *p;

	p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
	if (!p)
		return UADK_P_SUCCESS;

	mdname = ctx->md ? EVP_MD_get0_name(ctx->md) : ctx->mdname;

	return OSSL_PARAM_set_utf8_string(p, mdname);
}

static int uadk_signature_ecdsa_get_ctx_params(void *vctx, OSSL_PARAM *params)
{
	struct ecdsa_ctx *ctx = (struct ecdsa_ctx *)vctx;
	int ret;

	if (!ctx) {
		fprintf(stderr, "invalid: ctx is NULL to get_ctx_params!\n");
		return UADK_P_FAIL;
	}

	if (!params)
		return UADK_P_SUCCESS;

	ret = ecdsa_get_ctx_digest(ctx, params);
	if (!ret)
		return ret;

	ret = ecdsa_get_ctx_digest_size(ctx, params);
	if (!ret)
		return ret;

	return ecdsa_get_ctx_aid(ctx, params);
}

static const OSSL_PARAM known_gettable_ctx_params[] = {
	OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
	OSSL_PARAM_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE, NULL),
	OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
	OSSL_PARAM_END
};

static const OSSL_PARAM *
uadk_signature_ecdsa_gettable_ctx_params(ossl_unused void *vctx,
					 ossl_unused void *provctx)
{
	return known_gettable_ctx_params;
}

static int ecdsa_set_ctx_digest(struct ecdsa_ctx *ctx, const OSSL_PARAM params[])
{
	char mdname[DIGEST_MAX_NAME_SIZE] = {0};
	char mdprops[MAX_PROPQUERY_SIZE] = {0};
	const OSSL_PARAM *p_digest, *propsp;
	char *pmdprops = mdprops;
	char *pmdname = mdname;
	int ret;

	p_digest = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
	if (!p_digest)
		return UADK_P_SUCCESS;

	ret = OSSL_PARAM_get_utf8_string(p_digest, &pmdname, DIGEST_MAX_NAME_SIZE);
	if (!ret)
		return UADK_P_FAIL;

	propsp = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PROPERTIES);
	if (propsp) {
		ret = OSSL_PARAM_get_utf8_string(propsp, &pmdprops, MAX_PROPQUERY_SIZE);
		if (!ret)
			return UADK_P_FAIL;
	}

	return ecdsa_setup_md(ctx, mdname, mdprops);
}

static int ecdsa_set_ctx_digest_size(struct ecdsa_ctx *ctx, const OSSL_PARAM params[])
{
	const OSSL_PARAM *p;
	size_t mdsize = 0;
	int ret;

	p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST_SIZE);
	if (!p)
		return UADK_P_SUCCESS;

	ret = OSSL_PARAM_get_size_t(p, &mdsize);
	if (!ret)
		return UADK_P_FAIL;

	if (!ctx->flag_allow_md && mdsize != ctx->mdsize)
		return UADK_P_FAIL;

	ctx->mdsize = mdsize;

	return UADK_P_SUCCESS;
}

static int uadk_signature_ecdsa_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
	struct ecdsa_ctx *ctx = (struct ecdsa_ctx *)vctx;
	int ret;

	if (!ctx) {
		fprintf(stderr, "invalid: ctx is NULL to set_ctx_params!\n");
		return UADK_P_FAIL;
	}

	if (!params)
		return UADK_P_SUCCESS;

	ret = ecdsa_set_ctx_digest(ctx, params);
	if (!ret)
		return ret;

	return ecdsa_set_ctx_digest_size(ctx, params);
}

static const OSSL_PARAM settable_ctx_params[] = {
	OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
	OSSL_PARAM_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE, NULL),
	OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PROPERTIES, NULL, 0),
	OSSL_PARAM_uint(OSSL_SIGNATURE_PARAM_KAT, NULL),
	OSSL_PARAM_END
};

static const OSSL_PARAM settable_ctx_params_no_digest[] = {
	OSSL_PARAM_uint(OSSL_SIGNATURE_PARAM_KAT, NULL),
	OSSL_PARAM_END
};

static const OSSL_PARAM *
uadk_signature_ecdsa_settable_ctx_params(void *vctx, ossl_unused void *provctx)
{
	struct ecdsa_ctx *ctx = (struct ecdsa_ctx *)vctx;

	if (ctx && !ctx->flag_allow_md)
		return settable_ctx_params_no_digest;

	return settable_ctx_params;
}

static int uadk_signature_ecdsa_get_ctx_md_params(void *vctx, OSSL_PARAM *params)
{
	struct ecdsa_ctx *ctx = (struct ecdsa_ctx *)vctx;

	if (!ctx || !ctx->mdctx) {
		fprintf(stderr, "invalid: ctx or md ctx is NULL to get_ctx_md_params!\n");
		return UADK_P_FAIL;
	}

	return EVP_MD_CTX_get_params(ctx->mdctx, params);
}

static const OSSL_PARAM *uadk_signature_ecdsa_gettable_ctx_md_params(void *vctx)
{
	struct ecdsa_ctx *ctx = (struct ecdsa_ctx *)vctx;

	if (!ctx || !ctx->md) {
		fprintf(stderr, "invalid: ctx or md is NULL to gettable_ctx_md_params!\n");
		return NULL;
	}

	return EVP_MD_gettable_ctx_params(ctx->md);
}

static int uadk_signature_ecdsa_set_ctx_md_params(void *vctx, const OSSL_PARAM params[])
{
	struct ecdsa_ctx *ctx = (struct ecdsa_ctx *)vctx;

	if (!ctx || !ctx->mdctx) {
		fprintf(stderr, "invalid: ctx or md ctx is NULL to set_ctx_md_params!\n");
		return UADK_P_FAIL;
	}

	return EVP_MD_CTX_set_params(ctx->mdctx, params);
}

static const OSSL_PARAM *uadk_signature_ecdsa_settable_ctx_md_params(void *vctx)
{
	struct ecdsa_ctx *ctx = (struct ecdsa_ctx *)vctx;

	if (!ctx || !ctx->md) {
		fprintf(stderr, "invalid: ctx or md is NULL to settable_ctx_md_params!\n");
		return NULL;
	}

	return EVP_MD_settable_ctx_params(ctx->md);
}

static int uadk_signature_ecdsa_verify_recover_init(void *vctx, void *vecdsa,
						    const OSSL_PARAM params[])
{
	return UADK_P_SUCCESS;
}

static int uadk_signature_ecdsa_verify_recover(void *vctx, unsigned char *rout,
					       size_t *routlen, size_t routsize,
					       const unsigned char *sig, size_t siglen)
{
	return UADK_P_SUCCESS;
}
