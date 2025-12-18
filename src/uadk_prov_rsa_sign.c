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
#include "uadk_prov_rsa.h"
#include "uadk_prov_rsa_utils.h"

#define PRIME_CHECK_BIT_NUM        4
/* Size of an SSL signature: MD5+SHA1 */
#define SSL_SIG_LENGTH			36
#define MDC2_MESSAGE_LEN		16
#define MDC2_HEAD_LEN			2
#define RSA_MDC2_FIRST_BYTE		0x4
#define RSA_MDC2_SECOND_BYTE	0x10
#define RSA_PSS_SIZE_MASK		0x7

UADK_PKEY_SIGNATURE_DESCR(rsa, RSA);

struct PROV_RSA_SIG_CTX {
	OSSL_LIB_CTX *libctx;
	char *propq;
	RSA *rsa;
	int operation;

	/*
	 * Flag to determine if the hash function can be changed (1) or not (0)
	 * Because it's dangerous to change during a DigestSign or DigestVerify
	 * operation, this flag is cleared by their Init function, and set again
	 * by their Final function.
	 */
	unsigned int flag_allow_md : 1;
	unsigned int mgf1_md_set : 1;

	/* main digest */
	EVP_MD *md;
	EVP_MD_CTX *mdctx;
	int mdnid;
	char mdname[50]; /* Purely informational */

	/* RSA padding mode */
	int pad_mode;
	/* message digest for MGF1 */
	EVP_MD *mgf1_md;
	int mgf1_mdnid;
	char mgf1_mdname[50]; /* Purely informational */
	/* PSS salt length */
	int saltlen;
	/* Minimum salt length or -1 if no PSS parameter restriction */
	int min_saltlen;

	/* Temp buffer */
	unsigned char *tbuf;

	unsigned int soft : 1;
};

static pthread_mutex_t sig_mutex = PTHREAD_MUTEX_INITIALIZER;

static int encode_pkcs1(unsigned char **out, size_t *out_len, int type,
			const unsigned char *m, size_t m_len);

static UADK_PKEY_SIGNATURE get_default_rsa_signature(void)
{
	static UADK_PKEY_SIGNATURE s_signature;
	static int initilazed;

	pthread_mutex_lock(&sig_mutex);
	if (!initilazed) {
		UADK_PKEY_SIGNATURE *signature =
			(UADK_PKEY_SIGNATURE *)EVP_SIGNATURE_fetch(NULL, "RSA", "provider=default");

		if (signature) {
			s_signature = *signature;
			EVP_SIGNATURE_free((EVP_SIGNATURE *)signature);
			initilazed = 1;
		} else {
			UADK_ERR("failed to EVP_SIGNATURE_fetch default RSA provider\n");
		}
	}
	pthread_mutex_unlock(&sig_mutex);
	return s_signature;
}

static size_t uadk_rsa_get_md_size(struct PROV_RSA_SIG_CTX *prsactx)
{
	if (prsactx->md != NULL)
		return EVP_MD_get_size(prsactx->md);
	return UADK_P_FAIL;
}

static int setup_tbuf(struct PROV_RSA_SIG_CTX *ctx)
{
	if (ctx->tbuf != NULL)
		return UADK_P_SUCCESS;

	ctx->tbuf = OPENSSL_malloc(uadk_rsa_size(ctx->rsa));
	if (!ctx->tbuf) {
		UADK_ERR("failed to zalloc ctx tbuf!\n");
		return UADK_P_FAIL;
	}

	return UADK_P_SUCCESS;
}

static void clean_tbuf(struct PROV_RSA_SIG_CTX *ctx)
{
	if (ctx->tbuf != NULL)
		OPENSSL_cleanse(ctx->tbuf, uadk_rsa_size(ctx->rsa));
}

static void free_tbuf(struct PROV_RSA_SIG_CTX *ctx)
{
	clean_tbuf(ctx);
	OPENSSL_free(ctx->tbuf);
	ctx->tbuf = NULL;
}

static int add_rsa_prienc_padding(int flen, const unsigned char *from,
				  unsigned char *to_buf, int tlen,
				  int padding)
{
	int ret;

	switch (padding) {
	case RSA_PKCS1_PADDING:
		ret = RSA_padding_add_PKCS1_type_1(to_buf, tlen, from, flen);
		break;
	case RSA_X931_PADDING:
		ret = RSA_padding_add_X931(to_buf, tlen, from, flen);
		break;
	case RSA_NO_PADDING:
		ret = RSA_padding_add_none(to_buf, tlen, from, flen);
		break;
	default:
		ret = UADK_P_FAIL;
	}

	if (ret <= UADK_P_FAIL) {
		UADK_ERR("failed to add padding type %d in rsa sign\n", padding);
		ret = UADK_P_FAIL;
	}

	return ret;
}

static int check_rsa_pubdec_padding(unsigned char *to, int num,
				    const unsigned char *buf, int len,
				    int padding)
{
	int ret;

	switch (padding) {
	case RSA_PKCS1_PADDING:
		ret = RSA_padding_check_PKCS1_type_1(to, num, buf, len, num);
		break;
	case RSA_X931_PADDING:
		ret = RSA_padding_check_X931(to, num, buf, len, num);
		break;
	case RSA_NO_PADDING:
		memcpy(to, buf, len);
		ret = len;
		break;
	default:
		ret = UADK_P_FAIL;
		UADK_ERR("failed to check padding type %d in rsa verify\n", padding);
		break;
	}

	if (ret < 0) {
		UADK_ERR("failed to check padding type %d in rsa verify\n", padding);
		ret = UADK_P_FAIL;
	}

	return ret;
}

static BN_ULONG *bn_get_words(const BIGNUM *a)
{
	return a->d;
}

static int rsa_get_sign_res(int padding, BIGNUM *to_bn, const BIGNUM *n,
			    BIGNUM *ret_bn, BIGNUM **res)
{
	if (padding == RSA_X931_PADDING) {
		if (!BN_sub(to_bn, n, ret_bn))
			return UADK_P_FAIL;
		if (BN_cmp(ret_bn, to_bn) > 0)
			*res = to_bn;
		else
			*res = ret_bn;
	} else {
		*res = ret_bn;
	}

	return UADK_P_SUCCESS;
}

static int rsa_get_verify_res(int padding, const BIGNUM *n, BIGNUM *ret_bn)
{
	if ((padding == RSA_X931_PADDING) && ((bn_get_words(ret_bn)[0] & 0xf)
	    != 0x0c)) {
		if (!BN_sub(ret_bn, n, ret_bn))
			return UADK_P_FAIL;
	}

	return UADK_P_SUCCESS;
}

static int sign_trans_bn(struct uadk_rsa_sess *rsa_sess, unsigned char *from_buf,
			 struct rsa_prikey_param *pri, int padding,
			 unsigned char *to, int num_bytes)
{
	BIGNUM *res = NULL;
	BIGNUM *sign_bn;
	BIGNUM *to_bn;
	int ret;

	sign_bn = BN_bin2bn((const unsigned char *)rsa_sess->req.dst,
			    rsa_sess->req.dst_bytes, NULL);
	if (!sign_bn)
		return UADK_P_FAIL;

	to_bn = BN_bin2bn(from_buf, num_bytes, NULL);
	if (!to_bn) {
		ret = UADK_P_FAIL;
		goto free_sign_bn;
	}

	ret = rsa_get_sign_res(padding, to_bn, pri->n, sign_bn, &res);
	if (!ret)
		goto free_to_bn;

	ret = BN_bn2binpad(res, to, num_bytes);

free_to_bn:
	BN_free(to_bn);
free_sign_bn:
	BN_free(sign_bn);
	return ret;
}

static int uadk_prov_rsa_private_sign(int flen, const unsigned char *from,
				      unsigned char *to, RSA *rsa, int padding)
{
	struct rsa_prikey_param *prik = NULL;
	struct uadk_rsa_sess *rsa_sess;
	unsigned char *from_buf = NULL;
	int ret, num_bytes;

	ret = check_rsa_input_para(flen, from, to, rsa);
	if (ret != UADK_P_SUCCESS)
		return ret;

	ret = rsa_pkey_param_alloc(NULL, &prik);
	if (ret == -ENOMEM)
		return UADK_P_FAIL;

	prik->is_crt = check_rsa_is_crt(rsa);

	rsa_sess = rsa_get_eng_session(rsa, uadk_rsa_bits(rsa), prik->is_crt);
	if (!rsa_sess) {
		ret = UADK_DO_SOFT;
		goto free_pkey;
	}

	ret = rsa_create_pri_bn_ctx(rsa, prik, &from_buf, &num_bytes);
	if (ret <= 0 || flen > num_bytes) {
		ret = UADK_P_FAIL;
		goto free_sess;
	}

	ret = add_rsa_prienc_padding(flen, from, from_buf, num_bytes, padding);
	if (!ret) {
		ret = UADK_P_FAIL;
		goto free_buf;
	}

	ret = rsa_fill_prikey(rsa, rsa_sess, prik, from_buf, to);
	if (!ret) {
		ret = UADK_P_FAIL;
		goto free_buf;
	}

	ret = rsa_do_crypto(rsa_sess);
	if (!ret || rsa_sess->req.status) {
		ret = UADK_DO_SOFT;
		goto free_buf;
	}

	ret = sign_trans_bn(rsa_sess, from_buf, prik, padding, to, num_bytes);

free_buf:
	rsa_free_pri_bn_ctx(from_buf);
free_sess:
	rsa_free_eng_session(rsa_sess);
free_pkey:
	rsa_pkey_param_free(NULL, &prik);
	return ret;
}

static int verify_trans_bn(struct uadk_rsa_sess *rsa_sess, unsigned char *from_buf,
			   int num_bytes, struct rsa_pubkey_param *pub,
			   int padding, int *len)
{
	BIGNUM *verify_bn;
	int ret;

	verify_bn = BN_bin2bn((const unsigned char *)rsa_sess->req.dst,
			      rsa_sess->req.dst_bytes, NULL);
	if (!verify_bn)
		return UADK_P_FAIL;

	ret = rsa_get_verify_res(padding, pub->n, verify_bn);
	if (!ret)
		goto verify_end;

	*len = BN_bn2binpad(verify_bn, from_buf, num_bytes);
	if (*len == 0)
		ret = UADK_P_FAIL;

verify_end:
	BN_free(verify_bn);
	return ret;
}

static int uadk_prov_rsa_public_verify(int flen, const unsigned char *from,
				       unsigned char *to, RSA *rsa, int padding)
{
	struct rsa_pubkey_param *pub = NULL;
	int num_bytes, is_crt, len, ret;
	struct uadk_rsa_sess *rsa_sess;
	unsigned char *from_buf = NULL;

	ret = check_rsa_input_para(flen, from, to, rsa);
	if (ret != UADK_P_SUCCESS)
		return ret;

	ret = rsa_pkey_param_alloc(&pub, NULL);
	if (ret == -ENOMEM)
		return UADK_P_FAIL;

	is_crt = check_rsa_is_crt(rsa);

	rsa_sess = rsa_get_eng_session(rsa, uadk_rsa_bits(rsa), is_crt);
	if (!rsa_sess) {
		ret = UADK_DO_SOFT;
		goto free_pkey;
	}

	ret = rsa_create_pub_bn_ctx(rsa, pub, &from_buf, &num_bytes);
	if (ret <= 0 || flen > num_bytes) {
		ret = UADK_P_FAIL;
		goto free_sess;
	}

	ret = rsa_fill_pubkey(pub, rsa_sess, from_buf, to);
	if (!ret) {
		ret = UADK_P_FAIL;
		goto free_buff;
	}

	memcpy(rsa_sess->req.src, from, rsa_sess->req.src_bytes);
	ret = rsa_do_crypto(rsa_sess);
	if (!ret || rsa_sess->req.status) {
		ret = UADK_DO_SOFT;
		goto free_buff;
	}

	ret = verify_trans_bn(rsa_sess, from_buf, num_bytes, pub, padding, &len);
	if (!ret)
		goto free_buff;

	ret = check_rsa_pubdec_padding(to, num_bytes, from_buf, len, padding);

free_buff:
	rsa_free_pub_bn_ctx(from_buf);
free_sess:
	rsa_free_eng_session(rsa_sess);
free_pkey:
	rsa_pkey_param_free(&pub, NULL);
	return ret;
}

static int rsa_check_parameters(struct PROV_RSA_SIG_CTX *prsactx, int min_saltlen)
{
	int max_saltlen;

	if (prsactx->pad_mode == RSA_PKCS1_PSS_PADDING) {
		/* See if minimum salt length exceeds maximum possible */
		max_saltlen = RSA_size(prsactx->rsa) - EVP_MD_get_size(prsactx->md);
		if ((RSA_bits(prsactx->rsa) & RSA_PSS_SIZE_MASK) == 1)
			max_saltlen--;
		if (min_saltlen < 0 || min_saltlen > max_saltlen) {
			UADK_ERR("invalid: incorrect salt length %d\n", min_saltlen);
			return UADK_P_FAIL;
		}
		prsactx->min_saltlen = min_saltlen;
	}
	return UADK_P_SUCCESS;
}

static int rsa_check_padding(const struct PROV_RSA_SIG_CTX *prsactx,
			     const char *mdname, const char *mgf1_mdname,
			     int mdnid)
{
	switch (prsactx->pad_mode) {
	case RSA_NO_PADDING:
		if (mdname != NULL || mdnid != NID_undef) {
			UADK_ERR("invalid: digest %s or mdnid %d not allowed in NO_PADDING mode\n",
				 mdname, mdnid);
			return UADK_P_FAIL;
		}
		break;
	case RSA_X931_PADDING:
		if (RSA_X931_hash_id(mdnid) == -1) {
			UADK_ERR("invalid: mdnid %d not allowed in X931_PADDING mode\n", mdnid);
			return UADK_P_FAIL;
		}
		break;
	case RSA_PKCS1_PSS_PADDING:
		if (rsa_pss_restricted(prsactx))
			if ((mdname != NULL && !EVP_MD_is_a(prsactx->md, mdname))
			|| (mgf1_mdname != NULL
				&& !EVP_MD_is_a(prsactx->mgf1_md, mgf1_mdname))) {
				UADK_ERR("invalid: incorrect digest %s in PSS mode\n", mdname);
				return UADK_P_FAIL;
			}
		break;
	default:
		break;
	}

	return UADK_P_SUCCESS;
}

static int rsa_setup_mgf1_md(struct PROV_RSA_SIG_CTX *ctx, const char *mdname,
			     const char *mdprops)
{
	size_t len;
	EVP_MD *md;
	int mdnid;

	if (!mdprops)
		mdprops = ctx->propq;

	md = EVP_MD_fetch(ctx->libctx, mdname, mdprops);
	if (!md) {
		UADK_ERR("failed to fetch digest %s\n", mdname);
		return UADK_P_FAIL;
	}
	/* The default for mgf1 is SHA1 - so allow SHA1 */
	mdnid = ossl_digest_rsa_sign_get_md_nid(ctx->libctx, md, 1);
	if (mdnid  <= 0 || !rsa_check_padding(ctx, NULL, mdname, mdnid)) {
		if (mdnid <= 0)
			UADK_ERR("invalid: %s is not a supported digest\n", mdname);
		EVP_MD_free(md);
		return UADK_P_FAIL;
	}
	len = OPENSSL_strlcpy(ctx->mgf1_mdname, mdname, sizeof(ctx->mgf1_mdname));
	if (len >= sizeof(ctx->mgf1_mdname)) {
		UADK_ERR("invalid: %s exceeds name buffer length\n", mdname);
		EVP_MD_free(md);
		return UADK_P_FAIL;
	}

	EVP_MD_free(ctx->mgf1_md);
	ctx->mgf1_md = md;
	ctx->mgf1_mdnid = mdnid;
	ctx->mgf1_md_set = 1;
	return UADK_P_SUCCESS;
}

static int rsa_setup_md(struct PROV_RSA_SIG_CTX *ctx, const char *mdname,
			const char *mdprops)
{
	if (!mdprops)
		mdprops = ctx->propq;

	if (mdname != NULL) {
		EVP_MD *md = EVP_MD_fetch(ctx->libctx, mdname, mdprops);
		int sha1_allowed = (ctx->operation != EVP_PKEY_OP_SIGN);
		int md_nid = ossl_digest_rsa_sign_get_md_nid(ctx->libctx, md, sha1_allowed);
		size_t mdname_len = strlen(mdname);
		bool md_ret = (!md) || (md_nid <= 0);

		if (md_ret || !rsa_check_padding(ctx, mdname, NULL, md_nid) ||
		    mdname_len >= sizeof(ctx->mdname)) {
			if (!md)
				UADK_ERR("invalid: %s could not be fetched\n", mdname);
			if (md_nid <= 0)
				UADK_ERR("invalid: %s is not a supported digest\n", mdname);
			if (mdname_len >= sizeof(ctx->mdname))
				UADK_ERR("invalid: %s exceeds name buffer length\n", mdname);
			EVP_MD_free(md);
			return UADK_P_FAIL;
		}

		if (!ctx->flag_allow_md) {
			if (ctx->mdname[0] != '\0' && !EVP_MD_is_a(md, ctx->mdname)) {
				UADK_ERR("invalid: %s is not the same as ctx %s\n",
					mdname, ctx->mdname);
				EVP_MD_free(md);
				return UADK_P_FAIL;
			}
			EVP_MD_free(md);
			return UADK_P_SUCCESS;
		}

		if (!ctx->mgf1_md_set) {
			if (!EVP_MD_up_ref(md)) {
				EVP_MD_free(md);
				return UADK_P_FAIL;
			}
			EVP_MD_free(ctx->mgf1_md);
			ctx->mgf1_md = md;
			ctx->mgf1_mdnid = md_nid;
			OPENSSL_strlcpy(ctx->mgf1_mdname, mdname, sizeof(ctx->mgf1_mdname));
		}

		EVP_MD_CTX_free(ctx->mdctx);
		EVP_MD_free(ctx->md);

		ctx->mdctx = NULL;
		ctx->md = md;
		ctx->mdnid = md_nid;
		OPENSSL_strlcpy(ctx->mdname, mdname, sizeof(ctx->mdname));
	}

	return UADK_P_SUCCESS;
}

static int uadk_signature_rsa_set_ctx_params(void *vprsactx, const OSSL_PARAM params[])
{
	if (!get_default_rsa_signature().set_ctx_params)
		return UADK_P_FAIL;
	return get_default_rsa_signature().set_ctx_params(vprsactx, params);
}

static int uadk_rsa_init_pss_mode(struct PROV_RSA_SIG_CTX *ctx, void *vrsa)
{
	const struct rsa_pss_params_30_st *pss;
	int md_nid, mgf1md_nid, min_saltlen;
	const char *mdname, *mgf1mdname;
	size_t len;

	pss = ossl_rsa_get0_pss_params_30(ctx->rsa);
	if (ossl_rsa_pss_params_30_is_unrestricted(pss))
		return UADK_P_SUCCESS;

	md_nid = ossl_rsa_pss_params_30_hashalg(pss);
	mgf1md_nid = ossl_rsa_pss_params_30_maskgenhashalg(pss);
	min_saltlen = ossl_rsa_pss_params_30_saltlen(pss);
	mdname = ossl_rsa_oaeppss_nid2name(md_nid);
	if (!mdname) {
		UADK_ERR("invalid: PSS restrictions lack digest\n");
		return UADK_P_FAIL;
	}
	mgf1mdname = ossl_rsa_oaeppss_nid2name(mgf1md_nid);
	if (!mgf1mdname) {
		UADK_ERR("invalid: PSS restrictions lack MGF1 digest\n");
		return UADK_P_FAIL;
	}

	len = OPENSSL_strlcpy(ctx->mdname, mdname, sizeof(ctx->mdname));
	if (len >= sizeof(ctx->mdname)) {
		UADK_ERR("invalid: hash algorithm name too long\n");
		return UADK_P_FAIL;
	}
	len = OPENSSL_strlcpy(ctx->mgf1_mdname, mgf1mdname, sizeof(ctx->mgf1_mdname));
	if (len >= sizeof(ctx->mgf1_mdname)) {
		UADK_ERR("invalid: MGF1 hash algorithm name too long\n");
		return UADK_P_FAIL;
	}

	ctx->saltlen = min_saltlen;
	if (!rsa_setup_mgf1_md(ctx, mgf1mdname, ctx->propq) ||
		!rsa_setup_md(ctx, mdname, ctx->propq) ||
		!rsa_check_parameters(ctx, min_saltlen)) {
		return UADK_P_FAIL;
	}

	return UADK_P_SUCCESS;
}

static int uadk_rsa_signverify_init(void *vprsactx, void *vrsa,
			 const OSSL_PARAM params[], int operation)
{
	struct PROV_RSA_SIG_CTX *ctx = (struct PROV_RSA_SIG_CTX *)vprsactx;

	if (!ctx)
		return UADK_P_FAIL;

	if (!vrsa && !ctx->rsa) {
		UADK_ERR("invalid: no available rsa\n");
		return UADK_P_FAIL;
	}

	if (vrsa != NULL) {
		if (!RSA_up_ref(vrsa))
			return UADK_P_FAIL;
		RSA_free(ctx->rsa);
		ctx->rsa = vrsa;
	}

	ctx->operation = operation;

	/* Maximum for sign, auto for verify */
	ctx->saltlen = RSA_PSS_SALTLEN_AUTO;
	ctx->min_saltlen = -1;

	switch (uadk_rsa_test_flags(ctx->rsa, RSA_FLAG_TYPE_MASK)) {
	case RSA_FLAG_TYPE_RSA:
		ctx->pad_mode = RSA_PKCS1_PADDING;
		break;
	case RSA_FLAG_TYPE_RSASSAPSS:
		ctx->pad_mode = RSA_PKCS1_PSS_PADDING;
		if (!uadk_rsa_init_pss_mode(ctx, vrsa))
			return UADK_P_FAIL;
		break;
	default:
		UADK_ERR("rsa init operation not supported this keytype!\n");
		return UADK_P_FAIL;
	}

	if (uadk_prov_rsa_init())
		ctx->soft = 1;

	if (!uadk_signature_rsa_set_ctx_params(ctx, params))
		return UADK_P_FAIL;

	return UADK_P_SUCCESS;
}

static int uadk_signature_rsa_verify_recover_init(void *vprsactx, void *vrsa,
						  const OSSL_PARAM params[])
{
	return uadk_rsa_signverify_init(vprsactx, vrsa, params,
					EVP_PKEY_OP_VERIFYRECOVER);
}

static int uadk_rsa_sw_verify_recover(void *vprsactx, unsigned char *rout,
				      size_t *routlen, size_t routsize,
				      const unsigned char *sig, size_t siglen)
{
	if (!enable_sw_offload || !get_default_rsa_signature().verify_recover)
		return UADK_P_FAIL;

	UADK_INFO("switch to openssl software calculation in verify recover.\n");
	return get_default_rsa_signature().verify_recover(vprsactx, rout, routlen,
							  routsize, sig, siglen);
}

static int uadk_signature_rsa_verify_x931_recover(struct PROV_RSA_SIG_CTX *priv,
						  unsigned char *rout,
						  size_t *routlen, size_t routsize,
						  const unsigned char *sig, size_t siglen)
{
	int ret;

	if (!setup_tbuf(priv))
		return UADK_P_FAIL;

	/* RSA in X931 mode returns both the hash's length and algorithm identifier. */
	ret = uadk_prov_rsa_public_verify(siglen, sig, priv->tbuf, priv->rsa, RSA_X931_PADDING);
	if (ret <= UADK_P_FAIL)
		return ret;
	ret--;
	if (priv->tbuf[ret] != RSA_X931_hash_id(priv->mdnid)) {
		UADK_ERR("invalid: hash id mismatch in rsa x931 verify recover\n");
		return UADK_P_FAIL;
	}

	if (ret != EVP_MD_get_size(priv->md)) {
		UADK_ERR("invalid: incorrect digest size in rsa x931 verify recover\n");
		return UADK_P_FAIL;
	}

	*routlen = ret;
	if (rout != priv->tbuf) {
		if (routsize < (size_t)ret) {
			UADK_ERR("invalid: incorrect buf size in rsa x931 verify recover\n");
			return UADK_P_FAIL;
		}
		memcpy(rout, priv->tbuf, ret);
	}
	return ret;
}

static int uadk_signature_rsa_verify_recover(void *vprsactx, unsigned char *rout,
					     size_t *routlen, size_t routsize,
					     const unsigned char *sig, size_t siglen)
{
	struct PROV_RSA_SIG_CTX *priv = (struct PROV_RSA_SIG_CTX *)vprsactx;
	int ret;

	if (!priv || priv->soft) {
		ret = UADK_DO_SOFT;
		goto exe_soft;
	}

	if (!rout) {
		*routlen = RSA_size(priv->rsa);
		return UADK_P_SUCCESS;
	}

	if (!priv->md) {
		ret = uadk_prov_rsa_public_verify(siglen, sig, rout,
						  priv->rsa, priv->pad_mode);
		goto end;
	}

	switch (priv->pad_mode) {
	case RSA_X931_PADDING:
		ret = uadk_signature_rsa_verify_x931_recover(priv, rout, routlen, routsize,
							     sig, siglen);
		break;
	default:
		if (!get_default_rsa_signature().verify_recover)
			return UADK_P_FAIL;
		return get_default_rsa_signature().verify_recover(priv, rout, routlen,
								  routsize, sig, siglen);
	}

end:
	if (ret == UADK_DO_SOFT)
		goto exe_soft;
	if (ret <= UADK_P_FAIL) {
		UADK_ERR("failed to do rsa verify recover with padding %d\n", priv->pad_mode);
		return UADK_P_FAIL;
	}
	*routlen = ret;
	return UADK_P_SUCCESS;

exe_soft:
	return uadk_rsa_sw_verify_recover(vprsactx, rout, routlen, routsize, sig, siglen);
}

static int uadk_signature_rsa_verify_init(void *vprsactx, void *vrsa,
					  const OSSL_PARAM params[])
{
	return uadk_rsa_signverify_init(vprsactx, vrsa, params, EVP_PKEY_OP_VERIFY);
}

static int uadk_rsa_sw_verify(void *vprsactx, const unsigned char *sig,
			      size_t siglen, const unsigned char *tbs,
			      size_t tbslen)
{
	if (!enable_sw_offload || !get_default_rsa_signature().verify)
		return UADK_P_FAIL;

	UADK_INFO("switch to openssl software calculation in verifaction.\n");

	return get_default_rsa_signature().verify(vprsactx, sig, siglen, tbs, tbslen);
}

static int uadk_rsa_pkcs1_verify(struct PROV_RSA_SIG_CTX *priv, const unsigned char *sig,
				 size_t siglen, const unsigned char *tbs,
				 size_t tbslen)
{
	unsigned char *decrypt_buf, *encoded = NULL;
	size_t decrypt_len, encoded_len = 0;
	int ret;

	if (siglen != (size_t)uadk_rsa_size(priv->rsa)) {
		UADK_ERR("invalid: siglen size %zu is wrong\n", siglen);
		return UADK_P_FAIL;
	}

	/* Recover the encoded digest. */
	decrypt_buf = OPENSSL_malloc(siglen);
	if (!decrypt_buf) {
		UADK_ERR("failed to alloc decrypt_buf\n");
		return UADK_P_FAIL;
	}

	ret = uadk_prov_rsa_public_verify(siglen, sig, decrypt_buf,
					  priv->rsa, RSA_PKCS1_PADDING);
	if (ret <= 0)
		goto err;
	decrypt_len = ret;

#ifndef FIPS_MODULE
	if (priv->mdnid == NID_md5_sha1) {
		/*
		 * NID_md5_sha1 corresponds to the MD5/SHA1 combination in TLS 1.1 and
		 * earlier. It has no DigestInfo wrapper but otherwise is
		 * RSASSA-PKCS1-v1_5.
		 */
		if (decrypt_len != SSL_SIG_LENGTH || tbslen != SSL_SIG_LENGTH) {
			UADK_ERR("invalid: decrypt_len %zu or tbslen %zu\n"
					"not equal to siglen %d\n",
				decrypt_len, tbslen, SSL_SIG_LENGTH);
			ret = UADK_P_FAIL;
			goto err;
		}

		if (memcmp(decrypt_buf, tbs, SSL_SIG_LENGTH) != 0) {
			UADK_ERR("invalid: decrypt_buf is not equal to tbs\n");
			ret = UADK_P_FAIL;
			goto err;
		}
	} else if ((priv->mdnid == NID_mdc2 &&
		    decrypt_len == (MDC2_MESSAGE_LEN + MDC2_HEAD_LEN) &&
		    decrypt_buf[0] == RSA_MDC2_FIRST_BYTE &&
		    decrypt_buf[1] == RSA_MDC2_SECOND_BYTE)) {
		if (tbslen != MDC2_MESSAGE_LEN) {
			UADK_ERR("invalid: tbslen size %zu is wrong\n", tbslen);
			ret = UADK_P_FAIL;
			goto err;
		}

		if (memcmp(tbs, decrypt_buf + MDC2_HEAD_LEN, MDC2_MESSAGE_LEN) != 0) {
			UADK_ERR("invalid: decrypt_buf is not equal to tbs\n");
			ret = UADK_P_FAIL;
			goto err;
		}
	} else {
#endif /* FIPS_MODULE */
		/* Construct the encoded digest and ensure it matches. */
		if (!encode_pkcs1(&encoded, &encoded_len, priv->mdnid, tbs, tbslen)) {
			ret = UADK_P_FAIL;
			goto err;
		}

		if (encoded_len != decrypt_len ||
		    memcmp(encoded, decrypt_buf, encoded_len) != 0) {
			UADK_ERR("invalid: encoded_len %zu is not equal to decrypt_len %zu\n"
					"or encoded is not equal to encoded_len\n",
				encoded_len, decrypt_len);
			ret = UADK_P_FAIL;
			goto err;
		}
#ifndef FIPS_MODULE
	}
#endif /* FIPS_MODULE */
	ret = UADK_P_SUCCESS;
err:
	OPENSSL_clear_free(encoded, encoded_len);
	OPENSSL_clear_free(decrypt_buf, siglen);
	return ret;
}

static int uadk_rsa_pkcs1_pss_verify(struct PROV_RSA_SIG_CTX *priv,
				     const unsigned char *sig, size_t siglen,
				     const unsigned char *tbs, size_t tbslen)
{
	size_t mdsize = uadk_rsa_get_md_size(priv);
	int ret;

	if (tbslen != mdsize) {
		UADK_ERR("RSA verify fail, tbslen %zu is not equal to mdsize %zu\n",
			tbslen, mdsize);
		return UADK_P_FAIL;
	}

	if (!setup_tbuf(priv))
		return UADK_P_FAIL;

	ret = uadk_prov_rsa_public_verify(siglen, sig, priv->tbuf,
					    priv->rsa, RSA_NO_PADDING);
	if (ret <= UADK_P_FAIL)
		return ret;

	ret = RSA_verify_PKCS1_PSS_mgf1(priv->rsa, tbs,
					priv->md, priv->mgf1_md,
					priv->tbuf,
					priv->saltlen);
	if (ret <= UADK_P_FAIL) {
		UADK_ERR("failed to do RSA_verify_PKCS1_PSS_mgf1\n");
		return UADK_P_FAIL;
	}

	return UADK_P_SUCCESS;
}

static int uadk_signature_rsa_verify(void *vprsactx, const unsigned char *sig,
				     size_t siglen, const unsigned char *tbs,
				     size_t tbslen)
{
	struct PROV_RSA_SIG_CTX *priv = (struct PROV_RSA_SIG_CTX *)vprsactx;
	size_t rslen = 0;
	int ret;

	if (!priv || priv->soft) {
		ret = UADK_DO_SOFT;
		goto exe_soft;
	}

	if (!priv->md) {
		if (!setup_tbuf(priv)) {
			UADK_ERR("failed to setup tbuf in rsa verify\n");
			return UADK_P_FAIL;
		}
		ret = uadk_prov_rsa_public_verify(siglen, sig, priv->tbuf,
						  priv->rsa, priv->pad_mode);
		if (ret > UADK_P_FAIL)
			rslen = ret;
		goto end;
	}

	switch (priv->pad_mode) {
	case RSA_PKCS1_PADDING:
		ret = uadk_rsa_pkcs1_verify(priv, sig, siglen, tbs, tbslen);
		if (ret == UADK_P_SUCCESS)
			return ret;
		break;
	case RSA_X931_PADDING:
		if (!setup_tbuf(priv)) {
			UADK_ERR("failed to setup tbuf in rsa x931 verify\n");
			return UADK_P_FAIL;
		}
		/* software fallback will be done once in verify_recover, don't fallback here */
		ret = uadk_signature_rsa_verify_recover(priv, priv->tbuf, &rslen, 0, sig, siglen);
		if (ret <= UADK_P_FAIL)
			return ret;
		break;
	case RSA_PKCS1_PSS_PADDING:
		ret = uadk_rsa_pkcs1_pss_verify(priv, sig, siglen, tbs, tbslen);
		if (ret == UADK_P_SUCCESS)
			return ret;
		break;
	default:
		ret = UADK_DO_SOFT;
	}

end:
	if (ret == UADK_DO_SOFT)
		goto exe_soft;
	if (ret <= UADK_P_FAIL) {
		UADK_ERR("failed to do rsa verify with padding %d\n", priv->pad_mode);
		return UADK_P_FAIL;
	}

	if ((rslen != tbslen) || memcmp(tbs, priv->tbuf, rslen))
		return UADK_P_FAIL;

	return UADK_P_SUCCESS;

exe_soft:
	return uadk_rsa_sw_verify(vprsactx, sig, siglen, tbs, tbslen);
}

static int uadk_rsa_sw_sign(void *vprsactx, unsigned char *sig,
			    size_t *siglen, size_t sigsize,
			    const unsigned char *tbs, size_t tbslen)
{
	if (!enable_sw_offload || !get_default_rsa_signature().sign)
		return UADK_P_FAIL;

	UADK_INFO("switch to openssl software calculation in rsa signature.\n");
	return get_default_rsa_signature().sign(vprsactx, sig, siglen, sigsize, tbs, tbslen);
}


static int uadk_rsa_pks1_sign(struct PROV_RSA_SIG_CTX *priv, const unsigned char *tbs,
			      size_t tbslen, unsigned char *sig)
{
	const unsigned char *encoded = NULL;
	unsigned char *tmps = NULL;
	size_t encoded_len = 0;
	int ret;

	/* Compute the encoded digest. */
	if (priv->mdnid == NID_md5_sha1) {
		/*
		 * NID_md5_sha1 corresponds to the MD5/SHA1 combination in TLS 1.1 and
		 * earlier. It has no DigestInfo wrapper but otherwise is
		 * RSASSA-PKCS1-v1_5.
		 */
		if (tbslen != SSL_SIG_LENGTH) {
			UADK_ERR("invalid: rsa message length %zu is error\n", tbslen);
			return UADK_P_FAIL;
		}
		encoded_len = SSL_SIG_LENGTH;
		encoded = tbs;
	} else {
		if (!encode_pkcs1(&tmps, &encoded_len, priv->mdnid, tbs, tbslen))
			return UADK_P_FAIL;
		encoded = tmps;
	}

	ret = uadk_prov_rsa_private_sign(encoded_len, encoded, sig, priv->rsa, priv->pad_mode);
	OPENSSL_clear_free(tmps, encoded_len);
	return ret;
}

static int uadk_rsa_pks1_pss_sign(struct PROV_RSA_SIG_CTX *priv,
				  const unsigned char *tbs,
				  unsigned char *sig)
{
	int md_size = uadk_rsa_get_md_size(priv);
	int rsa_size = uadk_rsa_size(priv->rsa);
	int ret;

	/* Check PSS restrictions */
	if (rsa_pss_restricted(priv)) {
		switch (priv->saltlen) {
		case RSA_PSS_SALTLEN_DIGEST:
			if (priv->min_saltlen > md_size) {
				UADK_ERR("min pss saltlen %d is too small, mdsize %d\n",
					priv->min_saltlen, md_size);
				return UADK_P_FAIL;
			}
			[[fallthrough]];
		default:
			if (priv->saltlen >= 0 && priv->saltlen < priv->min_saltlen) {
				UADK_ERR("minpss saltlen %d is too small, saltlen %d\n",
					priv->min_saltlen, priv->saltlen);
				return UADK_P_FAIL;
			}
			break;
		}
	}

	if (!setup_tbuf(priv))
		return UADK_P_FAIL;

	if (!RSA_padding_add_PKCS1_PSS_mgf1(priv->rsa,
					    priv->tbuf, tbs,
					    priv->md, priv->mgf1_md,
					    priv->saltlen)) {
		UADK_ERR("failed to RSA_padding_add_PKCS1_PSS_mgf1\n");
		return UADK_P_FAIL;
	}

	ret = uadk_prov_rsa_private_sign(rsa_size, priv->tbuf, sig, priv->rsa, RSA_NO_PADDING);
	clean_tbuf(priv);

	return ret;
}

static int uadk_rsa_x931_sign(struct PROV_RSA_SIG_CTX *priv, const unsigned char *tbs,
			      size_t tbslen, unsigned char *sig)
{
	int rsa_size = uadk_rsa_size(priv->rsa);
	int ret;

	if ((size_t)rsa_size < tbslen + 1) {
		UADK_ERR("invalid: RSA key size = %d, expected minimum = %d in rsa x931 sign\n",
			(int)rsa_size, (int)tbslen + 1);
		return UADK_P_FAIL;
	}

	if (!setup_tbuf(priv)) {
		UADK_ERR("failed to setup tbuf in rsa x931 sign\n");
		return UADK_P_FAIL;
	}

	memcpy(priv->tbuf, tbs, tbslen);
	priv->tbuf[tbslen] = RSA_X931_hash_id(priv->mdnid);
	ret = uadk_prov_rsa_private_sign(tbslen + 1, priv->tbuf, sig,
					  priv->rsa, RSA_X931_PADDING);
	clean_tbuf(priv);
	return ret;
}

#ifndef FIPS_MODULE
static int uadk_rsa_asn1_octet_string_sign(struct PROV_RSA_SIG_CTX *priv,
					   const unsigned char *tbs, size_t tbslen,
					   unsigned char *sig)
{
	ASN1_OCTET_STRING tmpsig;
	int sigsize, rsasize;
	unsigned char *p, *s;
	int ret;

	tmpsig.type = V_ASN1_OCTET_STRING;
	tmpsig.length = tbslen;
	tmpsig.data = (unsigned char *)tbs;
	sigsize = i2d_ASN1_OCTET_STRING(&tmpsig, NULL);

	rsasize = uadk_rsa_size(priv->rsa);
	if (sigsize > (rsasize - RSA_PKCS1_PADDING_SIZE)) {
		UADK_ERR("signature size %d is too big for rsa key\n", sigsize);
		return UADK_P_FAIL;
	}

	s = OPENSSL_malloc((unsigned int)rsasize + 1);
	if (!s) {
		UADK_ERR("failed to malloc s\n");
		return UADK_P_FAIL;
	}

	p = s;
	i2d_ASN1_OCTET_STRING(&tmpsig, &p);
	ret = uadk_prov_rsa_private_sign(sigsize, s, sig, priv->rsa, RSA_PKCS1_PADDING);

	OPENSSL_clear_free(s, (unsigned int)rsasize + 1);
	return ret;
}

static int uadk_rsa_mdc2_sign(struct PROV_RSA_SIG_CTX *priv,
			      const unsigned char *tbs, size_t tbslen,
			      unsigned char *sig)
{
	if (priv->pad_mode != RSA_PKCS1_PADDING) {
		UADK_ERR("only PKCS#1 padding supported with MDC2\n");
		return UADK_P_FAIL;
	}
	return uadk_rsa_asn1_octet_string_sign(priv, tbs, tbslen, sig);
}
#endif

static int uadk_signature_rsa_sign(void *vprsactx, unsigned char *sig,
				   size_t *siglen, size_t sigsize,
				   const unsigned char *tbs, size_t tbslen)
{
	struct PROV_RSA_SIG_CTX *priv = (struct PROV_RSA_SIG_CTX *)vprsactx;
	size_t rsasize;
	size_t mdsize;
	int ret;

	if (!priv || priv->soft) {
		ret = UADK_DO_SOFT;
		goto exe_soft;
	}

	rsasize = uadk_rsa_size(priv->rsa);
	mdsize = uadk_rsa_get_md_size(priv);

	if (!sig) {
		*siglen = rsasize;
		return UADK_P_SUCCESS;
	}
	if (sigsize < rsasize) {
		UADK_ERR("invalid: signature size is %zu, should be at least %zu!\n",
			 sigsize, rsasize);
		return UADK_P_FAIL;
	}

	if (!mdsize) {
		ret = uadk_prov_rsa_private_sign(tbslen, tbs, sig,
						 priv->rsa, priv->pad_mode);
		goto end;
	}

	if (tbslen != mdsize) {
		UADK_ERR("invalid: rsa sign tbslen %zu is not equal to mdsize %zu\n",
			tbslen, mdsize);
		return UADK_P_FAIL;
	}

#ifndef FIPS_MODULE
	if (EVP_MD_is_a(priv->md, OSSL_DIGEST_NAME_MDC2)) {
		ret = uadk_rsa_mdc2_sign(priv, tbs, tbslen, sig);
		goto end;
	}
#endif
	switch (priv->pad_mode) {
	case RSA_X931_PADDING:
		ret = uadk_rsa_x931_sign(priv, tbs, tbslen, sig);
		break;
	case RSA_PKCS1_PADDING:
		ret = uadk_rsa_pks1_sign(priv, tbs, tbslen, sig);
		break;
	case RSA_PKCS1_PSS_PADDING:
		ret = uadk_rsa_pks1_pss_sign(priv, tbs, sig);
		break;
	default:
		ret = UADK_DO_SOFT;
	}

end:
	if (ret == UADK_DO_SOFT)
		goto exe_soft;
	if (ret <= UADK_P_FAIL) {
		UADK_ERR("failed to do rsa sign with padding %d\n", priv->pad_mode);
		return UADK_P_FAIL;
	}
	*siglen = ret;
	return UADK_P_SUCCESS;

exe_soft:
	return uadk_rsa_sw_sign(vprsactx, sig, siglen, sigsize, tbs, tbslen);
}

static int uadk_signature_rsa_sign_init(void *vprsactx, void *vrsa, const OSSL_PARAM params[])
{
	return uadk_rsa_signverify_init(vprsactx, vrsa, params, EVP_PKEY_OP_SIGN);
}

static void *uadk_signature_rsa_newctx(void *provctx, const char *propq)
{
	struct PROV_RSA_SIG_CTX *priv = OPENSSL_zalloc(sizeof(struct PROV_RSA_SIG_CTX));
	char *propq_copy = NULL;

	if (!priv)
		goto err;

	if  (propq != NULL) {
		propq_copy = OPENSSL_strdup(propq);
		if (!propq_copy)
			goto err;
	}

	priv->libctx = prov_libctx_of(provctx);
	priv->flag_allow_md = 1;
	priv->propq = propq_copy;
	/* Maximum for sign, auto for verify */
	priv->saltlen = RSA_PSS_SALTLEN_AUTO;
	priv->min_saltlen = -1;
	return priv;

err:
	OPENSSL_free(priv);
	UADK_ERR("%s failed.\n", __func__);
	return NULL;
}

static void uadk_signature_rsa_freectx(void *vprsactx)
{
	struct PROV_RSA_SIG_CTX *priv = (struct PROV_RSA_SIG_CTX *)vprsactx;

	if (!priv)
		return;

	EVP_MD_CTX_free(priv->mdctx);
	EVP_MD_free(priv->md);
	EVP_MD_free(priv->mgf1_md);
	OPENSSL_free(priv->propq);
	free_tbuf(priv);
	RSA_free(priv->rsa);

	OPENSSL_clear_free(priv, sizeof(*priv));
}

static const OSSL_PARAM settable_ctx_params[] = {
	OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
	OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PROPERTIES, NULL, 0),
	OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
	OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, NULL, 0),
	OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_PROPERTIES, NULL, 0),
	OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL, 0),
	OSSL_PARAM_END
};

static const OSSL_PARAM settable_ctx_params_no_digest[] = {
	OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
	OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, NULL, 0),
	OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_PROPERTIES, NULL, 0),
	OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL, 0),
	OSSL_PARAM_END
};

static const OSSL_PARAM *uadk_signature_rsa_settable_ctx_params(void *vprsactx,
								void *provctx)
{
	struct PROV_RSA_SIG_CTX *priv = (struct PROV_RSA_SIG_CTX *)vprsactx;

	if (priv != NULL && !priv->flag_allow_md)
		return settable_ctx_params_no_digest;

	return settable_ctx_params;
}

static int uadk_rsa_check_padding(const struct PROV_RSA_SIG_CTX *prsactx,
				  const char *mdname, const char *mgf1_mdname,
				  int mdnid)
{
	switch (prsactx->pad_mode) {
	case RSA_NO_PADDING:
		UADK_ERR("invalid rsa padding mode.\n");
		return UADK_P_FAIL;
	case RSA_X931_PADDING:
		if (RSA_X931_hash_id(mdnid) == -1) {
			UADK_ERR("invalid rsa x931 digest.\n");
			return UADK_P_FAIL;
		}
		break;
	case RSA_PKCS1_PSS_PADDING:
		if (prsactx->min_saltlen != -1) {
			if ((mdname != NULL && !EVP_MD_is_a(prsactx->md, mdname)) ||
			    (mgf1_mdname != NULL &&
			    !EVP_MD_is_a(prsactx->mgf1_md, mgf1_mdname))) {
				UADK_ERR("rsa digest is not allowed.\n");
				return UADK_P_FAIL;
			}
		}
		break;
	default:
		break;
	}

	return UADK_P_SUCCESS;
}

static int uadk_digest_md_to_nid(const EVP_MD *md, const OSSL_ITEM *it, size_t it_len)
{
	size_t i;

	if (!md)
		return NID_undef;

	for (i = 0; i < it_len; i++)
		if (EVP_MD_is_a(md, it[i].ptr))
			return (int)it[i].id;
	return NID_undef;
}

static int uadk_digest_get_approved_nid(const EVP_MD *md)
{
	static const OSSL_ITEM name_to_nid[] = {
		{ NID_sha1,      OSSL_DIGEST_NAME_SHA1      },
		{ NID_sha224,    OSSL_DIGEST_NAME_SHA2_224  },
		{ NID_sha256,    OSSL_DIGEST_NAME_SHA2_256  },
		{ NID_sha384,    OSSL_DIGEST_NAME_SHA2_384  },
		{ NID_sha512,    OSSL_DIGEST_NAME_SHA2_512  },
		{ NID_sha512_224, OSSL_DIGEST_NAME_SHA2_512_224 },
		{ NID_sha512_256, OSSL_DIGEST_NAME_SHA2_512_256 },
		{ NID_sha3_224,  OSSL_DIGEST_NAME_SHA3_224  },
		{ NID_sha3_256,  OSSL_DIGEST_NAME_SHA3_256  },
		{ NID_sha3_384,  OSSL_DIGEST_NAME_SHA3_384  },
		{ NID_sha3_512,  OSSL_DIGEST_NAME_SHA3_512  },
	};

	return uadk_digest_md_to_nid(md, name_to_nid, OSSL_NELEM(name_to_nid));
}

static int uadk_digest_rsa_sign_get_md_nid(OSSL_LIB_CTX *ctx, const EVP_MD *md,
				    int sha1_allowed)
{
	return uadk_digest_get_approved_nid(md);
}

static int uadk_rsa_setup_md(struct PROV_RSA_SIG_CTX *ctx, const char *mdname,
			     const char *mdprops)
{
	size_t mdname_len;
	int sha1_allowed;
	int md_nid;
	EVP_MD *md;

	if (!mdprops)
		mdprops = ctx->propq;

	if (mdname != NULL) {
		md = EVP_MD_fetch(ctx->libctx, mdname, mdprops);
		sha1_allowed = (ctx->operation != EVP_PKEY_OP_SIGN);
		md_nid = uadk_digest_rsa_sign_get_md_nid(ctx->libctx, md, sha1_allowed);
		mdname_len = strlen(mdname);
		if (!md || md_nid <= 0 ||
		    !uadk_rsa_check_padding(ctx, mdname, NULL, md_nid) ||
		    mdname_len >= sizeof(ctx->mdname)) {
			UADK_ERR("invalid: mdname %s, md_nid %d or name length %zu is incorrect\n",
				 mdname, md_nid, mdname_len);
			if (md)
				EVP_MD_free(md);
			return UADK_P_FAIL;
		}

		if (!ctx->mgf1_md_set) {
			if (!EVP_MD_up_ref(md)) {
				if (md)
					EVP_MD_free(md);
				return UADK_P_FAIL;
			}
			if (ctx->mgf1_md)
				EVP_MD_free(ctx->mgf1_md);
			ctx->mgf1_md = md;
			ctx->mgf1_mdnid = md_nid;
			OPENSSL_strlcpy(ctx->mgf1_mdname, mdname, sizeof(ctx->mgf1_mdname));
		}

		if (ctx->mdctx) {
			EVP_MD_CTX_free(ctx->mdctx);
			ctx->mdctx = NULL;
		}

		if (ctx->md)
			EVP_MD_free(ctx->md);

		ctx->md = md;
		ctx->mdnid = md_nid;
		OPENSSL_strlcpy(ctx->mdname, mdname, sizeof(ctx->mdname));
	}

	return UADK_P_SUCCESS;
}

static int uadk_signature_rsa_digest_signverify_init(void *vprsactx, const char *mdname,
						     void *vrsa, const OSSL_PARAM params[],
						     int operation)
{
	struct PROV_RSA_SIG_CTX *priv = (struct PROV_RSA_SIG_CTX *)vprsactx;

	if (!uadk_rsa_signverify_init(vprsactx, vrsa, params, operation))
		return UADK_P_FAIL;

	if (mdname != NULL &&
	    (mdname[0] == '\0' || OPENSSL_strcasecmp(priv->mdname, mdname) != 0) &&
	    !uadk_rsa_setup_md(priv, mdname, priv->propq))
		return UADK_P_FAIL;

	priv->flag_allow_md = 0;

	if (!priv->mdctx) {
		priv->mdctx = EVP_MD_CTX_new();
		if (!priv->mdctx)
			goto error;
	}

	if (!EVP_DigestInit_ex2(priv->mdctx, priv->md, params))
		goto error;

	return UADK_P_SUCCESS;

error:
	if (priv->mdctx) {
		EVP_MD_CTX_free(priv->mdctx);
		priv->mdctx = NULL;
	}

	return UADK_P_FAIL;
}

static int uadk_signature_rsa_digest_sign_init(void *vprsactx, const char *mdname,
					       void *vrsa, const OSSL_PARAM params[])
{
	return uadk_signature_rsa_digest_signverify_init(vprsactx, mdname, vrsa,
							 params, EVP_PKEY_OP_SIGN);
}

static int uadk_signature_rsa_digest_sign_update(void *vprsactx,
						 const unsigned char *data,
						 size_t datalen)
{
	struct PROV_RSA_SIG_CTX *priv = (struct PROV_RSA_SIG_CTX *)vprsactx;

	if (!priv || !priv->mdctx)
		return UADK_P_FAIL;

	return EVP_DigestUpdate(priv->mdctx, data, datalen);
}

#define ASN1_SEQUENCE_RSA 0x30
#define ASN1_OCTET_STRING_ 0x04
#define ASN1_NULL 0x05
#define ASN1_OID 0x06

/* SHA OIDs are of the form: (2 16 840 1 101 3 4 2 |n|) */
#define ENCODE_DIGESTINFO_SHA(name, n, sz)				\
static const unsigned char digestinfo_##name##_der[] = {		\
	ASN1_SEQUENCE_RSA, 0x11 + sz,					\
	ASN1_SEQUENCE_RSA, 0x0d,					\
	ASN1_OID, 0x09, 2 * 40 + 16, 0x86, 0x48, 1, 101, 3, 4, 2, n,	\
	ASN1_NULL, 0x00,						\
	ASN1_OCTET_STRING_, sz						\
}

/* SHA-1 (1 3 14 3 2 26) */
static const unsigned char digestinfo_sha1_der[] = {
	ASN1_SEQUENCE_RSA, 0x0d + SHA_DIGEST_LENGTH,
	ASN1_SEQUENCE_RSA, 0x09,
	ASN1_OID, 0x05, 1 * 40 + 3, 14, 3, 2, 26,
	ASN1_NULL, 0x00,
	ASN1_OCTET_STRING_, SHA_DIGEST_LENGTH
};

ENCODE_DIGESTINFO_SHA(sha256, 0x01, SHA256_DIGEST_LENGTH);
ENCODE_DIGESTINFO_SHA(sha384, 0x02, SHA384_DIGEST_LENGTH);
ENCODE_DIGESTINFO_SHA(sha512, 0x03, SHA512_DIGEST_LENGTH);
ENCODE_DIGESTINFO_SHA(sha224, 0x04, SHA224_DIGEST_LENGTH);
ENCODE_DIGESTINFO_SHA(sha512_224, 0x05, SHA224_DIGEST_LENGTH);
ENCODE_DIGESTINFO_SHA(sha512_256, 0x06, SHA256_DIGEST_LENGTH);
ENCODE_DIGESTINFO_SHA(sha3_224, 0x07, SHA224_DIGEST_LENGTH);
ENCODE_DIGESTINFO_SHA(sha3_256, 0x08, SHA256_DIGEST_LENGTH);
ENCODE_DIGESTINFO_SHA(sha3_384, 0x09, SHA384_DIGEST_LENGTH);
ENCODE_DIGESTINFO_SHA(sha3_512, 0x0a, SHA512_DIGEST_LENGTH);

#define MD_CASE(name)					\
	case NID_##name:				\
		*len = sizeof(digestinfo_##name##_der);	\
		return digestinfo_##name##_der


static const unsigned char *uadk_rsa_digestinfo_encoding(int md_nid, size_t *len)
{
	switch (md_nid) {
	MD_CASE(sha1);
	MD_CASE(sha224);
	MD_CASE(sha256);
	MD_CASE(sha384);
	MD_CASE(sha512);
	MD_CASE(sha512_224);
	MD_CASE(sha512_256);
	MD_CASE(sha3_224);
	MD_CASE(sha3_256);
	MD_CASE(sha3_384);
	MD_CASE(sha3_512);
	default:
		return NULL;
	}
}

/*
 * Encodes a DigestInfo prefix of hash |type| and digest |m|, as
 * described in EMSA-PKCS1-v1_5-ENCODE, RFC 3447 section 9.2 step 2. This
 * encodes the DigestInfo (T and tLen) but does not add the padding.
 *
 * On success, it returns one and sets |*out| to a newly allocated buffer
 * containing the result and |*out_len| to its length. The caller must free
 * |*out| with OPENSSL_free(). Otherwise, it returns zero.
 */
static int encode_pkcs1(unsigned char **out, size_t *out_len, int type,
			const unsigned char *m, size_t m_len)
{
	size_t di_prefix_len, dig_info_len;
	const unsigned char *di_prefix;
	unsigned char *dig_info;

	if (type == NID_undef) {
		UADK_ERR("invalid: rsa unknown algorithm type.\n");
		return UADK_P_FAIL;
	}
	di_prefix = uadk_rsa_digestinfo_encoding(type, &di_prefix_len);
	if (!di_prefix) {
		UADK_ERR("invalid: rsa di prefix is NULL.\n");
		return UADK_P_FAIL;
	}
	dig_info_len = di_prefix_len + m_len;
	dig_info = OPENSSL_malloc(dig_info_len);
	if (!dig_info) {
		UADK_ERR("failed to malloc dig info.\n");
		return UADK_P_FAIL;
	}
	memcpy(dig_info, di_prefix, di_prefix_len);
	memcpy(dig_info + di_prefix_len, m, m_len);

	*out = dig_info;
	*out_len = dig_info_len;
	return UADK_P_SUCCESS;
}

static int uadk_signature_rsa_digest_sign_final(void *vprsactx, unsigned char *sig,
						size_t *siglen, size_t sigsize)
{
	struct PROV_RSA_SIG_CTX *priv = (struct PROV_RSA_SIG_CTX *)vprsactx;
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int dlen = 0;

	if (!priv)
		return UADK_P_FAIL;

	if (!priv->mdctx)
		return UADK_P_FAIL;

	/*
	 * If sig is NULL then we're just finding out the sig size. Other fields
	 * are ignored. Defer to rsa_sign.
	 */
	if (sig != NULL) {
		/*
		 * The digests used here are all known (see rsa_get_md_nid()), so they
		 * should not exceed the internal buffer size of EVP_MAX_MD_SIZE.
		 */
		if (!EVP_DigestFinal_ex(priv->mdctx, digest, &dlen))
			return UADK_P_FAIL;
	}

	priv->flag_allow_md = 1;

	return uadk_signature_rsa_sign(vprsactx, sig, siglen, sigsize, digest, (size_t)dlen);
}

static int uadk_signature_rsa_digest_verify_init(void *vprsactx, const char *mdname,
						 void *vrsa, const OSSL_PARAM params[])
{
	return uadk_signature_rsa_digest_signverify_init(vprsactx, mdname, vrsa,
							 params, EVP_PKEY_OP_VERIFY);
}

static int uadk_signature_rsa_digest_verify_update(void *vprsactx, const unsigned char *data,
						   size_t datalen)
{
	struct PROV_RSA_SIG_CTX *priv = (struct PROV_RSA_SIG_CTX *)vprsactx;

	if (!priv || !priv->mdctx)
		return UADK_P_FAIL;

	return EVP_DigestUpdate(priv->mdctx, data, datalen);
}

static int uadk_signature_rsa_digest_verify_final(void *vprsactx, const unsigned char *sig,
						  size_t siglen)
{
	struct PROV_RSA_SIG_CTX *priv = (struct PROV_RSA_SIG_CTX *)vprsactx;
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int dlen = 0;

	if (!priv)
		return UADK_P_FAIL;

	if (!priv->mdctx)
		return UADK_P_FAIL;

	/*
	 * The digests used here are all known (see rsa_get_md_nid()), so they
	 * should not exceed the internal buffer size of EVP_MAX_MD_SIZE.
	 */
	if (!EVP_DigestFinal_ex(priv->mdctx, digest, &dlen))
		return UADK_P_FAIL;

	priv->flag_allow_md = 1;
	return uadk_signature_rsa_verify(vprsactx, sig, siglen, digest, (size_t)dlen);
}

static void *uadk_signature_rsa_dupctx(void *vprsactx)
{
	if (!get_default_rsa_signature().dupctx)
		return NULL;

	return get_default_rsa_signature().dupctx(vprsactx);
}

static int uadk_signature_rsa_get_ctx_params(void *vprsactx, OSSL_PARAM *params)
{
	if (!get_default_rsa_signature().get_ctx_params)
		return UADK_P_FAIL;

	return get_default_rsa_signature().get_ctx_params(vprsactx, params);
}

static const OSSL_PARAM *uadk_signature_rsa_gettable_ctx_md_params(void *vprsactx)
{
	if (!get_default_rsa_signature().gettable_ctx_md_params)
		return NULL;

	return get_default_rsa_signature().gettable_ctx_md_params(vprsactx);
}

static int uadk_signature_rsa_set_ctx_md_params(void *vprsactx, const OSSL_PARAM params[])
{
	if (!get_default_rsa_signature().set_ctx_md_params)
		return UADK_P_FAIL;

	return get_default_rsa_signature().set_ctx_md_params(vprsactx, params);
}

static const OSSL_PARAM *uadk_signature_rsa_settable_ctx_md_params(void *vprsactx)
{
	if (!get_default_rsa_signature().settable_ctx_md_params)
		return NULL;

	return get_default_rsa_signature().settable_ctx_md_params(vprsactx);
}

static const OSSL_PARAM *uadk_signature_rsa_gettable_ctx_params(ossl_unused void *vprsactx,
								ossl_unused void *provctx)
{
	if (!get_default_rsa_signature().gettable_ctx_params)
		return NULL;

	return get_default_rsa_signature().gettable_ctx_params(vprsactx, provctx);
}

static int uadk_signature_rsa_get_ctx_md_params(void *vprsactx, OSSL_PARAM *params)
{
	if (!get_default_rsa_signature().get_ctx_md_params)
		return UADK_P_FAIL;

	return get_default_rsa_signature().get_ctx_md_params(vprsactx, params);
}
