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

UADK_PKEY_ASYM_CIPHER_DESCR(rsa, RSA);

struct PROV_RSA_ASYM_CTX {
	OSSL_LIB_CTX *libctx;
	RSA *rsa;
	int pad_mode;
	int operation;
	/* OAEP message digest */
	EVP_MD *oaep_md;
	/* message digest for MGF1 */
	EVP_MD *mgf1_md;
	/* OAEP label */
	unsigned char *oaep_label;
	size_t oaep_labellen;
	/* TLS padding */
	unsigned int client_version;
	unsigned int alt_version;

	unsigned int soft : 1;
};

static pthread_mutex_t asym_mutex = PTHREAD_MUTEX_INITIALIZER;

static UADK_PKEY_ASYM_CIPHER get_default_rsa_asym_cipher(void)
{
	static UADK_PKEY_ASYM_CIPHER s_asym_cipher;
	static int initilazed;

	pthread_mutex_lock(&asym_mutex);
	if (!initilazed) {
		UADK_PKEY_ASYM_CIPHER *asym_cipher =
			(UADK_PKEY_ASYM_CIPHER *)EVP_ASYM_CIPHER_fetch(NULL, "RSA",
								       "provider=default");

		if (asym_cipher) {
			s_asym_cipher = *asym_cipher;
			EVP_ASYM_CIPHER_free((EVP_ASYM_CIPHER *)asym_cipher);
			initilazed = 1;
		} else {
			UADK_ERR("failed to EVP_ASYM_CIPHER_fetch default RSA provider\n");
		}
	}
	pthread_mutex_unlock(&asym_mutex);
	return s_asym_cipher;
}

static int add_rsa_pubenc_padding(int flen, const unsigned char *from,
				  unsigned char *buf, int num, int padding)
{
	int ret;

	switch (padding) {
	case RSA_PKCS1_PADDING:
		ret = RSA_padding_add_PKCS1_type_2(buf, num, from, flen);
		if (!ret)
			UADK_ERR("RSA_PKCS1_PADDING err.\n");
		break;
	case RSA_PKCS1_OAEP_PADDING:
		ret = RSA_padding_add_PKCS1_OAEP(buf, num, from, flen, NULL, 0);
		if (!ret)
			UADK_ERR("RSA_PKCS1_OAEP_PADDING err.\n");
		break;
	default:
		ret = UADK_P_FAIL;
	}

	return ret;
}

static int check_rsa_pridec_padding(unsigned char *to, int num,
				    const unsigned char *buf, int flen,
				    int padding)
{
	int ret;

	switch (padding) {
	case RSA_PKCS1_PADDING:
		ret = RSA_padding_check_PKCS1_type_2(to, num, buf, flen, num);
		if (ret == CHECK_PADDING_FAIL)
			UADK_ERR("RSA_PKCS1_PADDING err.\n");
		break;
	case RSA_PKCS1_OAEP_PADDING:
		ret = RSA_padding_check_PKCS1_OAEP(to, num, buf, flen, num,
						   NULL, 0);
		if (ret == CHECK_PADDING_FAIL)
			UADK_ERR("RSA_PKCS1_OAEP_PADDING err.\n");
		break;
	default:
		ret = UADK_P_FAIL;
	}

	if (ret == CHECK_PADDING_FAIL)
		ret = UADK_P_FAIL;

	return ret;
}

static int crypt_trans_bn(struct uadk_rsa_sess *rsa_sess, unsigned char *buf, int num_bytes)
{
	BIGNUM *bn;
	int ret;

	bn = BN_bin2bn((const unsigned char *)rsa_sess->req.dst,
			   rsa_sess->req.dst_bytes, NULL);
	if (!bn)
		return UADK_P_FAIL;

	ret = BN_bn2binpad(bn, buf, num_bytes);
	if (ret == BN_ERR)
		ret = UADK_P_FAIL;

	BN_free(bn);

	return ret;
}

static int uadk_prov_rsa_public_encrypt(int flen, const unsigned char *from,
					unsigned char *to, RSA *rsa, int padding)
{
	struct rsa_pubkey_param *pub_enc = NULL;
	struct uadk_rsa_sess *rsa_sess;
	unsigned char *from_buf = NULL;
	int num_bytes, is_crt, ret;

	ret = check_rsa_input_para(flen, from, to, rsa);
	if (ret != UADK_P_SUCCESS)
		return ret;

	ret = rsa_pkey_param_alloc(&pub_enc, NULL);
	if (ret == -ENOMEM)
		return UADK_P_FAIL;

	is_crt = check_rsa_is_crt(rsa);

	rsa_sess = rsa_get_eng_session(rsa, uadk_rsa_bits(rsa), is_crt);
	if (!rsa_sess) {
		ret = UADK_DO_SOFT;
		goto free_pkey;
	}

	ret = rsa_create_pub_bn_ctx(rsa, pub_enc, &from_buf, &num_bytes);
	if (ret <= 0) {
		ret = UADK_P_FAIL;
		goto free_sess;
	}

	ret = add_rsa_pubenc_padding(flen, from, from_buf, num_bytes, padding);
	if (!ret) {
		ret = UADK_P_FAIL;
		goto free_buf;
	}

	ret = rsa_fill_pubkey(pub_enc, rsa_sess, from_buf, to);
	if (!ret) {
		ret = UADK_P_FAIL;
		goto free_buf;
	}

	ret = rsa_do_crypto(rsa_sess);
	if (!ret || rsa_sess->req.status) {
		ret = UADK_DO_SOFT;
		goto free_buf;
	}

	ret = crypt_trans_bn(rsa_sess, to, num_bytes);

free_buf:
	rsa_free_pub_bn_ctx(from_buf);
free_sess:
	rsa_free_eng_session(rsa_sess);
free_pkey:
	rsa_pkey_param_free(&pub_enc, NULL);
	return ret;
}

static int uadk_prov_rsa_private_decrypt(int flen, const unsigned char *from,
					 unsigned char *to, RSA *rsa, int padding)
{
	struct rsa_prikey_param *pri = NULL;
	unsigned char *from_buf = NULL;
	struct uadk_rsa_sess *rsa_sess;
	int num_bytes, ret;

	ret = check_rsa_input_para(flen, from, to, rsa);
	if (ret != UADK_P_SUCCESS)
		return ret;

	ret = rsa_pkey_param_alloc(NULL, &pri);
	if (ret == -ENOMEM)
		return UADK_P_FAIL;

	pri->is_crt = check_rsa_is_crt(rsa);

	rsa_sess = rsa_get_eng_session(rsa, uadk_rsa_bits(rsa), pri->is_crt);
	if (!rsa_sess) {
		ret = UADK_DO_SOFT;
		goto free_pkey;
	}

	ret = rsa_create_pri_bn_ctx(rsa, pri, &from_buf, &num_bytes);
	if (ret <= 0) {
		ret = UADK_P_FAIL;
		goto free_sess;
	}

	if (flen != num_bytes) {
		ret = UADK_P_FAIL;
		goto free_buf;
	}

	ret = rsa_fill_prikey(rsa, rsa_sess, pri, from_buf, to);
	if (!ret) {
		ret = UADK_P_FAIL;
		goto free_buf;
	}

	memcpy(rsa_sess->req.src, from, rsa_sess->req.src_bytes);

	ret = rsa_do_crypto(rsa_sess);
	if (!ret || rsa_sess->req.status) {
		ret = UADK_DO_SOFT;
		goto free_buf;
	}

	ret = crypt_trans_bn(rsa_sess, from_buf, num_bytes);
	if (!ret)
		goto free_buf;

	ret = check_rsa_pridec_padding(to, num_bytes, from_buf, flen, padding);
	if (!ret)
		ret = UADK_P_FAIL;

free_buf:
	rsa_free_pri_bn_ctx(from_buf);
free_sess:
	rsa_free_eng_session(rsa_sess);
free_pkey:
	rsa_pkey_param_free(NULL, &pri);
	return ret;
}

static int uadk_rsa_asym_init(void *vprsactx, void *vrsa,
			      const OSSL_PARAM params[], int operation)
{
	struct PROV_RSA_ASYM_CTX *priv = (struct PROV_RSA_ASYM_CTX *)vprsactx;

	if (priv == NULL || vrsa == NULL)
		return UADK_P_FAIL;

	priv->rsa = vrsa;
	priv->operation = operation;

	switch (uadk_rsa_test_flags(priv->rsa, RSA_FLAG_TYPE_MASK)) {
	case RSA_FLAG_TYPE_RSA:
		priv->pad_mode = RSA_PKCS1_PADDING;
		break;
	case RSA_FLAG_TYPE_RSASSAPSS:
		priv->pad_mode = RSA_PKCS1_PSS_PADDING;
		break;
	default:
		UADK_ERR("rsa asym operation not supported this keytype!\n");
		return UADK_P_FAIL;
	}

	if (uadk_prov_rsa_init())
		priv->soft = 1;

	return UADK_P_SUCCESS;
}

static void *uadk_asym_cipher_rsa_newctx(void *provctx)
{
	struct PROV_RSA_ASYM_CTX *priv = NULL;

	priv = OPENSSL_zalloc(sizeof(*priv));
	if (priv == NULL)
		return NULL;
	priv->libctx = prov_libctx_of(provctx);

	return priv;
}

static void uadk_asym_cipher_rsa_freectx(void *vprsactx)
{
	struct PROV_RSA_ASYM_CTX *priv = (struct PROV_RSA_ASYM_CTX *)vprsactx;

	if (priv == NULL)
		return;

	OPENSSL_free(priv);
}

static void *uadk_asym_cipher_rsa_dupctx(void *vprsactx)
{
	if (!get_default_rsa_asym_cipher().dupctx)
		return NULL;
	return get_default_rsa_asym_cipher().dupctx(vprsactx);
}

static int uadk_asym_cipher_rsa_encrypt_init(void *vprsactx, void *vrsa,
					     const OSSL_PARAM params[])
{
	return uadk_rsa_asym_init(vprsactx, vrsa, params, EVP_PKEY_OP_ENCRYPT);
}

static int uadk_asym_cipher_rsa_decrypt_init(void *vprsactx, void *vrsa,
					     const OSSL_PARAM params[])
{
	return uadk_rsa_asym_init(vprsactx, vrsa, params, EVP_PKEY_OP_DECRYPT);
}

static int uadk_rsa_sw_encrypt(void *vprsactx, unsigned char *out,
			       size_t *outlen, size_t outsize,
			       const unsigned char *in, size_t inlen)
{
	if (!enable_sw_offload || !get_default_rsa_asym_cipher().encrypt)
		return UADK_P_FAIL;

	UADK_INFO("switch to openssl software calculation in rsa encryption.\n");

	return get_default_rsa_asym_cipher().encrypt(vprsactx, out, outlen, outsize, in, inlen);
}

static int uadk_asym_cipher_rsa_encrypt(void *vprsactx, unsigned char *out,
					size_t *outlen, size_t outsize,
					const unsigned char *in, size_t inlen)
{
	struct PROV_RSA_ASYM_CTX *priv = (struct PROV_RSA_ASYM_CTX *)vprsactx;
	size_t len;
	int ret;

	if (!priv || priv->soft) {
		ret = UADK_DO_SOFT;
		goto exe_soft;
	}

	if (out == NULL) {
		len = uadk_rsa_size(priv->rsa);
		if (len == 0) {
			UADK_ERR("invalid: rsa encrypt size.\n");
			return UADK_P_FAIL;
		}
		*outlen = len;
		return UADK_P_SUCCESS;
	}

	ret = uadk_prov_rsa_public_encrypt(inlen, in, out, priv->rsa, priv->pad_mode);
	if (ret == UADK_DO_SOFT || ret == UADK_P_FAIL)
		goto exe_soft;

	*outlen = ret;

	return UADK_P_SUCCESS;
exe_soft:
	if (ret == UADK_DO_SOFT)
		return uadk_rsa_sw_encrypt(vprsactx, out, outlen, outsize, in, inlen);
	return UADK_P_FAIL;
}

static int uadk_rsa_sw_decrypt(void *vprsactx, unsigned char *out,
			       size_t *outlen, size_t outsize,
			       const unsigned char *in, size_t inlen)
{
	if (!enable_sw_offload || !get_default_rsa_asym_cipher().decrypt)
		return UADK_P_FAIL;

	UADK_INFO("switch to openssl software calculation in rsa decryption.\n");
	return get_default_rsa_asym_cipher().decrypt(vprsactx, out, outlen, outsize, in, inlen);
}

static int uadk_asym_cipher_rsa_decrypt(void *vprsactx, unsigned char *out,
					size_t *outlen, size_t outsize,
					const unsigned char *in, size_t inlen)
{
	struct PROV_RSA_ASYM_CTX *priv = (struct PROV_RSA_ASYM_CTX *)vprsactx;
	size_t len = uadk_rsa_size(priv->rsa);
	int ret;

	if (priv->soft) {
		ret = UADK_DO_SOFT;
		goto exe_soft;
	}

	if (out == NULL) {
		if (len == 0) {
			UADK_ERR("invalid: rsa decrypt size.\n");
			return UADK_P_FAIL;
		}
		*outlen = len;
		return UADK_P_SUCCESS;
	}

	if (outsize < len) {
		UADK_ERR("invalid: rsa decrypt outsize is too small.\n");
		return UADK_P_FAIL;
	}

	ret = uadk_prov_rsa_private_decrypt(inlen, in, out, priv->rsa, priv->pad_mode);
	if (ret == UADK_DO_SOFT || ret == UADK_P_FAIL)
		goto exe_soft;

	*outlen = ret;

	return UADK_P_SUCCESS;
exe_soft:
	if (ret == UADK_DO_SOFT)
		return uadk_rsa_sw_decrypt(vprsactx, out, outlen, outsize, in, inlen);
	return UADK_P_FAIL;
}

static int uadk_asym_cipher_rsa_get_ctx_params(void *vprsactx, OSSL_PARAM *params)
{
	if (!get_default_rsa_asym_cipher().get_ctx_params)
		return UADK_P_FAIL;

	return get_default_rsa_asym_cipher().get_ctx_params(vprsactx, params);
}

static const OSSL_PARAM *uadk_asym_cipher_rsa_gettable_ctx_params(void *vprsactx,
								  void *provctx)
{
	if (!get_default_rsa_asym_cipher().gettable_ctx_params)
		return NULL;

	return get_default_rsa_asym_cipher().gettable_ctx_params(vprsactx, provctx);
}

static int uadk_asym_cipher_rsa_set_ctx_params(void *vprsactx, const OSSL_PARAM params[])
{
	if (!get_default_rsa_asym_cipher().set_ctx_params)
		return UADK_P_FAIL;

	return get_default_rsa_asym_cipher().set_ctx_params(vprsactx, params);
}

static const OSSL_PARAM *uadk_asym_cipher_rsa_settable_ctx_params(void *vprsactx,
								  void *provctx)
{
	if (!get_default_rsa_asym_cipher().settable_ctx_params)
		return NULL;

	return get_default_rsa_asym_cipher().settable_ctx_params(vprsactx, provctx);
}
