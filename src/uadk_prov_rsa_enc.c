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
#include <openssl/prov_ssl.h>
#include <openssl/rand.h>

#define RSA_PKCS1_PADDING_SIZE		11
#define PKCS1_TLS_ZERO_PADD		0x00
#define PKCS1_TLS_NONE_ZERO_PADD	0x02
#define CLIENT_VERSION_SHIFT		8
#define PKCS1_TLS_PADDING_POS		2
#define CLIENT_VERSION_MASK		0xFF

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

/**
 * Checks and removes PKCS#1 v1.5 padding for TLS RSA decryption.
 * This function validates and strips PKCS#1 type 2 (v1.5) padding from an RSA-encrypted
 * pre-master secret as used in TLS. It ensures the decrypted data conforms to the expected
 * format, checks the client version, and provides constant-time fallback to random data
 * if the padding or version is invalid, as required by the TLS protocol to prevent
 * side-channel attacks.
 */
static int RSA_padding_check_PKCS1_type_2_TLS(OSSL_LIB_CTX *libctx,
					      unsigned char *to, size_t tlen,
					      const unsigned char *from, size_t flen,
					      int client_version, int alt_version)
{
	unsigned char rand_premaster[SSL_MAX_MASTER_KEY_LENGTH];
	int premaster_len = SSL_MAX_MASTER_KEY_LENGTH;
	int plen, good;
	unsigned char *p;
	int i;

	if (flen < RSA_PKCS1_PADDING_SIZE || tlen < premaster_len)
		goto err;

	p = (unsigned char *)from;
	if (p[0] != PKCS1_TLS_ZERO_PADD || p[1] != PKCS1_TLS_NONE_ZERO_PADD)
		goto err;

	for (i = PKCS1_TLS_PADDING_POS; i < flen; i++) {
		if (p[i] == PKCS1_TLS_ZERO_PADD)
			break;
	}

	if (i == flen || i < (RSA_PKCS1_PADDING_SIZE - 1))
		goto err;
	plen = flen - (i + 1);
	if (plen != premaster_len)
		goto err;
	memcpy(to, p + i + 1, premaster_len);

	good = (to[0] == (client_version >> CLIENT_VERSION_SHIFT) &&
		to[1] == (client_version & CLIENT_VERSION_MASK));
	if (!good && alt_version > 0)
		good = (to[0] == (alt_version >> CLIENT_VERSION_SHIFT)
			&& to[1] ==
			(alt_version & CLIENT_VERSION_MASK));
	if (!good) {
		if (RAND_bytes_ex(libctx, rand_premaster, premaster_len, 0) <= 0)
			goto err;
		memcpy(to, rand_premaster, premaster_len);
	}

	OPENSSL_cleanse(rand_premaster, premaster_len);
	return premaster_len;
err:
	if (RAND_bytes_ex(libctx, rand_premaster, premaster_len, 0) > 0)
		memcpy(to, rand_premaster, premaster_len);
	OPENSSL_cleanse(rand_premaster, premaster_len);

	return CHECK_PADDING_FAIL;
}

static int add_rsa_pubenc_padding(int flen, const unsigned char *from,
				  unsigned char *buf, int num, int padding)
{
	int ret;

	switch (padding) {
	case RSA_PKCS1_PADDING:
		ret = RSA_padding_add_PKCS1_type_2(buf, num, from, flen);
		break;
	case RSA_PKCS1_OAEP_PADDING:
		ret = RSA_padding_add_PKCS1_OAEP(buf, num, from, flen, NULL, 0);
		break;
	case RSA_NO_PADDING:
		ret = RSA_padding_add_none(buf, num, from, flen);
		break;
	default:
		ret = UADK_P_FAIL;
	}

	if (ret <= UADK_P_FAIL) {
		ret = UADK_P_FAIL;
		UADK_ERR("failed to add rsa encrypt padding %d\n", padding);
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
		break;
	case RSA_PKCS1_OAEP_PADDING:
		ret = RSA_padding_check_PKCS1_OAEP(to, num, buf, flen, num,
						   NULL, 0);
		break;
	case RSA_NO_PADDING:
		memcpy(to, buf, flen);
		ret = flen;
		break;
	default:
		ret = CHECK_PADDING_FAIL;
	}

	if (ret == CHECK_PADDING_FAIL) {
		UADK_ERR("failed to check rsa decrypt %d\n", padding);
		ret = UADK_P_FAIL;
	}

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

	if (!priv || !vrsa)
		return UADK_P_FAIL;

	if (!RSA_up_ref(vrsa))
		return UADK_P_FAIL;

	RSA_free(priv->rsa);
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
	if (!priv)
		return NULL;
	priv->libctx = prov_libctx_of(provctx);

	return priv;
}

static void uadk_asym_cipher_rsa_freectx(void *vprsactx)
{
	struct PROV_RSA_ASYM_CTX *priv = (struct PROV_RSA_ASYM_CTX *)vprsactx;

	if (!priv)
		return;

	RSA_free(priv->rsa);
	EVP_MD_free(priv->oaep_md);
	EVP_MD_free(priv->mgf1_md);
	OPENSSL_free(priv->oaep_label);

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

static int uadk_asym_cipher_rsa_oaep_encrypt(void *vprsactx, unsigned char *out,
					     const unsigned char *in, size_t inlen)
{
	struct PROV_RSA_ASYM_CTX *priv = (struct PROV_RSA_ASYM_CTX *)vprsactx;
	unsigned char *tbuf;
	int rsasize, ret;

	rsasize = RSA_size(priv->rsa);
	tbuf = OPENSSL_malloc(rsasize);
	if (!tbuf) {
		UADK_ERR("failed to malloc buffer in rsa oaep encrypt\n");
		return UADK_P_FAIL;
	}

	if (!priv->oaep_md) {
		priv->oaep_md = EVP_MD_fetch(priv->libctx, "SHA-1", NULL);
		if (!priv->oaep_md) {
			OPENSSL_free(tbuf);
			UADK_ERR("failed to fetch SHA-1 digest method in rsa oaep encrypt\n");
			return UADK_P_FAIL;
		}
	}

	ret = RSA_padding_add_PKCS1_OAEP_mgf1(tbuf, rsasize,
					      in, inlen,
					      priv->oaep_label,
					      priv->oaep_labellen,
					      priv->oaep_md,
					      priv->mgf1_md);
	if (!ret) {
		OPENSSL_free(tbuf);
		return UADK_P_FAIL;
	}

	ret = uadk_prov_rsa_public_encrypt(rsasize, tbuf, out, priv->rsa, RSA_NO_PADDING);
	OPENSSL_free(tbuf);

	return ret;
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

	if (!out) {
		len = uadk_rsa_size(priv->rsa);
		if (len == 0) {
			UADK_ERR("invalid: rsa encrypt size.\n");
			return UADK_P_FAIL;
		}
		*outlen = len;
		return UADK_P_SUCCESS;
	}

	if (priv->pad_mode == RSA_PKCS1_OAEP_PADDING)
		ret = uadk_asym_cipher_rsa_oaep_encrypt(priv, out, in, inlen);
	else
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

static int uadk_asym_cipher_rsa_oaep_decrypt(struct PROV_RSA_ASYM_CTX *priv,
					     unsigned char *out, size_t *outlen, size_t outsize,
					     const unsigned char *in, size_t inlen)
{
	size_t len = uadk_rsa_size(priv->rsa);
	unsigned char *tbuf;
	int ret;

	tbuf = OPENSSL_malloc(len);
	if (!tbuf) {
		UADK_ERR("failed to malloc buf in rsa oaep decrypt\n");
		return UADK_P_FAIL;
	}

	ret = uadk_prov_rsa_private_decrypt(inlen, in, tbuf, priv->rsa, RSA_NO_PADDING);
	if (ret != (int)len) {
		OPENSSL_free(tbuf);
		UADK_ERR("failed to do rsa oaep decrypt\n");
		return ret;
	}

	if (!priv->oaep_md) {
		priv->oaep_md = EVP_MD_fetch(priv->libctx, "SHA-1", NULL);
		if (!priv->oaep_md) {
			OPENSSL_free(tbuf);
			UADK_ERR("faile to fetch SHA-1 digest method in rsa oaep decrypt\n");
			return UADK_P_FAIL;
		}
	}
	ret = RSA_padding_check_PKCS1_OAEP_mgf1(out, outsize, tbuf,
						len, len,
						priv->oaep_label,
						priv->oaep_labellen,
						priv->oaep_md,
						priv->mgf1_md);
	if (ret == CHECK_PADDING_FAIL)
		ret = UADK_P_FAIL;

	OPENSSL_free(tbuf);
	return ret;
}

static int uadk_asym_cipher_rsa_tls_decrypt(struct PROV_RSA_ASYM_CTX *priv,
					    unsigned char *out, size_t *outlen, size_t outsize,
					    const unsigned char *in, size_t inlen)
{
	size_t len = uadk_rsa_size(priv->rsa);
	unsigned char *tbuf;
	int ret;

	/* RSA_PKCS1_WITH_TLS_PADDING */
	if (priv->client_version == 0) {
		UADK_ERR("invalid: tls client version is %u\n", priv->client_version);
		return UADK_P_FAIL;
	}

	tbuf = OPENSSL_malloc(len);
	if (!tbuf) {
		UADK_ERR("failed to malloc buf in rsa tls decrypt\n");
		return UADK_P_FAIL;
	}

	ret = uadk_prov_rsa_private_decrypt(inlen, in, tbuf, priv->rsa, RSA_NO_PADDING);
	if (ret != (int)len) {
		OPENSSL_free(tbuf);
		UADK_ERR("failed to do rsa tls decrypt\n");
		return ret;
	}

	ret = RSA_padding_check_PKCS1_type_2_TLS(priv->libctx, out, outsize,
						 tbuf, len, priv->client_version,
						 priv->alt_version);
	if (ret == CHECK_PADDING_FAIL)
		ret = UADK_P_FAIL;

	OPENSSL_free(tbuf);
	return ret;
}

static int uadk_asym_cipher_rsa_decrypt(void *vprsactx, unsigned char *out,
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

	len = uadk_rsa_size(priv->rsa);
	if (priv->pad_mode == RSA_PKCS1_WITH_TLS_PADDING) {
		if (!out) {
			*outlen = SSL_MAX_MASTER_KEY_LENGTH;
			return UADK_P_SUCCESS;
		}
		if (outsize < SSL_MAX_MASTER_KEY_LENGTH) {
			UADK_ERR("invalid: incorrect rsa decrypt outsize in padding %d\n",
				 priv->pad_mode);
			return UADK_P_FAIL;
		}
	} else {
		if (!out) {
			if (len == 0) {
				UADK_ERR("invalid: incorrect rsa decrypt size in padding %d\n",
					priv->pad_mode);
				return UADK_P_FAIL;
			}
			*outlen = len;
			return UADK_P_SUCCESS;
		}

		if (outsize < len) {
			UADK_ERR("invalid: incorrect rsa decrypt outsize in padding %d\n",
				 priv->pad_mode);
			return UADK_P_FAIL;
		}
	}

	switch (priv->pad_mode) {
	case RSA_PKCS1_OAEP_PADDING:
		ret = uadk_asym_cipher_rsa_oaep_decrypt(priv, out, outlen, outsize, in, inlen);
		break;
	case RSA_PKCS1_WITH_TLS_PADDING:
		ret = uadk_asym_cipher_rsa_tls_decrypt(priv, out, outlen, outsize, in, inlen);
		break;
	default:
		ret = uadk_prov_rsa_private_decrypt(inlen, in, out, priv->rsa, priv->pad_mode);
	}

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
