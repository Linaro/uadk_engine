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
#include <stdbool.h>
#include <string.h>
#include <dlfcn.h>
#include <openssl/core_names.h>
#include <openssl/proverr.h>
#include <uadk/wd_cipher.h>
#include <uadk/wd_sched.h>
#include "uadk.h"
#include "uadk_async.h"

#define UADK_DO_SOFT         (-0xE0)
#define CTX_SYNC_ENC		0
#define CTX_SYNC_DEC		1
#define CTX_ASYNC_ENC		2
#define CTX_ASYNC_DEC		3
#define CTX_NUM			4
#define CTR_128BIT_COUNTER	16
#define CTR_MODE_LEN_SHIFT	4
#define BYTE_BITS		8
#define IV_LEN			16
#define ENV_ENABLED		1
#define MAX_KEY_LEN		64
#define ALG_NAME_SIZE           128

/* Internal flags that can be queried */
#define PROV_CIPHER_FLAG_AEAD             0x0001
#define PROV_CIPHER_FLAG_CUSTOM_IV        0x0002
#define PROV_CIPHER_FLAG_CTS              0x0004
#define PROV_CIPHER_FLAG_TLS1_MULTIBLOCK  0x0008
#define PROV_CIPHER_FLAG_RAND_KEY         0x0010

/* Internal flags that are only used within the provider */
#define PROV_CIPHER_FLAG_VARIABLE_LENGTH  0x0100
#define PROV_CIPHER_FLAG_INVERSE_CIPHER   0x0200

#define SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT 192

struct cipher_prov {
	int pid;
};
static struct cipher_prov prov;
static pthread_mutex_t cipher_mutex = PTHREAD_MUTEX_INITIALIZER;

struct cipher_priv_ctx {
	int nid;
	handle_t sess;
	struct wd_cipher_sess_setup setup;
	struct wd_cipher_req req;
	unsigned char iv[IV_LEN];
	unsigned char key[MAX_KEY_LEN];
	int switch_flag;
	EVP_CIPHER_CTX *sw_ctx;
	EVP_CIPHER *sw_cipher;
	/* Crypto small packet offload threshold */
	size_t switch_threshold;
	unsigned int enc : 1;
	size_t blksize;
	size_t keylen;
	size_t ivlen;
	char alg_name[ALG_NAME_SIZE];
};

struct cipher_info {
	int nid;
	enum wd_cipher_alg alg;
	enum wd_cipher_mode mode;
	__u32 out_bytes;
};

static struct cipher_info cipher_info_table[] = {
	{ NID_aes_128_ecb, WD_CIPHER_AES, WD_CIPHER_ECB, 16},
	{ NID_aes_192_ecb, WD_CIPHER_AES, WD_CIPHER_ECB, 16},
	{ NID_aes_256_ecb, WD_CIPHER_AES, WD_CIPHER_ECB, 16},
	{ NID_aes_128_cbc, WD_CIPHER_AES, WD_CIPHER_CBC, 16},
	{ NID_aes_192_cbc, WD_CIPHER_AES, WD_CIPHER_CBC, 64},
	{ NID_aes_256_cbc, WD_CIPHER_AES, WD_CIPHER_CBC, 64},
	{ NID_aes_128_xts, WD_CIPHER_AES, WD_CIPHER_XTS, 32},
	{ NID_aes_256_xts, WD_CIPHER_AES, WD_CIPHER_XTS, 512},
	{ NID_sm4_cbc, WD_CIPHER_SM4, WD_CIPHER_CBC, 16},
	{ NID_des_ede3_cbc, WD_CIPHER_3DES, WD_CIPHER_CBC, 16},
	{ NID_des_ede3_ecb, WD_CIPHER_3DES, WD_CIPHER_ECB, 16},
	{ NID_aes_128_ctr, WD_CIPHER_AES, WD_CIPHER_CTR, 64},
	{ NID_aes_192_ctr, WD_CIPHER_AES, WD_CIPHER_CTR, 64},
	{ NID_aes_256_ctr, WD_CIPHER_AES, WD_CIPHER_CTR, 64},
	{ NID_aes_128_ofb128, WD_CIPHER_AES, WD_CIPHER_OFB, 16},
	{ NID_aes_192_ofb128, WD_CIPHER_AES, WD_CIPHER_OFB, 16},
	{ NID_aes_256_ofb128, WD_CIPHER_AES, WD_CIPHER_OFB, 16},
	{ NID_aes_128_cfb128, WD_CIPHER_AES, WD_CIPHER_CFB, 16},
	{ NID_aes_192_cfb128, WD_CIPHER_AES, WD_CIPHER_CFB, 16},
	{ NID_aes_256_cfb128, WD_CIPHER_AES, WD_CIPHER_CFB, 16},
	{ NID_sm4_ofb128, WD_CIPHER_SM4, WD_CIPHER_OFB, 16},
	{ NID_sm4_cfb128, WD_CIPHER_SM4, WD_CIPHER_CFB, 16},
	{ NID_sm4_ecb, WD_CIPHER_SM4, WD_CIPHER_ECB, 16},
	{ NID_sm4_ctr, WD_CIPHER_SM4, WD_CIPHER_CTR, 16},
};

static int uadk_fetch_sw_cipher(struct cipher_priv_ctx *priv)
{
	if (priv->sw_cipher)
		return 1;

	switch (priv->nid) {
	case NID_aes_128_cbc:
		priv->sw_cipher = EVP_CIPHER_fetch(NULL, "AES-128-CBC", "provider=default");
	case NID_aes_192_cbc:
		priv->sw_cipher = EVP_CIPHER_fetch(NULL, "AES-192-CBC", "provider=default");
	case NID_aes_256_cbc:
		priv->sw_cipher = EVP_CIPHER_fetch(NULL, "AES-256-CBC", "provider=default");
	case NID_aes_128_ecb:
		priv->sw_cipher = EVP_CIPHER_fetch(NULL, "AES-128-ECB", "provider=default");
	case NID_aes_192_ecb:
		priv->sw_cipher = EVP_CIPHER_fetch(NULL, "AES-192-ECB", "provider=default");
	case NID_aes_256_ecb:
		priv->sw_cipher = EVP_CIPHER_fetch(NULL, "AES-256-ECB", "provider=default");
	case NID_aes_128_xts:
		priv->sw_cipher = EVP_CIPHER_fetch(NULL, "AES-128-XTS", "provider=default");
	case NID_aes_256_xts:
		priv->sw_cipher = EVP_CIPHER_fetch(NULL, "AES-256-XTS", "provider=default");
	case NID_sm4_cbc:
		priv->sw_cipher = EVP_CIPHER_fetch(NULL, "SM4-CBC", "provider=default");
	case NID_sm4_ecb:
		priv->sw_cipher = EVP_CIPHER_fetch(NULL, "SM4-ECB", "provider=default");
	case NID_des_ede3_cbc:
		priv->sw_cipher = EVP_CIPHER_fetch(NULL, "DES-EDE3-CBC", "provider=default");
	case NID_des_ede3_ecb:
		priv->sw_cipher = EVP_CIPHER_fetch(NULL, "DES-EDE3-ECB", "provider=default");
	case NID_aes_128_ctr:
		priv->sw_cipher = EVP_CIPHER_fetch(NULL, "AES-128-CTR", "provider=default");
	case NID_aes_192_ctr:
		priv->sw_cipher = EVP_CIPHER_fetch(NULL, "AES-192-CTR", "provider=default");
	case NID_aes_256_ctr:
		priv->sw_cipher = EVP_CIPHER_fetch(NULL, "AES-256-CTR", "provider=default");
	case NID_aes_128_ofb128:
		priv->sw_cipher = EVP_CIPHER_fetch(NULL, "AES-128-OFB", "provider=default");
	case NID_aes_192_ofb128:
		priv->sw_cipher = EVP_CIPHER_fetch(NULL, "AES-192-OFB", "provider=default");
	case NID_aes_256_ofb128:
		priv->sw_cipher = EVP_CIPHER_fetch(NULL, "AES-256-OFB", "provider=default");
	case NID_aes_128_cfb128:
		priv->sw_cipher = EVP_CIPHER_fetch(NULL, "AES-128-CFB", "provider=default");
	case NID_aes_192_cfb128:
		priv->sw_cipher = EVP_CIPHER_fetch(NULL, "AES-192-CFB", "provider=default");
	case NID_aes_256_cfb128:
		priv->sw_cipher = EVP_CIPHER_fetch(NULL, "AES-256-CFB", "provider=default");
	case NID_sm4_ofb128:
		priv->sw_cipher = EVP_CIPHER_fetch(NULL, "SM4-OFB", "provider=default");
	case NID_sm4_cfb128:
		priv->sw_cipher = EVP_CIPHER_fetch(NULL, "SM4-CFB", "provider=default");
	case NID_sm4_ctr:
		priv->sw_cipher = EVP_CIPHER_fetch(NULL, "SM4-CTR", "provider=default");
	default:
		break;
	}

	if (unlikely(priv->sw_cipher == NULL)) {
		fprintf(stderr, "fail to fetch sw_cipher\n");
		return 0;
	}

	return 1;
}

static int uadk_prov_cipher_sw_init(struct cipher_priv_ctx *priv,
				    const unsigned char *key,
				    const unsigned char *iv)
{
	if (!uadk_fetch_sw_cipher(priv))
		return 0;

	if (!EVP_CipherInit_ex2(priv->sw_ctx, priv->sw_cipher, key, iv,
				priv->enc, NULL)) {
		fprintf(stderr, "SW cipher init error!\n");
		return 0;
	}

	return 1;
}

static int uadk_prov_cipher_soft_work(struct cipher_priv_ctx *priv, unsigned char *out,
				      const unsigned char *in, size_t len)
{
	int sw_final_len = 0;
	int outlen = 0;

	if (priv->sw_cipher == NULL)
		return 0;

	if (!EVP_CipherUpdate(priv->sw_ctx, out, &outlen, in, len)) {
		fprintf(stderr, "EVP_CipherUpdate sw_ctx failed.\n");
		return 0;
	}

	if (!EVP_CipherFinal_ex(priv->sw_ctx, out + outlen, &sw_final_len)) {
		fprintf(stderr, "EVP_CipherFinal_ex sw_ctx failed.\n");
		return 0;
	}

	return 1;
}

static int uadk_cipher_env_poll(void *ctx)
{
	__u64 rx_cnt = 0;
	__u32 recv = 0;
	/* Poll one packet currently */
	int expt = 1;
	int ret;

	do {
		ret = wd_cipher_poll(expt, &recv);
		if (ret < 0 || recv == expt)
			return ret;
		rx_cnt++;
	} while (rx_cnt < ENGINE_RECV_MAX_CNT);

	fprintf(stderr, "failed to poll msg: timeout!\n");

	return -ETIMEDOUT;
}

static int uadk_prov_cipher_init(struct cipher_priv_ctx *priv,
				 const unsigned char *key, size_t keylen,
				 const unsigned char *iv, size_t ivlen)
{
	int cipher_counts = ARRAY_SIZE(cipher_info_table);
	int ret, i;

	if (iv)
		memcpy(priv->iv, iv, ivlen);

	for (i = 0; i < cipher_counts; i++) {
		if (priv->nid == cipher_info_table[i].nid) {
			priv->setup.alg = cipher_info_table[i].alg;
			priv->setup.mode = cipher_info_table[i].mode;
			priv->req.out_bytes = cipher_info_table[i].out_bytes;
			break;
		}
	}

	if (i == cipher_counts) {
		fprintf(stderr, "failed to setup the private ctx.\n");
		return 0;
	}

	if (key) {
		memcpy(priv->key, key, keylen);
		ret = uadk_prov_cipher_sw_init(priv, key, iv);
		if (unlikely(ret != 1))
			return 0;
	}

	priv->switch_threshold = SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT;

	return 1;
}

static void async_cb(struct wd_cipher_req *req, void *data)
{
	struct uadk_e_cb_info *cb_param;
	struct async_op *op;

	if (!req)
		return;

	cb_param = req->cb_param;
	if (!cb_param)
		return;

	op = cb_param->op;
	if (op && op->job && !op->done) {
		op->done = 1;
		async_free_poll_task(op->idx, 1);
		async_wake_job(op->job);
	}
}

/* Increment counter (128-bit int) by c */
static void ctr_iv_inc(uint8_t *counter, __u32 c)
{
	uint32_t n = CTR_128BIT_COUNTER;
	uint8_t *counter1 = counter;
	__u32 c_value = c;

	/*
	 * Since the counter has been increased 1 by the hardware,
	 * so the c need to  decrease 1.
	 */
	c_value -= 1;
	do {
		--n;
		c_value += counter1[n];
		counter1[n] = (uint8_t)c_value;
		c_value >>= BYTE_BITS;
	} while (n);
}

static void uadk_cipher_update_priv_ctx(struct cipher_priv_ctx *priv)
{
	__u16 iv_bytes = priv->req.iv_bytes;
	int offset = priv->req.in_bytes - iv_bytes;
	unsigned char K[IV_LEN] = {0};
	int i;

	switch (priv->setup.mode) {
	case WD_CIPHER_CFB:
	case WD_CIPHER_CBC:
		if (priv->req.op_type == WD_CIPHER_ENCRYPTION)
			memcpy(priv->iv, priv->req.dst + offset, iv_bytes);
		else
			memcpy(priv->iv, priv->req.src + offset, iv_bytes);

		break;
	case WD_CIPHER_OFB:
		for (i = 0; i < IV_LEN; i++) {
			K[i] = *((unsigned char *)priv->req.src + offset + i) ^
			       *((unsigned char *)priv->req.dst + offset + i);
		}
		memcpy(priv->iv, K, iv_bytes);
		break;
	case WD_CIPHER_CTR:
		ctr_iv_inc(priv->iv, priv->req.in_bytes >> CTR_MODE_LEN_SHIFT);
		break;
	default:
		break;
	}
}

static int uadk_do_cipher_sync(struct cipher_priv_ctx *priv)
{
	int ret;

	if (unlikely(priv->switch_flag == UADK_DO_SOFT))
		return 0;

	if (priv->switch_threshold >= priv->req.in_bytes)
		return 0;

	ret = wd_do_cipher_sync(priv->sess, &priv->req);
	if (ret)
		return 0;
	return 1;
}

static int uadk_do_cipher_async(struct cipher_priv_ctx *priv, struct async_op *op)
{
	struct uadk_e_cb_info cb_param;
	int idx, ret;

	if (unlikely(priv->switch_flag == UADK_DO_SOFT)) {
		fprintf(stderr, "async cipher init failed.\n");
		return 0;
	}

	cb_param.op = op;
	cb_param.priv = priv;
	priv->req.cb = (void *)async_cb;
	priv->req.cb_param = &cb_param;
	ret = async_get_free_task(&idx);
	if (!ret)
		return 0;

	op->idx = idx;
	do {
		ret = wd_do_cipher_async(priv->sess, &priv->req);
		if (ret < 0 && ret != -EBUSY) {
			fprintf(stderr, "do sec cipher failed, switch to soft cipher.\n");
			async_free_poll_task(op->idx, 0);
			return 0;
		}
	} while (ret == -EBUSY);

	ret = async_pause_job(priv, op, ASYNC_TASK_CIPHER, idx);
	if (!ret)
		return 0;
	return 1;
}

static void uadk_prov_cipher_ctx_init(struct cipher_priv_ctx *priv)
{
	struct sched_params params = {0};
	int ret;

	priv->req.iv_bytes = priv->ivlen;
	priv->req.iv = priv->iv;

	if (priv->switch_flag == UADK_DO_SOFT)
		return;

	pthread_mutex_lock(&cipher_mutex);
	if (prov.pid != getpid()) {
		ret = wd_cipher_init2(priv->alg_name, 0, 0);
		if (unlikely(ret)) {
			priv->switch_flag = UADK_DO_SOFT;
			pthread_mutex_unlock(&cipher_mutex);
			fprintf(stderr, "uadk failed to init cipher HW!\n");
			return;
		}
		prov.pid = getpid();
		async_register_poll_fn(ASYNC_TASK_CIPHER, uadk_cipher_env_poll);
	}
	pthread_mutex_unlock(&cipher_mutex);

	params.type = priv->req.op_type;
	/* Use the default numa parameters */
	params.numa_id = -1;
	priv->setup.sched_param = &params;

	if (!priv->sess) {
		priv->sess = wd_cipher_alloc_sess(&priv->setup);
		if (!priv->sess)
			fprintf(stderr, "uadk failed to alloc session!\n");
	}

	ret = wd_cipher_set_key(priv->sess, priv->key, priv->keylen);
	if (ret) {
		wd_cipher_free_sess(priv->sess);
		priv->sess = 0;
		fprintf(stderr, "uadk failed to set key!\n");
	}
}

static int uadk_prov_do_cipher(struct cipher_priv_ctx *priv, unsigned char *out,
			       const unsigned char *in, size_t inlen)
{
	struct async_op op;
	int ret;

	priv->req.src = (unsigned char *)in;
	priv->req.in_bytes = inlen;
	priv->req.dst = out;
	priv->req.out_buf_bytes = inlen;

	uadk_prov_cipher_ctx_init(priv);
	ret = async_setup_async_event_notification(&op);
	if (!ret) {
		fprintf(stderr, "failed to setup async event notification.\n");
		return 0;
	}

	if (op.job == NULL) {
		/* Synchronous, only the synchronous mode supports soft computing */
		ret = uadk_do_cipher_sync(priv);
		if (!ret)
			goto sync_err;
	} else {
		/*
		 * If the length of the input data
		 * does not reach to hardware computing threshold,
		 * directly switch to soft cipher.
		 */
		if (priv->req.in_bytes <= priv->switch_threshold)
			goto sync_err;

		ret = uadk_do_cipher_async(priv, &op);
		if (!ret)
			goto out_notify;
	}
	uadk_cipher_update_priv_ctx(priv);

	return 1;
sync_err:
	ret = uadk_prov_cipher_soft_work(priv, out, in, inlen);
	if (ret != 1)
		fprintf(stderr, "do soft ciphers failed.\n");
out_notify:
	async_clear_async_event_notification();
	return ret;
}

void uadk_prov_destroy_cipher(void)
{
	pthread_mutex_lock(&cipher_mutex);
	if (prov.pid == getpid()) {
		wd_cipher_uninit2();
		prov.pid = 0;
	}
	pthread_mutex_unlock(&cipher_mutex);
}

static OSSL_FUNC_cipher_encrypt_init_fn uadk_prov_cipher_einit;
static OSSL_FUNC_cipher_decrypt_init_fn uadk_prov_cipher_dinit;
static OSSL_FUNC_cipher_freectx_fn uadk_prov_cipher_freectx;
static OSSL_FUNC_cipher_get_ctx_params_fn uadk_prov_cipher_get_ctx_params;
static OSSL_FUNC_cipher_gettable_ctx_params_fn uadk_prov_cipher_gettable_ctx_params;
static OSSL_FUNC_cipher_set_ctx_params_fn uadk_prov_cipher_set_ctx_params;
static OSSL_FUNC_cipher_settable_ctx_params_fn uadk_prov_cipher_settable_ctx_params;

static int uadk_prov_cipher_cipher(void *vctx, unsigned char *out, size_t *outl,
				   size_t outsize, const unsigned char *in,
				   size_t inl)
{
	struct cipher_priv_ctx *priv = (struct cipher_priv_ctx *)vctx;
	int ret;

	if (inl == 0) {
		*outl = 0;
		return 1;
	}

	if (outsize < inl) {
		ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
		return 0;
	}

	ret = uadk_prov_do_cipher(priv, out, in, inl);
	if (ret != 1)
		return ret;

	*outl = inl;
	return 1;

}

static int uadk_prov_cipher_final(void *vctx, unsigned char *out,
				  size_t *outl, size_t outsize)
{
	*outl = 0;
	return 1;
}

static int uadk_prov_cipher_update(void *vctx, unsigned char *out,
				   size_t *outl, size_t outsize,
				   const unsigned char *in, size_t inl)
{
	struct cipher_priv_ctx *priv = (struct cipher_priv_ctx *)vctx;
	int ret;

	if (inl == 0) {
		*outl = 0;
		return 1;
	}

	if (outsize < inl) {
		ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
		return 0;
	}

	ret = uadk_prov_do_cipher(priv, out, in, inl);
	if (ret != 1)
		return ret;

	*outl = inl;
	return 1;
}

static int uadk_prov_cipher_einit(void *vctx, const unsigned char *key, size_t keylen,
				  const unsigned char *iv, size_t ivlen,
				  const OSSL_PARAM params[])
{
	struct cipher_priv_ctx *priv = (struct cipher_priv_ctx *)vctx;
	int ret;

	priv->req.op_type = WD_CIPHER_ENCRYPTION;
	priv->enc = 1;

	ret = uadk_prov_cipher_init(priv, key, keylen, iv, ivlen);
	if (unlikely(ret != 1))
		return 0;

	return 1;
}

static int uadk_prov_cipher_dinit(void *vctx, const unsigned char *key, size_t keylen,
				  const unsigned char *iv, size_t ivlen,
				  const OSSL_PARAM params[])
{
	struct cipher_priv_ctx *priv = (struct cipher_priv_ctx *)vctx;
	int ret;

	priv->req.op_type = WD_CIPHER_DECRYPTION;
	priv->enc = 0;

	ret = uadk_prov_cipher_init(priv, key, keylen, iv, ivlen);
	if (unlikely(ret != 1))
		return 0;

	return 1;
}

static const OSSL_PARAM uadk_prov_settable_ctx_params[] = {
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
	OSSL_PARAM_END
};

const OSSL_PARAM *uadk_prov_cipher_settable_ctx_params(ossl_unused void *cctx,
						       ossl_unused void *provctx)
{
	return uadk_prov_settable_ctx_params;
}

static int uadk_prov_cipher_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
	struct cipher_priv_ctx *priv = (struct cipher_priv_ctx *)vctx;
	const OSSL_PARAM *p;
	int ret = 1;

	if (params == NULL)
		return 1;

	p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
	if (p != NULL) {
		size_t keylen;

		if (!OSSL_PARAM_get_size_t(p, &keylen)) {
			ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
			return 0;
		}
		if (priv->keylen != keylen) {
			ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
			return 0;
		}
	}

	return ret;
}

static int uadk_prov_cipher_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
	struct cipher_priv_ctx *priv = (struct cipher_priv_ctx *)vctx;
	OSSL_PARAM *p;

	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
	if (p != NULL && !OSSL_PARAM_set_size_t(p, priv->keylen)) {
		ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
		return 0;
	}
	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
	if (p != NULL && !OSSL_PARAM_set_size_t(p, priv->ivlen)) {
		ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
		return 0;
	}
	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
	if (p != NULL && !OSSL_PARAM_set_octet_string(p, priv->iv, priv->ivlen)
	    && !OSSL_PARAM_set_octet_ptr(p, &priv->iv, priv->ivlen)) {
		ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
		return 0;
	}
	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
	if (p != NULL && !OSSL_PARAM_set_octet_string(p, priv->iv, priv->ivlen)
	    && !OSSL_PARAM_set_octet_ptr(p, &priv->iv, priv->ivlen)) {
		ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
		return 0;
	}
	return 1;
}

static const OSSL_PARAM uadk_prov_default_ctx_params[] = {
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
	OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
	OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, NULL, 0),
	OSSL_PARAM_END
};

const OSSL_PARAM *uadk_prov_cipher_gettable_ctx_params(ossl_unused void *cctx,
						       ossl_unused void *provctx)
{
	return uadk_prov_default_ctx_params;
}

static const OSSL_PARAM cipher_known_gettable_params[] = {
	OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
	OSSL_PARAM_int(OSSL_CIPHER_PARAM_AEAD, NULL),
	OSSL_PARAM_int(OSSL_CIPHER_PARAM_CUSTOM_IV, NULL),
	OSSL_PARAM_int(OSSL_CIPHER_PARAM_CTS, NULL),
	OSSL_PARAM_int(OSSL_CIPHER_PARAM_HAS_RAND_KEY, NULL),
	OSSL_PARAM_END
};

static const OSSL_PARAM *uadk_prov_cipher_gettable_params(ossl_unused void *provctx)
{
	return cipher_known_gettable_params;
}

static int ossl_cipher_generic_get_params(OSSL_PARAM params[], unsigned int md,
					  uint64_t flags, size_t kbits,
					  size_t blkbits, size_t ivbits)
{
	OSSL_PARAM *p;

	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
	if (p != NULL && !OSSL_PARAM_set_uint(p, md)) {
		ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
		return 0;
	}
	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CUSTOM_IV);
	if (p != NULL && !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_CUSTOM_IV) != 0)) {
		ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
		return 0;
	}
	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
	if (p != NULL && !OSSL_PARAM_set_size_t(p, kbits)) {
		ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
		return 0;
	}
	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
	if (p != NULL && !OSSL_PARAM_set_size_t(p, blkbits)) {
		ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
		return 0;
	}
	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
	if (p != NULL && !OSSL_PARAM_set_size_t(p, ivbits)) {
		ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
		return 0;
	}
	return 1;
}

static void uadk_prov_cipher_freectx(void *ctx)
{
	struct cipher_priv_ctx *priv = (struct cipher_priv_ctx *)ctx;

	EVP_CIPHER_free(priv->sw_cipher);
	EVP_CIPHER_CTX_free(priv->sw_ctx);

	if (priv->sess) {
		wd_cipher_free_sess(priv->sess);
		priv->sess = 0;
	}
	OPENSSL_clear_free(priv, sizeof(*priv));
}

#define UADK_CIPHER_DESCR(nm, blk_size, key_len, iv_len,			\
			  flags, e_nid, algnm, mode)				\
static OSSL_FUNC_cipher_newctx_fn uadk_##nm##_newctx;				\
static void *uadk_##nm##_newctx(void *provctx)					\
{										\
	struct cipher_priv_ctx *ctx = OPENSSL_zalloc(sizeof(*ctx));		\
										\
	if (ctx == NULL)							\
		return NULL;							\
	ctx->blksize = blk_size;						\
	ctx->keylen = key_len;							\
	ctx->ivlen = iv_len;							\
	ctx->nid = e_nid;							\
	ctx->sw_ctx = EVP_CIPHER_CTX_new();					\
	if (ctx->sw_ctx == NULL)						\
		fprintf(stderr, "EVP_CIPHER_CTX_new failed.\n");		\
	strncpy(ctx->alg_name, #algnm, ALG_NAME_SIZE - 1);			\
	return ctx;								\
}                                                                               \
static OSSL_FUNC_cipher_get_params_fn uadk_##nm##_get_params;			\
static int uadk_##nm##_get_params(OSSL_PARAM params[])				\
{										\
	return ossl_cipher_generic_get_params(params, mode, flags,		\
					      key_len, blk_size, iv_len);	\
}										\
const OSSL_DISPATCH uadk_##nm##_functions[] = {					\
	{ OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))uadk_##nm##_newctx },	\
	{ OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))uadk_prov_cipher_freectx },	\
	{ OSSL_FUNC_CIPHER_ENCRYPT_INIT,					\
		(void (*)(void))uadk_prov_cipher_einit },			\
	{ OSSL_FUNC_CIPHER_DECRYPT_INIT,					\
		(void (*)(void))uadk_prov_cipher_dinit },			\
	{ OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))uadk_prov_cipher_update },	\
	{ OSSL_FUNC_CIPHER_FINAL, (void (*)(void))uadk_prov_cipher_final },	\
	{ OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))uadk_prov_cipher_cipher },	\
	{ OSSL_FUNC_CIPHER_GET_PARAMS,						\
		(void (*)(void))uadk_##nm##_get_params },			\
	{ OSSL_FUNC_CIPHER_GETTABLE_PARAMS,					\
		(void (*)(void))uadk_prov_cipher_gettable_params },		\
	{ OSSL_FUNC_CIPHER_GET_CTX_PARAMS,					\
		(void (*)(void))uadk_prov_cipher_get_ctx_params },		\
	{ OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,					\
		(void (*)(void))uadk_prov_cipher_gettable_ctx_params },		\
	{ OSSL_FUNC_CIPHER_SET_CTX_PARAMS,					\
		(void (*)(void))uadk_prov_cipher_set_ctx_params },		\
	{ OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,					\
		(void (*)(void))uadk_prov_cipher_settable_ctx_params },		\
	{ 0, NULL }								\
}

UADK_CIPHER_DESCR(aes_128_cbc, 16, 16, 16, 0, NID_aes_128_cbc, cbc(aes), EVP_CIPH_CBC_MODE);
UADK_CIPHER_DESCR(aes_192_cbc, 16, 24, 16, 0, NID_aes_192_cbc, cbc(aes), EVP_CIPH_CBC_MODE);
UADK_CIPHER_DESCR(aes_256_cbc, 16, 32, 16, 0, NID_aes_256_cbc, cbc(aes), EVP_CIPH_CBC_MODE);
UADK_CIPHER_DESCR(aes_128_ecb, 16, 16, 0, 0, NID_aes_128_ecb, ecb(aes), EVP_CIPH_ECB_MODE);
UADK_CIPHER_DESCR(aes_192_ecb, 16, 24, 0, 0, NID_aes_192_ecb, ecb(aes), EVP_CIPH_ECB_MODE);
UADK_CIPHER_DESCR(aes_256_ecb, 16, 32, 0, 0, NID_aes_256_ecb, ecb(aes), EVP_CIPH_ECB_MODE);
UADK_CIPHER_DESCR(aes_128_xts, 1, 32, 16, 0, NID_aes_128_xts, xts(aes), EVP_CIPH_XTS_MODE | EVP_CIPH_CUSTOM_IV);
UADK_CIPHER_DESCR(aes_256_xts, 1, 64, 16, 0, NID_aes_256_xts, xts(aes), EVP_CIPH_XTS_MODE | EVP_CIPH_CUSTOM_IV);
UADK_CIPHER_DESCR(sm4_cbc, 16, 16, 16, 0, NID_sm4_cbc, cbc(sm4), EVP_CIPH_CBC_MODE);
UADK_CIPHER_DESCR(sm4_ecb, 16, 16, 0, 0, NID_sm4_ecb, ecb(sm4), EVP_CIPH_ECB_MODE);
UADK_CIPHER_DESCR(des_ede3_cbc, 8, 24, 8, 0, NID_des_ede3_cbc, cbc(des), EVP_CIPH_CBC_MODE);
UADK_CIPHER_DESCR(des_ede3_ecb, 8, 24, 0, 0, NID_des_ede3_ecb, ecb(des), EVP_CIPH_ECB_MODE);

/* v3 */
UADK_CIPHER_DESCR(aes_128_ctr, 1, 16, 16, 0, NID_aes_128_ctr, ctr(aes), EVP_CIPH_CTR_MODE);
UADK_CIPHER_DESCR(aes_192_ctr, 1, 24, 16, 0, NID_aes_192_ctr, ctr(aes), EVP_CIPH_CTR_MODE);
UADK_CIPHER_DESCR(aes_256_ctr, 1, 32, 16, 0, NID_aes_256_ctr, ctr(aes), EVP_CIPH_CTR_MODE);
UADK_CIPHER_DESCR(aes_128_ofb128, 1, 16, 16, 0, NID_aes_128_ofb128, ofb(aes), EVP_CIPH_OFB_MODE);
UADK_CIPHER_DESCR(aes_192_ofb128, 1, 24, 16, 0, NID_aes_192_ofb128, ofb(aes), EVP_CIPH_OFB_MODE);
UADK_CIPHER_DESCR(aes_256_ofb128, 1, 32, 16, 0, NID_aes_256_ofb128, ofb(aes), EVP_CIPH_OFB_MODE);
UADK_CIPHER_DESCR(aes_128_cfb128, 1, 16, 16, 0, NID_aes_128_cfb128, cfb(aes), EVP_CIPH_CFB_MODE);
UADK_CIPHER_DESCR(aes_192_cfb128, 1, 24, 16, 0, NID_aes_192_cfb128, cfb(aes), EVP_CIPH_CFB_MODE);
UADK_CIPHER_DESCR(aes_256_cfb128, 1, 32, 16, 0, NID_aes_256_cfb128, cfb(aes), EVP_CIPH_CFB_MODE);
UADK_CIPHER_DESCR(sm4_ofb128, 1, 16, 16, 0, NID_sm4_ofb128, ofb(sm4), EVP_CIPH_OFB_MODE);
UADK_CIPHER_DESCR(sm4_cfb128, 1, 16, 16, 0, NID_sm4_cfb128, cfb(sm4), EVP_CIPH_CFB_MODE);
UADK_CIPHER_DESCR(sm4_ctr, 1, 16, 16, 0, NID_sm4_ctr, ctr(sm4), EVP_CIPH_CTR_MODE);
