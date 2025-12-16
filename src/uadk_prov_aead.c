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

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <dlfcn.h>
#include <numa.h>
#include <openssl/core_names.h>
#include <openssl/proverr.h>
#include <uadk/wd_aead.h>
#include <uadk/wd_sched.h>
#include "uadk.h"
#include "uadk_async.h"
#include "uadk_prov.h"
#include "uadk_utils.h"

#define MAX_IV_LEN			16
#define MAX_KEY_LEN			64
#define MAX_AAD_LEN			0xFFFF
#define ALG_NAME_SIZE			128
#define AES_GCM_TAG_LEN			16
/* The max data length is 16M-512B */
#define AEAD_BLOCK_SIZE			0xFFFE00

#define UADK_OSSL_FAIL			0
#define UADK_AEAD_SUCCESS		1
#define SWITCH_TO_SOFT			2
#define UADK_AEAD_FAIL			(-1)

#define UNINITIALISED_SIZET		((size_t)-1)
#define IV_STATE_UNINITIALISED		0
#define IV_STATE_SET			1
#define KEY_STATE_SET			1

/* Internal flags that can be queried */
#define PROV_CIPHER_FLAG_AEAD		0x0001
#define PROV_CIPHER_FLAG_CUSTOM_IV	0x0002
#define AEAD_FLAGS			(PROV_CIPHER_FLAG_AEAD | PROV_CIPHER_FLAG_CUSTOM_IV)

#define UADK_DO_HW			(-0xF0)
#define UADK_AEAD_DEF_CTXS		2
#define UADK_AEAD_OP_NUM		1

struct aead_prov {
	int pid;
};
static struct aead_prov aprov;
static pthread_mutex_t aead_mutex = PTHREAD_MUTEX_INITIALIZER;

enum uadk_aead_mode {
	UNINIT_MODE,
	ASYNC_MODE,
	SYNC_MODE
};

enum aead_tag_status {
	INIT_TAG,
	READ_TAG,    /* The MAC has been read. */
	SET_TAG      /* The MAC has been set to req. */
};

struct aead_priv_ctx {
	int nid;
	char alg_name[ALG_NAME_SIZE];
	size_t keylen;
	size_t ivlen;
	size_t taglen;

	unsigned int enc : 1;
	unsigned int key_set : 1;     /* Whether key is copied to priv key buffers */
	unsigned int iv_set : 1;      /* Whether iv is copied to priv iv buffers */
	enum aead_tag_status tag_set; /* Whether mac is copied to priv mac buffers */

	unsigned char iv[MAX_IV_LEN];
	unsigned char key[MAX_KEY_LEN];
	unsigned char buf[AES_GCM_TAG_LEN];       /* mac buffers */
	unsigned char *data;          /* store input and output when block mode */

	struct wd_aead_sess_setup setup;
	struct wd_aead_req req;
	enum uadk_aead_mode mode;
	handle_t sess;

	int stream_switch_flag;    /* soft calculation switch flag for stream mode */
	EVP_CIPHER_CTX *sw_ctx;
	EVP_CIPHER *sw_aead;
};

struct aead_info {
	int nid;
	enum wd_cipher_alg alg;
	enum wd_cipher_mode mode;
};

static struct aead_info aead_info_table[] = {
	{ NID_aes_128_gcm, WD_CIPHER_AES, WD_CIPHER_GCM },
	{ NID_aes_192_gcm, WD_CIPHER_AES, WD_CIPHER_GCM },
	{ NID_aes_256_gcm, WD_CIPHER_AES, WD_CIPHER_GCM }
};

static EVP_CIPHER_CTX *EVP_CIPHER_CTX_dup(const EVP_CIPHER_CTX *in)
{
	EVP_CIPHER_CTX *out = EVP_CIPHER_CTX_new();

	if (out != NULL && !EVP_CIPHER_CTX_copy(out, in)) {
		EVP_CIPHER_CTX_free(out);
		out = NULL;
	}

	return out;
}

static int uadk_aead_poll(void *ctx)
{
	__u64 rx_cnt = 0;
	__u32 recv = 0;
	/* Poll one packet currently */
	int expt = 1;
	int ret;

	do {
		ret = wd_aead_poll(expt, &recv);
		if (ret < 0 || recv >= expt)
			return ret;
		rx_cnt++;
	} while (rx_cnt < PROV_SCH_RECV_MAX_CNT);

	UADK_ERR("failed to poll msg: timeout!\n");

	return -ETIMEDOUT;
}

static void uadk_aead_mutex_infork(void)
{
	/* Release the replication lock of the child process */
	pthread_mutex_unlock(&aead_mutex);
}

static int uadk_create_aead_soft_ctx(struct aead_priv_ctx *priv)
{
	if (priv->sw_aead)
		return UADK_AEAD_SUCCESS;

	switch (priv->nid) {
	case NID_aes_128_gcm:
		priv->sw_aead = EVP_CIPHER_fetch(NULL, "AES-128-GCM", "provider=default");
		break;
	case NID_aes_192_gcm:
		priv->sw_aead = EVP_CIPHER_fetch(NULL, "AES-192-GCM", "provider=default");
		break;
	case NID_aes_256_gcm:
		priv->sw_aead = EVP_CIPHER_fetch(NULL, "AES-256-GCM", "provider=default");
		break;
	default:
		break;
	}

	if (unlikely(!priv->sw_aead)) {
		UADK_ERR("aead failed to fetch\n");
		return UADK_AEAD_FAIL;
	}

	priv->sw_ctx = EVP_CIPHER_CTX_new();
	if (!priv->sw_ctx) {
		UADK_ERR("EVP_AEAD_CTX_new failed.\n");
		goto free;
	}

	return UADK_AEAD_SUCCESS;

free:
	EVP_CIPHER_free(priv->sw_aead);
	priv->sw_aead = NULL;

	return UADK_AEAD_FAIL;
}

static int uadk_prov_aead_soft_init(struct aead_priv_ctx *priv, const unsigned char *key,
				    const unsigned char *iv, const OSSL_PARAM *params)
{
	int ret;

	if (!priv->sw_aead)
		return UADK_AEAD_FAIL;

	if (priv->req.op_type == WD_CIPHER_ENCRYPTION_DIGEST)
		ret = EVP_EncryptInit_ex2(priv->sw_ctx, priv->sw_aead, key, iv, params);
	else
		ret = EVP_DecryptInit_ex2(priv->sw_ctx, priv->sw_aead, key, iv, params);

	if (!ret) {
		UADK_ERR("aead soft init error!\n");
		return UADK_AEAD_FAIL;
	}

	priv->stream_switch_flag = UADK_DO_SOFT;

	return UADK_AEAD_SUCCESS;
}

static int uadk_aead_soft_update(struct aead_priv_ctx *priv, unsigned char *out,
				 int *outl, const unsigned char *in, size_t len)
{
	int ret;

	if (!priv->sw_aead)
		return UADK_AEAD_FAIL;

	if (priv->req.op_type == WD_CIPHER_ENCRYPTION_DIGEST)
		ret = EVP_EncryptUpdate(priv->sw_ctx, out, outl, in, len);
	else
		ret = EVP_DecryptUpdate(priv->sw_ctx, out, outl, in, len);

	if (!ret) {
		UADK_ERR("aead soft update error.\n");
		return UADK_AEAD_FAIL;
	}

	priv->stream_switch_flag = UADK_DO_SOFT;

	return UADK_AEAD_SUCCESS;
}

static int uadk_aead_soft_final(struct aead_priv_ctx *priv, unsigned char *digest, size_t *outl)
{
	int ret;

	if (!priv->sw_aead)
		goto error;

	if (priv->req.op_type == WD_CIPHER_ENCRYPTION_DIGEST) {
		ret = EVP_EncryptFinal_ex(priv->sw_ctx, digest, (int *)outl);
		if (!ret)
			goto error;

		ret = EVP_CIPHER_CTX_ctrl(priv->sw_ctx, EVP_CTRL_GCM_GET_TAG,
					  priv->taglen, priv->buf);
		if (!ret)
			goto error;
	} else {
		ret = EVP_CIPHER_CTX_ctrl(priv->sw_ctx, EVP_CTRL_GCM_SET_TAG,
					  priv->taglen, priv->buf);
		if (!ret)
			goto error;

		ret = EVP_DecryptFinal_ex(priv->sw_ctx, digest, (int *)outl);
		if (!ret)
			goto error;
	}

	priv->stream_switch_flag = 0;

	return UADK_AEAD_SUCCESS;

error:
	UADK_ERR("aead soft final failed.\n");
	return UADK_AEAD_FAIL;
}

static void uadk_aead_soft_cleanup(struct aead_priv_ctx *priv)
{
	if (priv->sw_ctx) {
		EVP_CIPHER_CTX_free(priv->sw_ctx);
		priv->sw_ctx = NULL;
	}

	if (priv->sw_aead) {
		EVP_CIPHER_free(priv->sw_aead);
		priv->sw_aead = NULL;
	}
}

static int uadk_prov_aead_dev_init(struct aead_priv_ctx *priv)
{
	struct wd_ctx_nums ctx_set_num;
	struct wd_ctx_params cparams = {0};
	int ret = UADK_AEAD_SUCCESS;

	pthread_atfork(NULL, NULL, uadk_aead_mutex_infork);
	pthread_mutex_lock(&aead_mutex);
	if (aprov.pid == getpid())
		goto mutex_unlock;

	cparams.op_type_num = UADK_AEAD_OP_NUM;
	cparams.ctx_set_num = &ctx_set_num;
	cparams.bmp = numa_allocate_nodemask();
	if (!cparams.bmp) {
		ret = UADK_AEAD_FAIL;
		UADK_ERR("failed to create nodemask!\n");
		goto mutex_unlock;
	}

	numa_bitmask_setall(cparams.bmp);

	ctx_set_num.sync_ctx_num = UADK_AEAD_DEF_CTXS;
	ctx_set_num.async_ctx_num = UADK_AEAD_DEF_CTXS;

	ret = wd_aead_init2_(priv->alg_name, TASK_MIX, SCHED_POLICY_RR, &cparams);
	if (unlikely(ret)) {
		ret = UADK_AEAD_FAIL;
		UADK_ERR("failed to init aead!\n");
		goto free_nodemask;
	}

	aprov.pid = getpid();
	async_register_poll_fn(ASYNC_TASK_AEAD, uadk_aead_poll);

free_nodemask:
	numa_free_nodemask(cparams.bmp);
mutex_unlock:
	pthread_mutex_unlock(&aead_mutex);
	return ret;
}

static int uadk_prov_aead_ctx_init(struct aead_priv_ctx *priv)
{
	struct wd_aead_sess_setup setup = {0};
	struct sched_params params = {0};
	int ret;

	if (!priv->key_set || !priv->iv_set) {
		UADK_ERR("key or iv is not set yet!\n");
		return UADK_AEAD_FAIL;
	}

	priv->req.iv_bytes = priv->ivlen;
	priv->req.iv = priv->iv;
	priv->req.out_bytes = 0;
	priv->req.mac = priv->buf;
	priv->req.mac_bytes = priv->taglen;

	ret = uadk_prov_aead_dev_init(priv);
	if (unlikely(ret < 0))
		return UADK_AEAD_FAIL;

	/* dec and enc use the same op */
	params.type = 0;
	/* Use the default numa parameters */
	params.numa_id = -1;
	setup.sched_param = &params;
	setup.calg = priv->setup.calg;
	setup.cmode = priv->setup.cmode;

	if (!priv->sess) {
		priv->sess = wd_aead_alloc_sess(&setup);
		if (!priv->sess) {
			UADK_ERR("uadk failed to alloc session!\n");
			return UADK_AEAD_FAIL;
		}

		ret = wd_aead_set_authsize(priv->sess, priv->taglen);
		if (ret) {
			UADK_ERR("uadk failed to set authsize!\n");
			goto free_sess;
		}

		ret = wd_aead_set_ckey(priv->sess, priv->key, priv->keylen);
		if (ret) {
			UADK_ERR("uadk failed to set key!\n");
			goto free_sess;
		}
	}

	return UADK_AEAD_SUCCESS;

free_sess:
	wd_aead_free_sess(priv->sess);
	priv->sess = 0;
	return UADK_AEAD_FAIL;
}

static void *uadk_prov_aead_cb(struct wd_aead_req *req, void *data)
{
	struct uadk_e_cb_info *aead_cb_param;
	struct wd_aead_req *req_origin;
	struct async_op *op;

	if (!req || !req->cb_param)
		return NULL;

	aead_cb_param = req->cb_param;
	req_origin = aead_cb_param->priv;
	req_origin->state = req->state;
	op = aead_cb_param->op;
	if (op && op->job && !op->done) {
		op->done = 1;
		async_free_poll_task(op->idx, 1);
		(void) async_wake_job(op->job);
	}

	return NULL;
}

static int do_aes_gcm_prepare(struct aead_priv_ctx *priv)
{
	if (priv->mode == UNINIT_MODE) {
		if (ASYNC_get_current_job())
			priv->mode = ASYNC_MODE;
		else
			priv->mode = SYNC_MODE;
	}

	if (!priv->enc && priv->tag_set == READ_TAG) {
		if (likely(priv->taglen == AES_GCM_TAG_LEN)) {
			memcpy(priv->req.mac, priv->buf, AES_GCM_TAG_LEN);
			priv->tag_set = SET_TAG;
		} else {
			UADK_ERR("invalid: aead gcm mac length only support 16B.\n");
			return UADK_AEAD_FAIL;
		}
	}

	return UADK_AEAD_SUCCESS;
}

static void uadk_do_aead_async_prepare(struct aead_priv_ctx *priv, unsigned char *output,
				       const unsigned char *input, size_t inlen)
{
	priv->req.in_bytes = inlen;
	/* AAD data will be input and output together with plaintext or ciphertext. */
	if (priv->req.assoc_bytes) {
		memcpy(priv->data + priv->req.assoc_bytes, input, inlen);
		priv->req.src = priv->data;
		priv->req.dst = priv->data + AEAD_BLOCK_SIZE;
	} else {
		priv->req.src = (unsigned char *)input;
		priv->req.dst = output;
	}
}

static int uadk_do_aead_sync_inner(struct aead_priv_ctx *priv, unsigned char *out,
				   const unsigned char *in, size_t inlen,
				   enum wd_aead_msg_state state)
{
	int ret;

	if ((state == AEAD_MSG_BLOCK || state == AEAD_MSG_END)
		&& !priv->enc && priv->tag_set != SET_TAG) {
		UADK_ERR("The tag for synchronous decryption is not set.\n");
		return UADK_AEAD_FAIL;
	}

	priv->req.msg_state = state;
	priv->req.src = (unsigned char *)in;
	priv->req.dst = out;
	priv->req.in_bytes = inlen;
	priv->req.state = 0;
	ret = wd_do_aead_sync(priv->sess, &priv->req);
	if (unlikely(ret < 0 || priv->req.state)) {
		UADK_ERR("do aead task failed, msg state: %u, ret: %d, state: %u!\n",
			state, ret, priv->req.state);
		return UADK_AEAD_FAIL;
	}

	return UADK_AEAD_SUCCESS;
}

static int uadk_do_aead_sync(struct aead_priv_ctx *priv, unsigned char *out,
			     const unsigned char *in, size_t inlen)
{
	size_t nbytes, tail, processing_len, max_mid_len;
	const unsigned char *in_block = in;
	unsigned char *out_block = out;
	int ret;

	tail = inlen % AES_BLOCK_SIZE;
	nbytes = inlen - tail;
	max_mid_len = AEAD_BLOCK_SIZE - priv->req.assoc_bytes;

	/* If the data length is not 16-byte aligned, it is split according to the protocol. */
	while (nbytes > 0) {
		processing_len = nbytes > max_mid_len ? max_mid_len : nbytes;
		processing_len -= (processing_len % AES_BLOCK_SIZE);

		ret = uadk_do_aead_sync_inner(priv, out_block, in_block,
						processing_len, AEAD_MSG_MIDDLE);
		if (ret < 0)
			return UADK_AEAD_FAIL;
		nbytes -= processing_len;
		in_block = in_block + processing_len;
		out_block = out_block + processing_len;
	}

	if (tail) {
		ret = uadk_do_aead_sync_inner(priv, out_block, in_block, tail, AEAD_MSG_END);
		if (ret < 0)
			return UADK_AEAD_FAIL;
	}

	return UADK_AEAD_SUCCESS;
}

static int uadk_do_aead_async(struct aead_priv_ctx *priv, struct async_op *op,
			      unsigned char *out, const unsigned char *in, size_t inlen)
{
	struct uadk_e_cb_info cb_param;
	int cnt = 0;
	int ret;

	if (!priv->enc && priv->tag_set != SET_TAG) {
		UADK_ERR("The tag for asynchronous decryption is not set.\n");
		return UADK_AEAD_FAIL;
	}

	if (unlikely(priv->req.assoc_bytes + inlen > AEAD_BLOCK_SIZE)) {
		UADK_ERR("aead input data length is too long!\n");
		return UADK_AEAD_FAIL;
	}

	uadk_do_aead_async_prepare(priv, out, in, inlen);

	cb_param.op = op;
	cb_param.priv = &priv->req;
	priv->req.cb = uadk_prov_aead_cb;
	priv->req.cb_param = &cb_param;
	priv->req.msg_state = AEAD_MSG_BLOCK;
	priv->req.state = POLL_ERROR;

	ret = async_get_free_task(&op->idx);
	if (unlikely(!ret))
		return UADK_AEAD_FAIL;

	do {
		ret = wd_do_aead_async(priv->sess, &priv->req);
		if (unlikely(ret < 0)) {
			if (unlikely(ret != -EBUSY))
				UADK_ERR("do aead async operation failed ret = %d.\n", ret);
			else if (unlikely(cnt++ > ENGINE_SEND_MAX_CNT))
				UADK_ERR("do aead async operation timeout.\n");
			else
				continue;

			async_free_poll_task(op->idx, 0);
			return UADK_AEAD_FAIL;
		}
	} while (ret == -EBUSY);

	ret = async_pause_job(priv, op, ASYNC_TASK_AEAD);
	if (unlikely(!ret || priv->req.state)) {
		UADK_ERR("do aead async job failed, ret: %d, state: %u!\n",
			ret, priv->req.state);
		return UADK_AEAD_FAIL;
	}

	if (priv->req.assoc_bytes)
		memcpy(out, priv->req.dst + priv->req.assoc_bytes, inlen);

	return ret;
}

static int uadk_prov_do_aes_gcm_first(struct aead_priv_ctx *priv, unsigned char *out,
				      const unsigned char *in, size_t inlen)
{
	int ret;

	if (inlen > MAX_AAD_LEN) {
		if (priv->mode != ASYNC_MODE)
			goto soft;

		UADK_ERR("the aad len is out of range, aad len = %zu.\n", inlen);
		return UADK_AEAD_FAIL;
	}

	priv->req.assoc_bytes = inlen;

	/* Asynchronous jobs use the block mode. */
	if (priv->mode == ASYNC_MODE) {
		memcpy(priv->data, in, inlen);
		return UADK_AEAD_SUCCESS;
	}

	if (!priv->req.assoc_bytes)
		goto soft;

	ret = uadk_do_aead_sync_inner(priv, out, in, inlen, AEAD_MSG_FIRST);
	if (unlikely(ret < 0))
		goto soft;

	return UADK_AEAD_SUCCESS;

soft:
	UADK_ERR("aead failed to update aad, switch to soft.\n");
	return SWITCH_TO_SOFT;
}

static int uadk_prov_do_aes_gcm_update(struct aead_priv_ctx *priv, unsigned char *out,
				       const unsigned char *in, size_t inlen)
{
	struct async_op *op;
	int ret;

	if (priv->mode == ASYNC_MODE) {
		op = malloc(sizeof(struct async_op));
		if (unlikely(!op))
			return UADK_AEAD_FAIL;

		ret = async_setup_async_event_notification(op);
		if (unlikely(!ret)) {
			UADK_ERR("failed to setup async event notification.\n");
			goto free_op;
		}

		ret = uadk_do_aead_async(priv, op, out, in, inlen);
		if (unlikely(ret < 0)) {
			UADK_ERR("uadk_do_aead_async failed ret = %d.\n", ret);
			goto free_notification;
		}

		free(op);
		return UADK_AEAD_SUCCESS;
	}

	if (priv->stream_switch_flag == UADK_DO_SOFT)
		return SWITCH_TO_SOFT;

	return uadk_do_aead_sync(priv, out, in, inlen);

free_notification:
	(void)async_clear_async_event_notification();
free_op:
	free(op);
	return UADK_AEAD_FAIL;
}

static int uadk_prov_do_aes_gcm_final(struct aead_priv_ctx *priv, unsigned char *out,
				      const unsigned char *in, size_t inlen)
{
	int ret;

	if (priv->mode == ASYNC_MODE || !priv->req.assoc_bytes ||
	    priv->req.msg_state == AEAD_MSG_END)
		goto out;

	ret = uadk_do_aead_sync_inner(priv, out, in, inlen, AEAD_MSG_END);
	if (unlikely(ret < 0))
		return UADK_AEAD_FAIL;

out:
	if (priv->enc)
		memcpy(priv->buf, priv->req.mac, priv->taglen);
	else
		priv->tag_set = INIT_TAG;

	priv->mode = UNINIT_MODE;
	return UADK_AEAD_SUCCESS;
}

static int uadk_prov_do_aes_gcm(struct aead_priv_ctx *priv, unsigned char *out,
				size_t *outl, size_t outsize,
				const unsigned char *in, size_t inlen)
{
	int ret;

	ret = uadk_prov_aead_ctx_init(priv);
	if (ret != UADK_AEAD_SUCCESS)
		return UADK_AEAD_FAIL;

	ret = do_aes_gcm_prepare(priv);
	if (unlikely(ret < 0))
		return UADK_AEAD_FAIL;

	if (in) {
		if (!out)
			return uadk_prov_do_aes_gcm_first(priv, out, in, inlen);

		return uadk_prov_do_aes_gcm_update(priv, out, in, inlen);
	}

	return uadk_prov_do_aes_gcm_final(priv, out, NULL, 0);
}

void uadk_prov_destroy_aead(void)
{
	pthread_mutex_lock(&aead_mutex);
	if (aprov.pid == getpid()) {
		wd_aead_uninit2();
		aprov.pid = 0;
	}
	pthread_mutex_unlock(&aead_mutex);
}

static OSSL_FUNC_cipher_encrypt_init_fn uadk_prov_aead_einit;
static OSSL_FUNC_cipher_decrypt_init_fn uadk_prov_aead_dinit;
static OSSL_FUNC_cipher_freectx_fn uadk_prov_aead_freectx;
static OSSL_FUNC_cipher_dupctx_fn uadk_prov_aead_dupctx;
static OSSL_FUNC_cipher_get_ctx_params_fn uadk_prov_aead_get_ctx_params;
static OSSL_FUNC_cipher_gettable_ctx_params_fn uadk_prov_aead_gettable_ctx_params;
static OSSL_FUNC_cipher_set_ctx_params_fn uadk_prov_aead_set_ctx_params;
static OSSL_FUNC_cipher_settable_ctx_params_fn uadk_prov_aead_settable_ctx_params;

static int uadk_prov_aead_cipher(void *vctx, unsigned char *out, size_t *outl,
				 size_t outsize, const unsigned char *in,
				 size_t inl)
{
	struct aead_priv_ctx *priv = (struct aead_priv_ctx *)vctx;
	int ret;

	if (!vctx || !out || !outl)
		return UADK_OSSL_FAIL;

	if (outsize < inl) {
		UADK_ERR("invalid: aead cipher outsize is too small.\n");
		return UADK_OSSL_FAIL;
	}

	ret = uadk_prov_do_aes_gcm(priv, out, outl, outsize, in, inl);
	if (ret < 0)
		return UADK_OSSL_FAIL;

	*outl = inl;
	return UADK_AEAD_SUCCESS;
}

static int uadk_prov_aead_stream_update(void *vctx, unsigned char *out,
					size_t *outl, size_t outsize,
					const unsigned char *in, size_t inl)
{
	struct aead_priv_ctx *priv = (struct aead_priv_ctx *)vctx;
	int ret, outlen;

	if (!vctx)
		return UADK_OSSL_FAIL;

	if (outsize < inl) {
		UADK_ERR("invalid: input param outsize is too small.\n");
		return UADK_OSSL_FAIL;
	}

	if (priv->stream_switch_flag == UADK_DO_SOFT)
		goto do_soft;
	ret = uadk_prov_do_aes_gcm(priv, out, outl, outsize, in, inl);
	if (ret == SWITCH_TO_SOFT)
		goto do_soft;
	else if (ret < 0) {
		UADK_ERR("stream data update failed.\n");
		return UADK_OSSL_FAIL;
	} else {
		*outl = inl;
		return UADK_AEAD_SUCCESS;
	}

do_soft:
	if (priv->stream_switch_flag != UADK_DO_SOFT) {
		ret = uadk_prov_aead_soft_init(priv, priv->key, priv->iv, NULL);
		if (ret <= 0)
			return UADK_OSSL_FAIL;
	}

	ret = uadk_aead_soft_update(priv, out, &outlen, in, inl);
	if (ret <= 0)
		return UADK_OSSL_FAIL;

	*outl = outlen;
	return UADK_AEAD_SUCCESS;
}

static int uadk_prov_aead_stream_final(void *vctx, unsigned char *out,
				       size_t *outl, size_t outsize)
{
	struct aead_priv_ctx *priv = (struct aead_priv_ctx *)vctx;
	int ret;

	if (!vctx || !out || !outl)
		return UADK_OSSL_FAIL;

	if (priv->stream_switch_flag == UADK_DO_SOFT)
		goto do_soft;

	ret = uadk_prov_do_aes_gcm(priv, out, outl, outsize, NULL, 0);
	if (ret < 0) {
		UADK_ERR("stream data final failed, ret = %d\n", ret);
		return UADK_OSSL_FAIL;
	}

	*outl = 0;
	return UADK_AEAD_SUCCESS;

do_soft:
	ret = uadk_aead_soft_final(priv, out, outl);
	if (ret) {
		*outl = 0;
		return UADK_AEAD_SUCCESS;
	}

	return UADK_OSSL_FAIL;
}

static int uadk_get_aead_info(struct aead_priv_ctx *priv)
{
	int aead_counts = ARRAY_SIZE(aead_info_table);
	int i;

	for (i = 0; i < aead_counts; i++) {
		if (priv->nid == aead_info_table[i].nid) {
			priv->setup.calg = aead_info_table[i].alg;
			priv->setup.cmode = aead_info_table[i].mode;
			break;
		}
	}

	if (unlikely(i == aead_counts)) {
		UADK_ERR("failed to get aead info.\n");
		return UADK_AEAD_FAIL;
	}

	return UADK_AEAD_SUCCESS;
}

static int uadk_prov_aead_init(struct aead_priv_ctx *priv, const unsigned char *key, size_t keylen,
			       const unsigned char *iv, size_t ivlen, const OSSL_PARAM *params)
{
	int ret;

	if (ivlen > MAX_IV_LEN || keylen > MAX_KEY_LEN) {
		UADK_ERR("invalid keylen or ivlen.\n");
		return UADK_OSSL_FAIL;
	}

	if (iv) {
		memcpy(priv->iv, iv, ivlen);
		priv->iv_set = IV_STATE_SET;
	}

	ret = uadk_get_aead_info(priv);
	if (unlikely(ret < 0))
		return UADK_OSSL_FAIL;

	if (key) {
		memcpy(priv->key, key, keylen);
		priv->key_set = KEY_STATE_SET;
	}

	priv->stream_switch_flag = 0;

	if (uadk_get_sw_offload_state())
		uadk_create_aead_soft_ctx(priv);

	ret = uadk_prov_aead_dev_init(priv);
	if (unlikely(ret < 0)) {
		if (ASYNC_get_current_job())
			return UADK_OSSL_FAIL;

		UADK_ERR("aead switch to soft init.!\n");
		return uadk_prov_aead_soft_init(priv, key, iv, params);
	}

	return UADK_AEAD_SUCCESS;
}

static int uadk_prov_aead_einit(void *vctx, const unsigned char *key, size_t keylen,
				const unsigned char *iv, size_t ivlen,
				const OSSL_PARAM params[])
{
	struct aead_priv_ctx *priv = (struct aead_priv_ctx *)vctx;

	if (!vctx)
		return UADK_OSSL_FAIL;

	priv->req.op_type = WD_CIPHER_ENCRYPTION_DIGEST;
	priv->enc = 1;

	return uadk_prov_aead_init(priv, key, keylen, iv, ivlen, params);
}

static int uadk_prov_aead_dinit(void *vctx, const unsigned char *key, size_t keylen,
				const unsigned char *iv, size_t ivlen,
				const OSSL_PARAM params[])
{
	struct aead_priv_ctx *priv = (struct aead_priv_ctx *)vctx;

	if (!vctx)
		return UADK_OSSL_FAIL;

	priv->req.op_type = WD_CIPHER_DECRYPTION_DIGEST;
	priv->enc = 0;

	return uadk_prov_aead_init(priv, key, keylen, iv, ivlen, params);
}

static const OSSL_PARAM uadk_prov_settable_ctx_params[] = {
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN, NULL),
	OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
	OSSL_PARAM_END
};

const OSSL_PARAM *uadk_prov_aead_settable_ctx_params(ossl_unused void *cctx,
						       ossl_unused void *provctx)
{
	return uadk_prov_settable_ctx_params;
}

static int uadk_prov_aead_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
	struct aead_priv_ctx *priv = (struct aead_priv_ctx *)vctx;
	const OSSL_PARAM *p;
	size_t sz = 0;
	void *vp;

	if (!vctx)
		return UADK_OSSL_FAIL;

	p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
	if (p) {
		vp = priv->buf;
		if (!OSSL_PARAM_get_octet_string(p, &vp, EVP_GCM_TLS_TAG_LEN, &sz)) {
			UADK_ERR("failed to get string parameter: sz.\n");
			return UADK_OSSL_FAIL;
		}

		if (sz == 0 || priv->enc) {
			UADK_ERR("invalid sz or enc.\n");
			return UADK_OSSL_FAIL;
		}
		priv->tag_set = READ_TAG;
		priv->taglen = sz;
	}

	p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
	if (p) {
		size_t keylen;

		if (!OSSL_PARAM_get_size_t(p, &keylen)) {
			UADK_ERR("failed to get parameter: keylen.\n");
			return UADK_OSSL_FAIL;
		}
		if (priv->keylen != keylen) {
			UADK_ERR("keylen is invalid.\n");
			return UADK_OSSL_FAIL;
		}
	}

	p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_IVLEN);
	if (p) {
		if (!OSSL_PARAM_get_size_t(p, &sz)) {
			UADK_ERR("failed to get size parameter: sz.\n");
			return UADK_OSSL_FAIL;
		}
		if (sz == 0 || sz > priv->ivlen) {
			UADK_ERR("invalid sz or ivlen.\n");
			return UADK_OSSL_FAIL;
		}
		priv->ivlen = sz;
	}

	return UADK_AEAD_SUCCESS;
}

static const OSSL_PARAM uadk_prov_aead_ctx_params[] = {
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, NULL),
	OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
	OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, NULL, 0),
	OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
	OSSL_PARAM_END
};

static const OSSL_PARAM *uadk_prov_aead_gettable_ctx_params(ossl_unused void *cctx,
							    ossl_unused void *provctx)
{
	return uadk_prov_aead_ctx_params;
}

static int uadk_prov_aead_get_ctx_iv(OSSL_PARAM *p, struct aead_priv_ctx *priv)
{
	if (priv->iv_set == IV_STATE_UNINITIALISED)
		return UADK_OSSL_FAIL;

	if (priv->ivlen > p->data_size) {
		UADK_ERR("invalid: input param ivlen is too long.\n");
		return UADK_OSSL_FAIL;
	}

	if (!OSSL_PARAM_set_octet_string(p, priv->iv, priv->ivlen)
		&& !OSSL_PARAM_set_octet_ptr(p, &priv->iv, priv->ivlen)) {
		UADK_ERR("failed to set octet ptr parameter: iv.\n");
		return UADK_OSSL_FAIL;
	}

	return UADK_AEAD_SUCCESS;
}

static int uadk_prov_aead_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
	struct aead_priv_ctx *priv = (struct aead_priv_ctx *)vctx;
	OSSL_PARAM *p;

	if (!vctx || !params)
		return UADK_OSSL_FAIL;

	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
	if (p && !OSSL_PARAM_set_size_t(p, priv->ivlen)) {
		UADK_ERR("failed to set size parameter: ivlen.\n");
		return UADK_OSSL_FAIL;
	}

	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
	if (p && !OSSL_PARAM_set_size_t(p, priv->keylen)) {
		UADK_ERR("failed to set size parameter: keylen.\n");
		return UADK_OSSL_FAIL;
	}

	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
	if (p) {
		size_t taglen = (priv->taglen != UNINITIALISED_SIZET) ?
				priv->taglen : AES_GCM_TAG_LEN;

		if (!OSSL_PARAM_set_size_t(p, taglen)) {
			UADK_ERR("failed to set size parameter: taglen.\n");
			return UADK_OSSL_FAIL;
		}
	}

	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
	if (p && !uadk_prov_aead_get_ctx_iv(p, priv))
		return UADK_OSSL_FAIL;

	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
	if (p && !uadk_prov_aead_get_ctx_iv(p, priv))
		return UADK_OSSL_FAIL;

	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAG);
	if (p) {
		size_t sz = p->data_size;

		if (sz == 0 || sz > EVP_GCM_TLS_TAG_LEN || !priv->enc
			|| priv->taglen == UNINITIALISED_SIZET) {
			UADK_ERR("invalid size enc or taglen.\n");
			return UADK_OSSL_FAIL;
		}

		if (!OSSL_PARAM_set_octet_string(p, priv->buf, sz)) {
			UADK_ERR("failed to set octet string parameter: sz.\n");
			return UADK_OSSL_FAIL;
		}
	}

	return UADK_AEAD_SUCCESS;
}

static const OSSL_PARAM aead_known_gettable_params[] = {
	OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
	OSSL_PARAM_int(OSSL_CIPHER_PARAM_AEAD, NULL),
	OSSL_PARAM_int(OSSL_CIPHER_PARAM_CUSTOM_IV, NULL),
	OSSL_PARAM_END
};

static const OSSL_PARAM *uadk_prov_aead_gettable_params(ossl_unused void *provctx)
{
	return aead_known_gettable_params;
}

static int uadk_cipher_aead_get_params(OSSL_PARAM params[], unsigned int md,
				       uint64_t flags, size_t kbits,
				       size_t blkbits, size_t ivbits)
{
	OSSL_PARAM *p;

	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
	if (p && !OSSL_PARAM_set_uint(p, md)) {
		UADK_ERR("failed to set uint parameter: md.\n");
		return UADK_OSSL_FAIL;
	}
	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD);
	if (p && !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_AEAD) != 0)) {
		UADK_ERR("failed to set int parameter: flag aead.\n");
		return UADK_OSSL_FAIL;
	}
	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CUSTOM_IV);
	if (p && !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_CUSTOM_IV) != 0)) {
		UADK_ERR("failed to set int parameter: flag custom iv.\n");
		return UADK_OSSL_FAIL;
	}
	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
	if (p && !OSSL_PARAM_set_size_t(p, kbits)) {
		UADK_ERR("failed to set size parameter: kbits.\n");
		return UADK_OSSL_FAIL;
	}
	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
	if (p && !OSSL_PARAM_set_size_t(p, blkbits)) {
		UADK_ERR("failed to set size parameter: blkbits.\n");
		return UADK_OSSL_FAIL;
	}
	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
	if (p && !OSSL_PARAM_set_size_t(p, ivbits)) {
		UADK_ERR("failed to set size parameter: ivbits.\n");
		return UADK_OSSL_FAIL;
	}

	return UADK_AEAD_SUCCESS;
}

static void *uadk_prov_aead_dupctx(void *ctx)
{
	struct aead_priv_ctx *dst_ctx, *src_ctx;
	int ret;

	src_ctx = (struct aead_priv_ctx *)ctx;
	if (!src_ctx)
		return NULL;

	dst_ctx = OPENSSL_memdup(src_ctx, sizeof(*src_ctx));
	if (!dst_ctx)
		return NULL;

	dst_ctx->sess = 0;
	dst_ctx->data = OPENSSL_memdup(src_ctx->data, AEAD_BLOCK_SIZE << 1);
	if (!dst_ctx->data)
		goto free_ctx;

	if (dst_ctx->sw_ctx) {
		dst_ctx->sw_ctx = EVP_CIPHER_CTX_dup(src_ctx->sw_ctx);
		if (!dst_ctx->sw_ctx) {
			UADK_ERR("EVP_CIPHER_CTX_dup failed in ctx copy.\n");
			goto free_data;
		}

		ret = EVP_CIPHER_up_ref(dst_ctx->sw_aead);
		if (!ret)
			goto free_dup;
	}

	return dst_ctx;

free_dup:
	if (dst_ctx->sw_ctx)
		EVP_CIPHER_CTX_free(dst_ctx->sw_ctx);
free_data:
	OPENSSL_clear_free(dst_ctx->data, AEAD_BLOCK_SIZE << 1);
free_ctx:
	OPENSSL_clear_free(dst_ctx, sizeof(*dst_ctx));
	return NULL;
}

static void uadk_prov_aead_freectx(void *ctx)
{
	struct aead_priv_ctx *priv = (struct aead_priv_ctx *)ctx;

	if (!ctx)
		return;

	if (priv->sess)
		wd_aead_free_sess(priv->sess);

	if (priv->data)
		OPENSSL_clear_free(priv->data, AEAD_BLOCK_SIZE << 1);

	if (priv->sw_ctx)
		uadk_aead_soft_cleanup(priv);

	OPENSSL_clear_free(priv, sizeof(*priv));
}

#define UADK_AEAD_DESCR(nm, tag_len, key_len, iv_len, blk_size,			\
			flags, e_nid, algnm, mode)				\
static OSSL_FUNC_cipher_newctx_fn uadk_##nm##_newctx;				\
static void *uadk_##nm##_newctx(void *provctx)					\
{										\
	struct aead_priv_ctx *ctx = OPENSSL_zalloc(sizeof(*ctx));		\
	if (!ctx)								\
		return NULL;							\
										\
	ctx->data = OPENSSL_zalloc(AEAD_BLOCK_SIZE << 1);			\
	if (!ctx->data) {							\
		OPENSSL_free(ctx);						\
		return NULL;							\
	}									\
										\
	ctx->keylen = key_len;							\
	ctx->ivlen = iv_len;							\
	ctx->nid = e_nid;							\
	ctx->taglen = tag_len;							\
	strncpy(ctx->alg_name, #algnm, ALG_NAME_SIZE - 1);			\
										\
	return ctx;								\
}										\
static OSSL_FUNC_cipher_get_params_fn uadk_##nm##_get_params;			\
static int uadk_##nm##_get_params(OSSL_PARAM params[])				\
{										\
	return uadk_cipher_aead_get_params(params, mode, flags,			\
					      key_len, blk_size, iv_len);	\
}										\
const OSSL_DISPATCH uadk_##nm##_functions[] = {					\
	{ OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))uadk_##nm##_newctx },	\
	{ OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))uadk_prov_aead_freectx },	\
	{ OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))uadk_prov_aead_dupctx },	\
	{ OSSL_FUNC_CIPHER_ENCRYPT_INIT,					\
		(void (*)(void))uadk_prov_aead_einit },				\
	{ OSSL_FUNC_CIPHER_DECRYPT_INIT,					\
		(void (*)(void))uadk_prov_aead_dinit },				\
	{ OSSL_FUNC_CIPHER_UPDATE,						\
		(void (*)(void))uadk_prov_aead_stream_update },			\
	{ OSSL_FUNC_CIPHER_FINAL,						\
		(void (*)(void))uadk_prov_aead_stream_final },			\
	{ OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))uadk_prov_aead_cipher },	\
	{ OSSL_FUNC_CIPHER_GET_PARAMS,						\
		(void (*)(void))uadk_##nm##_get_params },			\
	{ OSSL_FUNC_CIPHER_GETTABLE_PARAMS,					\
		(void (*)(void))uadk_prov_aead_gettable_params },		\
	{ OSSL_FUNC_CIPHER_GET_CTX_PARAMS,					\
		(void (*)(void))uadk_prov_aead_get_ctx_params },		\
	{ OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,					\
		(void (*)(void))uadk_prov_aead_gettable_ctx_params },		\
	{ OSSL_FUNC_CIPHER_SET_CTX_PARAMS,					\
		(void (*)(void))uadk_prov_aead_set_ctx_params },		\
	{ OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,					\
		(void (*)(void))uadk_prov_aead_settable_ctx_params },		\
	{ 0, NULL }								\
}

UADK_AEAD_DESCR(aes_128_gcm, AES_GCM_TAG_LEN, 16, 12, 8, AEAD_FLAGS, NID_aes_128_gcm, gcm(aes),
		EVP_CIPH_GCM_MODE);
UADK_AEAD_DESCR(aes_192_gcm, AES_GCM_TAG_LEN, 24, 12, 8, AEAD_FLAGS, NID_aes_192_gcm, gcm(aes),
		EVP_CIPH_GCM_MODE);
UADK_AEAD_DESCR(aes_256_gcm, AES_GCM_TAG_LEN, 32, 12, 8, AEAD_FLAGS, NID_aes_256_gcm, gcm(aes),
		EVP_CIPH_GCM_MODE);
