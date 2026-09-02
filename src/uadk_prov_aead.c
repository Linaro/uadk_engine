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

#define AES_CTR_IV_LEN			16
#define GCM_IV_DEFAULT_SIZE		12
#define AES_GCM_COUNTER_SIZE		4

#define AES_BLOCK_OFFSET		4
#define AES_CTR_COUNTER_SIZE		8
#define BYTE_TO_BITS			8
#define ALIGN_DOWN(x, align)		((x) & ~((align) - 1))

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

	struct wd_aead_req req;
	enum uadk_aead_mode mode;
	handle_t sess;

	int stream_switch_flag;    /* soft calculation switch flag for stream mode */
	EVP_CIPHER_CTX *sw_ctx;
	EVP_CIPHER *sw_aead;
	unsigned char partial_data[AES_BLOCK_SIZE];
	OSSL_LIB_CTX *libctx;
	size_t partial_len;
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

static int uadk_prov_aead_alloc_sess(struct aead_priv_ctx *priv);

# if OPENSSL_VERSION_NUMBER <= 0x30200000L
static EVP_CIPHER_CTX *EVP_CIPHER_CTX_dup(const EVP_CIPHER_CTX *in)
{
	EVP_CIPHER_CTX *out = EVP_CIPHER_CTX_new();

	if (out != NULL && !EVP_CIPHER_CTX_copy(out, in)) {
		EVP_CIPHER_CTX_free(out);
		out = NULL;
	}

	return out;
}
# endif

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
		priv->sw_aead = EVP_CIPHER_fetch(priv->libctx, "AES-128-GCM", "provider=default");
		break;
	case NID_aes_192_gcm:
		priv->sw_aead = EVP_CIPHER_fetch(priv->libctx, "AES-192-GCM", "provider=default");
		break;
	case NID_aes_256_gcm:
		priv->sw_aead = EVP_CIPHER_fetch(priv->libctx, "AES-256-GCM", "provider=default");
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

static int uadk_prov_aead_soft_init(struct aead_priv_ctx *priv)
{
	int ret;

	if (!priv->sw_aead)
		return UADK_AEAD_FAIL;

	if (priv->req.op_type == WD_CIPHER_ENCRYPTION_DIGEST)
		ret = EVP_EncryptInit_ex2(priv->sw_ctx, priv->sw_aead,
					  priv->key, priv->iv, NULL);
	else
		ret = EVP_DecryptInit_ex2(priv->sw_ctx, priv->sw_aead,
					  priv->key, priv->iv, NULL);

	if (!ret) {
		UADK_ERR("aead soft init error!\n");
		return UADK_AEAD_FAIL;
	}

	priv->stream_switch_flag = UADK_DO_SOFT;

	return UADK_AEAD_SUCCESS;
}

static int uadk_aead_soft_update(struct aead_priv_ctx *priv, unsigned char *out,
				 size_t *outl, const unsigned char *in, size_t len)
{
	int outsize;
	int ret;

	if (!priv->sw_aead)
		return UADK_AEAD_FAIL;

	if (priv->req.op_type == WD_CIPHER_ENCRYPTION_DIGEST)
		ret = EVP_EncryptUpdate(priv->sw_ctx, out, &outsize, in, len);
	else
		ret = EVP_DecryptUpdate(priv->sw_ctx, out, &outsize, in, len);

	if (!ret) {
		UADK_ERR("aead soft update error.\n");
		return UADK_AEAD_FAIL;
	}

	*outl = outsize;

	return UADK_AEAD_SUCCESS;
}

static void uadk_prov_aead_reset_ctx(struct aead_priv_ctx *priv)
{
	priv->stream_switch_flag = 0;
	priv->req.assoc_bytes = 0;
	priv->partial_len = 0;
	priv->mode = UNINIT_MODE;
	priv->req.msg_state = AEAD_MSG_INVALID;
}

static int uadk_aead_soft_final(struct aead_priv_ctx *priv, unsigned char *digest, size_t *outl)
{
	int ret, outsize = 0;

	if (!priv->sw_aead)
		return UADK_OSSL_FAIL;

	if (priv->req.op_type == WD_CIPHER_ENCRYPTION_DIGEST) {
		ret = EVP_EncryptFinal_ex(priv->sw_ctx, digest, &outsize);
		if (!ret)
			goto error;

		ret = EVP_CIPHER_CTX_ctrl(priv->sw_ctx, EVP_CTRL_GCM_GET_TAG,
					  priv->taglen, priv->buf);
		if (ret == UADK_AEAD_SUCCESS)
			priv->tag_set = SET_TAG;
	} else {
		ret = EVP_CIPHER_CTX_ctrl(priv->sw_ctx, EVP_CTRL_GCM_SET_TAG,
					  priv->taglen, priv->buf);
		if (!ret)
			goto error;

		ret = EVP_DecryptFinal_ex(priv->sw_ctx, digest, &outsize);
	}

error:
	if (!ret)
		UADK_ERR("aead soft final failed.\n");
	*outl = 0;
	uadk_prov_aead_reset_ctx(priv);
	return ret;
}

static int uadk_prov_aead_dev_init(struct aead_priv_ctx *priv)
{
	struct wd_ctx_nums ctx_set_num;
	struct wd_ctx_params cparams = {0};
	int ret = UADK_AEAD_SUCCESS;

	if (aprov.pid == getpid())
		return ret;

	cparams.op_type_num = UADK_AEAD_OP_NUM;
	cparams.ctx_set_num = &ctx_set_num;
	cparams.bmp = numa_allocate_nodemask();
	if (!cparams.bmp) {
		UADK_ERR("failed to create nodemask!\n");
		return UADK_AEAD_FAIL;
	}

	numa_bitmask_setall(cparams.bmp);

	ctx_set_num.sync_ctx_num = UADK_AEAD_DEF_CTXS;
	ctx_set_num.async_ctx_num = UADK_AEAD_DEF_CTXS;

	pthread_atfork(NULL, NULL, uadk_aead_mutex_infork);
	pthread_mutex_lock(&aead_mutex);
	if (aprov.pid == getpid())
		goto free_nodemask;

	ret = wd_aead_init2_(priv->alg_name, SCHED_POLICY_RR, TASK_MIX, &cparams);
	if (unlikely(ret)) {
		ret = UADK_AEAD_FAIL;
		UADK_ERR("failed to init aead!\n");
		goto free_nodemask;
	}

	async_register_poll_fn(ASYNC_TASK_AEAD, uadk_aead_poll);
	mb();
	aprov.pid = getpid();

free_nodemask:
	pthread_mutex_unlock(&aead_mutex);
	numa_free_nodemask(cparams.bmp);
	return ret;
}

static int uadk_prov_aead_ctx_init(struct aead_priv_ctx *priv)
{
	int ret;

	if (!priv->key_set || !priv->iv_set) {
		UADK_ERR("key or iv is not set yet!\n");
		return UADK_AEAD_FAIL;
	}

	priv->req.iv_bytes = priv->ivlen;
	priv->req.iv = priv->iv;
	/* Initialize the counter value for CTR (Counter) mode encryption. */
	memset(priv->iv + GCM_IV_DEFAULT_SIZE, 0, AES_GCM_COUNTER_SIZE);
	priv->iv[AES_CTR_IV_LEN - 1] = 0x2;

	priv->req.out_bytes = 0;
	priv->req.mac = priv->buf;
	priv->req.mac_bytes = AES_GCM_TAG_LEN;

	if (!priv->sess) {
		ret = uadk_prov_aead_alloc_sess(priv);
		if (unlikely(ret < 0))
			return UADK_AEAD_FAIL;
	}

	ret = wd_aead_set_authsize(priv->sess, AES_GCM_TAG_LEN);
	if (ret) {
		UADK_ERR("uadk failed to set authsize!\n");
		return UADK_AEAD_FAIL;
	}

	return UADK_AEAD_SUCCESS;
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

static int uadk_do_aead_sync_inner(struct aead_priv_ctx *priv)
{
	int ret;

	ret = wd_do_aead_sync(priv->sess, &priv->req);
	if (unlikely(ret < 0 || priv->req.state)) {
		UADK_ERR("do aead sync task failed, ret: %d, state: %u!\n",
			 ret, priv->req.state);
		return UADK_AEAD_FAIL;
	}

	return UADK_AEAD_SUCCESS;
}

static int uadk_do_aead_async_inner(struct aead_priv_ctx *priv)
{
	struct uadk_e_cb_info cb_param;
	struct async_op op;
	int cnt = 0;
	int ret;

	ret = async_setup_async_event_notification(&op);
	if (unlikely(!ret)) {
		UADK_ERR("failed to setup async event notification.\n");
		return UADK_AEAD_FAIL;
	}

	cb_param.op = &op;
	cb_param.priv = &priv->req;
	priv->req.cb = uadk_prov_aead_cb;
	priv->req.cb_param = &cb_param;

	ret = async_get_free_task(&op.idx);
	if (unlikely(!ret))
		goto free_notification;

	do {
		ret = wd_do_aead_async(priv->sess, &priv->req);
		if (unlikely(ret < 0)) {
			if (unlikely(ret != -EBUSY))
				UADK_ERR("do aead async operation failed ret = %d.\n", ret);
			else if (unlikely(cnt++ > PROV_SEND_MAX_CNT))
				UADK_ERR("do aead async operation timeout.\n");
			else
				continue;

			async_free_poll_task(op.idx, 0);
			goto free_notification;
		}
	} while (ret == -EBUSY);

	ret = async_pause_job(priv, &op, ASYNC_TASK_AEAD);
	if (unlikely(!ret || priv->req.state)) {
		UADK_ERR("do aead async job failed, ret: %d, state: %u!\n",
			 ret, priv->req.state);
		goto free_notification;
	}

	return UADK_AEAD_SUCCESS;

free_notification:
	(void)async_clear_async_event_notification();
	return UADK_AEAD_FAIL;
}

static int uadk_do_aes_gcm_inner(struct aead_priv_ctx *priv, unsigned char *out,
				 const unsigned char *in, size_t inlen,
				 enum wd_aead_msg_state state)
{
	priv->req.msg_state = state;
	priv->req.src = (unsigned char *)in;
	priv->req.dst = out;
	priv->req.in_bytes = inlen;
	priv->req.state = POLL_ERROR;

	if (priv->mode == ASYNC_MODE)
		return uadk_do_aead_async_inner(priv);

	return uadk_do_aead_sync_inner(priv);
}

static int uadk_prov_do_aes_gcm_first(struct aead_priv_ctx *priv, unsigned char *out,
				      size_t *outl, const unsigned char *in, size_t inlen)
{
	int ret;

	if (inlen > MAX_AAD_LEN || !inlen)
		return SWITCH_TO_SOFT;

	ret = uadk_prov_aead_ctx_init(priv);
	if (ret != UADK_AEAD_SUCCESS)
		return ret;

	if (ASYNC_get_current_job())
		priv->mode = ASYNC_MODE;
	else
		priv->mode = SYNC_MODE;

	priv->req.assoc_bytes = inlen;
	ret = uadk_do_aes_gcm_inner(priv, out, in, inlen, AEAD_MSG_FIRST);
	if (ret == UADK_AEAD_FAIL) {
		priv->req.msg_state = AEAD_MSG_INVALID;
		priv->req.assoc_bytes = 0;
		UADK_ERR("aead failed to update aad, switch to soft.\n");
		return SWITCH_TO_SOFT;
	}

	*outl = 0;

	return UADK_AEAD_SUCCESS;
}

/*
 * Increment counter (128-bit int) by software,
 * in CTR mode, the last 8 bytes are the counter.
 */
static void ctr_iv_inc(__u8 *counter, __u32 len)
{
	__u32 n = AES_CTR_COUNTER_SIZE;
	__u32 c = len;

	do {
		--n;
		c += counter[n];
		counter[n] = (__u8)c;
		c >>= BYTE_TO_BITS;
	} while (n);
}

static int uadk_prov_process_partial_data(struct aead_priv_ctx *priv, unsigned char *out,
					  const unsigned char *in, size_t inlen,
					  size_t *processed_len)
{
	size_t processing_len = AES_BLOCK_SIZE - priv->partial_len;
	unsigned char block_out[AES_BLOCK_SIZE];
	int ret;

	if (!priv->partial_len)
		return UADK_AEAD_SUCCESS;

	/* If input can't complete the partial block, switch to soft */
	if (inlen < processing_len)
		return SWITCH_TO_SOFT;

	memcpy(priv->partial_data + priv->partial_len, in, processing_len);
	ret = uadk_do_aes_gcm_inner(priv, block_out, priv->partial_data,
				    AES_BLOCK_SIZE, AEAD_MSG_MIDDLE);
	if (unlikely(ret == UADK_AEAD_FAIL)) {
		UADK_ERR("failed to process partial block.\n");
		return UADK_AEAD_FAIL;
	}

	memcpy(out, block_out + priv->partial_len, processing_len);
	priv->partial_len = 0;
	ctr_iv_inc(priv->iv + AES_CTR_COUNTER_SIZE, 1);
	*processed_len = processing_len;

	return UADK_AEAD_SUCCESS;
}

/* Process last incomplete block, encrypt/decrypt using OpenSSL software implementation */
static int uadk_prov_process_tail_data(struct aead_priv_ctx *priv, unsigned char *out,
				       const unsigned char *in, size_t inlen)
{
	unsigned char block_out[AES_BLOCK_SIZE];
	EVP_CIPHER *cipher = NULL;
	int ret = UADK_AEAD_FAIL;
	EVP_CIPHER_CTX *ctx;
	int outsize = 0;

	if (!inlen)
		return UADK_AEAD_SUCCESS;

	/* Buffer the tail data */
	memcpy(priv->partial_data + priv->partial_len, in, inlen);

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return UADK_AEAD_FAIL;

	switch (priv->nid) {
	case NID_aes_128_gcm:
		cipher = EVP_CIPHER_fetch(priv->libctx, "AES-128-CTR", "provider=default");
		break;
	case NID_aes_192_gcm:
		cipher = EVP_CIPHER_fetch(priv->libctx, "AES-192-CTR", "provider=default");
		break;
	case NID_aes_256_gcm:
		cipher = EVP_CIPHER_fetch(priv->libctx, "AES-256-CTR", "provider=default");
		break;
	default:
		break;
	}
	if (!cipher)
		goto free_ctx;

	ret = EVP_CipherInit_ex2(ctx, cipher, priv->key, priv->iv, priv->enc, NULL);
	if (!ret)
		goto free_cipher;

	ret = EVP_CipherUpdate(ctx, block_out, &outsize, priv->partial_data,
				priv->partial_len + inlen);
	if (!ret)
		goto free_cipher;

	ret = EVP_CipherFinal_ex(ctx, block_out + inlen, &outsize);
	if (!ret)
		goto free_cipher;

	memcpy(out, block_out + priv->partial_len, inlen);
	priv->partial_len += inlen;

free_cipher:
	EVP_CIPHER_free(cipher);
free_ctx:
	EVP_CIPHER_CTX_free(ctx);
	return ret;
}

/* Process complete blocks in bulk */
static int uadk_process_complete_blocks(struct aead_priv_ctx *priv, unsigned char *out,
					const unsigned char *in, size_t len)
{
	size_t max_mid_len = AEAD_BLOCK_SIZE - priv->req.assoc_bytes;
	size_t remain_len = len;
	size_t chunk;
	int ret;

	while (remain_len > 0) {
		chunk = (remain_len > max_mid_len) ? max_mid_len : remain_len;
		chunk = ALIGN_DOWN(chunk, AES_BLOCK_SIZE);

		ret = uadk_do_aes_gcm_inner(priv, out, in, chunk, AEAD_MSG_MIDDLE);
		if (unlikely(ret == UADK_AEAD_FAIL)) {
			UADK_ERR("failed to process complete block.\n");
			return UADK_AEAD_FAIL;
		}

		remain_len -= chunk;
		out += chunk;
		in += chunk;
	}

	ctr_iv_inc(priv->iv + AES_CTR_COUNTER_SIZE, len >> AES_BLOCK_OFFSET);

	return UADK_AEAD_SUCCESS;
}

/*
 * The uadk does not support the scenario where the length of the intermediate
 * packet is not 16-byte aligned. To avoid task failures, AES-CTR is used for
 * encryption and decryption, and the data and the next task are combined to make the
 * length 16-byte aligned. Then, the uadk calculates the hash value. However, it is
 * recommended that the packet length be aligned to ensure that the performance is not
 * affected by this problem.
 */
static int uadk_prov_do_aes_gcm_update(struct aead_priv_ctx *priv, unsigned char *out,
				       size_t *outl, const unsigned char *in, size_t inlen)
{
	size_t remain_len = inlen;
	size_t processed_len = 0;
	int ret;

	if (!priv->req.assoc_bytes)
		return SWITCH_TO_SOFT;

	*outl = inlen;
	/* Process buffered partial data */
	ret = uadk_prov_process_partial_data(priv, out, in, remain_len, &processed_len);
	if (ret == SWITCH_TO_SOFT)
		goto soft_fallback;
	else if (ret < 0)
		return UADK_AEAD_FAIL;

	out += processed_len;
	in += processed_len;
	remain_len -= processed_len;

	if (remain_len >= AES_BLOCK_SIZE) {
		processed_len = ALIGN_DOWN(remain_len, AES_BLOCK_SIZE);
		ret = uadk_process_complete_blocks(priv, out, in, processed_len);
		if (ret != UADK_AEAD_SUCCESS)
			return UADK_AEAD_FAIL;
		remain_len -= processed_len;
		out += processed_len;
		in += processed_len;
	}

soft_fallback:
	return uadk_prov_process_tail_data(priv, out, in, remain_len);
}

static int uadk_prov_do_aes_gcm_final(struct aead_priv_ctx *priv, unsigned char *out,
				      size_t *outl, const unsigned char *in, size_t inlen)
{
	unsigned char block_out[AES_BLOCK_SIZE];
	int ret;

	if (!priv->req.assoc_bytes)
		return SWITCH_TO_SOFT;

	if (!priv->enc) {
		if (priv->tag_set != READ_TAG) {
			UADK_ERR("decrypt tag not set.\n");
			ret = UADK_OSSL_FAIL;
			goto out;
		}

		if (priv->taglen != AES_GCM_TAG_LEN) {
			ret = wd_aead_set_authsize(priv->sess, priv->taglen);
			if (ret) {
				ret = UADK_OSSL_FAIL;
				goto out;
			}
		}
	}

	if (priv->partial_len)
		ret = uadk_do_aes_gcm_inner(priv, block_out, priv->partial_data,
					    priv->partial_len, AEAD_MSG_END);
	else
		ret = uadk_do_aes_gcm_inner(priv, out, in, inlen, AEAD_MSG_END);
	if (unlikely(ret == UADK_AEAD_FAIL)) {
		UADK_ERR("uadk_prov_do_aes_gcm_final failed.\n");
		goto out;
	}

	if (priv->enc)
		priv->tag_set = SET_TAG;

out:
	uadk_prov_aead_reset_ctx(priv);
	*outl = 0;

	return ret;
}

static int uadk_prov_sw_aes_gcm(struct aead_priv_ctx *priv, unsigned char *out,
				size_t *outl, const unsigned char *in, size_t inlen)
{
	int ret;

	if (priv->stream_switch_flag != UADK_DO_SOFT) {
		ret = uadk_prov_aead_soft_init(priv);
		if (ret <= 0)
			return UADK_OSSL_FAIL;
	}

	if (in)
		return uadk_aead_soft_update(priv, out, outl, in, inlen);

	return uadk_aead_soft_final(priv, out, outl);
}

static int uadk_prov_do_aes_gcm(struct aead_priv_ctx *priv, unsigned char *out,
				size_t *outl, const unsigned char *in, size_t inlen)
{
	int ret;

	if (priv->stream_switch_flag == UADK_DO_SOFT)
		return uadk_prov_sw_aes_gcm(priv, out, outl, in, inlen);

	if (in) {
		if (!out)
			ret = uadk_prov_do_aes_gcm_first(priv, out, outl, in, inlen);
		else
			ret = uadk_prov_do_aes_gcm_update(priv, out, outl, in, inlen);
	} else {
		ret = uadk_prov_do_aes_gcm_final(priv, out, outl, NULL, 0);
	}
	if (ret == SWITCH_TO_SOFT)
		return uadk_prov_sw_aes_gcm(priv, out, outl, in, inlen);

	return ret;
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

	if (!vctx || !outl)
		return UADK_OSSL_FAIL;

	if (out && outsize < inl) {
		UADK_ERR("invalid: aead cipher outsize is too small.\n");
		return UADK_OSSL_FAIL;
	}

	ret = uadk_prov_do_aes_gcm(priv, out, outl, in, inl);
	if (ret <= 0) {
		*outl = 0;
		return UADK_OSSL_FAIL;
	}

	return UADK_AEAD_SUCCESS;
}

static int uadk_prov_aead_stream_update(void *vctx, unsigned char *out,
					size_t *outl, size_t outsize,
					const unsigned char *in, size_t inl)
{
	struct aead_priv_ctx *priv = (struct aead_priv_ctx *)vctx;
	int ret;

	if (!vctx || !outl)
		return UADK_OSSL_FAIL;

	if (!inl) {
		*outl = 0;
		return UADK_AEAD_SUCCESS;
	}

	if (out && outsize < inl) {
		UADK_ERR("invalid: input param outsize is too small.\n");
		return UADK_OSSL_FAIL;
	}

	ret = uadk_prov_do_aes_gcm(priv, out, outl, in, inl);
	if (ret <= 0) {
		*outl = 0;
		return UADK_OSSL_FAIL;
	}

	return UADK_AEAD_SUCCESS;
}

static int uadk_prov_aead_stream_final(void *vctx, unsigned char *out,
				       size_t *outl, size_t outsize)
{
	struct aead_priv_ctx *priv = (struct aead_priv_ctx *)vctx;
	int ret;

	if (!vctx || !outl)
		return UADK_OSSL_FAIL;

	ret = uadk_prov_do_aes_gcm(priv, out, outl, NULL, 0);
	if (ret <= 0) {
		*outl = 0;
		return UADK_OSSL_FAIL;
	}

	return UADK_AEAD_SUCCESS;
}

static int uadk_get_aead_info(struct wd_aead_sess_setup *setup, int nid)
{
	int aead_counts = ARRAY_SIZE(aead_info_table);
	int i;

	for (i = 0; i < aead_counts; i++) {
		if (nid == aead_info_table[i].nid) {
			setup->calg = aead_info_table[i].alg;
			setup->cmode = aead_info_table[i].mode;
			break;
		}
	}

	if (unlikely(i == aead_counts)) {
		UADK_ERR("failed to get aead info.\n");
		return UADK_AEAD_FAIL;
	}

	return UADK_AEAD_SUCCESS;
}

static int uadk_prov_aead_alloc_sess(struct aead_priv_ctx *priv)
{
	struct wd_aead_sess_setup setup = {0};
	struct sched_params params = {0};
	int ret;

	if (priv->sess)
		return UADK_AEAD_SUCCESS;

	ret = uadk_prov_aead_dev_init(priv);
	if (unlikely(ret < 0))
		return SWITCH_TO_SOFT;

	ret = uadk_get_aead_info(&setup, priv->nid);
	if (unlikely(ret < 0))
		return UADK_OSSL_FAIL;

	/* dec and enc use the same op */
	params.type = 0;
	/* Use the default numa parameters */
	params.numa_id = -1;
	setup.sched_param = &params;
	priv->sess = wd_aead_alloc_sess(&setup);
	if (!priv->sess) {
		UADK_ERR("uadk failed to alloc session, switch to soft\n");
		return SWITCH_TO_SOFT;
	}

	if (priv->key_set == KEY_STATE_SET) {
		ret = wd_aead_set_ckey(priv->sess, priv->key, priv->keylen);
		if (ret) {
			UADK_ERR("uadk failed to set key!\n");
			return UADK_OSSL_FAIL;
		}
	}

	return UADK_AEAD_SUCCESS;
}

static int uadk_prov_aead_set_key(struct aead_priv_ctx *priv,
				  const unsigned char *key,
				  size_t keylen)
{
	int ret;

	if (keylen != priv->keylen) {
		UADK_ERR("invalid keylen %zu!\n", keylen);
		return UADK_OSSL_FAIL;
	}

	memcpy(priv->key, key, keylen);
	priv->key_set = KEY_STATE_SET;

	/* use default provider */
	if (!priv->sess)
		return UADK_AEAD_SUCCESS;

	ret = wd_aead_set_ckey(priv->sess, priv->key, priv->keylen);
	if (ret) {
		UADK_ERR("uadk failed to set key!\n");
		return UADK_OSSL_FAIL;
	}

	return UADK_AEAD_SUCCESS;
}

static int uadk_prov_aead_init(struct aead_priv_ctx *priv, const unsigned char *key, size_t keylen,
			       const unsigned char *iv, size_t ivlen, const OSSL_PARAM *params)
{
	int ret;

	/* will free in freectx */
	ret = uadk_prov_aead_alloc_sess(priv);
	if (ret == UADK_OSSL_FAIL)
		return UADK_OSSL_FAIL;

	if (iv) {
		if (!ivlen || ivlen > MAX_IV_LEN) {
			UADK_ERR("invalid ivlen %zu.\n", ivlen);
			return UADK_OSSL_FAIL;
		}
		memcpy(priv->iv, iv, ivlen);
		priv->ivlen = ivlen;
		priv->iv_set = IV_STATE_SET;
	}

	if (key) {
		ret = uadk_prov_aead_set_key(priv, key, keylen);
		if (ret == UADK_OSSL_FAIL)
			return UADK_OSSL_FAIL;
	}

	priv->stream_switch_flag = 0;
	priv->tag_set = INIT_TAG;
	priv->partial_len = 0;
	priv->req.msg_state = AEAD_MSG_INVALID;

	return uadk_prov_aead_set_ctx_params(priv, params);
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
			UADK_ERR("invalid ivlen %zu.\n", sz);
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
			|| priv->tag_set != SET_TAG) {
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

static void uadk_prov_aead_free_sess(struct aead_priv_ctx *priv)
{
	if (priv->sess)
		wd_aead_free_sess(priv->sess);
}

static int uadk_prov_aead_copy_sess(struct aead_priv_ctx *priv)
{
	if (!priv->sess)
		return UADK_AEAD_SUCCESS;
	priv->sess = 0;

	/*
	 * Encryption and decryption have already started, so it cannot
	 * switch to software calculation, hence it returns a failure.
	 */
	if (priv->req.msg_state != AEAD_MSG_INVALID) {
		UADK_ERR("invalid: The data has been processed by hardware, cannot be copied.\n");
		return UADK_OSSL_FAIL;
	}

	return uadk_prov_aead_alloc_sess(priv);
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

	ret = uadk_prov_aead_copy_sess(dst_ctx);
	if (ret == UADK_OSSL_FAIL)
		goto free_ctx;

	if (dst_ctx->sw_ctx) {
		dst_ctx->sw_ctx = EVP_CIPHER_CTX_dup(src_ctx->sw_ctx);
		if (!dst_ctx->sw_ctx) {
			UADK_ERR("EVP_CIPHER_CTX_dup failed in ctx copy.\n");
			goto free_sess;
		}

		ret = EVP_CIPHER_up_ref(dst_ctx->sw_aead);
		if (!ret)
			goto free_dup;
	}

	return dst_ctx;

free_dup:
	if (dst_ctx->sw_ctx)
		EVP_CIPHER_CTX_free(dst_ctx->sw_ctx);
free_sess:
	uadk_prov_aead_free_sess(dst_ctx);
free_ctx:
	OPENSSL_clear_free(dst_ctx, sizeof(*dst_ctx));
	return NULL;
}

static void uadk_aead_soft_cleanup(struct aead_priv_ctx *priv)
{
	if (priv->sw_ctx)
		EVP_CIPHER_CTX_free(priv->sw_ctx);

	if (priv->sw_aead)
		EVP_CIPHER_free(priv->sw_aead);
}

static void uadk_prov_aead_freectx(void *ctx)
{
	struct aead_priv_ctx *priv = (struct aead_priv_ctx *)ctx;

	if (!ctx)
		return;

	uadk_prov_aead_free_sess(priv);
	uadk_aead_soft_cleanup(priv);
	OPENSSL_clear_free(priv, sizeof(*priv));
}

#define UADK_AEAD_DESCR(nm, tag_len, key_len, iv_len, blk_size,			\
			flags, e_nid, algnm, mode)				\
static OSSL_FUNC_cipher_newctx_fn uadk_##nm##_newctx;				\
static void *uadk_##nm##_newctx(void *provctx)					\
{										\
	struct aead_priv_ctx *ctx;						\
										\
	ctx = OPENSSL_zalloc(sizeof(*ctx));					\
	if (!ctx)								\
		return NULL;							\
										\
	ctx->keylen = key_len;							\
	ctx->ivlen = iv_len;							\
	ctx->nid = e_nid;							\
	ctx->taglen = tag_len;							\
	strncpy(ctx->alg_name, #algnm, ALG_NAME_SIZE - 1);			\
	ctx->libctx = prov_libctx_of(provctx);					\
										\
	if (uadk_get_sw_offload_state())					\
		uadk_create_aead_soft_ctx(ctx);					\
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
