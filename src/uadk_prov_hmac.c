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

#include <ctype.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <dlfcn.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/proverr.h>
#include <uadk/wd_digest.h>
#include <uadk/wd_sched.h>
#include "uadk.h"
#include "uadk_async.h"
#include "uadk_prov.h"
#include "uadk_utils.h"

/* The max BD data length is 16M-512B */
#define BUF_LEN			0xFFFE00

#define MAX_DIGEST_LENGTH	64
#define MAX_KEY_LEN		144
#define HMAC_BLOCK_SIZE		16384
#define ALG_NAME_SIZE		128
#define PARAMS_SIZE		2

#define KEY_4BYTE_ALIGN(keylen)		(((keylen) + 3) & ~3)
#define SW_SWITCH_PRINT_ENABLE(SW)	((SW) ? ", switch to soft hmac" : "")

#define SM3_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT	(512)
#define MD5_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT	(8 * 1024)
#define SHA_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT	(512)

#define UADK_DIGEST_DEF_CTXS	1
#define UADK_DIGEST_OP_NUM	1

enum sec_digest_state {
	SEC_DIGEST_INIT,
	SEC_DIGEST_FIRST_UPDATING,
	SEC_DIGEST_DOING,
	SEC_DIGEST_FINAL
};

struct hmac_prov {
	int pid;
};

static struct hmac_prov hprov;
static pthread_mutex_t hmac_mutex = PTHREAD_MUTEX_INITIALIZER;

struct hmac_priv_ctx {
	__u32 alg_id;
	__u32 state;
	int switch_flag;
	size_t out_len;
	size_t blk_size;
	size_t keylen;
	size_t last_update_bufflen;
	size_t total_data_len;
	size_t switch_threshold;
	OSSL_LIB_CTX *libctx;
	OSSL_LIB_CTX *soft_libctx;
	EVP_MAC_CTX *soft_ctx;
	EVP_MAC *soft_md;
	handle_t sess;
	struct wd_digest_sess_setup setup;
	struct wd_digest_req req;
	unsigned char *data;
	unsigned char key[MAX_KEY_LEN];
	unsigned char out[MAX_DIGEST_LENGTH];
	char alg_name[ALG_NAME_SIZE];
	bool is_stream_copy;
};

struct hmac_info {
	enum wd_digest_type alg;
	__u32 alg_id;
	__u32 threshold;
	size_t out_len;
	size_t blk_size;
	const char ossl_alg_name[ALG_NAME_SIZE];
};

static struct hmac_info hmac_info_table[] = {
	{WD_DIGEST_MD5, NID_md5, MD5_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT,
	 16, 64, PROV_NAMES_MD5},
	{WD_DIGEST_SM3, NID_sm3, SM3_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT,
	 32, 64, PROV_NAMES_SM3},
	{WD_DIGEST_SHA1, NID_sha1, SHA_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT,
	 20, 64, PROV_NAMES_SHA1},
	{WD_DIGEST_SHA224, NID_sha224, SHA_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT,
	 28, 64, PROV_NAMES_SHA2_224},
	{WD_DIGEST_SHA256, NID_sha256, SHA_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT,
	 32, 64, PROV_NAMES_SHA2_256},
	{WD_DIGEST_SHA384, NID_sha384, SHA_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT,
	 48, 128, PROV_NAMES_SHA2_384},
	{WD_DIGEST_SHA512, NID_sha512, SHA_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT,
	 64, 128, PROV_NAMES_SHA2_512},
	{WD_DIGEST_SHA512_224, NID_sha512_224, SHA_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT,
	 28, 128, PROV_NAMES_SHA2_512_224},
	{WD_DIGEST_SHA512_256, NID_sha512_256, SHA_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT,
	 32, 128, PROV_NAMES_SHA2_512_256}
};

static int uadk_create_hmac_soft_ctx(struct hmac_priv_ctx *priv)
{
	if (priv->soft_md)
		return UADK_P_SUCCESS;

	priv->soft_libctx = OSSL_LIB_CTX_new();
	if (!priv->soft_libctx) {
		UADK_ERR("new soft libctx failed.\n");
		return UADK_P_FAIL;
	}

	switch (priv->alg_id) {
	case NID_md5:
	case NID_sm3:
	case NID_sha1:
	case NID_sha224:
	case NID_sha256:
	case NID_sha384:
	case NID_sha512:
	case NID_sha512_224:
	case NID_sha512_256:
		priv->soft_md = EVP_MAC_fetch(priv->soft_libctx, "HMAC", NULL);
		break;
	default:
		break;
	}

	if (unlikely(!priv->soft_md)) {
		UADK_ERR("hmac soft fetch failed.\n");
		goto free_libctx;
	}

	priv->soft_ctx = EVP_MAC_CTX_new(priv->soft_md);
	if (!priv->soft_ctx) {
		UADK_ERR("hmac soft new ctx failed.\n");
		goto free_mac_md;
	}

	return UADK_P_SUCCESS;

free_mac_md:
	EVP_MAC_free(priv->soft_md);
	priv->soft_md = NULL;
free_libctx:
	OSSL_LIB_CTX_free(priv->soft_libctx);
	priv->soft_libctx = NULL;

	return UADK_P_FAIL;
}

static int uadk_hmac_soft_init(struct hmac_priv_ctx *priv)
{
	OSSL_PARAM params[PARAMS_SIZE];
	OSSL_PARAM *p = params;
	int ret;

	if (!priv->soft_md)
		return UADK_P_FAIL;

	/* The underlying digest to be used */
	*p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, priv->alg_name,
						sizeof(priv->alg_name));
	*p = OSSL_PARAM_construct_end();

	ret = EVP_MAC_init(priv->soft_ctx, priv->key, priv->keylen, params);
	if (!ret) {
		UADK_ERR("do soft hmac init failed!\n");
		return UADK_P_FAIL;
	}

	priv->switch_flag = UADK_DO_SOFT;

	return ret;
}

static int uadk_hmac_soft_update(struct hmac_priv_ctx *priv,
				 const void *data, size_t len)
{
	int ret;

	if (!priv->soft_md)
		return UADK_P_FAIL;

	ret = EVP_MAC_update(priv->soft_ctx, data, len);
	if (!ret)
		UADK_ERR("do soft hmac update failed!\n");

	return ret;
}

static int uadk_hmac_soft_final(struct hmac_priv_ctx *priv, unsigned char *out)
{
	size_t hmac_length;
	int ret;

	if (!priv->soft_md)
		return UADK_P_FAIL;

	ret = EVP_MAC_final(priv->soft_ctx, out, &hmac_length, priv->out_len);
	if (!ret)
		UADK_ERR("do soft hmac final failed!\n");

	return ret;
}

static void hmac_soft_cleanup(struct hmac_priv_ctx *priv)
{
	if (priv->soft_ctx) {
		EVP_MAC_CTX_free(priv->soft_ctx);
		priv->soft_ctx = NULL;
	}

	if (priv->soft_md) {
		EVP_MAC_free(priv->soft_md);
		priv->soft_md = NULL;
	}

	if (priv->soft_libctx) {
		OSSL_LIB_CTX_free(priv->soft_libctx);
		priv->soft_libctx = NULL;
	}

	priv->switch_flag = 0;
}

static int uadk_hmac_soft_work(struct hmac_priv_ctx *priv, int inl,
			       unsigned char *out)
{
	int ret;

	if (!priv->soft_md)
		return UADK_P_FAIL;

	if (!priv->switch_flag) {
		ret = uadk_hmac_soft_init(priv);
		if (unlikely(!ret))
			return UADK_P_FAIL;
	}

	if (inl) {
		ret = uadk_hmac_soft_update(priv, priv->data, inl);
		if (unlikely(!ret))
			goto out;
	}

	ret = uadk_hmac_soft_final(priv, out);

out:
	hmac_soft_cleanup(priv);
	return ret;
}

static OSSL_FUNC_mac_newctx_fn		uadk_prov_hmac_newctx;
static OSSL_FUNC_mac_dupctx_fn		uadk_prov_hmac_dupctx;
static OSSL_FUNC_mac_freectx_fn		uadk_prov_hmac_freectx;
static OSSL_FUNC_mac_init_fn		uadk_prov_hmac_init;
static OSSL_FUNC_mac_update_fn		uadk_prov_hmac_update;
static OSSL_FUNC_mac_final_fn		uadk_prov_hmac_final;
static OSSL_FUNC_mac_gettable_ctx_params_fn
					uadk_prov_hmac_gettable_ctx_params;
static OSSL_FUNC_mac_get_ctx_params_fn	uadk_prov_hmac_get_ctx_params;
static OSSL_FUNC_mac_settable_ctx_params_fn
					uadk_prov_hmac_settable_ctx_params;
static OSSL_FUNC_mac_set_ctx_params_fn	uadk_prov_hmac_set_ctx_params;

static void uadk_hmac_reset(struct hmac_priv_ctx *priv)
{
	priv->state = SEC_DIGEST_INIT;
	priv->last_update_bufflen = 0;
	priv->total_data_len = 0;
}

static int uadk_hmac_poll(void *ctx)
{
	__u64 rx_cnt = 0;
	__u32 recv = 0;
	/* Poll one packet currently */
	__u32 expt = 1;
	int ret;

	do {
		ret = wd_digest_poll(expt, &recv);
		if (ret < 0 || recv == expt)
			return ret;
		rx_cnt++;
	} while (rx_cnt < PROV_SCH_RECV_MAX_CNT);

	UADK_ERR("failed to poll msg: timeout!\n");

	return -ETIMEDOUT;
}

static void uadk_fill_mac_buffer_len(struct hmac_priv_ctx *priv, bool is_end)
{
	/* Sha224 and Sha384 and Sha512-XXX need full length mac buffer as doing long hash */
	switch (priv->alg_id) {
	case NID_sha224:
		priv->req.out_bytes = is_end ? WD_DIGEST_SHA224_LEN : WD_DIGEST_SHA224_FULL_LEN;
		break;
	case NID_sha384:
		priv->req.out_bytes = is_end ? WD_DIGEST_SHA384_LEN : WD_DIGEST_SHA384_FULL_LEN;
		break;
	case NID_sha512_224:
		priv->req.out_bytes = is_end ?
				      WD_DIGEST_SHA512_224_LEN : WD_DIGEST_SHA512_224_FULL_LEN;
		break;
	case NID_sha512_256:
		priv->req.out_bytes = is_end ?
				      WD_DIGEST_SHA512_256_LEN : WD_DIGEST_SHA512_256_FULL_LEN;
		break;
	default:
		break;
	}
}

static void uadk_digest_set_msg_state(struct hmac_priv_ctx *priv, bool is_end)
{
	if (priv->is_stream_copy) {
		priv->req.has_next = is_end ? WD_DIGEST_STREAM_END : WD_DIGEST_STREAM_DOING;
		priv->is_stream_copy = false;
	} else {
		priv->req.has_next = is_end ? WD_DIGEST_END : WD_DIGEST_DOING;
	}
}

static int uadk_get_hmac_info(struct hmac_priv_ctx *priv)
{
	int digest_counts = ARRAY_SIZE(hmac_info_table);
	int i;

	for (i = 0; i < digest_counts; i++) {
		if (strstr(hmac_info_table[i].ossl_alg_name, priv->alg_name)) {
			priv->alg_id = hmac_info_table[i].alg_id;
			priv->out_len = hmac_info_table[i].out_len;
			priv->blk_size = hmac_info_table[i].blk_size;
			priv->setup.alg = hmac_info_table[i].alg;
			priv->setup.mode = WD_DIGEST_HMAC;
			priv->req.out_buf_bytes = MAX_DIGEST_LENGTH;
			priv->req.out_bytes = hmac_info_table[i].out_len;
			priv->switch_threshold = hmac_info_table[i].threshold;

			return UADK_P_SUCCESS;
		}
	}

	UADK_ERR("failed to get hmac info, algname = %s.\n", priv->alg_name);

	return UADK_P_FAIL;
}

static const char *get_uadk_alg_name(__u32 alg_id)
{
	switch (alg_id) {
	case NID_md5:
		return "md5";
	case NID_sm3:
		return "sm3";
	case NID_sha1:
		return "sha1";
	case NID_sha224:
		return "sha224";
	case NID_sha256:
		return "sha256";
	case NID_sha384:
		return "sha384";
	case NID_sha512:
		return "sha512";
	case NID_sha512_224:
		return "sha512-224";
	case NID_sha512_256:
		return "sha512-256";
	default:
		break;
	}

	UADK_ERR("failed to find alg, nid = %u.\n", alg_id);

	return NULL;
}

static void uadk_hmac_mutex_infork(void)
{
	/* Release the replication lock of the child process */
	pthread_mutex_unlock(&hmac_mutex);
}

static int uadk_prov_hmac_dev_init(struct hmac_priv_ctx *priv)
{
	struct wd_ctx_params cparams = {0};
	struct wd_ctx_nums ctx_set_num;
	int ret = UADK_P_SUCCESS;
	const char *alg_name;

	pthread_atfork(NULL, NULL, uadk_hmac_mutex_infork);
	pthread_mutex_lock(&hmac_mutex);
	if (hprov.pid == getpid())
		goto mutex_unlock;

	alg_name = get_uadk_alg_name(priv->alg_id);
	if (!alg_name) {
		ret = UADK_P_FAIL;
		goto mutex_unlock;
	}

	cparams.op_type_num = UADK_DIGEST_OP_NUM;
	cparams.ctx_set_num = &ctx_set_num;
	cparams.bmp = numa_allocate_nodemask();
	if (!cparams.bmp) {
		ret = UADK_P_FAIL;
		UADK_ERR("failed to create nodemask!\n");
		goto mutex_unlock;
	}

	numa_bitmask_setall(cparams.bmp);

	ctx_set_num.sync_ctx_num = UADK_DIGEST_DEF_CTXS;
	ctx_set_num.async_ctx_num = UADK_DIGEST_DEF_CTXS;

	ret = wd_digest_init2_((char *)alg_name, TASK_MIX, SCHED_POLICY_RR, &cparams);
	if (unlikely(ret && ret != -WD_EEXIST)) {
		UADK_ERR("uadk failed to initialize hmac, ret = %d\n", ret);
		goto free_nodemask;
	}
	ret = UADK_P_SUCCESS;

	hprov.pid = getpid();
	async_register_poll_fn(ASYNC_TASK_HMAC, uadk_hmac_poll);

free_nodemask:
	numa_free_nodemask(cparams.bmp);
mutex_unlock:
	pthread_mutex_unlock(&hmac_mutex);
	return ret;
}

static int uadk_prov_compute_key_hash(struct hmac_priv_ctx *priv,
				      const unsigned char *key, size_t keylen)
{
	int ret = UADK_P_FAIL;
	__u32 outlen = 0;
	EVP_MD_CTX *ctx;
	EVP_MD *key_md;

	key_md = EVP_MD_fetch(priv->libctx, priv->alg_name, NULL);
	if (!key_md)
		return UADK_P_FAIL;

	ctx = EVP_MD_CTX_new();
	if (!ctx)
		goto free_md;

	if (!EVP_DigestInit_ex2(ctx, key_md, NULL) ||
	    !EVP_DigestUpdate(ctx, key, keylen) ||
	    !EVP_DigestFinal_ex(ctx, priv->key, &outlen))
		goto free_ctx;

	priv->keylen = outlen;
	ret = UADK_P_SUCCESS;

free_ctx:
	EVP_MD_CTX_free(ctx);
free_md:
	EVP_MD_free(key_md);

	return ret;
}

static int uadk_hmac_ctx_init(struct hmac_priv_ctx *priv)
{
	struct wd_digest_sess_setup setup = {0};
	struct sched_params params = {0};
	int ret;

	if (enable_sw_offload)
		uadk_create_hmac_soft_ctx(priv);

	ret = uadk_prov_hmac_dev_init(priv);
	if (unlikely(ret <= 0)) {
		UADK_ERR("uadk failed to initialize hmac%s.\n",
			 SW_SWITCH_PRINT_ENABLE(enable_sw_offload));
		goto soft_init;
	}

	/* Use the default numa parameters */
	params.numa_id = -1;
	setup.sched_param = &params;
	setup.alg = priv->setup.alg;
	setup.mode = priv->setup.mode;

	if (!priv->sess) {
		priv->sess = wd_digest_alloc_sess(&setup);
		if (unlikely(!priv->sess)) {
			UADK_ERR("uadk failed to alloc hmac sess%s.\n",
				 SW_SWITCH_PRINT_ENABLE(enable_sw_offload));
			goto soft_init;
		}

		ret = wd_digest_set_key(priv->sess, priv->key, priv->keylen);
		if (ret) {
			UADK_ERR("uadk failed to set hmac key%s.\n",
				 SW_SWITCH_PRINT_ENABLE(enable_sw_offload));
			goto free_sess;
		}
	}

	return UADK_P_SUCCESS;

free_sess:
	wd_digest_free_sess(priv->sess);
	priv->sess = 0;

soft_init:
	return uadk_hmac_soft_init(priv);
}

static void uadk_hmac_async_cb(struct wd_digest_req *req)
{
	struct uadk_e_cb_info *hmac_cb_param;
	struct wd_digest_req *req_origin;
	struct async_op *op;

	if (!req || !req->cb_param)
		return;

	hmac_cb_param = req->cb_param;
	req_origin = hmac_cb_param->priv;
	req_origin->state = req->state;
	op = hmac_cb_param->op;
	if (op && op->job && !op->done) {
		op->done = 1;
		async_free_poll_task(op->idx, 1);
		(void) async_wake_job(op->job);
	}
}

static int uadk_do_hmac_sync(struct hmac_priv_ctx *priv)
{
	int ret;

	if (priv->soft_md &&
	    priv->req.in_bytes <= priv->switch_threshold &&
	    priv->state == SEC_DIGEST_INIT)
		return UADK_P_FAIL;

	ret = wd_do_digest_sync(priv->sess, &priv->req);
	if (ret) {
		UADK_ERR("do sec hmac sync failed.\n");
		return UADK_P_FAIL;
	}

	return UADK_P_SUCCESS;
}

static int uadk_do_hmac_async(struct hmac_priv_ctx *priv, struct async_op *op)
{
	struct uadk_e_cb_info cb_param;
	int idx, ret;
	int cnt = 0;

	if (unlikely(priv->switch_flag == UADK_DO_SOFT)) {
		UADK_ERR("soft switching is not supported in asynchronous mode.\n");
		return UADK_P_FAIL;
	}

	cb_param.op = op;
	cb_param.priv = &priv->req;
	priv->req.cb = (void *)uadk_hmac_async_cb;
	priv->req.cb_param = &cb_param;
	priv->req.state = POLL_ERROR;

	ret = async_get_free_task(&idx);
	if (!ret)
		return UADK_P_FAIL;

	op->idx = idx;
	do {
		ret = wd_do_digest_async(priv->sess, &priv->req);
		if (ret < 0 && ret != -EBUSY) {
			UADK_ERR("do sec digest async failed.\n");
			goto free_poll_task;
		}

		if (unlikely(++cnt > ENGINE_SEND_MAX_CNT)) {
			UADK_ERR("do digest async operation timeout.\n");
			goto free_poll_task;
		}
	} while (ret == -EBUSY);

	ret = async_pause_job(priv, op, ASYNC_TASK_HMAC);
	if (!ret || priv->req.state)
		return UADK_P_FAIL;

	return UADK_P_SUCCESS;

free_poll_task:
	async_free_poll_task(op->idx, 0);
	return UADK_P_FAIL;
}

static int uadk_hmac_update_inner(struct hmac_priv_ctx *priv, const void *data, size_t data_len)
{
	unsigned char *input_data = (unsigned char *)data;
	size_t remain_len = data_len;
	size_t processing_len;
	int ret;

	ret = uadk_hmac_ctx_init(priv);
	if (ret != UADK_P_SUCCESS)
		return UADK_P_FAIL;

	uadk_digest_set_msg_state(priv, false);
	uadk_fill_mac_buffer_len(priv, false);

	do {
		/*
		 * If there is data in the buffer, it will be filled and processed. Otherwise, it
		 * will be processed according to the UADK package len(16M-512Byte). Finally the
		 * remaining data less than the size of the buffer will be stored in the buffer.
		 */
		if (priv->last_update_bufflen != 0) {
			processing_len = HMAC_BLOCK_SIZE - priv->last_update_bufflen;
			uadk_memcpy(priv->data + priv->last_update_bufflen, input_data,
				    processing_len);

			priv->req.in_bytes = HMAC_BLOCK_SIZE;
			priv->req.in = priv->data;
			priv->last_update_bufflen = 0;
		} else {
			if (remain_len > BUF_LEN)
				processing_len = BUF_LEN;
			else
				processing_len = remain_len - (remain_len % HMAC_BLOCK_SIZE);

			priv->req.in_bytes = processing_len;
			priv->req.in = input_data;
		}

		if (priv->state == SEC_DIGEST_INIT)
			priv->state = SEC_DIGEST_FIRST_UPDATING;
		else if (priv->state == SEC_DIGEST_FIRST_UPDATING)
			priv->state = SEC_DIGEST_DOING;

		priv->req.out = priv->out;

		ret = uadk_do_hmac_sync(priv);
		if (!ret) {
			UADK_ERR("do sec hmac update failed%s.\n",
				 SW_SWITCH_PRINT_ENABLE(enable_sw_offload));
			goto do_soft_hmac;
		}

		remain_len -= processing_len;
		input_data += processing_len;
	} while (remain_len > HMAC_BLOCK_SIZE);

	priv->last_update_bufflen = remain_len;
	uadk_memcpy(priv->data, input_data, priv->last_update_bufflen);

	return UADK_P_SUCCESS;

do_soft_hmac:
	if (priv->state == SEC_DIGEST_FIRST_UPDATING) {
		ret = uadk_hmac_soft_init(priv);
		if (!ret)
			return ret;

		/*
		 * If the hardware fails to process the data in the cache,
		 * the software computing needs to finish the cached data first.
		 */
		if (processing_len < HMAC_BLOCK_SIZE) {
			ret = uadk_hmac_soft_update(priv, priv->data, HMAC_BLOCK_SIZE);
			if (!ret)
				goto err_out;

			remain_len -= processing_len;
			input_data += processing_len;
		}

		ret = uadk_hmac_soft_update(priv, input_data, remain_len);
		if (!ret)
			goto err_out;

		/* the soft ctx will be free in the final stage. */
		return ret;
	}

	return UADK_P_FAIL;

err_out:
	hmac_soft_cleanup(priv);
	return ret;
}

static int uadk_hmac_update(struct hmac_priv_ctx *priv, const void *data, size_t data_len)
{
	if (!priv->data) {
		UADK_ERR("failed to do digest update, data in CTX is NULL.\n");
		return UADK_P_FAIL;
	}

	if (unlikely(priv->switch_flag == UADK_DO_SOFT))
		goto soft_update;

	priv->total_data_len += data_len;

	if (priv->last_update_bufflen + data_len <= HMAC_BLOCK_SIZE) {
		uadk_memcpy(priv->data + priv->last_update_bufflen, data, data_len);
		priv->last_update_bufflen += data_len;
		return UADK_P_SUCCESS;
	}

	return uadk_hmac_update_inner(priv, data, data_len);

soft_update:
	return uadk_hmac_soft_update(priv, data, data_len);
}

static int uadk_hmac_final(struct hmac_priv_ctx *priv, unsigned char *digest)
{
	struct async_op op;
	int ret;

	if (!priv->data) {
		UADK_ERR("failed to do digest final, data in CTX is NULL.\n");
		return UADK_P_FAIL;
	}

	/* It dose not need to be initialized again if the software calculation is applied. */
	if (priv->switch_flag != UADK_DO_SOFT) {
		ret = uadk_hmac_ctx_init(priv);
		if (!ret)
			return UADK_P_FAIL;
	}

	priv->req.in = priv->data;
	priv->req.out = priv->state == SEC_DIGEST_INIT ? digest : priv->out;
	priv->req.in_bytes = priv->last_update_bufflen;

	uadk_digest_set_msg_state(priv, true);
	uadk_fill_mac_buffer_len(priv, true);

	ret = async_setup_async_event_notification(&op);
	if (unlikely(!ret)) {
		UADK_ERR("failed to setup async event notification.\n");
		return UADK_P_FAIL;
	}

	if (!op.job) {
		/* Synchronous, only the synchronous mode supports soft computing */
		if (unlikely(priv->switch_flag == UADK_DO_SOFT)) {
			ret = uadk_hmac_soft_final(priv, digest);
			hmac_soft_cleanup(priv);
			goto clear;
		}

		ret = uadk_do_hmac_sync(priv);
		if (!ret)
			goto do_hmac_err;
	} else {
		ret = uadk_do_hmac_async(priv, &op);
		if (!ret)
			goto clear;
	}

	if (priv->state != SEC_DIGEST_INIT)
		memcpy(digest, priv->req.out, priv->req.out_bytes);

	return UADK_P_SUCCESS;

do_hmac_err:
	if (priv->state == SEC_DIGEST_INIT) {
		UADK_ERR("do sec digest final failed%s.\n",
			 SW_SWITCH_PRINT_ENABLE(enable_sw_offload));
		ret = uadk_hmac_soft_work(priv, priv->req.in_bytes, digest);
	} else {
		ret = UADK_P_FAIL;
		UADK_ERR("do sec digest final failed.\n");
	}
clear:
	async_clear_async_event_notification();
	return ret;
}

static void *uadk_prov_hmac_dupctx(void *hctx)
{
	struct hmac_priv_ctx *dst_ctx, *src_ctx;
	int ret;

	if (!hctx)
		return NULL;

	src_ctx = (struct hmac_priv_ctx *)hctx;
	dst_ctx = OPENSSL_memdup(src_ctx, sizeof(struct hmac_priv_ctx));
	if (!dst_ctx)
		return NULL;

	/*
	 * When a copy is performed during digest execution,
	 * the status in the sess needs to be synchronized.
	 */
	if (dst_ctx->sess && dst_ctx->state != SEC_DIGEST_INIT) {
		dst_ctx->is_stream_copy = true;
		/*
		 * Length that the hardware has processed should be equal to
		 * total input data length minus software cache data length.
		 */
		dst_ctx->req.long_data_len = dst_ctx->total_data_len -
					     dst_ctx->last_update_bufflen;
	}

	dst_ctx->sess = 0;
	dst_ctx->data = OPENSSL_memdup(src_ctx->data, HMAC_BLOCK_SIZE);
	if (!dst_ctx->data)
		goto free_ctx;

	if (dst_ctx->soft_ctx) {
		dst_ctx->soft_libctx = NULL;
		dst_ctx->soft_ctx = EVP_MAC_CTX_dup(src_ctx->soft_ctx);
		if (!dst_ctx->soft_ctx) {
			UADK_ERR("create soft_ctx failed in ctx copy.\n");
			goto free_data;
		}

		ret = EVP_MAC_up_ref(dst_ctx->soft_md);
		if (!ret)
			goto free_dup;
	}

	return dst_ctx;

free_dup:
	EVP_MAC_CTX_free(dst_ctx->soft_ctx);
free_data:
	OPENSSL_clear_free(dst_ctx->data, HMAC_BLOCK_SIZE);
free_ctx:
	OPENSSL_clear_free(dst_ctx, sizeof(*dst_ctx));
	return NULL;
}

static void uadk_hmac_cleanup(struct hmac_priv_ctx *priv)
{
	if (priv->sess)
		wd_digest_free_sess(priv->sess);

	if (priv->data)
		OPENSSL_clear_free(priv->data, HMAC_BLOCK_SIZE);
}

static void uadk_prov_hmac_freectx(void *hctx)
{
	struct hmac_priv_ctx *priv = (struct hmac_priv_ctx *)hctx;

	if (!hctx) {
		UADK_ERR("the CTX to be free is NULL.\n");
		return;
	}

	hmac_soft_cleanup(priv);
	uadk_hmac_cleanup(priv);
	OPENSSL_clear_free(priv, sizeof(*priv));
}

static int uadk_prov_hmac_setkey(struct hmac_priv_ctx *priv,
				 const unsigned char *key, size_t keylen)
{
	size_t padding;

	memset(priv->key, 0, MAX_KEY_LEN);

	if (keylen > priv->blk_size)
		return uadk_prov_compute_key_hash(priv, key, keylen);

	padding = KEY_4BYTE_ALIGN(keylen);
	memcpy(priv->key, key, keylen);
	priv->keylen = padding;

	return UADK_P_SUCCESS;
}

static int uadk_prov_hmac_init(void *hctx, const unsigned char *key,
			       size_t keylen, const OSSL_PARAM params[])
{
	struct hmac_priv_ctx *priv = (struct hmac_priv_ctx *)hctx;
	int ret;

	if (!hctx) {
		UADK_ERR("CTX is NULL.\n");
		return UADK_P_FAIL;
	}

	ret = uadk_prov_hmac_set_ctx_params(hctx, params);
	if (unlikely(!ret))
		return UADK_P_FAIL;

	ret = uadk_get_hmac_info(priv);
	if (unlikely(!ret))
		return UADK_P_FAIL;

	if (enable_sw_offload)
		uadk_create_hmac_soft_ctx(hctx);

	if (key) {
		ret = uadk_prov_hmac_setkey(priv, key, keylen);
		if (!ret)
			return UADK_P_FAIL;
	}

	ret = uadk_prov_hmac_dev_init(priv);
	if (unlikely(ret <= 0))
		goto soft_init;

	return UADK_P_SUCCESS;

soft_init:
	UADK_ERR("uadk failed to initialize dev%s.\n",
		 SW_SWITCH_PRINT_ENABLE(enable_sw_offload));
	return uadk_hmac_soft_init(priv);
}

static int uadk_prov_hmac_update(void *hctx, const unsigned char *data, size_t datalen)
{
	if (!hctx || !data) {
		UADK_ERR("CTX or input data is NULL.\n");
		return UADK_P_FAIL;
	}

	return uadk_hmac_update((struct hmac_priv_ctx *)hctx, data, datalen);
}

/*
 * Note:
 * The I<hctx> parameter contains a pointer to the provider side context.
 * The digest should be written to I<*out> and the length of the digest to I<*outl>.
 * The digest should not exceed I<outsz> bytes.
 */
static int uadk_prov_hmac_final(void *hctx, unsigned char *out, size_t *outl,
				size_t outsize)
{
	struct hmac_priv_ctx *priv = (struct hmac_priv_ctx *)hctx;
	int ret = UADK_P_SUCCESS;

	if (!hctx) {
		UADK_ERR("hmac CTX or output data is NULL.\n");
		return UADK_P_FAIL;
	}

	if (out && outsize > 0) {
		ret = uadk_hmac_final(priv, out);
		if (!ret)
			goto reset_ctx;
	}

	if (outl)
		*outl = priv->out_len;

reset_ctx:
	uadk_hmac_reset(priv);

	return ret;
}

void uadk_prov_destroy_hmac(void)
{
	pthread_mutex_lock(&hmac_mutex);
	if (hprov.pid == getpid()) {
		wd_digest_uninit2();
		hprov.pid = 0;
	}
	pthread_mutex_unlock(&hmac_mutex);
}

static const OSSL_PARAM uadk_prov_hmac_known_gettable_ctx_params[] = {
	OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
	OSSL_PARAM_size_t(OSSL_MAC_PARAM_BLOCK_SIZE, NULL),
	OSSL_PARAM_END
};

static const OSSL_PARAM *uadk_prov_hmac_gettable_ctx_params(ossl_unused void *ctx,
							    ossl_unused void *provctx)
{
	return uadk_prov_hmac_known_gettable_ctx_params;
}

static int uadk_prov_hmac_get_ctx_params(void *hctx, OSSL_PARAM params[])
{
	struct hmac_priv_ctx *priv = (struct hmac_priv_ctx *)hctx;
	OSSL_PARAM *p = NULL;

	if (!hctx)
		return UADK_P_FAIL;

	p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE);
	if (p && !OSSL_PARAM_set_size_t(p, priv->out_len))
		return UADK_P_FAIL;

	p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_BLOCK_SIZE);
	if (p && !OSSL_PARAM_set_size_t(p, priv->blk_size))
		return UADK_P_FAIL;

	return UADK_P_SUCCESS;
}

static const OSSL_PARAM uadk_prov_settable_ctx_params[] = {
	OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, NULL, 0),
	OSSL_PARAM_octet_string(OSSL_MAC_PARAM_KEY, NULL, 0),
	OSSL_PARAM_END
};

static const OSSL_PARAM *uadk_prov_hmac_settable_ctx_params(ossl_unused void *ctx,
							    ossl_unused void *provctx)
{
	return uadk_prov_settable_ctx_params;
}

static void uadk_hmac_name_uppercase(char *str)
{
	size_t length = strlen(str);

	for (size_t i = 0; i < length; i++)
		str[i] = toupper(str[i]);
}

/*
 * ALL parameters should be set before init().
 */
static int uadk_prov_hmac_set_ctx_params(void *hctx, const OSSL_PARAM params[])
{
	struct hmac_priv_ctx *priv = (struct hmac_priv_ctx *)hctx;
	const OSSL_PARAM *p;
	int ret;

	if (!params || !params->key)
		return UADK_P_SUCCESS;

	if (!hctx)
		return UADK_P_FAIL;

	p = OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_DIGEST);
	if (p) {
		if (p->data_type != OSSL_PARAM_UTF8_STRING ||
			strlen((char *)p->data) > ALG_NAME_SIZE - 1)
			return UADK_P_FAIL;

		/*
		 * For subsequent character string matching, no end flag is added,
		 * and the length will be within the value of ALG_NAME_SIZE.
		 */
		ret = snprintf(priv->alg_name, ALG_NAME_SIZE, "%s", (char *)p->data);
		if (ret < 0) {
			UADK_ERR("Invalid alg name %s.\n", (char *)p->data);
			return UADK_P_FAIL;
		}

		uadk_hmac_name_uppercase(priv->alg_name);
	}

	p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_KEY);
	if (p) {
		if (p->data_type != OSSL_PARAM_OCTET_STRING)
			return UADK_P_FAIL;

		if (!uadk_prov_hmac_setkey(priv, p->data, p->data_size))
			return UADK_P_FAIL;
	}

	return UADK_P_SUCCESS;
}

static void *uadk_prov_hmac_newctx(void *hctx)
{
	struct hmac_priv_ctx *ctx;

	ctx = OPENSSL_zalloc(sizeof(*ctx));
	if (!ctx)
		return NULL;

	ctx->libctx = prov_libctx_of(hctx);

	ctx->data = OPENSSL_zalloc(HMAC_BLOCK_SIZE);
	if (!ctx->data) {
		OPENSSL_free(ctx);
		return NULL;
	}

	return ctx;
}

const OSSL_DISPATCH uadk_hmac_functions[] = {
	{ OSSL_FUNC_MAC_NEWCTX, (void (*)(void))uadk_prov_hmac_newctx },
	{ OSSL_FUNC_MAC_DUPCTX, (void (*)(void))uadk_prov_hmac_dupctx },
	{ OSSL_FUNC_MAC_FREECTX, (void (*)(void))uadk_prov_hmac_freectx },
	{ OSSL_FUNC_MAC_INIT, (void (*)(void))uadk_prov_hmac_init },
	{ OSSL_FUNC_MAC_UPDATE, (void (*)(void))uadk_prov_hmac_update },
	{ OSSL_FUNC_MAC_FINAL, (void (*)(void))uadk_prov_hmac_final },
	{ OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS,
		(void (*)(void))uadk_prov_hmac_gettable_ctx_params },
	{ OSSL_FUNC_MAC_GET_CTX_PARAMS,
		(void (*)(void))uadk_prov_hmac_get_ctx_params },
	{ OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS,
		(void (*)(void))uadk_prov_hmac_settable_ctx_params },
	{ OSSL_FUNC_MAC_SET_CTX_PARAMS,
		(void (*)(void))uadk_prov_hmac_set_ctx_params },
	{ 0, NULL }
};
