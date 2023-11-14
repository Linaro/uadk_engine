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
#include <openssl/md5.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/proverr.h>
#include <uadk/wd_cipher.h>
#include <uadk/wd_digest.h>
#include <uadk/wd_sched.h>
#include "uadk.h"
#include "uadk_async.h"
#include "uadk_prov.h"
#include "uadk_utils.h"

#define UADK_DO_SOFT	(-0xE0)
#define CTX_SYNC	0
#define CTX_ASYNC	1
#define CTX_NUM		2
#define DIGEST_DOING	1
#define DIGEST_END	0

/* The max BD data length is 16M-512B */
#define BUF_LEN      0xFFFE00

#define SM3_DIGEST_LENGTH	32
#define SM3_CBLOCK		64
#define SM3_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT (512)
#define MD5_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT (8 * 1024)
#define SHA_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT (512)
#define MAX_DIGEST_LENGTH	64
#define DIGEST_BLOCK_SIZE (512 * 1024)
#define ALG_NAME_SIZE           128

enum sec_digest_state {
	SEC_DIGEST_INIT,
	SEC_DIGEST_FIRST_UPDATING,
	SEC_DIGEST_DOING,
	SEC_DIGEST_FINAL
};

struct digest_prov {
	int pid;
};

static struct digest_prov prov;
static pthread_mutex_t digest_mutex = PTHREAD_MUTEX_INITIALIZER;

struct evp_md_ctx_st {
	const EVP_MD *digest;
	/* Functional reference if 'digest' is ENGINE-provided */
	ENGINE *engine;
	unsigned long flags;
	void *md_data;
	/* Public key context for sign/verify */
	EVP_PKEY_CTX *pctx;
	/* Update function: usually copied from EVP_MD */
	int (*update)(EVP_MD_CTX *ctx, const void *data, size_t count);
};

struct digest_priv_ctx {
	handle_t sess;
	struct wd_digest_sess_setup setup;
	struct wd_digest_req req;
	unsigned char *data;
	unsigned char out[MAX_DIGEST_LENGTH];
	EVP_MD_CTX *soft_ctx;
	EVP_MD *soft_md;
	size_t last_update_bufflen;
	uint32_t e_nid;
	uint32_t state;
	uint32_t switch_threshold;
	int switch_flag;
	size_t md_size;
	size_t blk_size;
	char alg_name[ALG_NAME_SIZE];
};

struct digest_info {
	int nid;
	enum wd_digest_mode mode;
	enum wd_digest_type alg;
	__u32 out_len;
	__u32 threshold;
};

static struct digest_info digest_info_table[] = {
	{NID_md5, WD_DIGEST_NORMAL, WD_DIGEST_MD5,
	 16, MD5_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT},
	{NID_sm3, WD_DIGEST_NORMAL, WD_DIGEST_SM3,
	 32, SM3_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT},
	{NID_sha1, WD_DIGEST_NORMAL, WD_DIGEST_SHA1,
	 20, SHA_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT},
	{NID_sha224, WD_DIGEST_NORMAL, WD_DIGEST_SHA224,
	 28, SHA_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT},
	{NID_sha256, WD_DIGEST_NORMAL, WD_DIGEST_SHA256,
	 32, SHA_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT},
	{NID_sha384, WD_DIGEST_NORMAL, WD_DIGEST_SHA384,
	 48, SHA_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT},
	{NID_sha512, WD_DIGEST_NORMAL, WD_DIGEST_SHA512,
	 64, SHA_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT},
};

static int uadk_digests_soft_md(struct digest_priv_ctx *priv)
{
	if (priv->soft_md)
		return 1;

	switch (priv->e_nid) {
	case NID_sm3:
		priv->soft_md = EVP_MD_fetch(NULL, OSSL_DIGEST_NAME_SM3, "provider=default");
		break;
	case NID_md5:
		priv->soft_md = EVP_MD_fetch(NULL, OSSL_DIGEST_NAME_MD5, "provider=default");
		break;
	case NID_sha1:
		priv->soft_md = EVP_MD_fetch(NULL, OSSL_DIGEST_NAME_SHA1, "provider=default");
		break;
	case NID_sha224:
		priv->soft_md = EVP_MD_fetch(NULL, OSSL_DIGEST_NAME_SHA3_224, "provider=default");
		break;
	case NID_sha256:
		priv->soft_md = EVP_MD_fetch(NULL, OSSL_DIGEST_NAME_SHA3_256, "provider=default");
		break;
	case NID_sha384:
		priv->soft_md = EVP_MD_fetch(NULL, OSSL_DIGEST_NAME_SHA3_384, "provider=default");
		break;
	case NID_sha512:
		priv->soft_md = EVP_MD_fetch(NULL, OSSL_DIGEST_NAME_SHA3_512, "provider=default");
		break;
	default:
		break;
	}

	if (unlikely(priv->soft_md == NULL))
		return 0;

	return 1;
}

static int uadk_digest_soft_init(struct digest_priv_ctx *priv)
{
	if (priv->soft_md)
		return EVP_DigestInit_ex(priv->soft_ctx, priv->soft_md, NULL);

	return 0;
}

static int uadk_digest_soft_update(struct digest_priv_ctx *priv,
				   const void *data, size_t len)
{
	if (priv->soft_md)
		return EVP_DigestUpdate(priv->soft_ctx, data, len);

	return 0;
}

static int uadk_digest_soft_final(struct digest_priv_ctx *priv, unsigned char *digest)
{
	if (priv->soft_md) {
		unsigned int digest_length;

		return EVP_DigestFinal_ex(priv->soft_ctx, digest, &digest_length);
	}

	return 0;
}

static void digest_soft_cleanup(struct digest_priv_ctx *priv)
{
	EVP_MD_CTX *ctx = priv->soft_ctx;

	if (ctx != NULL) {
		if (ctx->md_data) {
			OPENSSL_free(ctx->md_data);
			ctx->md_data  = NULL;
		}
		EVP_MD_CTX_free(ctx);
		ctx = NULL;
	}

	if (priv->soft_md) {
		EVP_MD_free(priv->soft_md);
		priv->soft_md = NULL;
	}
}

static int uadk_digest_soft_work(struct digest_priv_ctx *priv, int len,
				   unsigned char *digest)
{
	if (!priv->soft_md)
		return 0;

	uadk_digest_soft_init(priv);

	if (len != 0)
		uadk_digest_soft_update(priv, priv->data, len);

	uadk_digest_soft_final(priv, digest);
	digest_soft_cleanup(priv);

	return 1;
}

static int uadk_digest_env_poll(void *ctx)
{
	__u64 rx_cnt = 0;
	__u32 recv = 0;
	/* Poll one packet currently */
	int expt = 1;
	int ret;

	do {
		ret = wd_digest_poll(expt, &recv);
		if (ret < 0 || recv == expt)
			return ret;
		rx_cnt++;
	} while (rx_cnt < ENGINE_RECV_MAX_CNT);

	fprintf(stderr, "failed to poll msg: timeout!\n");

	return -ETIMEDOUT;
}

static int uadk_digest_init(struct digest_priv_ctx *priv)
{
	int digest_counts = ARRAY_SIZE(digest_info_table);
	struct sched_params params = {0};
	int nid = priv->e_nid;
	int ret, i;

	pthread_mutex_lock(&digest_mutex);
	if (prov.pid != getpid()) {
		ret = wd_digest_init2(priv->alg_name, 0, 0);
		if (unlikely(ret)) {
			priv->switch_flag = UADK_DO_SOFT;
			goto soft_init;
		}
		prov.pid = getpid();
		async_register_poll_fn(ASYNC_TASK_DIGEST, uadk_digest_env_poll);
	}
	pthread_mutex_unlock(&digest_mutex);

	for (i = 0; i < digest_counts; i++) {
		if (nid == digest_info_table[i].nid) {
			priv->setup.alg = digest_info_table[i].alg;
			priv->setup.mode = digest_info_table[i].mode;
			priv->req.out_buf_bytes = MAX_DIGEST_LENGTH;
			priv->req.out_bytes = digest_info_table[i].out_len;
			priv->switch_threshold = digest_info_table[i].threshold;
			break;
		}
	}

	if (unlikely(i == digest_counts)) {
		fprintf(stderr, "failed to setup the private ctx.\n");
		return 0;
	}

	/* Use the default numa parameters */
	params.numa_id = -1;
	priv->setup.sched_param = &params;
	priv->sess = wd_digest_alloc_sess(&priv->setup);
	if (unlikely(!priv->sess))
		return 0;

	priv->data = malloc(DIGEST_BLOCK_SIZE);
	if (unlikely(!priv->data)) {
		wd_digest_free_sess(priv->sess);
		return 0;
	}

	if (enable_sw_offload)
		uadk_digests_soft_md(priv);

	return 1;

soft_init:
	pthread_mutex_unlock(&digest_mutex);
	fprintf(stderr, "uadk failed to initialize digest.\n");
	return uadk_digest_soft_init(priv);
}

static int uadk_digest_update_inner(struct digest_priv_ctx *priv, const void *data, size_t data_len)
{
	const unsigned char *tmpdata = (const unsigned char *)data;
	size_t left_len = data_len;
	int copy_to_bufflen;
	int ret;

	/* Sha224 and Sha384 need full length mac buffer as doing long hash */
	if (priv->e_nid == NID_sha224)
		priv->req.out_bytes = WD_DIGEST_SHA224_FULL_LEN;

	if (priv->e_nid == NID_sha384)
		priv->req.out_bytes = WD_DIGEST_SHA384_FULL_LEN;

	priv->req.has_next = DIGEST_DOING;

	while (priv->last_update_bufflen + left_len > DIGEST_BLOCK_SIZE) {
		copy_to_bufflen = DIGEST_BLOCK_SIZE - priv->last_update_bufflen;
		uadk_memcpy(priv->data + priv->last_update_bufflen, tmpdata,
			    copy_to_bufflen);

		priv->last_update_bufflen = DIGEST_BLOCK_SIZE;
		priv->req.in_bytes = DIGEST_BLOCK_SIZE;
		priv->req.in = priv->data;
		priv->req.out = priv->out;
		left_len -= copy_to_bufflen;
		tmpdata += copy_to_bufflen;
		if (priv->state == SEC_DIGEST_INIT)
			priv->state = SEC_DIGEST_FIRST_UPDATING;
		else if (priv->state == SEC_DIGEST_FIRST_UPDATING)
			priv->state = SEC_DIGEST_DOING;

		ret = wd_do_digest_sync(priv->sess, &priv->req);
		if (ret) {
			fprintf(stderr, "do sec digest sync failed, switch to soft digest.\n");
			goto do_soft_digest;
		}

		priv->last_update_bufflen = 0;
		if (left_len <= DIGEST_BLOCK_SIZE) {
			priv->last_update_bufflen = left_len;
			uadk_memcpy(priv->data, tmpdata, priv->last_update_bufflen);
			break;
		}
	}

	return 1;

do_soft_digest:
	if (priv->state == SEC_DIGEST_FIRST_UPDATING
			&& priv->data
			&& priv->last_update_bufflen != 0) {
		priv->switch_flag = UADK_DO_SOFT;
		uadk_digest_soft_init(priv);
		ret = uadk_digest_soft_update(priv, priv->data, priv->last_update_bufflen);
		if (ret != 1)
			return ret;

		return uadk_digest_soft_update(priv, tmpdata, left_len);
	}

	fprintf(stderr, "do soft digest failed during updating!\n");
	return 0;
}

static int uadk_digest_update(struct digest_priv_ctx *priv, const void *data, size_t data_len)
{
	if (unlikely(priv->switch_flag == UADK_DO_SOFT))
		goto soft_update;

	if (priv->last_update_bufflen + data_len <= DIGEST_BLOCK_SIZE) {
		uadk_memcpy(priv->data + priv->last_update_bufflen, data, data_len);
		priv->last_update_bufflen += data_len;
		return 1;
	}

	return uadk_digest_update_inner(priv, data, data_len);

soft_update:
	return uadk_digest_soft_update(priv, data, data_len);
}

static void uadk_async_cb(struct wd_digest_req *req, void *data)
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

static int uadk_do_digest_sync(struct digest_priv_ctx *priv)
{
	int ret;

	if (priv->soft_md &&
	    priv->req.in_bytes <= priv->switch_threshold &&
	    priv->state == SEC_DIGEST_INIT)
		return 0;

	ret = wd_do_digest_sync(priv->sess, &priv->req);
	if (ret) {
		fprintf(stderr, "do sec digest sync failed, switch to soft digest.\n");
		return 0;
	}
	return 1;
}

static int uadk_do_digest_async(struct digest_priv_ctx *priv, struct async_op *op)
{
	struct uadk_e_cb_info cb_param;
	int idx, ret;

	if (unlikely(priv->switch_flag == UADK_DO_SOFT)) {
		fprintf(stderr, "async cipher init failed.\n");
		return 0;
	}

	cb_param.op = op;
	cb_param.priv = priv;
	priv->req.cb = (void *)uadk_async_cb;
	priv->req.cb_param = &cb_param;

	ret = async_get_free_task(&idx);
	if (!ret)
		return 0;

	op->idx = idx;

	do {
		ret = wd_do_digest_async(priv->sess, &priv->req);
		if (ret < 0 && ret != -EBUSY) {
			fprintf(stderr, "do sec digest async failed.\n");
			async_free_poll_task(op->idx, 0);
			return 0;
		}
	} while (ret == -EBUSY);

	ret = async_pause_job(priv, op, ASYNC_TASK_DIGEST);
	if (!ret)
		return 0;
	return 1;
}

static int uadk_digest_final(struct digest_priv_ctx *priv, unsigned char *digest)
{
	struct async_op op;
	int ret;

	priv->req.has_next = DIGEST_END;
	priv->req.in = priv->data;
	priv->req.out = priv->out;
	priv->req.in_bytes = priv->last_update_bufflen;

	if (priv->e_nid == NID_sha224)
		priv->req.out_bytes = WD_DIGEST_SHA224_LEN;

	if (priv->e_nid == NID_sha384)
		priv->req.out_bytes = WD_DIGEST_SHA384_LEN;

	ret = async_setup_async_event_notification(&op);
	if (unlikely(!ret)) {
		fprintf(stderr, "failed to setup async event notification.\n");
		return 0;
	}

	if (op.job == NULL) {
		/* Synchronous, only the synchronous mode supports soft computing */
		if (unlikely(priv->switch_flag == UADK_DO_SOFT)) {
			ret = uadk_digest_soft_final(priv, digest);
			digest_soft_cleanup(priv);
			goto clear;
		}

		ret = uadk_do_digest_sync(priv);
		if (!ret)
			goto sync_err;
	} else {
		ret = uadk_do_digest_async(priv, &op);
		if (!ret)
			goto clear;
	}
	memcpy(digest, priv->req.out, priv->req.out_bytes);

	return 1;

sync_err:
	if (priv->state == SEC_DIGEST_INIT) {
		ret = uadk_digest_soft_work(priv, priv->req.in_bytes, digest);
	} else {
		ret = 0;
		fprintf(stderr, "do sec digest stream mode failed.\n");
	}
clear:
	async_clear_async_event_notification();
	return ret;
}

static int uadk_digest_cleanup(struct digest_priv_ctx *priv)
{
	if (priv->sess) {
		wd_digest_free_sess(priv->sess);
		priv->sess = 0;
	}

	if (priv->data)
		OPENSSL_free(priv->data);

	return 1;
}

/* some params related code is copied from OpenSSL v3.0 prov/digestcommon.h */
static const OSSL_PARAM uadk_digest_default_known_gettable_params[] = {
	OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, NULL),
	OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL),
	OSSL_PARAM_int(OSSL_DIGEST_PARAM_XOF, NULL),
	OSSL_PARAM_int(OSSL_DIGEST_PARAM_ALGID_ABSENT, NULL),
	OSSL_PARAM_END
};

static const OSSL_PARAM *uadk_prov_gettable_params(void *provctx)
{
	return uadk_digest_default_known_gettable_params;
}

static int uadk_digest_default_get_params(OSSL_PARAM params[], size_t blksz,
					  size_t paramsz)
{
	OSSL_PARAM *p = NULL;

	p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_BLOCK_SIZE);
	if (p != NULL && !OSSL_PARAM_set_size_t(p, blksz)) {
		ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
		return 0;
	}
	p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE);
	if (p != NULL && !OSSL_PARAM_set_size_t(p, paramsz)) {
		ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
		return 0;
	}
	p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_XOF);
	if (p != NULL
		&& !OSSL_PARAM_set_int(p, 0)) {
		ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
		return 0;
	}
	p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_ALGID_ABSENT);
	if (p != NULL
		&& !OSSL_PARAM_set_int(p, 0)) {
		ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
		return 0;
	}

	return 1;
}

static void uadk_prov_freectx(void *dctx)
{
	struct digest_priv_ctx *priv = (struct digest_priv_ctx *)dctx;

	uadk_digest_cleanup(priv);
	OPENSSL_clear_free(priv, sizeof(*priv));
}

static void *uadk_prov_dupctx(void *dctx)
{
	struct digest_priv_ctx *in;
	struct digest_priv_ctx *ret;

	in = (struct digest_priv_ctx *)dctx;
	ret = OPENSSL_zalloc(sizeof(struct digest_priv_ctx *));

	if (ret != NULL)
		*ret = *in;
	return ret;
}

static int uadk_prov_init(void *dctx, const OSSL_PARAM params[])
{
	struct digest_priv_ctx *priv =
		(struct digest_priv_ctx *) dctx;

	return uadk_digest_init(priv);
}

static int uadk_prov_update(void *dctx, const unsigned char *in, size_t inl)
{
	return uadk_digest_update((struct digest_priv_ctx *)dctx, in, inl);
}

/*
 * Note:
 * The I<dctx> parameter contains a pointer to the provider side context.
 * The digest should be written to I<*out> and the length of the digest to I<*outl>.
 * The digest should not exceed I<outsz> bytes.
 */
static int uadk_prov_final(void *dctx, unsigned char *out,
			   size_t *outl, size_t outsz)
{
	struct digest_priv_ctx *priv =
		(struct digest_priv_ctx *) dctx;
	int ret;

	if (outsz > 0) {
		ret = uadk_digest_final(priv, out);
		if (!ret)
			return ret;
	}

	if (unlikely(outl != NULL))
		*outl = priv->md_size;

	return 1;
}

void uadk_prov_destroy_digest(void)
{
	pthread_mutex_lock(&digest_mutex);
	if (prov.pid == getpid()) {
		wd_digest_uninit2();
		prov.pid = 0;
	}
	pthread_mutex_unlock(&digest_mutex);
}

static OSSL_FUNC_digest_freectx_fn	uadk_prov_freectx;
static OSSL_FUNC_digest_dupctx_fn	uadk_prov_dupctx;
static OSSL_FUNC_digest_init_fn		uadk_prov_init;
static OSSL_FUNC_digest_update_fn	uadk_prov_update;
static OSSL_FUNC_digest_final_fn	uadk_prov_final;
static OSSL_FUNC_digest_gettable_params_fn
					uadk_prov_gettable_params;

#define UADK_PROVIDER_IMPLEMENTATION(name, nid, mdsize, blksize)		\
static OSSL_FUNC_digest_newctx_fn uadk_##name##_newctx;				\
static void *uadk_##name##_newctx(void *provctx)				\
{										\
	struct digest_priv_ctx *ctx = OPENSSL_zalloc(sizeof(*ctx));		\
										\
	if (ctx == NULL)							\
		return NULL;							\
	ctx->blk_size = blksize;						\
	ctx->md_size = mdsize;							\
	ctx->e_nid = nid;							\
	ctx->soft_ctx = EVP_MD_CTX_new();					\
	if (ctx->soft_ctx == NULL)						\
		fprintf(stderr, "EVP_MD_CTX_new failed.\n");			\
	strncpy(ctx->alg_name, #name, ALG_NAME_SIZE - 1);			\
	return ctx;								\
}										\
static OSSL_FUNC_digest_get_params_fn uadk_##name##_get_params;			\
static int uadk_##name##_get_params(OSSL_PARAM params[])			\
{										\
	return uadk_digest_default_get_params(params, blksize, mdsize);		\
}										\
const OSSL_DISPATCH uadk_##name##_functions[] = {				\
	{ OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))uadk_##name##_newctx },	\
	{ OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))uadk_prov_freectx },	\
	{ OSSL_FUNC_DIGEST_DUPCTX, (void (*)(void))uadk_prov_dupctx },		\
	{ OSSL_FUNC_DIGEST_INIT, (void (*)(void))uadk_prov_init },		\
	{ OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))uadk_prov_update },		\
	{ OSSL_FUNC_DIGEST_FINAL, (void (*)(void))uadk_prov_final },		\
	{ OSSL_FUNC_DIGEST_GET_PARAMS,						\
		(void (*)(void))uadk_##name##_get_params },			\
	{ OSSL_FUNC_DIGEST_GETTABLE_PARAMS,					\
		(void (*)(void))uadk_prov_gettable_params },			\
	{ 0, NULL }								\
}

UADK_PROVIDER_IMPLEMENTATION(md5, NID_md5, MD5_DIGEST_LENGTH, MD5_CBLOCK);
UADK_PROVIDER_IMPLEMENTATION(sm3, NID_sm3, SM3_DIGEST_LENGTH, SM3_CBLOCK);
UADK_PROVIDER_IMPLEMENTATION(sha1, NID_sha1, 20, 64);
UADK_PROVIDER_IMPLEMENTATION(sha224, NID_sha224, 28, 64);
UADK_PROVIDER_IMPLEMENTATION(sha256, NID_sha256, 32, 64);
UADK_PROVIDER_IMPLEMENTATION(sha384, NID_sha384, 48, 128);
UADK_PROVIDER_IMPLEMENTATION(sha512, NID_sha512, 64, 128);
