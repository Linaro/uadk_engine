/*
 * Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved.
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
#include <openssl/engine.h>
#include <openssl/md5.h>
#include <openssl/evp.h>
#include <uadk/wd_cipher.h>
#include <uadk/wd_digest.h>
#include "uadk.h"
#include "uadk_async.h"

#define UADK_DO_SOFT	(-0xE0)
#define CTX_SYNC	0
#define CTX_ASYNC	1
#define CTX_NUM		2

/* The max BD data length is 16M-512B */
#define BUF_LEN      0xFFFE00

#define SM3_DIGEST_LENGTH	32
#define SM3_CBLOCK		64
#define SM3_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT (512)
#define MD5_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT (8 * 1024)
#define SHA_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT (512)

struct digest_threshold_table {
	int nid;
	int threshold;
};

struct digest_engine {
	struct wd_ctx_config ctx_cfg;
	struct wd_sched sched;
	int numa_id;
	int pid;
	pthread_spinlock_t lock;
};

static struct digest_engine engine;

struct evp_md_ctx_st {
	const EVP_MD *digest;
	/* functional reference if 'digest' is ENGINE-provided */
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
	long tail;
	bool copy;
	uint32_t e_nid;
	EVP_MD_CTX *soft_ctx;
	size_t switch_threshold;
	int switch_flag;
};

static int digest_nids[] = {
	NID_md5,
	NID_sm3,
	NID_sha1,
	NID_sha224,
	NID_sha256,
	NID_sha384,
	NID_sha512,
	0,
};

static struct digest_threshold_table digest_pkt_threshold_table[] = {
	{ NID_sm3, SM3_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT },
	{ NID_md5, MD5_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT },
	{ NID_sha1, SHA_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT },
	{ NID_sha224, SHA_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT },
	{ NID_sha256, SHA_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT },
	{ NID_sha384, SHA_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT },
	{ NID_sha512, SHA_SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT },
};

static EVP_MD *uadk_md5;
static EVP_MD *uadk_sm3;
static EVP_MD *uadk_sha1;
static EVP_MD *uadk_sha224;
static EVP_MD *uadk_sha256;
static EVP_MD *uadk_sha384;
static EVP_MD *uadk_sha512;

static const EVP_MD *uadk_e_digests_soft_md(uint32_t e_nid)
{
	const EVP_MD *digest_md = NULL;

	switch (e_nid) {
	case NID_sm3:
		digest_md = EVP_sm3();
		break;
	case NID_md5:
		digest_md = EVP_md5();
		break;
	case NID_sha1:
		digest_md = EVP_sha1();
		break;
	case NID_sha224:
		digest_md = EVP_sha224();
		break;
	case NID_sha256:
		digest_md = EVP_sha256();
		break;
	case NID_sha384:
		digest_md = EVP_sha384();
		break;
	case NID_sha512:
		digest_md = EVP_sha512();
		break;
	default:
		break;
	}
	return digest_md;
}

static int sec_digest_get_sw_threshold(int n_id)
{
	int threshold_table_size = ARRAY_SIZE(digest_pkt_threshold_table);
	int i = 0;

	do {
		if (digest_pkt_threshold_table[i].nid == n_id)
			return digest_pkt_threshold_table[i].threshold;
	} while (++i < threshold_table_size);

	fprintf(stderr, "nid %d not found in digest threshold table", n_id);
	return 0;
}

static int digest_soft_init(EVP_MD_CTX *ctx, uint32_t e_nid)
{
	const EVP_MD *digest_md = NULL;
	int ctx_len;

	digest_md = uadk_e_digests_soft_md(e_nid);
	if (unlikely(digest_md == NULL)) {
		fprintf(stderr, "get openssl software digest failed, nid = %u.\n", e_nid);
		return  0;
	}

	ctx_len = EVP_MD_meth_get_app_datasize(digest_md);
	if (ctx->md_data == NULL) {
		ctx->md_data = OPENSSL_malloc(ctx_len);
		if (ctx->md_data == NULL)
			return  0;
	}

	return EVP_MD_meth_get_init(digest_md)(ctx);
}

static int digest_soft_update(EVP_MD_CTX *ctx, uint32_t e_nid,
				const void *data, size_t len)
{
	const EVP_MD *digest_md = NULL;

	digest_md = uadk_e_digests_soft_md(e_nid);
	if (unlikely(digest_md == NULL)) {
		fprintf(stderr, "switch to soft:don't support by sec engine.\n");
		return  0;
	}

	return EVP_MD_meth_get_update(digest_md)(ctx, data, len);
}

static int digest_soft_final(EVP_MD_CTX *ctx, uint32_t e_nid, unsigned char *digest)
{
	const EVP_MD *digest_md = NULL;

	digest_md = uadk_e_digests_soft_md(e_nid);
	if (unlikely(digest_md == NULL)) {
		fprintf(stderr, "switch to soft:don't support by sec engine.\n");
		return  0;
	}

	return EVP_MD_meth_get_final(digest_md)(ctx, digest);
}

static void digest_soft_cleanup(struct digest_priv_ctx *md_ctx)
{
	EVP_MD_CTX *ctx = md_ctx->soft_ctx;

	if (ctx != NULL) {
		if (ctx->md_data) {
			OPENSSL_free(ctx->md_data);
			ctx->md_data  = NULL;
		}
		EVP_MD_CTX_free(ctx);
		ctx = NULL;
	}
}

static int uadk_e_digest_soft_work(struct digest_priv_ctx *md_ctx, int len,
				   unsigned char *digest)
{
	if (md_ctx->soft_ctx == NULL)
		md_ctx->soft_ctx = EVP_MD_CTX_new();

	(void)digest_soft_init(md_ctx->soft_ctx, md_ctx->e_nid);

	if (len != 0)
		(void)digest_soft_update(md_ctx->soft_ctx, md_ctx->e_nid,
				md_ctx->data, len);

	(void)digest_soft_final(md_ctx->soft_ctx, md_ctx->e_nid, digest);

	digest_soft_cleanup(md_ctx);

	return 1;
}

static int uadk_engine_digests(ENGINE *e, const EVP_MD **digest,
			       const int **nids, int nid)
{
	int ok = 1;

	if (!digest) {
		*nids = digest_nids;
		return (sizeof(digest_nids) - 1) / sizeof(digest_nids[0]);
	}

	switch (nid) {
	case NID_md5:
		*digest = uadk_md5;
		break;
	case NID_sm3:
		*digest = uadk_sm3;
		break;
	case NID_sha1:
		*digest = uadk_sha1;
		break;
	case NID_sha224:
		*digest = uadk_sha224;
		break;
	case NID_sha256:
		*digest = uadk_sha256;
		break;
	case NID_sha384:
		*digest = uadk_sha384;
		break;
	case NID_sha512:
		*digest = uadk_sha512;
		break;
	default:
		ok = 0;
		*digest = NULL;
		break;
	}

	return ok;
}

static __u32 sched_single_pick_next_ctx(handle_t h_sched_ctx, const void *req,
					const struct sched_key *key)
{
	const struct wd_digest_req *digest_req = req;

	if (digest_req->cb)
		return CTX_ASYNC;
	else
		return CTX_SYNC;
}

static int sched_single_poll_policy(handle_t h_sched_ctx,
				    __u32 expect, __u32 *count)
{
	return 0;
}

static int uadk_e_digest_poll(void *ctx)
{
	__u32 recv = 0;
	int expt = 1;
	int ret = 0;

	do {
		ret = wd_digest_poll_ctx(CTX_ASYNC, expt, &recv);
		if (recv >= expt)
			return 0;
		else if (ret < 0 && ret != -EAGAIN)
			return ret;
	} while (ret == -EAGAIN);

	return ret;
}

static int uadk_e_digest_env_poll(void *ctx)
{
	__u32 recv = 0;
	/* Poll one packet currently */
	int expt = 1;
	int ret;

	do {
		ret = wd_digest_poll(expt, &recv);
		if (ret < 0)
			return ret;
	} while (recv < expt);

	return ret;
}

static int uadk_e_wd_digest_env_init(struct uacce_dev *dev)
{
	const char *var_name = "WD_DIGEST_CTX_NUM";
	char env_string[ENV_STRING_LEN] = {0};
	char *var_s;
	int ret;

	var_s = getenv(var_name);
	if (!var_s || !strlen(var_s)) {
		snprintf(env_string, ENV_STRING_LEN, "%s%d%s%d",
			 "sync:2@", dev->numa_id, ",async:2@", dev->numa_id);
		setenv(var_name, env_string, 1);
	}

	ret = wd_digest_env_init();
	if (ret)
		return ret;

	async_register_poll_fn(ASYNC_TASK_DIGEST, uadk_e_digest_env_poll);

	return 0;
}

static int uadk_e_wd_digest_init(struct uacce_dev *dev)
{
	int ret, i, j;

	engine.numa_id = dev->numa_id;

	ret = uadk_is_env_enabled("digest");
	if (ret)
		return uadk_e_wd_digest_env_init(dev);

	memset(&engine.ctx_cfg, 0, sizeof(struct wd_ctx_config));
	engine.ctx_cfg.ctx_num = CTX_NUM;
	engine.ctx_cfg.ctxs = calloc(CTX_NUM, sizeof(struct wd_ctx));
	if (!engine.ctx_cfg.ctxs)
		return -ENOMEM;

	for (i = 0; i < CTX_NUM; i++) {
		engine.ctx_cfg.ctxs[i].ctx = wd_request_ctx(dev);
		if (!engine.ctx_cfg.ctxs[i].ctx) {
			ret = -ENOMEM;
			goto err_freectx;
		}

		engine.ctx_cfg.ctxs[i].op_type = CTX_TYPE_ENCRYPT;
		engine.ctx_cfg.ctxs[i].ctx_mode =
			(i == 0) ? CTX_MODE_SYNC : CTX_MODE_ASYNC;
	}

	engine.sched.name = "sched_single";
	engine.sched.pick_next_ctx = sched_single_pick_next_ctx;
	engine.sched.poll_policy = sched_single_poll_policy;

	ret = wd_digest_init(&engine.ctx_cfg, &engine.sched);
	if (ret)
		goto err_freectx;

	return async_register_poll_fn(ASYNC_TASK_DIGEST, uadk_e_digest_poll);

err_freectx:
	for (j = 0; j < i; j++)
		wd_release_ctx(engine.ctx_cfg.ctxs[j].ctx);

	free(engine.ctx_cfg.ctxs);

	return ret;
}

static int uadk_e_init_digest(void)
{
	struct uacce_dev *dev;
	int ret;

	if (engine.pid != getpid()) {
		pthread_spin_lock(&engine.lock);
		if (engine.pid == getpid()) {
			pthread_spin_unlock(&engine.lock);
			return 1;
		}

		dev = wd_get_accel_dev("digest");
		if (!dev) {
			pthread_spin_unlock(&engine.lock);
			fprintf(stderr, "failed to get device for digest.\n");
			return 0;
		}

		ret = uadk_e_wd_digest_init(dev);
		if (ret)
			goto err_unlock;

		engine.pid = getpid();
		pthread_spin_unlock(&engine.lock);
		free(dev);
	}

	return 1;

err_unlock:
	pthread_spin_unlock(&engine.lock);
	free(dev);
	fprintf(stderr, "failed to init digest(%d).\n", ret);

	return 0;
}

static void digest_priv_ctx_setup(struct digest_priv_ctx *priv,
			enum wd_digest_type alg, enum wd_digest_mode mode,
			 __u32 out_len)
{
	priv->setup.mode = alg;
	priv->setup.alg = mode;
	priv->req.out_buf_bytes = out_len;
	priv->req.out_bytes = out_len;
}

static int uadk_e_digest_init(EVP_MD_CTX *ctx)
{
	struct digest_priv_ctx *priv =
		(struct digest_priv_ctx *) EVP_MD_CTX_md_data(ctx);
	int nid = EVP_MD_nid(EVP_MD_CTX_md(ctx));
	int ret;

	/* Allocate a soft ctx for hardware engine */
	if (priv->soft_ctx == NULL)
		priv->soft_ctx = EVP_MD_CTX_new();
	priv->e_nid = nid;

	ret = uadk_e_init_digest();
	if (!ret) {
		priv->switch_flag = UADK_DO_SOFT;
		fprintf(stderr, "uadk failed to initialize digest.\n");
		goto soft_init;
	}

	switch (nid) {
	case NID_md5:
		digest_priv_ctx_setup(priv, WD_DIGEST_NORMAL, WD_DIGEST_MD5, 16);
		break;
	case NID_sm3:
		digest_priv_ctx_setup(priv, WD_DIGEST_NORMAL, WD_DIGEST_SM3, 32);
		break;
	case NID_sha1:
		digest_priv_ctx_setup(priv, WD_DIGEST_NORMAL, WD_DIGEST_SHA1, 20);
		break;
	case NID_sha224:
		digest_priv_ctx_setup(priv, WD_DIGEST_NORMAL, WD_DIGEST_SHA224, 28);
		break;
	case NID_sha256:
		digest_priv_ctx_setup(priv, WD_DIGEST_NORMAL, WD_DIGEST_SHA256, 32);
		break;
	case NID_sha384:
		digest_priv_ctx_setup(priv, WD_DIGEST_NORMAL, WD_DIGEST_SHA384, 48);
		break;
	case NID_sha512:
		digest_priv_ctx_setup(priv, WD_DIGEST_NORMAL, WD_DIGEST_SHA512, 64);
		break;
	default:
		return 0;
	}

	priv->setup.numa = engine.numa_id;
	priv->sess = wd_digest_alloc_sess(&priv->setup);
	if (unlikely(!priv->sess))
		return 0;

	priv->switch_threshold = sec_digest_get_sw_threshold(nid);

	return 1;

soft_init:
	return digest_soft_init(priv->soft_ctx, priv->e_nid);
}

static int uadk_e_digest_update(EVP_MD_CTX *ctx, const void *data, size_t data_len)
{
	struct digest_priv_ctx *priv =
		(struct digest_priv_ctx *)EVP_MD_CTX_md_data(ctx);

	if (unlikely(priv->switch_flag == UADK_DO_SOFT))
		goto soft_update;

	if ((data_len <= BUF_LEN - priv->tail) && (data_len > 0)) {
		if (!priv->data) {
			priv->data = OPENSSL_malloc(BUF_LEN);
			if (priv->data == NULL)
				return 0;
		}

		memcpy(priv->data + priv->tail, data, data_len);
		priv->tail += data_len;

		return 1;
	}

	return 0;

soft_update:
	return digest_soft_update(priv->soft_ctx, priv->e_nid, data, data_len);
}

static void async_cb(struct wd_digest_req *req, void *data)
{
}

static int do_digest_sync(struct digest_priv_ctx *priv)
{
	int ret;

	/* Fix me: not support switch the soft work as input is lower  */

	ret = wd_do_digest_sync(priv->sess, &priv->req);
	if (ret) {
		fprintf(stderr, "do sec digest sync failed, switch to soft digest.\n");
		return 0;
	}
	return 1;
}

static int do_digest_async(struct digest_priv_ctx *priv, struct async_op *op)
{
	int ret;

	if (unlikely(priv->switch_flag == UADK_DO_SOFT)) {
		fprintf(stderr, "async cipher init failed.\n");
		return 0;
	}

	priv->req.cb = (void *)async_cb;
	priv->req.cb_param = priv;
	do {
		ret = wd_do_digest_async(priv->sess, &priv->req);
		if (ret < 0 && ret != -EBUSY) {
			fprintf(stderr, "do sec digest async failed.\n");
			return 0;
		}
	} while (ret == -EBUSY);

	ret = async_pause_job(priv, op, ASYNC_TASK_DIGEST);
	if (!ret)
		return 0;
	return 1;
}

static int uadk_e_digest_final(EVP_MD_CTX *ctx, unsigned char *digest)
{
	struct digest_priv_ctx *priv =
		(struct digest_priv_ctx *)EVP_MD_CTX_md_data(ctx);
	int ret = 1;
	struct async_op op;

	priv->sess = wd_digest_alloc_sess(&priv->setup);
	if (unlikely(!priv->sess))
		return 0;

	priv->req.in = priv->data;
	priv->req.out = digest;
	priv->req.in_bytes = priv->tail;
	priv->e_nid = EVP_MD_nid(EVP_MD_CTX_md(ctx));

	async_setup_async_event_notification(&op);

	if (op.job == NULL) {
		/* Synchronous, only the synchronous mode supports soft computing */
		if (unlikely(priv->switch_flag == UADK_DO_SOFT)) {
			ret = digest_soft_final(priv->soft_ctx, priv->e_nid, digest);
			digest_soft_cleanup(priv);
			goto clear;
		}

		ret = do_digest_sync(priv);
		if (!ret)
			goto sync_err;
	} else {
		ret = do_digest_async(priv, &op);
		if (!ret)
			goto clear;
	}

	if (priv->sess) {
		wd_digest_free_sess(priv->sess);
		priv->sess = 0;
	}

	return 1;

sync_err:
	ret = uadk_e_digest_soft_work(priv, priv->tail, digest);
clear:
	async_clear_async_event_notification();
	if (priv->sess) {
		wd_digest_free_sess(priv->sess);
		priv->sess = 0;
	}
	return ret;
}

static int uadk_e_digest_cleanup(EVP_MD_CTX *ctx)
{
	struct digest_priv_ctx *priv =
		(struct digest_priv_ctx *)EVP_MD_CTX_md_data(ctx);

	if (!priv || priv->copy)
		return 1;

	if (priv && priv->data)
		OPENSSL_free(priv->data);

	return 1;
}

static int uadk_e_digest_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from)
{
	struct digest_priv_ctx *f =
		(struct digest_priv_ctx *)EVP_MD_CTX_md_data(from);
	struct digest_priv_ctx *t =
		(struct digest_priv_ctx *)EVP_MD_CTX_md_data(to);

	/*
	 * EVP_MD_CTX_copy will copy from->priv to to->priv,
	 * including data pointer. Instead of coping data contents,
	 * add a flag to prevent double-free.
	 */

	if (f && f->data)
		t->copy = true;

	return 1;
}


#define UADK_DIGEST_DESCR(name, pkey_type, md_size, flags,		\
	block_size, ctx_size, init, update, final, cleanup, copy)	\
do { \
	uadk_##name = EVP_MD_meth_new(NID_##name, NID_##pkey_type);	\
	if (uadk_##name == 0 ||						\
	    !EVP_MD_meth_set_result_size(uadk_##name, md_size) ||	\
	    !EVP_MD_meth_set_input_blocksize(uadk_##name, block_size) || \
	    !EVP_MD_meth_set_app_datasize(uadk_##name, ctx_size) ||	\
	    !EVP_MD_meth_set_flags(uadk_##name, flags) ||		\
	    !EVP_MD_meth_set_init(uadk_##name, init) ||			\
	    !EVP_MD_meth_set_update(uadk_##name, update) ||		\
	    !EVP_MD_meth_set_final(uadk_##name, final) ||		\
	    !EVP_MD_meth_set_cleanup(uadk_##name, cleanup) ||		\
	    !EVP_MD_meth_set_copy(uadk_##name, copy))			\
		return 0; \
} while (0)

int uadk_e_bind_digest(ENGINE *e)
{
	UADK_DIGEST_DESCR(md5, md5WithRSAEncryption, MD5_DIGEST_LENGTH,
			  0, MD5_CBLOCK,
			  sizeof(EVP_MD *) + sizeof(struct digest_priv_ctx),
			  uadk_e_digest_init, uadk_e_digest_update,
			  uadk_e_digest_final, uadk_e_digest_cleanup,
			  uadk_e_digest_copy);
	UADK_DIGEST_DESCR(sm3, sm3WithRSAEncryption, SM3_DIGEST_LENGTH,
			  0, SM3_CBLOCK,
			  sizeof(EVP_MD *) + sizeof(struct digest_priv_ctx),
			  uadk_e_digest_init, uadk_e_digest_update,
			  uadk_e_digest_final, uadk_e_digest_cleanup,
			  uadk_e_digest_copy);
	UADK_DIGEST_DESCR(sha1, sha1WithRSAEncryption, 20,
			  EVP_MD_FLAG_FIPS, 64,
			  sizeof(EVP_MD *) + sizeof(struct digest_priv_ctx),
			  uadk_e_digest_init, uadk_e_digest_update,
			  uadk_e_digest_final, uadk_e_digest_cleanup,
			  uadk_e_digest_copy);
	UADK_DIGEST_DESCR(sha224, sha224WithRSAEncryption, 28,
			  EVP_MD_FLAG_FIPS, 64,
			  sizeof(EVP_MD *) + sizeof(struct digest_priv_ctx),
			  uadk_e_digest_init, uadk_e_digest_update,
			  uadk_e_digest_final, uadk_e_digest_cleanup,
			  uadk_e_digest_copy);
	UADK_DIGEST_DESCR(sha256, sha256WithRSAEncryption, 32,
			  EVP_MD_FLAG_FIPS, 64,
			  sizeof(EVP_MD *) + sizeof(struct digest_priv_ctx),
			  uadk_e_digest_init, uadk_e_digest_update,
			  uadk_e_digest_final, uadk_e_digest_cleanup,
			  uadk_e_digest_copy);
	UADK_DIGEST_DESCR(sha384, sha384WithRSAEncryption, 48,
			  EVP_MD_FLAG_FIPS, 128,
			  sizeof(EVP_MD *) + sizeof(struct digest_priv_ctx),
			  uadk_e_digest_init, uadk_e_digest_update,
			  uadk_e_digest_final, uadk_e_digest_cleanup,
			  uadk_e_digest_copy);
	UADK_DIGEST_DESCR(sha512, sha512WithRSAEncryption, 64,
			  EVP_MD_FLAG_FIPS, 128,
			  sizeof(EVP_MD *) + sizeof(struct digest_priv_ctx),
			  uadk_e_digest_init, uadk_e_digest_update,
			  uadk_e_digest_final, uadk_e_digest_cleanup,
			  uadk_e_digest_copy);

	pthread_spin_init(&engine.lock, PTHREAD_PROCESS_PRIVATE);

	return ENGINE_set_digests(e, uadk_engine_digests);
}

void uadk_e_destroy_digest(void)
{
	int i, ret;

	if (engine.pid == getpid()) {
		ret = uadk_is_env_enabled("digest");
		if (ret) {
			wd_digest_env_uninit();
		} else {
			wd_digest_uninit();
			for (i = 0; i < engine.ctx_cfg.ctx_num; i++)
				wd_release_ctx(engine.ctx_cfg.ctxs[i].ctx);
			free(engine.ctx_cfg.ctxs);
			engine.pid = 0;
		}
	}

	pthread_spin_destroy(&engine.lock);

	EVP_MD_meth_free(uadk_md5);
	uadk_md5 = 0;
	EVP_MD_meth_free(uadk_sm3);
	uadk_sm3 = 0;
	EVP_MD_meth_free(uadk_sha1);
	uadk_sha1 = 0;
	EVP_MD_meth_free(uadk_sha224);
	uadk_sha224 = 0;
	EVP_MD_meth_free(uadk_sha256);
	uadk_sha256 = 0;
	EVP_MD_meth_free(uadk_sha384);
	uadk_sha384 = 0;
	EVP_MD_meth_free(uadk_sha512);
	uadk_sha512 = 0;
}
