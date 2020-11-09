/*
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
#include <string.h>
#include <dlfcn.h>
#include <openssl/engine.h>
#include <openssl/md5.h>
#include <uadk/wd_cipher.h>
#include <uadk/wd_digest.h>
#include "uadk.h"
#include "uadk_async.h"

struct digest_engine {
	struct wd_ctx_config ctx_cfg;
	struct wd_sched sched;
};

static struct digest_engine engine;

struct digest_priv_ctx {
	handle_t sess;
	struct wd_digest_sess_setup setup;
	struct wd_digest_req req;
	long tail;
};

#define CTX_SYNC	0
#define CTX_ASYNC	1
#define CTX_NUM		2

#define BUF_LEN (16 * 1024 * 1024)
#define SM3_DIGEST_LENGTH	32
#define SM3_CBLOCK		64

static int digest_nids[] = {
	NID_md5,
	NID_sm3,
	NID_sha1,
	NID_sha256,
	NID_sha512,
	0,
	};

static EVP_MD *uadk_md5;
static EVP_MD *uadk_sm3;
static EVP_MD *uadk_sha1;
static EVP_MD *uadk_sha256;
static EVP_MD *uadk_sha512;

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
	case NID_sha256:
		*digest = uadk_sha256;
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

static int uadk_digest_init(EVP_MD_CTX *ctx)
{
	struct digest_priv_ctx *priv =
		(struct digest_priv_ctx *) EVP_MD_CTX_md_data(ctx);
	int nid = EVP_MD_nid(EVP_MD_CTX_md(ctx));

	switch (nid) {
	case NID_md5:
		priv->setup.mode = WD_DIGEST_NORMAL; // fixme: how to distinguish hmac
		priv->setup.alg = WD_DIGEST_MD5;
		priv->req.out_buf_bytes = 16;
		priv->req.out_bytes = 16;
		break;
	case NID_sm3:
		priv->setup.mode = WD_DIGEST_NORMAL; // fixme: how to distinguish hmac
		priv->setup.alg = WD_DIGEST_SM3;
		priv->req.out_buf_bytes = 32;
		priv->req.out_bytes = 32;
		break;
	case NID_sha1:
		priv->setup.mode = WD_DIGEST_NORMAL; // fixme: how to distinguish hmac
		priv->setup.alg = WD_DIGEST_SHA1;
		priv->req.out_buf_bytes = 20;
		priv->req.out_bytes = 20;
		break;
	case NID_sha256:
		priv->setup.mode = WD_DIGEST_NORMAL; // fixme: how to distinguish hmac
		priv->setup.alg = WD_DIGEST_SHA256;
		priv->req.out_buf_bytes = 32;
		priv->req.out_bytes = 32;
		break;
	case NID_sha512:
		priv->setup.mode = WD_DIGEST_NORMAL; // fixme: how to distinguish hmac
		priv->setup.alg = WD_DIGEST_SHA512;
		priv->req.out_buf_bytes = 64;
		priv->req.out_bytes = 64;
		break;
	default:
		goto out;
	}

	priv->req.in = malloc(BUF_LEN);
	if (!priv->req.in)
		goto out;

	priv->sess = wd_digest_alloc_sess(&priv->setup);
	if (!priv->sess)
		goto out;

	return 1;

out:
	if (priv->req.in)
		free(priv->req.in);

	return 0;
}

static int uadk_digest_update(EVP_MD_CTX *ctx, const void *data, size_t data_len)
{
	struct digest_priv_ctx *priv =
		(struct digest_priv_ctx *) EVP_MD_CTX_md_data(ctx);

	if (data_len < BUF_LEN - priv->tail) {
		memcpy(priv->req.in + priv->tail, data, data_len);
		priv->tail += data_len;
	} else {
		return 0;
	}

	return 1;
}

static void async_cb(struct wd_cipher_req *req, void *data)
{
}

static int uadk_digest_final(EVP_MD_CTX *ctx, unsigned char *digest)
{
	struct digest_priv_ctx *priv =
		(struct digest_priv_ctx *) EVP_MD_CTX_md_data(ctx);
	enum task_type type = ASYNC_TASK_DIGEST;
	struct async_op op;
	int ret;

	priv->req.out = digest;
	priv->req.in_bytes = priv->tail;

	async_setup_async_event_notification(&op);
	if (op.job == NULL) {
		/* sync */
		ret = wd_do_digest_sync(priv->sess, &priv->req);
		if (ret)
			return 0;
	} else {
		/* async */
		priv->req.cb = (void *)async_cb;
		priv->req.cb_param = priv;

		do {
			ret = wd_do_digest_async(priv->sess, &priv->req);
			if (ret < 0 && ret != -EBUSY)
				goto err;
		} while (ret == -EBUSY);

		ret = async_pause_job(priv, &op, ASYNC_TASK_DIGEST);
		if (!ret)
			goto err;
	}

	return 1;
err:
	async_clear_async_event_notification();
	return 0;
}

static int uadk_digest_cleanup(EVP_MD_CTX *ctx)
{
	struct digest_priv_ctx *priv =
		(struct digest_priv_ctx *) EVP_MD_CTX_md_data(ctx);

	if (priv->req.in)
		free(priv->req.in);

	if (priv->sess)
		wd_digest_free_sess(priv->sess);
	return 1;
}

int uadk_digest_poll(void *ctx)
{
	int ret = 0;
	int expt = 1;
	int recv;

	do {
		ret = wd_digest_poll_ctx(CTX_ASYNC, expt, &recv);
		if (recv >= expt)
			return 0;
		else if (ret < 0 && ret != -EAGAIN)
			return ret;
	} while (ret == -EAGAIN);

	return ret;
}

#define UADK_DIGEST_DESCR(name, pkey_type, md_size, flags,		\
	block_size, ctx_size, init, update, final, cleanup)		\
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
	    !EVP_MD_meth_set_cleanup(uadk_##name, cleanup))		\
		return 0; \
} while (0)

int uadk_bind_digest(ENGINE *e, struct uacce_dev_list *list)
{
	int ret;
	int i;

	memset(&engine.ctx_cfg, 0, sizeof(struct wd_ctx_config));
	engine.ctx_cfg.ctx_num = CTX_NUM;
	engine.ctx_cfg.ctxs = calloc(CTX_NUM, sizeof(struct wd_ctx));
	if (!engine.ctx_cfg.ctxs)
		return 0;

	for (i = 0; i < CTX_NUM; i++) {
		engine.ctx_cfg.ctxs[i].ctx = wd_request_ctx(list->dev);
		if (!engine.ctx_cfg.ctxs[i].ctx)
			return 0;

		engine.ctx_cfg.ctxs[i].op_type = CTX_TYPE_ENCRYPT;
		engine.ctx_cfg.ctxs[i].ctx_mode = (i == 0) ? CTX_MODE_SYNC : CTX_MODE_ASYNC;
	}

	engine.sched.name = "sched_single";
	engine.sched.pick_next_ctx = sched_single_pick_next_ctx;
	engine.sched.poll_policy = sched_single_poll_policy;

	ret = wd_digest_init(&engine.ctx_cfg, &engine.sched);
	if (ret)
		return 0;

	async_register_poll_fn(ASYNC_TASK_DIGEST, uadk_digest_poll);

	UADK_DIGEST_DESCR(md5, md5WithRSAEncryption, MD5_DIGEST_LENGTH,
			  0, MD5_CBLOCK,
			  sizeof(EVP_MD *) + sizeof(struct digest_priv_ctx),
			  uadk_digest_init, uadk_digest_update,
			  uadk_digest_final, uadk_digest_cleanup);
	UADK_DIGEST_DESCR(sm3, sm3WithRSAEncryption, SM3_DIGEST_LENGTH,
			  0, SM3_CBLOCK,
			  sizeof(EVP_MD *) + sizeof(struct digest_priv_ctx),
			  uadk_digest_init, uadk_digest_update,
			  uadk_digest_final, uadk_digest_cleanup);
	UADK_DIGEST_DESCR(sha1, sha1WithRSAEncryption, 20,
			  EVP_MD_FLAG_FIPS, 64,
			  sizeof(EVP_MD *) + sizeof(struct digest_priv_ctx),
			  uadk_digest_init, uadk_digest_update,
			  uadk_digest_final, uadk_digest_cleanup);
	UADK_DIGEST_DESCR(sha256, sha256WithRSAEncryption, 32,
			  EVP_MD_FLAG_FIPS, 64,
			  sizeof(EVP_MD *) + sizeof(struct digest_priv_ctx),
			  uadk_digest_init, uadk_digest_update,
			  uadk_digest_final, uadk_digest_cleanup);
	UADK_DIGEST_DESCR(sha512, sha512WithRSAEncryption, 64,
			  EVP_MD_FLAG_FIPS, 128,
			  sizeof(EVP_MD *) + sizeof(struct digest_priv_ctx),
			  uadk_digest_init, uadk_digest_update,
			  uadk_digest_final, uadk_digest_cleanup);

	return ENGINE_set_digests(e, uadk_engine_digests);

out:
	for (i = 0; i < engine.ctx_cfg.ctx_num; i++)
		wd_release_ctx(engine.ctx_cfg.ctxs[i].ctx);
	free(engine.ctx_cfg.ctxs);

	return 0;
}

void uadk_destroy_digest(void)
{
	int i;

	wd_digest_uninit();
	for (i = 0; i < engine.ctx_cfg.ctx_num; i++)
		wd_release_ctx(engine.ctx_cfg.ctxs[i].ctx);
	free(engine.ctx_cfg.ctxs);

	EVP_MD_meth_free(uadk_md5);
	uadk_md5 = 0;
	EVP_MD_meth_free(uadk_sm3);
	uadk_sm3 = 0;
	EVP_MD_meth_free(uadk_sha1);
	uadk_sha1 = 0;
	EVP_MD_meth_free(uadk_sha256);
	uadk_sha256 = 0;
	EVP_MD_meth_free(uadk_sha512);
	uadk_sha512 = 0;
}
