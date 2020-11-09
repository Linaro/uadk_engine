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
#include <uadk/wd_cipher.h>
#include "uadk.h"
#include "uadk_async.h"

#define CTX_SYNC_ENC	0
#define CTX_SYNC_DEC	1
#define CTX_ASYNC_ENC	2
#define CTX_ASYNC_DEC	3
#define CTX_NUM		4

struct digest_engine {
	struct wd_ctx_config ctx_cfg;
	struct wd_sched sched;
};

static struct digest_engine engine;

struct cipher_priv_ctx {
	handle_t sess;
	struct wd_cipher_sess_setup setup;
	struct wd_cipher_req req;
};

static int cipher_nids[] = {
	NID_aes_128_cbc,
	NID_aes_192_cbc,
	NID_aes_256_cbc,
	NID_aes_128_ctr,
	NID_aes_192_ctr,
	NID_aes_256_ctr,
	NID_aes_128_xts,
	NID_aes_256_xts,
	0,
	};

static EVP_CIPHER *uadk_aes_128_cbc;
static EVP_CIPHER *uadk_aes_192_cbc;
static EVP_CIPHER *uadk_aes_256_cbc;
static EVP_CIPHER *uadk_aes_128_ctr;
static EVP_CIPHER *uadk_aes_192_ctr;
static EVP_CIPHER *uadk_aes_256_ctr;
static EVP_CIPHER *uadk_aes_128_xts;
static EVP_CIPHER *uadk_aes_256_xts;

static int uadk_engine_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
			       const int **nids, int nid)
{
	int ok = 1;

	if (!cipher) {
		*nids = cipher_nids;
		return (sizeof(cipher_nids) - 1) / sizeof(cipher_nids[0]);
	}

	switch (nid) {
	case NID_aes_128_cbc:
		*cipher = uadk_aes_128_cbc;
		break;
	case NID_aes_192_cbc:
		*cipher = uadk_aes_192_cbc;
		break;
	case NID_aes_256_cbc:
		*cipher = uadk_aes_256_cbc;
		break;
	case NID_aes_128_ctr:
		*cipher = uadk_aes_128_ctr;
		break;
	case NID_aes_192_ctr:
		*cipher = uadk_aes_192_ctr;
		break;
	case NID_aes_256_ctr:
		*cipher = uadk_aes_256_ctr;
		break;
	case NID_aes_128_xts:
		*cipher = uadk_aes_128_xts;
		break;
	case NID_aes_256_xts:
		*cipher = uadk_aes_256_xts;
		break;
	default:
		ok = 0;
		*cipher = NULL;
		break;
	}

	return ok;
}

static __u32 sched_single_pick_next_ctx(handle_t h_sched_ctx, const void *req,
					const struct sched_key *key)
{
	const struct wd_cipher_req *cipher_req = req;

	if (cipher_req->cb) {
		/* async */
		if (cipher_req->op_type == WD_CIPHER_ENCRYPTION)
			return CTX_ASYNC_ENC;
		else
			return CTX_ASYNC_DEC;
	} else {
		/* sync */
		if (cipher_req->op_type == WD_CIPHER_ENCRYPTION)
			return CTX_SYNC_ENC;
		else
			return CTX_SYNC_DEC;
	}
}

static int sched_single_poll_policy(handle_t h_sched_ctx,
				    __u32 expect, __u32 *count)
{
	return 0;
}

static int uadk_cipher_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
			    const unsigned char *iv, int enc)
{
	struct cipher_priv_ctx *priv =
		(struct cipher_priv_ctx *) EVP_CIPHER_CTX_get_cipher_data(ctx);
	int nid = EVP_CIPHER_CTX_nid(ctx);
	int ret, len;

	if (enc)
		priv->req.op_type = WD_CIPHER_ENCRYPTION;
	else
		priv->req.op_type = WD_CIPHER_DECRYPTION;

	len = EVP_CIPHER_CTX_iv_length(ctx);
	priv->req.iv_bytes = len;
	priv->req.iv = malloc(len);
	if (!priv->req.iv)
		goto out;
	if (iv)
		memcpy(priv->req.iv, iv, len);

	switch (nid) {
	case NID_aes_128_cbc:
		priv->setup.alg = WD_CIPHER_AES;
		priv->setup.mode = WD_CIPHER_CBC;
		priv->req.out_bytes = 16;
		break;
	case NID_aes_192_cbc:
		priv->setup.alg = WD_CIPHER_AES;
		priv->setup.mode = WD_CIPHER_CBC;
		priv->req.out_bytes = 64;
		break;
	case NID_aes_256_cbc:
		priv->setup.alg = WD_CIPHER_AES;
		priv->setup.mode = WD_CIPHER_CBC;
		priv->req.out_bytes = 64;
		break;
	case NID_aes_128_ctr:
		priv->setup.alg = WD_CIPHER_AES;
		priv->setup.mode = WD_CIPHER_CBC;
		priv->req.out_bytes = 64;
		break;
	case NID_aes_192_ctr:
		priv->setup.alg = WD_CIPHER_AES;
		priv->setup.mode = WD_CIPHER_CBC;
		priv->req.out_bytes = 64;
		break;
	case NID_aes_256_ctr:
		priv->setup.alg = WD_CIPHER_AES;
		priv->setup.mode = WD_CIPHER_CBC;
		priv->req.out_bytes = 64;
		break;
	case NID_aes_128_xts:
		break;
	case NID_aes_256_xts:
		break;
	default:
		goto out;
	}

	priv->sess = wd_cipher_alloc_sess(&priv->setup);
	if (!priv->sess)
		goto out;

	ret = wd_cipher_set_key(priv->sess, key, EVP_CIPHER_CTX_key_length(ctx));
	if (ret) {
		ret = 0;
		goto out;
	}

	return 1;

out:
	if (priv->req.iv)
		free(priv->req.iv);

	return 0;
}

static int uadk_cipher_cleanup(EVP_CIPHER_CTX *ctx)
{
	struct cipher_priv_ctx *priv =
		(struct cipher_priv_ctx *) EVP_CIPHER_CTX_get_cipher_data(ctx);

	if (priv->sess)
		wd_cipher_free_sess(priv->sess);

	if (priv->req.iv)
		free(priv->req.iv);

	return 1;
}

static void async_cb(struct wd_cipher_req *req, void *data)
{
}

static int uadk_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
			  const unsigned char *in, size_t inlen)
{
	struct cipher_priv_ctx *priv =
		(struct cipher_priv_ctx *) EVP_CIPHER_CTX_get_cipher_data(ctx);
	struct async_op op;
	int ret;

	priv->req.src = in;
	priv->req.in_bytes = inlen;
	priv->req.dst = out;
	priv->req.out_buf_bytes = inlen;

	async_setup_async_event_notification(&op);
	if (op.job == NULL) {
		/* sync */
		ret = wd_do_cipher_sync(priv->sess, &priv->req);
		if (ret)
			return 0;
	} else {
		/* async */
		priv->req.cb = (void *)async_cb;
		priv->req.cb_param = priv;
		do {
			ret = wd_do_cipher_async(priv->sess, &priv->req);
			if (ret < 0 && ret != -EBUSY)
				goto err;
		} while (ret == -EBUSY);

		ret = async_pause_job(priv, &op, ASYNC_TASK_CIPHER);
		if (!ret)
			goto err;
	}

	return 1;
err:
	async_clear_async_event_notification();
	return 0;
}

int uadk_cipher_poll(void *ctx)
{
	struct cipher_priv_ctx *priv = (struct cipher_priv_ctx *) ctx;
	int ret = 0;
	int expt = 1;
	int recv;
	int idx;

	if (priv->req.op_type == WD_CIPHER_ENCRYPTION)
		idx = CTX_ASYNC_ENC;
	else
		idx = CTX_ASYNC_DEC;

	do {
		ret = wd_cipher_poll_ctx(idx, expt, &recv);
		if (recv >= expt)
			return 0;
		else if (ret < 0 && ret != -EAGAIN)
			return ret;
	} while (ret == -EAGAIN);

	return ret;
}

#define UADK_CIPHER_DESCR(name, block_size, key_size, iv_len, flags, ctx_size,\
	init, cipher, cleanup, set_params, get_params)\
do { \
	uadk_##name = EVP_CIPHER_meth_new(NID_##name, block_size, key_size);\
	if (uadk_##name == 0 ||\
		!EVP_CIPHER_meth_set_iv_length(uadk_##name, iv_len) ||\
		!EVP_CIPHER_meth_set_flags(uadk_##name, flags) ||\
		!EVP_CIPHER_meth_set_impl_ctx_size(uadk_##name, ctx_size) ||\
		!EVP_CIPHER_meth_set_init(uadk_##name, init) ||\
		!EVP_CIPHER_meth_set_do_cipher(uadk_##name, cipher) ||\
		!EVP_CIPHER_meth_set_cleanup(uadk_##name, cleanup) ||\
		!EVP_CIPHER_meth_set_set_asn1_params(uadk_##name, set_params) ||\
		!EVP_CIPHER_meth_set_get_asn1_params(uadk_##name, get_params))\
		return 0;\
} while (0)

int uadk_bind_cipher(ENGINE *e, struct uacce_dev_list *list)
{
	int ret, i;

	memset(&engine.ctx_cfg, 0, sizeof(struct wd_ctx_config));
	engine.ctx_cfg.ctx_num = CTX_NUM;
	engine.ctx_cfg.ctxs = calloc(CTX_NUM, sizeof(struct wd_ctx));
	if (!engine.ctx_cfg.ctxs)
		return 0;

	for (i = 0; i < CTX_NUM; i++) {
		engine.ctx_cfg.ctxs[i].ctx = wd_request_ctx(list->dev);
		if (!engine.ctx_cfg.ctxs[i].ctx)
			goto out;
	}

	engine.ctx_cfg.ctxs[CTX_SYNC_ENC].op_type = CTX_TYPE_ENCRYPT;
	engine.ctx_cfg.ctxs[CTX_SYNC_DEC].op_type = CTX_TYPE_DECRYPT;
	engine.ctx_cfg.ctxs[CTX_ASYNC_ENC].op_type = CTX_TYPE_ENCRYPT;
	engine.ctx_cfg.ctxs[CTX_ASYNC_DEC].op_type = CTX_TYPE_DECRYPT;
	engine.ctx_cfg.ctxs[CTX_SYNC_ENC].ctx_mode = CTX_MODE_SYNC;
	engine.ctx_cfg.ctxs[CTX_SYNC_DEC].ctx_mode = CTX_MODE_SYNC;
	engine.ctx_cfg.ctxs[CTX_ASYNC_ENC].ctx_mode = CTX_MODE_ASYNC;
	engine.ctx_cfg.ctxs[CTX_ASYNC_DEC].ctx_mode = CTX_MODE_ASYNC;

	engine.sched.name = "sched_single";
	engine.sched.pick_next_ctx = sched_single_pick_next_ctx;
	engine.sched.poll_policy = sched_single_poll_policy;

	ret = wd_cipher_init(&engine.ctx_cfg, &engine.sched);
	if (ret)
		goto out;

	async_register_poll_fn(ASYNC_TASK_CIPHER, uadk_cipher_poll);

	UADK_CIPHER_DESCR(aes_128_cbc, 16, 16, 16, EVP_CIPH_CBC_MODE,
			  sizeof(struct cipher_priv_ctx), uadk_cipher_init,
			  uadk_do_cipher, uadk_cipher_cleanup,
			  EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv);
	UADK_CIPHER_DESCR(aes_192_cbc, 16, 24, 16, EVP_CIPH_CBC_MODE,
			  sizeof(struct cipher_priv_ctx), uadk_cipher_init,
			  uadk_do_cipher, uadk_cipher_cleanup,
			  EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv);
	UADK_CIPHER_DESCR(aes_256_cbc, 16, 32, 16, EVP_CIPH_CBC_MODE,
			  sizeof(struct cipher_priv_ctx), uadk_cipher_init,
			  uadk_do_cipher, uadk_cipher_cleanup,
			  EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv);
	UADK_CIPHER_DESCR(aes_128_ctr, 1, 16, 16, EVP_CIPH_CTR_MODE,
			  sizeof(struct cipher_priv_ctx), uadk_cipher_init,
			  uadk_do_cipher, uadk_cipher_cleanup,
			  EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv);
	UADK_CIPHER_DESCR(aes_192_ctr, 1, 24, 16, EVP_CIPH_CTR_MODE,
			  sizeof(struct cipher_priv_ctx), uadk_cipher_init,
			  uadk_do_cipher, uadk_cipher_cleanup,
			  EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv);
	UADK_CIPHER_DESCR(aes_256_ctr, 1, 32, 16, EVP_CIPH_CTR_MODE,
			  sizeof(struct cipher_priv_ctx), uadk_cipher_init,
			  uadk_do_cipher, uadk_cipher_cleanup,
			  EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv);
	UADK_CIPHER_DESCR(aes_128_xts, 1, 32, 16, EVP_CIPH_XTS_MODE | EVP_CIPH_CUSTOM_IV,
			  sizeof(struct cipher_priv_ctx), uadk_cipher_init,
			  uadk_do_cipher, uadk_cipher_cleanup,
			  EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv);
	UADK_CIPHER_DESCR(aes_256_xts, 1, 64, 16, EVP_CIPH_XTS_MODE | EVP_CIPH_CUSTOM_IV,
			  sizeof(struct cipher_priv_ctx), uadk_cipher_init,
			  uadk_do_cipher, uadk_cipher_cleanup,
			  EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv);

	return ENGINE_set_ciphers(e, uadk_engine_ciphers);

out:
	for (i = 0; i < engine.ctx_cfg.ctx_num; i++)
		wd_release_ctx(engine.ctx_cfg.ctxs[i].ctx);
	free(engine.ctx_cfg.ctxs);
	return 0;
}

void uadk_destroy_cipher(void)
{
	int i;

	wd_cipher_uninit();
	for (i = 0; i < engine.ctx_cfg.ctx_num; i++)
		wd_release_ctx(engine.ctx_cfg.ctxs[i].ctx);
	free(engine.ctx_cfg.ctxs);

	EVP_CIPHER_meth_free(uadk_aes_128_cbc);
	uadk_aes_128_cbc = 0;
	EVP_CIPHER_meth_free(uadk_aes_192_cbc);
	uadk_aes_192_cbc = 0;
	EVP_CIPHER_meth_free(uadk_aes_256_cbc);
	uadk_aes_256_cbc = 0;
	EVP_CIPHER_meth_free(uadk_aes_128_ctr);
	uadk_aes_128_ctr = 0;
	EVP_CIPHER_meth_free(uadk_aes_192_ctr);
	uadk_aes_192_ctr = 0;
	EVP_CIPHER_meth_free(uadk_aes_256_ctr);
	uadk_aes_256_ctr = 0;
	EVP_CIPHER_meth_free(uadk_aes_128_xts);
	uadk_aes_128_xts = 0;
	EVP_CIPHER_meth_free(uadk_aes_256_xts);
	uadk_aes_256_xts = 0;
}
