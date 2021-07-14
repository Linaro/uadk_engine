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
	int pid;
};

static struct digest_engine engine;

#define IV_LEN 16

struct cipher_priv_ctx {
	handle_t sess;
	struct wd_cipher_sess_setup setup;
	struct wd_cipher_req req;
	unsigned char iv[IV_LEN];
};

static int platform;

static int cipher_920_nids[] = {
	NID_aes_128_cbc,
	NID_aes_192_cbc,
	NID_aes_256_cbc,
	NID_aes_128_ctr,
	NID_aes_192_ctr,
	NID_aes_256_ctr,
	NID_aes_128_ecb,
	NID_aes_192_ecb,
	NID_aes_256_ecb,
	NID_aes_128_xts,
	NID_aes_256_xts,
	NID_sm4_cbc,
	NID_sm4_ecb,
	NID_des_ede3_cbc,
	NID_des_ede3_ecb,
	0,
};

static int cipher_930_nids[] = {
	NID_aes_128_cbc,
	NID_aes_192_cbc,
	NID_aes_256_cbc,
	NID_aes_128_ctr,
	NID_aes_192_ctr,
	NID_aes_256_ctr,
	NID_aes_128_ecb,
	NID_aes_192_ecb,
	NID_aes_256_ecb,
	NID_aes_128_xts,
	NID_aes_256_xts,
	NID_sm4_cbc,
	NID_sm4_ecb,
	NID_des_ede3_cbc,
	NID_des_ede3_ecb,
	NID_aes_128_cfb128,
	NID_aes_192_cfb128,
	NID_aes_256_cfb128,
	NID_aes_128_ofb128,
	NID_aes_192_ofb128,
	NID_aes_256_ofb128,
	NID_sm4_cfb128,
	NID_sm4_ofb128,
	NID_sm4_ctr,
	0,
};

static EVP_CIPHER *uadk_aes_128_cbc;
static EVP_CIPHER *uadk_aes_192_cbc;
static EVP_CIPHER *uadk_aes_256_cbc;
static EVP_CIPHER *uadk_aes_128_ctr;
static EVP_CIPHER *uadk_aes_192_ctr;
static EVP_CIPHER *uadk_aes_256_ctr;
static EVP_CIPHER *uadk_aes_128_ecb;
static EVP_CIPHER *uadk_aes_192_ecb;
static EVP_CIPHER *uadk_aes_256_ecb;
static EVP_CIPHER *uadk_aes_128_xts;
static EVP_CIPHER *uadk_aes_256_xts;
static EVP_CIPHER *uadk_sm4_cbc;
static EVP_CIPHER *uadk_sm4_ecb;
static EVP_CIPHER *uadk_des_ede3_cbc;
static EVP_CIPHER *uadk_des_ede3_ecb;
static EVP_CIPHER *uadk_aes_128_cfb128;
static EVP_CIPHER *uadk_aes_192_cfb128;
static EVP_CIPHER *uadk_aes_256_cfb128;
static EVP_CIPHER *uadk_aes_128_ofb128;
static EVP_CIPHER *uadk_aes_192_ofb128;
static EVP_CIPHER *uadk_aes_256_ofb128;
static EVP_CIPHER *uadk_sm4_cfb128;
static EVP_CIPHER *uadk_sm4_ofb128;
static EVP_CIPHER *uadk_sm4_ctr;

static int uadk_engine_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
			       const int **nids, int nid)
{
	int ok = 1;
	int size = 0;
	int *cipher_nids;
	int i;

	if (platform == KUNPENG920) {
		size = (sizeof(cipher_920_nids) - 1) / sizeof(int);
		cipher_nids = cipher_920_nids;
	} else {
		size = (sizeof(cipher_930_nids) - 1) / sizeof(int);
		cipher_nids = cipher_930_nids;
	}

	if (!cipher) {
		*nids = cipher_nids;
		return size;
	}

	for (i = 0; i < size; i++) {
		if (nid == cipher_nids[i])
			break;
	}

	if (i == size) {
		*cipher = NULL;
		return 0;
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
	case NID_aes_128_ecb:
		*cipher = uadk_aes_128_ecb;
		break;
	case NID_aes_192_ecb:
		*cipher = uadk_aes_192_ecb;
		break;
	case NID_aes_256_ecb:
		*cipher = uadk_aes_256_ecb;
		break;
	case NID_aes_128_xts:
		*cipher = uadk_aes_128_xts;
		break;
	case NID_aes_256_xts:
		*cipher = uadk_aes_256_xts;
		break;
	case NID_sm4_cbc:
		*cipher = uadk_sm4_cbc;
		break;
	case NID_sm4_ecb:
		*cipher = uadk_sm4_ecb;
		break;
	case NID_des_ede3_cbc:
		*cipher = uadk_des_ede3_cbc;
		break;
	case NID_des_ede3_ecb:
		*cipher = uadk_des_ede3_ecb;
		break;
	case NID_aes_128_ofb128:
		*cipher = uadk_aes_128_ofb128;
		break;
	case NID_aes_192_ofb128:
		*cipher = uadk_aes_192_ofb128;
		break;
	case NID_aes_256_ofb128:
		*cipher = uadk_aes_256_ofb128;
		break;
	case NID_aes_128_cfb128:
		*cipher = uadk_aes_128_cfb128;
		break;
	case NID_aes_192_cfb128:
		*cipher = uadk_aes_192_cfb128;
		break;
	case NID_aes_256_cfb128:
		*cipher = uadk_aes_256_cfb128;
		break;
	case NID_sm4_ofb128:
		*cipher = uadk_sm4_ofb128;
		break;
	case NID_sm4_cfb128:
		*cipher = uadk_sm4_cfb128;
		break;
	case NID_sm4_ctr:
		*cipher = uadk_sm4_ctr;
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

int uadk_cipher_poll(void *ctx)
{
	struct cipher_priv_ctx *priv = (struct cipher_priv_ctx *) ctx;
	int ret = 0;
	int expt = 1;
	__u32 recv;
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

static int uadk_init_cipher(void)
{
	struct uacce_dev *dev;
	int ret;
	int i;

	if (engine.pid != getpid()) {
		dev = wd_get_accel_dev("cipher");
		if (dev) {
			memset(&engine.ctx_cfg, 0, sizeof(struct wd_ctx_config));
			engine.ctx_cfg.ctx_num = CTX_NUM;
			engine.ctx_cfg.ctxs = calloc(CTX_NUM, sizeof(struct wd_ctx));
			if (!engine.ctx_cfg.ctxs)
				return 0;

			for (i = 0; i < CTX_NUM; i++) {
				engine.ctx_cfg.ctxs[i].ctx = wd_request_ctx(dev);
				if (!engine.ctx_cfg.ctxs[i].ctx)
					return 0;
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
				return 0;

			async_register_poll_fn(ASYNC_TASK_CIPHER, uadk_cipher_poll);
			free(dev);
		}
		engine.pid = getpid();
	}

	return 1;
}

static int uadk_cipher_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
			    const unsigned char *iv, int enc)
{
	struct cipher_priv_ctx *priv =
		(struct cipher_priv_ctx *) EVP_CIPHER_CTX_get_cipher_data(ctx);
	int nid, ret;

	if (unlikely(key == NULL)) {
		fprintf(stderr, "set key is NULL");
		return 0;
	}

	nid = EVP_CIPHER_CTX_nid(ctx);

	if (enc)
		priv->req.op_type = WD_CIPHER_ENCRYPTION;
	else
		priv->req.op_type = WD_CIPHER_DECRYPTION;

	if (iv)
		memcpy(priv->iv, iv, EVP_CIPHER_CTX_iv_length(ctx));

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
		priv->setup.mode = WD_CIPHER_CTR;
		priv->req.out_bytes = 64;
		break;
	case NID_aes_192_ctr:
		priv->setup.alg = WD_CIPHER_AES;
		priv->setup.mode = WD_CIPHER_CTR;
		priv->req.out_bytes = 64;
		break;
	case NID_aes_256_ctr:
		priv->setup.alg = WD_CIPHER_AES;
		priv->setup.mode = WD_CIPHER_CTR;
		priv->req.out_bytes = 64;
		break;
	case NID_aes_128_ecb:
		priv->setup.alg = WD_CIPHER_AES;
		priv->setup.mode = WD_CIPHER_ECB;
		priv->req.out_bytes = 16;
		break;
	case NID_aes_192_ecb:
		priv->setup.alg = WD_CIPHER_AES;
		priv->setup.mode = WD_CIPHER_ECB;
		priv->req.out_bytes = 16;
		break;
	case NID_aes_256_ecb:
		priv->setup.alg = WD_CIPHER_AES;
		priv->setup.mode = WD_CIPHER_ECB;
		priv->req.out_bytes = 16;
		break;
	case NID_aes_128_xts:
		priv->setup.alg = WD_CIPHER_AES;
		priv->setup.mode = WD_CIPHER_XTS;
		priv->req.out_bytes = 32;
		break;
	case NID_aes_256_xts:
		priv->setup.alg = WD_CIPHER_AES;
		priv->setup.mode = WD_CIPHER_XTS;
		priv->req.out_bytes = 512;
		break;
	case NID_sm4_cbc:
		priv->setup.alg = WD_CIPHER_SM4;
		priv->setup.mode = WD_CIPHER_CBC;
		priv->req.out_bytes = 16;
		break;
	case NID_sm4_ecb:
		priv->setup.alg = WD_CIPHER_SM4;
		priv->setup.mode = WD_CIPHER_ECB;
		priv->req.out_bytes = 16;
		break;
	case NID_des_ede3_cbc:
		priv->setup.alg = WD_CIPHER_3DES;
		priv->setup.mode = WD_CIPHER_CBC;
		priv->req.out_bytes = 16;
		break;
	case NID_des_ede3_ecb:
		priv->setup.alg = WD_CIPHER_3DES;
		priv->setup.mode = WD_CIPHER_ECB;
		priv->req.out_bytes = 16;
		break;
	case NID_aes_128_ofb128:
		priv->setup.alg = WD_CIPHER_AES;
		priv->setup.mode = WD_CIPHER_OFB;
		priv->req.out_bytes = 16;
		break;
	case NID_aes_192_ofb128:
		priv->setup.alg = WD_CIPHER_AES;
		priv->setup.mode = WD_CIPHER_OFB;
		priv->req.out_bytes = 16;
		break;
	case NID_aes_256_ofb128:
		priv->setup.alg = WD_CIPHER_AES;
		priv->setup.mode = WD_CIPHER_OFB;
		priv->req.out_bytes = 16;
		break;
	case NID_aes_128_cfb128:
		priv->setup.alg = WD_CIPHER_AES;
		priv->setup.mode = WD_CIPHER_CFB;
		priv->req.out_bytes = 16;
		break;
	case NID_sm4_ofb128:
		priv->setup.alg = WD_CIPHER_SM4;
		priv->setup.mode = WD_CIPHER_OFB;
		priv->req.out_bytes = 16;
		break;
	case NID_sm4_cfb128:
		priv->setup.alg = WD_CIPHER_SM4;
		priv->setup.mode = WD_CIPHER_CFB;
		priv->req.out_bytes = 16;
		break;
	case NID_sm4_ctr:
		priv->setup.alg = WD_CIPHER_SM4;
		priv->setup.mode = WD_CIPHER_CTR;
		priv->req.out_bytes = 16;
		break;
	default:
		return 0;
	}

	priv->sess = wd_cipher_alloc_sess(&priv->setup);
	if (!priv->sess)
		return 0;

	if (key) {
		ret = wd_cipher_set_key(priv->sess, key, EVP_CIPHER_CTX_key_length(ctx));
		if (ret) {
			wd_cipher_free_sess(priv->sess);
			return 0;
		}
	}

	return 1;
}

static int uadk_cipher_cleanup(EVP_CIPHER_CTX *ctx)
{
	struct cipher_priv_ctx *priv =
		(struct cipher_priv_ctx *) EVP_CIPHER_CTX_get_cipher_data(ctx);

	if (priv->sess)
		wd_cipher_free_sess(priv->sess);

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

	if (unlikely(inlen == 0)) {
		fprintf(stderr, "input length is zero.");
		return 0;
	}

	uadk_init_cipher();

	priv->req.iv_bytes = EVP_CIPHER_CTX_iv_length(ctx);
	priv->req.iv = priv->iv;
	priv->req.src = (unsigned char *)in;
	priv->req.in_bytes = inlen;
	priv->req.dst = out;
	priv->req.out_buf_bytes = inlen;

	async_setup_async_event_notification(&op);
	if (op.job == NULL) {
		/* sync */
		ret = wd_do_cipher_sync(priv->sess, &priv->req);
		if (ret)
			goto out_notify;
	} else {
		/* async */
		priv->req.cb = (void *)async_cb;
		priv->req.cb_param = priv;
		do {
			ret = wd_do_cipher_async(priv->sess, &priv->req);
			if (ret < 0 && ret != -EBUSY)
				goto out_notify;
		} while (ret == -EBUSY);

		ret = async_pause_job(priv, &op, ASYNC_TASK_CIPHER);
		if (!ret)
			goto out_notify;
	}

	return 1;

out_notify:
	async_clear_async_event_notification();
	return 0;
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

int uadk_bind_cipher(ENGINE *e)
{
	struct uacce_dev *dev;

	dev = wd_get_accel_dev("cipher");
	if (dev == NULL)
		return 0;

	if (!strcmp(dev->api, "hisi_qm_v2"))
		platform = KUNPENG920;
	else
		platform = KUNPENG930;
	free(dev);

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
	UADK_CIPHER_DESCR(aes_128_ctr, 16, 16, 16, EVP_CIPH_CTR_MODE,
			  sizeof(struct cipher_priv_ctx), uadk_cipher_init,
			  uadk_do_cipher, uadk_cipher_cleanup,
			  EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv);
	UADK_CIPHER_DESCR(aes_192_ctr, 16, 24, 16, EVP_CIPH_CTR_MODE,
			  sizeof(struct cipher_priv_ctx), uadk_cipher_init,
			  uadk_do_cipher, uadk_cipher_cleanup,
			  EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv);
	UADK_CIPHER_DESCR(aes_256_ctr, 16, 32, 16, EVP_CIPH_CTR_MODE,
			  sizeof(struct cipher_priv_ctx), uadk_cipher_init,
			  uadk_do_cipher, uadk_cipher_cleanup,
			  EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv);
	UADK_CIPHER_DESCR(aes_128_ecb, 16, 16, 16, EVP_CIPH_ECB_MODE,
			  sizeof(struct cipher_priv_ctx), uadk_cipher_init,
			  uadk_do_cipher, uadk_cipher_cleanup,
			  EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv);
	UADK_CIPHER_DESCR(aes_192_ecb, 16, 24, 16, EVP_CIPH_ECB_MODE,
			  sizeof(struct cipher_priv_ctx), uadk_cipher_init,
			  uadk_do_cipher, uadk_cipher_cleanup,
			  EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv);
	UADK_CIPHER_DESCR(aes_256_ecb, 16, 32, 16, EVP_CIPH_ECB_MODE,
			  sizeof(struct cipher_priv_ctx), uadk_cipher_init,
			  uadk_do_cipher, uadk_cipher_cleanup,
			  EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv);
	UADK_CIPHER_DESCR(aes_128_xts, 16, 32, 16, EVP_CIPH_XTS_MODE | EVP_CIPH_CUSTOM_IV,
			  sizeof(struct cipher_priv_ctx), uadk_cipher_init,
			  uadk_do_cipher, uadk_cipher_cleanup,
			  EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv);
	UADK_CIPHER_DESCR(aes_256_xts, 16, 64, 16, EVP_CIPH_XTS_MODE | EVP_CIPH_CUSTOM_IV,
			  sizeof(struct cipher_priv_ctx), uadk_cipher_init,
			  uadk_do_cipher, uadk_cipher_cleanup,
			  EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv);
	UADK_CIPHER_DESCR(sm4_cbc, 16, 16, 16, EVP_CIPH_CBC_MODE,
			  sizeof(struct cipher_priv_ctx), uadk_cipher_init,
			  uadk_do_cipher, uadk_cipher_cleanup,
			  EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv);
	UADK_CIPHER_DESCR(sm4_ecb, 16, 16, 16, EVP_CIPH_ECB_MODE,
			  sizeof(struct cipher_priv_ctx), uadk_cipher_init,
			  uadk_do_cipher, uadk_cipher_cleanup,
			  EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv);
	UADK_CIPHER_DESCR(des_ede3_cbc, 16, 16, 16, EVP_CIPH_CBC_MODE,
			  sizeof(struct cipher_priv_ctx), uadk_cipher_init,
			  uadk_do_cipher, uadk_cipher_cleanup,
			  EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv);
	UADK_CIPHER_DESCR(des_ede3_ecb, 16, 16, 16, EVP_CIPH_ECB_MODE,
			  sizeof(struct cipher_priv_ctx), uadk_cipher_init,
			  uadk_do_cipher, uadk_cipher_cleanup,
			  EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv);
	UADK_CIPHER_DESCR(aes_128_ofb128, 16, 16, 16, EVP_CIPH_OFB_MODE,
			  sizeof(struct cipher_priv_ctx), uadk_cipher_init,
			  uadk_do_cipher, uadk_cipher_cleanup,
			  EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv);
	UADK_CIPHER_DESCR(aes_192_ofb128, 16, 24, 16, EVP_CIPH_OFB_MODE,
			  sizeof(struct cipher_priv_ctx), uadk_cipher_init,
			  uadk_do_cipher, uadk_cipher_cleanup,
			  EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv);
	UADK_CIPHER_DESCR(aes_256_ofb128, 16, 32, 16, EVP_CIPH_OFB_MODE,
			  sizeof(struct cipher_priv_ctx), uadk_cipher_init,
			  uadk_do_cipher, uadk_cipher_cleanup,
			  EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv);
	UADK_CIPHER_DESCR(aes_128_cfb128, 16, 16, 16, EVP_CIPH_CFB_MODE,
			  sizeof(struct cipher_priv_ctx), uadk_cipher_init,
			  uadk_do_cipher, uadk_cipher_cleanup,
			  EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv);
	UADK_CIPHER_DESCR(aes_192_cfb128, 16, 24, 16, EVP_CIPH_CFB_MODE,
			  sizeof(struct cipher_priv_ctx), uadk_cipher_init,
			  uadk_do_cipher, uadk_cipher_cleanup,
			  EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv);
	UADK_CIPHER_DESCR(aes_256_cfb128, 16, 32, 16, EVP_CIPH_CFB_MODE,
			  sizeof(struct cipher_priv_ctx), uadk_cipher_init,
			  uadk_do_cipher, uadk_cipher_cleanup,
			  EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv);
	UADK_CIPHER_DESCR(sm4_ofb128, 16, 16, 16, EVP_CIPH_OFB_MODE,
			  sizeof(struct cipher_priv_ctx), uadk_cipher_init,
			  uadk_do_cipher, uadk_cipher_cleanup,
			  EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv);
	UADK_CIPHER_DESCR(sm4_cfb128, 16, 16, 16, EVP_CIPH_OFB_MODE,
			  sizeof(struct cipher_priv_ctx), uadk_cipher_init,
			  uadk_do_cipher, uadk_cipher_cleanup,
			  EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv);
	UADK_CIPHER_DESCR(sm4_ctr, 16, 16, 16, EVP_CIPH_CTR_MODE,
			  sizeof(struct cipher_priv_ctx), uadk_cipher_init,
			  uadk_do_cipher, uadk_cipher_cleanup,
			  EVP_CIPHER_set_asn1_iv, EVP_CIPHER_get_asn1_iv);

	return ENGINE_set_ciphers(e, uadk_engine_ciphers);
}

void uadk_destroy_cipher(void)
{
	int i;

	if (engine.pid == getpid()) {
		wd_cipher_uninit();
		for (i = 0; i < engine.ctx_cfg.ctx_num; i++)
			wd_release_ctx(engine.ctx_cfg.ctxs[i].ctx);
		free(engine.ctx_cfg.ctxs);
	}

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
	EVP_CIPHER_meth_free(uadk_aes_128_ecb);
	uadk_aes_128_ecb = 0;
	EVP_CIPHER_meth_free(uadk_aes_192_ecb);
	uadk_aes_192_ecb = 0;
	EVP_CIPHER_meth_free(uadk_aes_256_ecb);
	uadk_aes_256_ecb = 0;
	EVP_CIPHER_meth_free(uadk_aes_128_xts);
	uadk_aes_128_xts = 0;
	EVP_CIPHER_meth_free(uadk_aes_256_xts);
	uadk_aes_256_xts = 0;
	EVP_CIPHER_meth_free(uadk_sm4_cbc);
	uadk_sm4_cbc = 0;
	EVP_CIPHER_meth_free(uadk_sm4_ecb);
	uadk_sm4_ecb = 0;
	EVP_CIPHER_meth_free(uadk_des_ede3_cbc);
	uadk_des_ede3_cbc = 0;
	EVP_CIPHER_meth_free(uadk_des_ede3_ecb);
	uadk_des_ede3_ecb = 0;
	EVP_CIPHER_meth_free(uadk_aes_128_ofb128);
	uadk_aes_128_ofb128 = 0;
	EVP_CIPHER_meth_free(uadk_aes_192_ofb128);
	uadk_aes_192_ofb128 = 0;
	EVP_CIPHER_meth_free(uadk_aes_256_ofb128);
	uadk_aes_256_ofb128 = 0;
	EVP_CIPHER_meth_free(uadk_aes_128_cfb128);
	uadk_aes_128_cfb128 = 0;
	EVP_CIPHER_meth_free(uadk_aes_192_cfb128);
	uadk_aes_192_cfb128 = 0;
	EVP_CIPHER_meth_free(uadk_aes_256_cfb128);
	uadk_aes_256_cfb128 = 0;
	EVP_CIPHER_meth_free(uadk_sm4_cfb128);
	uadk_sm4_cfb128 = 0;
	EVP_CIPHER_meth_free(uadk_sm4_ofb128);
	uadk_sm4_ofb128 = 0;
	EVP_CIPHER_meth_free(uadk_sm4_ctr);
	uadk_sm4_ctr = 0;
}
