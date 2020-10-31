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

struct cipher_priv_ctx {
	handle_t sess;
	struct wd_cipher_sess_setup setup;
	struct wd_cipher_req req;
	struct wd_ctx_config ctx_cfg;
	struct wd_sched sched;
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
	return h_sched_ctx;
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
	struct uacce_dev_list *list;
	int nid = EVP_CIPHER_CTX_nid(ctx);
	int ret, len;

	list = wd_get_accel_list("cipher");
	if (!list)
		return 0;

	memset(&priv->ctx_cfg, 0, sizeof(struct wd_ctx_config));
	priv->ctx_cfg.ctx_num = 1;
	priv->ctx_cfg.ctxs = calloc(1, sizeof(struct wd_ctx));
	if (!priv->ctx_cfg.ctxs)
		return 0;

	/* Just use first found dev to test here */
	priv->ctx_cfg.ctxs[0].ctx = wd_request_ctx(list->dev);
	if (!priv->ctx_cfg.ctxs[0].ctx)
		goto out;

	if (enc)
		priv->ctx_cfg.ctxs[0].op_type = CTX_TYPE_ENCRYPT;
	else
		priv->ctx_cfg.ctxs[0].op_type = CTX_TYPE_DECRYPT;

	priv->ctx_cfg.ctxs[0].ctx_mode = CTX_MODE_SYNC;

	priv->sched.name = "sched_single";
	priv->sched.pick_next_ctx = sched_single_pick_next_ctx;
	priv->sched.poll_policy = sched_single_poll_policy;

	/*cipher init*/
	ret = wd_cipher_init(&priv->ctx_cfg, &priv->sched);
	if (ret)
		goto out;

	if (enc)
		priv->req.op_type = WD_CIPHER_ENCRYPTION;
	else
		priv->req.op_type = WD_CIPHER_DECRYPTION;

	len = EVP_CIPHER_CTX_iv_length(ctx);
	priv->req.iv = malloc(len);
	if (!priv->req.iv)
		goto out;
	memcpy(priv->req.iv, iv, len);
	priv->req.iv_bytes = len;

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

	wd_free_list_accels(list);

	return 1;

out:
	if (priv->req.iv)
		free(priv->req.iv);
	wd_free_list_accels(list);
	free(priv->ctx_cfg.ctxs);

	return 0;
}

static int uadk_cipher_cleanup(EVP_CIPHER_CTX *ctx)
{
	struct cipher_priv_ctx *priv =
		(struct cipher_priv_ctx *) EVP_CIPHER_CTX_get_cipher_data(ctx);
	int i;

	if (priv->sess)
		wd_cipher_free_sess(priv->sess);

	if (priv->req.iv)
		free(priv->req.iv);

	wd_cipher_uninit();
	for (i = 0; i < priv->ctx_cfg.ctx_num; i++)
		wd_release_ctx(priv->ctx_cfg.ctxs[i].ctx);
	free(priv->ctx_cfg.ctxs);
	return 1;
}

static int uadk_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
			  const unsigned char *in, size_t inlen)
{
	struct cipher_priv_ctx *priv =
		(struct cipher_priv_ctx *) EVP_CIPHER_CTX_get_cipher_data(ctx);
	int ret;

	priv->req.src = in;
	priv->req.in_bytes = inlen;
	priv->req.dst = out;
	priv->req.out_buf_bytes = inlen;

	ret = wd_do_cipher_sync(priv->sess, &priv->req);
	if (ret)
		return 0;
	return 1;
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
}

void uadk_destroy_cipher(void)
{
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
