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
#include <uadk/wd_cipher.h>
#include <uadk/wd_sched.h>
#include "uadk.h"
#include "uadk_async.h"
#include "uadk_prov.h"
#include "uadk_utils.h"

#define UADK_DO_HW		(-0xF0)
#define CTX_SYNC_ENC		0
#define CTX_SYNC_DEC		1
#define CTX_ASYNC_ENC		2
#define CTX_ASYNC_DEC		3
#define CTX_NUM			4
#define IV_LEN			16
#define MAX_KEY_LEN		64
#define ALG_NAME_SIZE		128
#define GENERIC_BLOCK_SIZE	16

/* Internal flags that can be queried */
#define PROV_CIPHER_FLAG_AEAD			0x0001
#define PROV_CIPHER_FLAG_CUSTOM_IV		0x0002
#define PROV_CIPHER_FLAG_CTS			0x0004
#define PROV_CIPHER_FLAG_TLS1_MULTIBLOCK	0x0008
#define PROV_CIPHER_FLAG_RAND_KEY		0x0010

#define UADK_CIPHER_DEF_CTXS	2
#define UADK_CIPHER_OP_NUM	1

/* OSSL_CIPHER_PARAM_CTS_MODE Values */
# define OSSL_CIPHER_CTS_MODE_CS1	"CS1"
# define OSSL_CIPHER_CTS_MODE_CS2	"CS2"
# define OSSL_CIPHER_CTS_MODE_CS3	"CS3"

# define UADK_CIPHER_CTS_CS1_NAME	"cbc-cs1(aes)"
# define UADK_CIPHER_CTS_CS2_NAME	"cbc-cs2(aes)"
# define UADK_CIPHER_CTS_CS3_NAME	"cbc-cs3(aes)"

enum uadk_cipher_alg_id {
	ID_aes_128_ecb,
	ID_aes_192_ecb,
	ID_aes_256_ecb,
	ID_aes_128_cbc,
	ID_aes_192_cbc,
	ID_aes_256_cbc,
	ID_aes_128_cts,
	ID_aes_192_cts,
	ID_aes_256_cts,
	ID_aes_128_xts,
	ID_aes_256_xts,
	ID_aes_128_ctr,
	ID_aes_192_ctr,
	ID_aes_256_ctr,
	ID_aes_128_ofb128,
	ID_aes_192_ofb128,
	ID_aes_256_ofb128,
	ID_aes_128_cfb128,
	ID_aes_192_cfb128,
	ID_aes_256_cfb128,
	ID_sm4_cbc,
	ID_sm4_ofb128,
	ID_sm4_cfb128,
	ID_sm4_ecb,
	ID_sm4_ctr,
	ID_des_ede3_cbc,
	ID_des_ede3_ecb,
};

/* Internal flags that are only used within the provider */
#define PROV_CIPHER_FLAG_VARIABLE_LENGTH	0x0100
#define PROV_CIPHER_FLAG_INVERSE_CIPHER		0x0200

#define SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT	192

struct cipher_prov {
	int pid;
};
static struct cipher_prov prov;
static enum HW_SYMM_ENC_DEV g_hw_symm_enc_dev;
static pthread_mutex_t cipher_mutex = PTHREAD_MUTEX_INITIALIZER;

struct cipher_priv_ctx {
	int nid;
	handle_t sess;
	struct wd_cipher_sess_setup setup;
	struct wd_cipher_req req;
	unsigned char iv[IV_LEN];
	/* Buffer of partial blocks processed via update calls */
	unsigned char buf[GENERIC_BLOCK_SIZE];
	unsigned char key[MAX_KEY_LEN];
	int switch_flag;
	EVP_CIPHER_CTX *sw_ctx;
	EVP_CIPHER *sw_cipher;
	/* Crypto small packet offload threshold */
	size_t switch_threshold;
	unsigned int enc : 1;
	unsigned int pad : 1;    /* Whether padding should be used or not */
	unsigned int cts_mode;   /* Use to set the type for CTS modes */
	unsigned int key_set : 1;    /* Whether key is copied to priv key buffers */
	unsigned int iv_set : 1;    /* Whether iv is copied to priv iv buffers */
	size_t blksize;
	size_t keylen;
	size_t ivlen;
	size_t bufsz;            /* Number of bytes in buf */
	char alg_name[ALG_NAME_SIZE];
};

struct cipher_info {
	int nid;
	enum wd_cipher_alg alg;
	enum wd_cipher_mode mode;
};

static struct cipher_info cipher_info_table[] = {
	{ ID_aes_128_ecb, WD_CIPHER_AES, WD_CIPHER_ECB},
	{ ID_aes_192_ecb, WD_CIPHER_AES, WD_CIPHER_ECB},
	{ ID_aes_256_ecb, WD_CIPHER_AES, WD_CIPHER_ECB},
	{ ID_aes_128_cbc, WD_CIPHER_AES, WD_CIPHER_CBC},
	{ ID_aes_192_cbc, WD_CIPHER_AES, WD_CIPHER_CBC},
	{ ID_aes_256_cbc, WD_CIPHER_AES, WD_CIPHER_CBC},
	{ ID_aes_128_cts, WD_CIPHER_AES, WD_CIPHER_CBC_CS1},
	{ ID_aes_192_cts, WD_CIPHER_AES, WD_CIPHER_CBC_CS1},
	{ ID_aes_256_cts, WD_CIPHER_AES, WD_CIPHER_CBC_CS1},
	{ ID_aes_128_xts, WD_CIPHER_AES, WD_CIPHER_XTS},
	{ ID_aes_256_xts, WD_CIPHER_AES, WD_CIPHER_XTS},
	{ ID_aes_128_ctr, WD_CIPHER_AES, WD_CIPHER_CTR},
	{ ID_aes_192_ctr, WD_CIPHER_AES, WD_CIPHER_CTR},
	{ ID_aes_256_ctr, WD_CIPHER_AES, WD_CIPHER_CTR},
	{ ID_aes_128_ofb128, WD_CIPHER_AES, WD_CIPHER_OFB},
	{ ID_aes_192_ofb128, WD_CIPHER_AES, WD_CIPHER_OFB},
	{ ID_aes_256_ofb128, WD_CIPHER_AES, WD_CIPHER_OFB},
	{ ID_aes_128_cfb128, WD_CIPHER_AES, WD_CIPHER_CFB},
	{ ID_aes_192_cfb128, WD_CIPHER_AES, WD_CIPHER_CFB},
	{ ID_aes_256_cfb128, WD_CIPHER_AES, WD_CIPHER_CFB},
	{ ID_sm4_cbc, WD_CIPHER_SM4, WD_CIPHER_CBC},
	{ ID_sm4_ofb128, WD_CIPHER_SM4, WD_CIPHER_OFB},
	{ ID_sm4_cfb128, WD_CIPHER_SM4, WD_CIPHER_CFB},
	{ ID_sm4_ecb, WD_CIPHER_SM4, WD_CIPHER_ECB},
	{ ID_sm4_ctr, WD_CIPHER_SM4, WD_CIPHER_CTR},
	{ ID_des_ede3_cbc, WD_CIPHER_3DES, WD_CIPHER_CBC},
	{ ID_des_ede3_ecb, WD_CIPHER_3DES, WD_CIPHER_ECB},
};

struct cts_mode_name2id_st {
	unsigned int id;
	const char *ossl_mode_name;
	const char *uadk_alg_name;
};

static struct cts_mode_name2id_st cts_modes[] = {
	{ WD_CIPHER_CBC_CS1, OSSL_CIPHER_CTS_MODE_CS1, UADK_CIPHER_CTS_CS1_NAME },
	{ WD_CIPHER_CBC_CS2, OSSL_CIPHER_CTS_MODE_CS2, UADK_CIPHER_CTS_CS2_NAME },
	{ WD_CIPHER_CBC_CS3, OSSL_CIPHER_CTS_MODE_CS3, UADK_CIPHER_CTS_CS3_NAME },
};

static const char *ossl_cipher_cbc_cts_mode_id2name(unsigned int id)
{
	size_t len = ARRAY_SIZE(cts_modes);
	size_t i;

	for (i = 0; i < len; ++i) {
		if (cts_modes[i].id == id)
			return cts_modes[i].ossl_mode_name;
	}

	return NULL;
}

static int ossl_cipher_cbc_cts_mode_name2id(const char *name)
{
	size_t len = ARRAY_SIZE(cts_modes);
	size_t i;

	for (i = 0; i < len; ++i) {
		if (OPENSSL_strcasecmp(name, cts_modes[i].ossl_mode_name) == 0)
			return (int)cts_modes[i].id;
	}

	return -1;
}

static int uadk_create_cipher_soft_ctx(struct cipher_priv_ctx *priv)
{
	if (priv->sw_cipher)
		return UADK_P_SUCCESS;

	switch (priv->nid) {
	case ID_aes_128_cbc:
		priv->sw_cipher = EVP_CIPHER_fetch(NULL, "AES-128-CBC", "provider=default");
		break;
	case ID_aes_192_cbc:
		priv->sw_cipher = EVP_CIPHER_fetch(NULL, "AES-192-CBC", "provider=default");
		break;
	case ID_aes_256_cbc:
		priv->sw_cipher = EVP_CIPHER_fetch(NULL, "AES-256-CBC", "provider=default");
		break;
	case ID_aes_128_cts:
		priv->sw_cipher = EVP_CIPHER_fetch(NULL, "AES-128-CBC-CTS", "provider=default");
		break;
	case ID_aes_192_cts:
		priv->sw_cipher = EVP_CIPHER_fetch(NULL, "AES-192-CBC-CTS", "provider=default");
		break;
	case ID_aes_256_cts:
		priv->sw_cipher = EVP_CIPHER_fetch(NULL, "AES-256-CBC-CTS", "provider=default");
		break;
	case ID_aes_128_ecb:
		priv->sw_cipher = EVP_CIPHER_fetch(NULL, "AES-128-ECB", "provider=default");
		break;
	case ID_aes_192_ecb:
		priv->sw_cipher = EVP_CIPHER_fetch(NULL, "AES-192-ECB", "provider=default");
		break;
	case ID_aes_256_ecb:
		priv->sw_cipher = EVP_CIPHER_fetch(NULL, "AES-256-ECB", "provider=default");
		break;
	case ID_sm4_cbc:
		priv->sw_cipher = EVP_CIPHER_fetch(NULL, "SM4-CBC", "provider=default");
		break;
	case ID_sm4_ecb:
		priv->sw_cipher = EVP_CIPHER_fetch(NULL, "SM4-ECB", "provider=default");
		break;
	case ID_des_ede3_cbc:
		priv->sw_cipher = EVP_CIPHER_fetch(NULL, "DES-EDE3-CBC", "provider=default");
		break;
	case ID_des_ede3_ecb:
		priv->sw_cipher = EVP_CIPHER_fetch(NULL, "DES-EDE3-ECB", "provider=default");
		break;
	case ID_aes_128_ctr:
		priv->sw_cipher = EVP_CIPHER_fetch(NULL, "AES-128-CTR", "provider=default");
		break;
	case ID_aes_192_ctr:
		priv->sw_cipher = EVP_CIPHER_fetch(NULL, "AES-192-CTR", "provider=default");
		break;
	case ID_aes_256_ctr:
		priv->sw_cipher = EVP_CIPHER_fetch(NULL, "AES-256-CTR", "provider=default");
		break;
	case ID_aes_128_ofb128:
		priv->sw_cipher = EVP_CIPHER_fetch(NULL, "AES-128-OFB", "provider=default");
		break;
	case ID_aes_192_ofb128:
		priv->sw_cipher = EVP_CIPHER_fetch(NULL, "AES-192-OFB", "provider=default");
		break;
	case ID_aes_256_ofb128:
		priv->sw_cipher = EVP_CIPHER_fetch(NULL, "AES-256-OFB", "provider=default");
		break;
	case ID_aes_128_cfb128:
		priv->sw_cipher = EVP_CIPHER_fetch(NULL, "AES-128-CFB", "provider=default");
		break;
	case ID_aes_192_cfb128:
		priv->sw_cipher = EVP_CIPHER_fetch(NULL, "AES-192-CFB", "provider=default");
		break;
	case ID_aes_256_cfb128:
		priv->sw_cipher = EVP_CIPHER_fetch(NULL, "AES-256-CFB", "provider=default");
		break;
	case ID_sm4_ofb128:
		priv->sw_cipher = EVP_CIPHER_fetch(NULL, "SM4-OFB", "provider=default");
		break;
	case ID_sm4_cfb128:
		priv->sw_cipher = EVP_CIPHER_fetch(NULL, "SM4-CFB", "provider=default");
		break;
	case ID_sm4_ctr:
		priv->sw_cipher = EVP_CIPHER_fetch(NULL, "SM4-CTR", "provider=default");
		break;
	case ID_aes_128_xts:
		priv->sw_cipher = EVP_CIPHER_fetch(NULL, "AES-128-XTS", "provider=default");
		break;
	case ID_aes_256_xts:
		priv->sw_cipher = EVP_CIPHER_fetch(NULL, "AES-256-XTS", "provider=default");
		break;
	default:
		break;
	}

	if (unlikely(!priv->sw_cipher)) {
		UADK_ERR("cipher failed to fetch\n");
		return UADK_P_FAIL;
	}

	priv->sw_ctx = EVP_CIPHER_CTX_new();
	if (!priv->sw_ctx) {
		UADK_ERR("EVP_CIPHER_CTX_new failed.\n");
		goto free;
	}

	return UADK_P_SUCCESS;

free:
	EVP_CIPHER_free(priv->sw_cipher);
	priv->sw_cipher = NULL;

	return UADK_P_FAIL;
}

static int uadk_prov_cipher_sw_init(struct cipher_priv_ctx *priv,
				    const unsigned char *key,
				    const unsigned char *iv)
{
	if (!priv->sw_cipher)
		return UADK_P_FAIL;

	if (!EVP_CipherInit_ex2(priv->sw_ctx, priv->sw_cipher, key, iv,
				priv->enc, NULL)) {
		UADK_ERR("cipher soft init failed!\n");
		return UADK_P_FAIL;
	}

	priv->switch_flag = UADK_DO_SOFT;

	return UADK_P_SUCCESS;
}

static int uadk_prov_cipher_soft_update(struct cipher_priv_ctx *priv, unsigned char *out,
					int *outl, const unsigned char *in, size_t len)
{
	if (!priv->sw_cipher)
		return UADK_P_FAIL;

	if (!EVP_CipherInit_ex2(priv->sw_ctx, priv->sw_cipher, priv->key, priv->iv,
				priv->enc, NULL)) {
		UADK_ERR("cipher soft init error!\n");
		return UADK_P_FAIL;
	}

	if (!EVP_CipherUpdate(priv->sw_ctx, out, outl, in, len)) {
		UADK_ERR("cipher soft update error!\n");
		return UADK_P_FAIL;
	}

	priv->switch_flag = UADK_DO_SOFT;

	return UADK_P_SUCCESS;
}

static int uadk_prov_cipher_soft_final(struct cipher_priv_ctx *priv, unsigned char *out,
				       size_t *outl)
{
	int sw_final_len = 0;

	if (!priv->sw_cipher)
		return UADK_P_FAIL;

	if (!EVP_CipherFinal_ex(priv->sw_ctx, out, &sw_final_len)) {
		UADK_ERR("cipher soft final failed.\n");
		return UADK_P_FAIL;
	}

	*outl = sw_final_len;
	priv->switch_flag = 0;

	return UADK_P_SUCCESS;
}

static int uadk_prov_cipher_dev_init(struct cipher_priv_ctx *priv);

static int uadk_cipher_poll(void *ctx)
{
	__u64 recv_cnt = 0;
	__u32 recv = 0;
	/* Poll one packet currently */
	int expt = 1;
	int ret;

	do {
		ret = wd_cipher_poll(expt, &recv);
		if (ret < 0 || recv >= expt)
			return ret;
		recv_cnt++;
	} while (recv_cnt < PROV_SCH_RECV_MAX_CNT);

	UADK_ERR("failed to poll provider cipher msg: timeout!\n");

	return -ETIMEDOUT;
}

static int uadk_get_cipher_info(struct cipher_priv_ctx *priv)
{
	int cipher_counts = ARRAY_SIZE(cipher_info_table);
	int i;

	for (i = 0; i < cipher_counts; i++) {
		if (priv->nid == cipher_info_table[i].nid) {
			priv->setup.alg = cipher_info_table[i].alg;
			priv->setup.mode = cipher_info_table[i].mode;
			return UADK_P_SUCCESS;
		}
	}

	UADK_ERR("failed to get cipher info.\n");

	return UADK_P_FAIL;
}

static int uadk_prov_cipher_init(struct cipher_priv_ctx *priv,
				 const unsigned char *key, size_t keylen,
				 const unsigned char *iv, size_t ivlen)
{
	int ret;

	if ((iv && ivlen != priv->ivlen) || (key && keylen != priv->keylen)) {
		UADK_ERR("invalid keylen or ivlen.\n");
		return UADK_P_FAIL;
	}

	if (iv) {
		memcpy(priv->iv, iv, ivlen);
		priv->iv_set = 1;
	}

	ret = uadk_get_cipher_info(priv);
	if (unlikely(!ret))
		return UADK_P_FAIL;

	if (key) {
		memcpy(priv->key, key, keylen);
		priv->key_set = 1;
	}

	priv->switch_flag = 0;
	priv->switch_threshold = SMALL_PACKET_OFFLOAD_THRESHOLD_DEFAULT;

	if (uadk_get_sw_offload_state())
		uadk_create_cipher_soft_ctx(priv);

	ret = uadk_prov_cipher_dev_init(priv);
	if (unlikely(ret <= 0)) {
		UADK_ERR("cipher switch to soft init!\n");
		return uadk_prov_cipher_sw_init(priv, key, iv);
	}

	return UADK_P_SUCCESS;
}

static void async_cb(struct wd_cipher_req *req, void *data)
{
	struct uadk_e_cb_info *cipher_cb_param;
	struct wd_cipher_req *req_origin;
	struct async_op *op;

	if (!req || !req->cb_param)
		return;

	cipher_cb_param = req->cb_param;
	req_origin = cipher_cb_param->priv;
	req_origin->state = req->state;
	op = cipher_cb_param->op;
	if (op && op->job && !op->done) {
		op->done = 1;
		async_free_poll_task(op->idx, 1);
		(void) async_wake_job(op->job);
	}
}

static int uadk_do_cipher_sync(struct cipher_priv_ctx *priv)
{
	int ret;

	ret = wd_do_cipher_sync(priv->sess, &priv->req);
	if (ret)
		return UADK_P_FAIL;

	return UADK_P_SUCCESS;
}

static int uadk_do_cipher_async(struct cipher_priv_ctx *priv, struct async_op *op)
{
	struct uadk_e_cb_info cb_param;
	int idx, ret;

	if (unlikely(priv->switch_flag == UADK_DO_SOFT)) {
		UADK_ERR("async cipher init failed.\n");
		return UADK_P_FAIL;
	}

	cb_param.op = op;
	cb_param.priv = &priv->req;
	priv->req.cb = (void *)async_cb;
	priv->req.cb_param = &cb_param;
	priv->req.state = POLL_ERROR;
	ret = async_get_free_task(&idx);
	if (!ret)
		return UADK_P_FAIL;

	op->idx = idx;
	do {
		ret = wd_do_cipher_async(priv->sess, &priv->req);
		if (ret < 0 && ret != -EBUSY) {
			UADK_ERR("do sec cipher failed, switch to soft cipher.\n");
			async_free_poll_task(op->idx, 0);
			return UADK_P_FAIL;
		}
	} while (ret == -EBUSY);

	ret = async_pause_job(priv, op, ASYNC_TASK_CIPHER);
	if (!ret || priv->req.state)
		return UADK_P_FAIL;

	return UADK_P_SUCCESS;
}

static void uadk_cipher_mutex_infork(void)
{
	/* Release the replication lock of the child process */
	pthread_mutex_unlock(&cipher_mutex);
}

static int uadk_prov_cipher_dev_init(struct cipher_priv_ctx *priv)
{
	int ret;

	pthread_atfork(NULL, NULL, uadk_cipher_mutex_infork);
	pthread_mutex_lock(&cipher_mutex);
	if (prov.pid != getpid()) {
		struct wd_ctx_nums *ctx_set_num;
		struct wd_ctx_params cparams = {0};

		ctx_set_num = calloc(UADK_CIPHER_OP_NUM, sizeof(*ctx_set_num));
		if (!ctx_set_num) {
			UADK_ERR("failed to alloc ctx_set_size!\n");
			ret = UADK_P_FAIL;
			goto init_err;
		}

		cparams.op_type_num = UADK_CIPHER_OP_NUM;
		cparams.ctx_set_num = ctx_set_num;
		cparams.bmp = numa_allocate_nodemask();
		if (!cparams.bmp) {
			UADK_ERR("failed to create nodemask!\n");
			free(ctx_set_num);
			ret = UADK_P_FAIL;
			goto init_err;
		}

		numa_bitmask_setall(cparams.bmp);

		ctx_set_num->sync_ctx_num = UADK_CIPHER_DEF_CTXS;
		ctx_set_num->async_ctx_num = UADK_CIPHER_DEF_CTXS;

		ret = wd_cipher_init2_(priv->alg_name, TASK_MIX, SCHED_POLICY_RR, &cparams);
		numa_free_nodemask(cparams.bmp);
		free(ctx_set_num);

		if (unlikely(ret)) {
			UADK_ERR("failed to init cipher!\n");
			ret = UADK_P_FAIL;
			goto init_err;
		}

		prov.pid = getpid();
		async_register_poll_fn(ASYNC_TASK_CIPHER, uadk_cipher_poll);
	}

	ret = UADK_P_SUCCESS;

init_err:
	pthread_mutex_unlock(&cipher_mutex);
	return ret;
}

static int uadk_prov_cipher_ctx_init(struct cipher_priv_ctx *priv)
{
	struct wd_cipher_sess_setup setup = {0};
	struct sched_params params = {0};
	int ret;

	if (!priv->key_set || (!priv->iv_set && priv->ivlen)) {
		UADK_ERR("key or iv is not set yet!\n");
		return UADK_P_FAIL;
	}

	priv->req.iv_bytes = priv->ivlen;
	priv->req.iv = priv->iv;

	if (priv->switch_flag == UADK_DO_SOFT)
		return UADK_P_FAIL;

	ret = uadk_prov_cipher_dev_init(priv);
	if (ret <= 0)
		return UADK_P_FAIL;

	/* dec and enc use the same op */
	params.type = 0;
	/* Use the default numa parameters */
	params.numa_id = -1;
	setup.sched_param = &params;
	setup.alg = priv->setup.alg;
	setup.mode = priv->setup.mode;

	if (!priv->sess) {
		priv->sess = wd_cipher_alloc_sess(&setup);
		if (!priv->sess) {
			UADK_ERR("uadk failed to alloc session!\n");
			return UADK_P_FAIL;
		}
	}

	ret = wd_cipher_set_key(priv->sess, priv->key, priv->keylen);
	if (ret) {
		wd_cipher_free_sess(priv->sess);
		priv->sess = 0;
		UADK_ERR("uadk failed to set key!\n");
		return UADK_P_FAIL;
	}

	return UADK_P_SUCCESS;
}

/*
 * Fills a single block of buffered data from the input, and returns the amount
 * of data remaining in the input that is a multiple of the blocksize. The buffer
 * is only filled if it already has some data in it, isn't full already or we
 * don't have at least one block in the input.
 *
 * buf: a buffer of blocksize bytes
 * buflen: contains the amount of data already in buf on entry. Updated with the
 *         amount of data in buf at the end. On entry *buflen must always be
 *         less than the blocksize
 * blocksize: size of a block. Must be greater than 0 and a power of 2
 * in: pointer to a pointer containing the input data
 * inlen: amount of input data available
 *
 * On return buf is filled with as much data as possible up to a full block,
 * *buflen is updated containing the amount of data in buf. *in is updated to
 * the new location where input data should be read from, *inlen is updated with
 * the remaining amount of data in *in. Returns the largest value <= *inlen
 * which is a multiple of the blocksize.
 */
static size_t ossl_cipher_fillblock(unsigned char *buf, size_t *buflen,
				    size_t blocksize,
				    const unsigned char **in, size_t *inlen)
{
	size_t blockmask = ~(blocksize - 1);
	size_t bufremain = blocksize - *buflen;

	if (*inlen < bufremain)
		bufremain = *inlen;
	memcpy(buf + *buflen, *in, bufremain);
	*in += bufremain;
	*inlen -= bufremain;
	*buflen += bufremain;

	return *inlen & blockmask;
}

/*
 * Fills the buffer with trailing data from an encryption/decryption that didn't
 * fit into a full block.
 */
static int ossl_cipher_trailingdata(unsigned char *buf, size_t *buflen, size_t blocksize,
				    const unsigned char **in, size_t *inlen)
{
	if (*inlen == 0)
		return UADK_P_SUCCESS;

	if (*buflen + *inlen > blocksize) {
		UADK_ERR("invalid: inlen is too long.\n");
		return UADK_P_FAIL;
	}

	memcpy(buf + *buflen, *in, *inlen);
	*buflen += *inlen;
	*inlen = 0;

	return UADK_P_SUCCESS;
}

/* Pad the final block for encryption */
static void ossl_cipher_padblock(unsigned char *buf, size_t *buflen, size_t blocksize)
{
	unsigned char pad = (unsigned char)(blocksize - *buflen);
	size_t i;

	for (i = *buflen; i < blocksize; i++)
		buf[i] = pad;
}

static int ossl_cipher_unpadblock(unsigned char *buf, size_t *buflen, size_t blocksize)
{
	size_t len = *buflen;
	size_t pad, i;

	if (len != blocksize) {
		UADK_ERR("invalid: length and block size are not equal.\n");
		return UADK_P_FAIL;
	}

	/*
	 * The following assumes that the ciphertext has been authenticated.
	 * Otherwise it provides a padding oracle.
	 */
	pad = buf[blocksize - 1];
	if (pad == 0 || pad > blocksize) {
		UADK_ERR("invalid: pad is too big or is 0.\n");
		return UADK_P_FAIL;
	}
	for (i = 0; i < pad; i++) {
		if (buf[--len] != pad) {
			UADK_ERR("invalid: pad and buf are not equal.\n");
			return UADK_P_FAIL;
		}
	}
	*buflen = len;

	return UADK_P_SUCCESS;
}

static int uadk_prov_hw_cipher(struct cipher_priv_ctx *priv, unsigned char *out,
			       size_t *outl, size_t outsize,
			       const unsigned char *in, size_t inlen)
{
	size_t blksz = priv->blksize;
	struct async_op op;
	int ret;

	if (outsize < blksz) {
		UADK_ERR("invalid: hw cipher outsize is too small.\n");
		return UADK_P_FAIL;
	}

	priv->switch_flag = UADK_DO_HW;
	priv->req.src = (unsigned char *)in;
	priv->req.in_bytes = inlen;
	priv->req.out_bytes = inlen;
	priv->req.dst = out;
	priv->req.out_buf_bytes = inlen;

	ret = uadk_prov_cipher_ctx_init(priv);
	if (ret != UADK_P_SUCCESS)
		return ret;

	ret = async_setup_async_event_notification(&op);
	if (!ret) {
		UADK_ERR("failed to setup async event notification.\n");
		return UADK_P_FAIL;
	}

	if (op.job == NULL) {
		/* Synchronous, only the synchronous mode supports soft computing */
		ret = uadk_do_cipher_sync(priv);
		if (!ret) {
			async_clear_async_event_notification();
			return UADK_P_FAIL;
		}
	} else {
		ret = uadk_do_cipher_async(priv, &op);
		if (!ret) {
			async_clear_async_event_notification();
			return UADK_P_FAIL;
		}
	}

	return UADK_P_SUCCESS;
}

static int uadk_prov_do_cipher(struct cipher_priv_ctx *priv, unsigned char *out,
			       size_t *outl, size_t outsize,
			       const unsigned char *in, size_t inlen)
{
	size_t blksz = priv->blksize;
	size_t nextblocks;
	int outlint = 0;
	int ret;

	if (priv->sw_cipher &&
	    (priv->switch_flag == UADK_DO_SOFT ||
	    (priv->switch_flag != UADK_DO_HW &&
	     inlen <= priv->switch_threshold))) {
		goto do_soft;
	}

	if (priv->bufsz != 0)
		nextblocks = ossl_cipher_fillblock(priv->buf, &priv->bufsz,
						   blksz, &in, &inlen);
	else
		nextblocks = inlen & ~(blksz-1);

	/*
	 * If we're decrypting and we end an update on a block boundary we hold
	 * the last block back in case this is the last update call and the last
	 * block is padded.
	 */
	if (priv->bufsz == blksz && (priv->enc || inlen > 0 || !priv->pad)) {
		ret = uadk_prov_hw_cipher(priv, out, outl, outsize, priv->buf, blksz);
		if (ret != UADK_P_SUCCESS) {
			UADK_ERR("do hw ciphers failed.\n");
			if (priv->sw_cipher)
				goto do_soft;
			return ret;
		}

		priv->bufsz = 0;
		outlint = blksz;
		out += blksz;
	}

	if (nextblocks == 0)
		goto out;

	if (!priv->enc && priv->pad && nextblocks == inlen)
		nextblocks -= blksz;

	if (nextblocks > 0) {
		ret = uadk_prov_hw_cipher(priv, out, outl, outsize, in, nextblocks);
		if (ret != UADK_P_SUCCESS) {
			UADK_ERR("last block do hw ciphers failed.\n");
			if (priv->sw_cipher)
				goto do_soft;
			return ret;
		}

		outlint += nextblocks;
		in += nextblocks;
		inlen -= nextblocks;
	}
out:
	if (inlen != 0 && !ossl_cipher_trailingdata(priv->buf,
	    &priv->bufsz, blksz, &in, &inlen))
		return UADK_P_FAIL;

	*outl = outlint;
	return inlen == 0;

do_soft:
	/*
	 * Using soft only if enable_sw_offload, which is set in conf file,
	 * then sw_cipher is initialzied
	 * 1. small packets
	 * 2. already choose DO_SOFT, can be hw fail case or following sw case
	 */
	ret = uadk_prov_cipher_soft_update(priv, out, &outlint, in, inlen);
	if (ret) {
		*outl = outlint;
		return UADK_P_SUCCESS;
	}

	return UADK_P_FAIL;
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

static int uadk_prov_cipher_cipher(void *vctx, unsigned char *output, size_t *outl,
				   size_t outsize, const unsigned char *input,
				   size_t inl)
{
	struct cipher_priv_ctx *priv = (struct cipher_priv_ctx *)vctx;
	int ret;

	if (!vctx || !output || !input || !outl)
		return UADK_P_FAIL;

	if (inl == 0) {
		*outl = 0;
		return UADK_P_SUCCESS;
	}

	if (outsize < inl) {
		UADK_ERR("invalid: cipher outsize is too small.\n");
		return UADK_P_FAIL;
	}

	ret = uadk_prov_do_cipher(priv, output, outl, outsize, input, inl);
	if (ret != UADK_P_SUCCESS)
		return ret;

	*outl = inl;

	return UADK_P_SUCCESS;
}

static int uadk_prov_cipher_block_encrypto(struct cipher_priv_ctx *priv, unsigned char *out,
					   size_t *outl, size_t outsize)
{
	size_t blksz = priv->blksize;
	int ret;

	if (priv->pad) {
		ossl_cipher_padblock(priv->buf, &priv->bufsz, blksz);
	} else if (priv->bufsz == 0) {
		*outl = 0;
		return UADK_P_SUCCESS;
	} else if (priv->bufsz != blksz) {
		UADK_ERR("invalid: wrong final block length.\n");
		return UADK_P_FAIL;
	}

	if (outsize < blksz) {
		UADK_ERR("invalid: cipher block outsize is too small.\n");
		return UADK_P_FAIL;
	}

	ret = uadk_prov_hw_cipher(priv, out, outl, outsize, priv->buf, blksz);
	if (ret != UADK_P_SUCCESS) {
		UADK_ERR("do hw ciphers encrypto failed, switch to soft ciphers.\n");
		return uadk_prov_cipher_soft_final(priv, out, outl);
	}

	*outl = blksz;

	return UADK_P_SUCCESS;
}

static int uadk_prov_cipher_block_decrypto(struct cipher_priv_ctx *priv, unsigned char *out,
					   size_t *outl, size_t outsize)
{
	size_t blksz = priv->blksize;
	int ret;

	/* Dec should handle last blk since pad */
	if (priv->bufsz != blksz) {
		if (priv->bufsz == 0 && !priv->pad) {
			*outl = 0;
			return UADK_P_SUCCESS;
		}
		UADK_ERR("invalid: cipher decrypto wrong final block length.\n");
		return UADK_P_FAIL;
	}

	ret = uadk_prov_hw_cipher(priv, priv->buf, outl, outsize, priv->buf, blksz);
	if (ret != UADK_P_SUCCESS) {
		UADK_ERR("do hw ciphers decrypto failed, switch to soft ciphers.\n");
		return uadk_prov_cipher_soft_final(priv, out, outl);
	}

	if (priv->pad && !ossl_cipher_unpadblock(priv->buf, &priv->bufsz, blksz)) {
		/* UADK_ERR already called */
		return UADK_P_FAIL;
	}

	if (outsize < priv->bufsz) {
		UADK_ERR("invalid: cipher decrypto outsize is too small.\n");
		return UADK_P_FAIL;
	}

	memcpy(out, priv->buf, priv->bufsz);
	*outl = priv->bufsz;
	priv->bufsz = 0;

	return UADK_P_SUCCESS;
}

static int uadk_prov_cipher_block_final(void *vctx, unsigned char *out,
					size_t *outl, size_t outsize)
{
	struct cipher_priv_ctx *priv = (struct cipher_priv_ctx *)vctx;
	int ret;

	if (!vctx || !out || !outl)
		return UADK_P_FAIL;

	if (priv->switch_flag == UADK_DO_SOFT)
		return uadk_prov_cipher_soft_final(priv, out, outl);

	if (priv->enc)
		ret = uadk_prov_cipher_block_encrypto(priv, out, outl, outsize);
	else
		ret = uadk_prov_cipher_block_decrypto(priv, out, outl, outsize);

	return ret;
}

static int uadk_prov_cipher_block_update(void *vctx, unsigned char *output,
					 size_t *outl, size_t outsize,
					 const unsigned char *input, size_t inl)
{
	struct cipher_priv_ctx *priv = (struct cipher_priv_ctx *)vctx;

	if (!vctx || !input || !output || !outl)
		return UADK_P_FAIL;

	if (inl == 0) {
		*outl = 0;
		return UADK_P_SUCCESS;
	}

	if (outsize < inl) {
		UADK_ERR("invalid: cipher update outsize is too small.\n");
		return UADK_P_FAIL;
	}

	return uadk_prov_do_cipher(priv, output, outl, outsize, input, inl);
}

static int uadk_prov_cipher_stream_update(void *vctx, unsigned char *output,
					  size_t *outl, size_t outsize,
					  const unsigned char *input, size_t inl)
{
	struct cipher_priv_ctx *priv = (struct cipher_priv_ctx *)vctx;
	int len = 0;
	int ret;

	if (!vctx || !outl || !input || !output)
		return UADK_P_FAIL;

	if (inl == 0) {
		*outl = 0;
		return UADK_P_SUCCESS;
	}

	if (outsize < inl) {
		UADK_ERR("invalid: cipher stream update outsize is too small.\n");
		return UADK_P_FAIL;
	}

	if (priv->sw_cipher &&
	    (priv->switch_flag == UADK_DO_SOFT ||
	    (priv->switch_flag != UADK_DO_HW &&
	     inl <= priv->switch_threshold))) {
		goto do_soft;
	}

	ret = uadk_prov_hw_cipher(priv, output, outl, outsize, input, inl);
	if (ret != UADK_P_SUCCESS) {
		if (priv->sw_cipher)
			goto do_soft;
		return ret;
	}

	*outl = inl;
	return UADK_P_SUCCESS;

do_soft:
	/* have isseu if both using hw and soft partly */
	ret = uadk_prov_cipher_soft_update(priv, output, &len, input, inl);
	if (ret) {
		*outl = len;
		return UADK_P_SUCCESS;
	}

	UADK_ERR("do soft ciphers failed.\n");

	return UADK_P_FAIL;
}

static int uadk_prov_cipher_stream_final(void *vctx, unsigned char *out,
					 size_t *outl, size_t outsize)
{
	struct cipher_priv_ctx *priv = (struct cipher_priv_ctx *)vctx;

	if (!vctx || !out || !outl)
		return UADK_P_FAIL;

	if (priv->switch_flag == UADK_DO_SOFT)
		return uadk_prov_cipher_soft_final(priv, out, outl);

	*outl = 0;

	return UADK_P_SUCCESS;
}

static int uadk_prov_cipher_einit(void *vctx, const unsigned char *key, size_t keylen,
				  const unsigned char *iv, size_t ivlen,
				  const OSSL_PARAM params[])
{
	struct cipher_priv_ctx *priv = (struct cipher_priv_ctx *)vctx;

	if (!vctx)
		return UADK_P_FAIL;

	priv->req.op_type = WD_CIPHER_ENCRYPTION;
	priv->enc = 1;

	return uadk_prov_cipher_init(priv, key, keylen, iv, ivlen);
}

static int uadk_prov_cipher_dinit(void *vctx, const unsigned char *key, size_t keylen,
				  const unsigned char *iv, size_t ivlen,
				  const OSSL_PARAM params[])
{
	struct cipher_priv_ctx *priv = (struct cipher_priv_ctx *)vctx;

	if (!vctx)
		return UADK_P_FAIL;

	priv->req.op_type = WD_CIPHER_DECRYPTION;
	priv->enc = 0;

	return uadk_prov_cipher_init(priv, key, keylen, iv, ivlen);
}

static const OSSL_PARAM uadk_prov_settable_ctx_params[] = {
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
	OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),
	OSSL_PARAM_utf8_string(OSSL_CIPHER_PARAM_CTS_MODE, NULL, 0),
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

	if (!vctx)
		return UADK_P_FAIL;

	p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_PADDING);
	if (p != NULL) {
		unsigned int pad;

		if (!OSSL_PARAM_get_uint(p, &pad)) {
			UADK_ERR("failed to get cipher uint: pad.\n");
			return UADK_P_FAIL;
		}
		priv->pad = pad ? 1 : 0;
		if (priv->sw_ctx)
			EVP_CIPHER_CTX_set_padding(priv->sw_ctx, pad);
	}

	p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
	if (p != NULL) {
		size_t keylen;

		if (!OSSL_PARAM_get_size_t(p, &keylen)) {
			UADK_ERR("failed to get cipher size parameter: keylen.\n");
			return UADK_P_FAIL;
		}
		if (priv->keylen != keylen) {
			UADK_ERR("invalid: cipher keylen.\n");
			return UADK_P_FAIL;
		}
	}

	p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_IVLEN);
	if (p != NULL) {
		size_t ivlen;

		if (!OSSL_PARAM_get_size_t(p, &ivlen)) {
			UADK_ERR("failed to get cipher size parameter: ivlen.\n");
			return UADK_P_FAIL;
		}
		if (priv->ivlen != ivlen) {
			UADK_ERR("invalid: cipher ivlen.\n");
			return UADK_P_FAIL;
		}
	}

	p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_CTS_MODE);
	if (p != NULL) {
		int id;

		if (p->data_type != OSSL_PARAM_UTF8_STRING) {
			UADK_ERR("failed to get cipher cts mode: data_type.\n");
			return UADK_P_FAIL;
		}

		id = ossl_cipher_cbc_cts_mode_name2id(p->data);
		if (id < 0) {
			UADK_ERR("failed to get cipher cts mode: id.\n");
			return UADK_P_FAIL;
		}

		priv->cts_mode = (unsigned int)id;
		priv->setup.mode = priv->cts_mode;
		strncpy(priv->alg_name, cts_modes[id - WD_CIPHER_CBC_CS1].uadk_alg_name,
			ALG_NAME_SIZE - 1);
	}

	return UADK_P_SUCCESS;
}

static int uadk_prov_cipher_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
	struct cipher_priv_ctx *priv = (struct cipher_priv_ctx *)vctx;
	OSSL_PARAM *p;

	if (!vctx || !params)
		return UADK_P_FAIL;

	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
	if (p != NULL && !OSSL_PARAM_set_size_t(p, priv->keylen)) {
		UADK_ERR("failed to set cipher size parameter: keylen.\n");
		return UADK_P_FAIL;
	}
	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
	if (p != NULL && !OSSL_PARAM_set_size_t(p, priv->ivlen)) {
		UADK_ERR("failed to set cipher size parameter: ivlen.\n");
		return UADK_P_FAIL;
	}
	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_PADDING);
	if (p != NULL && !OSSL_PARAM_set_uint(p, priv->pad)) {
		UADK_ERR("failed to set cipher uint parameter: pad.\n");
		return UADK_P_FAIL;
	}
	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
	if (p != NULL && !OSSL_PARAM_set_octet_string(p, priv->iv, priv->ivlen) &&
	    !OSSL_PARAM_set_octet_ptr(p, &priv->iv, priv->ivlen)) {
		UADK_ERR("failed to set cipher octet parameter: param iv.\n");
		return UADK_P_FAIL;
	}
	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
	if (p != NULL && !OSSL_PARAM_set_octet_string(p, priv->iv, priv->ivlen) &&
	    !OSSL_PARAM_set_octet_ptr(p, &priv->iv, priv->ivlen)) {
		UADK_ERR("failed to set cipher octet parameter: updated iv.\n");
		return UADK_P_FAIL;
	}
	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CTS_MODE);
	if (p != NULL) {
		const char *name = ossl_cipher_cbc_cts_mode_id2name(priv->cts_mode);

		if (name == NULL || !OSSL_PARAM_set_utf8_string(p, name)) {
			UADK_ERR("failed to set cipher utf8 parameter: name.\n");
			return UADK_P_FAIL;
		}
	}
	return UADK_P_SUCCESS;
}

static const OSSL_PARAM uadk_prov_default_ctx_params[] = {
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
	OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
	OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),
	OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
	OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, NULL, 0),
	OSSL_PARAM_utf8_string(OSSL_CIPHER_PARAM_CTS_MODE, NULL, 0),
	OSSL_PARAM_END
};

static const OSSL_PARAM *uadk_prov_cipher_gettable_ctx_params(ossl_unused void *cctx,
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
		UADK_ERR("failed to set cipher uint parameter: md.\n");
		return UADK_P_FAIL;
	}
	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CUSTOM_IV);
	if (p != NULL && !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_CUSTOM_IV) != 0)) {
		UADK_ERR("failed to set cipher int parameter: custom iv.\n");
		return UADK_P_FAIL;
	}
	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
	if (p != NULL && !OSSL_PARAM_set_size_t(p, kbits)) {
		UADK_ERR("failed to set cipher size parameter: kbits.\n");
		return UADK_P_FAIL;
	}
	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
	if (p != NULL && !OSSL_PARAM_set_size_t(p, blkbits)) {
		UADK_ERR("failed to set cipher size parameter: block size.\n");
		return UADK_P_FAIL;
	}
	p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
	if (p != NULL && !OSSL_PARAM_set_size_t(p, ivbits)) {
		UADK_ERR("failed to set cipher size parameter: ivbits.\n");
		return UADK_P_FAIL;
	}

	return UADK_P_SUCCESS;
}

static void uadk_prov_cipher_freectx(void *ctx)
{
	struct cipher_priv_ctx *priv = (struct cipher_priv_ctx *)ctx;

	if (ctx == NULL)
		return;

	if (priv->sw_cipher)
		EVP_CIPHER_free(priv->sw_cipher);

	if (priv->sw_ctx)
		EVP_CIPHER_CTX_free(priv->sw_ctx);

	if (priv->sess)
		wd_cipher_free_sess(priv->sess);

	OPENSSL_clear_free(priv, sizeof(*priv));
}

int uadk_prov_cipher_version(void)
{
	struct uacce_dev *dev;

	if (g_hw_symm_enc_dev != HW_SYMM_ENC_INVALID)
		return g_hw_symm_enc_dev;

	dev = uadk_get_accel_dev("cipher");
	if (!dev) {
		UADK_ERR("no cipher device available!\n");
		g_hw_symm_enc_dev = HW_SYMM_ENC_INVALID;
		return g_hw_symm_enc_dev;
	}

	if (!strcmp(dev->api, "hisi_qm_v2"))
		g_hw_symm_enc_dev = HW_SYMM_ENC_V2;
	else
		g_hw_symm_enc_dev = HW_SYMM_ENC_V3;

	free(dev);

	return g_hw_symm_enc_dev;
}

#define UADK_CIPHER_DESCR(nm, blk_size, key_len, iv_len,			\
			  flags, e_nid, algnm, mode, typ)			\
static OSSL_FUNC_cipher_newctx_fn uadk_##nm##_newctx;				\
static void *uadk_##nm##_newctx(void *provctx)					\
{										\
	struct cipher_priv_ctx *ctx = OPENSSL_zalloc(sizeof(*ctx));		\
	if (ctx == NULL)							\
		return NULL;							\
										\
	ctx->blksize = blk_size;						\
	ctx->keylen = key_len;							\
	ctx->ivlen = iv_len;							\
	ctx->nid = e_nid;							\
	ctx->cts_mode = WD_CIPHER_CBC_CS1;					\
	strncpy(ctx->alg_name, #algnm, ALG_NAME_SIZE - 1);			\
	if (strcmp(#typ, "block") == 0)						\
		ctx->pad = 1;							\
	return ctx;								\
}										\
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
	{ OSSL_FUNC_CIPHER_UPDATE,						\
		(void (*)(void))uadk_prov_cipher_##typ##_update },		\
	{ OSSL_FUNC_CIPHER_FINAL,						\
		(void (*)(void))uadk_prov_cipher_##typ##_final },		\
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

UADK_CIPHER_DESCR(aes_128_cbc, 16, 16, 16, 0, ID_aes_128_cbc, cbc(aes), EVP_CIPH_CBC_MODE, block);
UADK_CIPHER_DESCR(aes_192_cbc, 16, 24, 16, 0, ID_aes_192_cbc, cbc(aes), EVP_CIPH_CBC_MODE, block);
UADK_CIPHER_DESCR(aes_256_cbc, 16, 32, 16, 0, ID_aes_256_cbc, cbc(aes), EVP_CIPH_CBC_MODE, block);
UADK_CIPHER_DESCR(aes_128_cts, 1, 16, 16, 0, ID_aes_128_cts, cbc-cs1(aes), EVP_CIPH_CBC_MODE, stream);
UADK_CIPHER_DESCR(aes_192_cts, 1, 24, 16, 0, ID_aes_192_cts, cbc-cs1(aes), EVP_CIPH_CBC_MODE, stream);
UADK_CIPHER_DESCR(aes_256_cts, 1, 32, 16, 0, ID_aes_256_cts, cbc-cs1(aes), EVP_CIPH_CBC_MODE, stream);
UADK_CIPHER_DESCR(aes_128_ecb, 16, 16, 0, 0, ID_aes_128_ecb, ecb(aes), EVP_CIPH_ECB_MODE, block);
UADK_CIPHER_DESCR(aes_192_ecb, 16, 24, 0, 0, ID_aes_192_ecb, ecb(aes), EVP_CIPH_ECB_MODE, block);
UADK_CIPHER_DESCR(aes_256_ecb, 16, 32, 0, 0, ID_aes_256_ecb, ecb(aes), EVP_CIPH_ECB_MODE, block);
UADK_CIPHER_DESCR(aes_128_xts, 1, 32, 16, PROV_CIPHER_FLAG_CUSTOM_IV, ID_aes_128_xts, xts(aes), EVP_CIPH_XTS_MODE, stream);
UADK_CIPHER_DESCR(aes_256_xts, 1, 64, 16, PROV_CIPHER_FLAG_CUSTOM_IV, ID_aes_256_xts, xts(aes), EVP_CIPH_XTS_MODE, stream);
UADK_CIPHER_DESCR(sm4_cbc, 16, 16, 16, 0, ID_sm4_cbc, cbc(sm4), EVP_CIPH_CBC_MODE, block);
UADK_CIPHER_DESCR(sm4_ecb, 16, 16, 0, 0, ID_sm4_ecb, ecb(sm4), EVP_CIPH_ECB_MODE, block);
UADK_CIPHER_DESCR(des_ede3_cbc, 8, 24, 8, 0, ID_des_ede3_cbc, cbc(des), EVP_CIPH_CBC_MODE, block);
UADK_CIPHER_DESCR(des_ede3_ecb, 8, 24, 0, 0, ID_des_ede3_ecb, ecb(des), EVP_CIPH_ECB_MODE, block);

/* v3 */
UADK_CIPHER_DESCR(aes_128_ctr, 1, 16, 16, 0, ID_aes_128_ctr, ctr(aes), EVP_CIPH_CTR_MODE, stream);
UADK_CIPHER_DESCR(aes_192_ctr, 1, 24, 16, 0, ID_aes_192_ctr, ctr(aes), EVP_CIPH_CTR_MODE, stream);
UADK_CIPHER_DESCR(aes_256_ctr, 1, 32, 16, 0, ID_aes_256_ctr, ctr(aes), EVP_CIPH_CTR_MODE, stream);
UADK_CIPHER_DESCR(aes_128_ofb128, 1, 16, 16, 0, ID_aes_128_ofb128, ofb(aes), EVP_CIPH_OFB_MODE, stream);
UADK_CIPHER_DESCR(aes_192_ofb128, 1, 24, 16, 0, ID_aes_192_ofb128, ofb(aes), EVP_CIPH_OFB_MODE, stream);
UADK_CIPHER_DESCR(aes_256_ofb128, 1, 32, 16, 0, ID_aes_256_ofb128, ofb(aes), EVP_CIPH_OFB_MODE, stream);
UADK_CIPHER_DESCR(aes_128_cfb128, 1, 16, 16, 0, ID_aes_128_cfb128, cfb(aes), EVP_CIPH_CFB_MODE, stream);
UADK_CIPHER_DESCR(aes_192_cfb128, 1, 24, 16, 0, ID_aes_192_cfb128, cfb(aes), EVP_CIPH_CFB_MODE, stream);
UADK_CIPHER_DESCR(aes_256_cfb128, 1, 32, 16, 0, ID_aes_256_cfb128, cfb(aes), EVP_CIPH_CFB_MODE, stream);
UADK_CIPHER_DESCR(sm4_ofb128, 1, 16, 16, 0, ID_sm4_ofb128, ofb(sm4), EVP_CIPH_OFB_MODE, stream);
UADK_CIPHER_DESCR(sm4_cfb128, 1, 16, 16, 0, ID_sm4_cfb128, cfb(sm4), EVP_CIPH_CFB_MODE, stream);
UADK_CIPHER_DESCR(sm4_ctr, 1, 16, 16, 0, ID_sm4_ctr, ctr(sm4), EVP_CIPH_CTR_MODE, stream);
