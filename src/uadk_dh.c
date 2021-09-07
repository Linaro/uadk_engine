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
#include <errno.h>
#include <openssl/bn.h>
#include <openssl/engine.h>
#include <openssl/crypto.h>
#include <openssl/ossl_typ.h>
#include <openssl/err.h>
#include <openssl/dh.h>
#include <string.h>
#include <uadk/wd_dh.h>
#include "uadk.h"
#include "uadk_async.h"

#define DH768BITS	768
#define DH1024BITS	1024
#define DH1536BITS	1536
#define DH2048BITS	2048
#define DH3072BITS	3072
#define DH4096BITS	4096
#define UADK_DH_MAX_MODULE_BIT	4096
#define DH_GENERATOR_2		2
#define DH_GENERATOR_5		5
#define CHAR_BIT_SIZE		3
#define DH_PARAMS_CNT		3
#define DH_FAIL			0
#define DH_SUCCESS		1
#define CTX_MODE_NUM		2
#define DH_MAX_DEV_NUM		16
#define SYNC_CTX_NUM		1
#define ASYNC_CTX_NUM		20
#define CTX_MODE_NUM		2
#define OPENSSL_SUCCESS		1
#define OPENSSL_FAIL		0
#define UN_SET			0
#define IS_SET			1
#define CTX_ASYNC		1
#define CTX_SYNC		0
#define CTX_NUM			2

static DH_METHOD *uadk_dh_method;

struct bignum_st {
	BN_ULONG *d;
	int top;
	int dmax;
	int neg;
	int flags;
};

typedef struct bignum_st BIGNUM;

struct uadk_dh_sess {
	handle_t sess;
	struct wd_dh_sess_setup setup;
	struct wd_dh_req req;
	DH *ssl_alg;
	int key_size;
};

typedef struct uadk_dh_sess  uadk_dh_sess_t;

struct alg_res {
	struct wd_ctx_config *ctx_res;
	int pid;
};

struct alg_res_per_dev {
	int numa_id;
	int sync_ctx_num;
	int async_ctx_num;
};

struct alg_sched {
	int sched_type;
	struct wd_sched wd_sched;
};

struct alg_res dh_res;

struct dh_res_config {
	struct alg_sched sched;
};

static int generate_new_priv_key(const DH *dh, BIGNUM *new_priv_key)
{
	const BIGNUM *q = DH_get0_q(dh);
	int bits;

	if (q) {
		do {
			if (!BN_priv_rand_range(new_priv_key, q))
				return OPENSSL_FAIL;
		} while (BN_is_zero(new_priv_key) || BN_is_one(new_priv_key));
	} else {
		bits = DH_get_length(dh) ? DH_get_length(dh) : BN_num_bits(DH_get0_p(dh)) - 1;
		if (!BN_priv_rand(new_priv_key, bits, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY))
			return OPENSSL_FAIL;
	}

	return OPENSSL_SUCCESS;
}

int uadk_dh_try_get_priv_key(const DH *dh, BIGNUM **priv_key)
{
	int generate_new_key = 0;
	BIGNUM *new_priv_key = NULL;

	*priv_key = (BIGNUM *)DH_get0_priv_key(dh);
	if (*priv_key == NULL) {
		new_priv_key = BN_secure_new();
	if (new_priv_key == NULL)
		goto err;
	generate_new_key = 1;
	}
	if (generate_new_key) {
		if (generate_new_priv_key(dh, new_priv_key) == OPENSSL_FAIL)
			goto err;
		else
			*priv_key = new_priv_key;
	}
	return OPENSSL_SUCCESS;
err:
	BN_free(new_priv_key);
	return OPENSSL_FAIL;
}

static __u32 dh_pick_next_ctx(handle_t sched_ctx, const void *req,
			      const struct sched_key *key)
{
	const struct wd_dh_req *dh_req = req;

	if (dh_req->cb)
		return CTX_ASYNC;
	else
		return CTX_SYNC;
}

int uadk_dh_poll(void *ctx)
{
	__u32 recv;
	int ret = 0;
	int expect = 1;
	int idx = SYNC_CTX_NUM;

	do {
		ret = wd_dh_poll_ctx(idx, expect, &recv);
		if (recv >= expect)
			return 0;
		else if (ret < 0 && ret != -EAGAIN)
			return ret;
	} while (ret == -EAGAIN);
	return ret;
}

static int dh_poll_policy(handle_t h_sched_ctx, __u32 expect, __u32 *count)
{
	return 0;
}

static void uadk_dh_cb(void *req_t)
{
}

struct dh_res_config dh_res_config = {
	.sched = {
		.sched_type = -1,
		.wd_sched = {
			.name = "dh-sched-0",
			.pick_next_ctx = dh_pick_next_ctx,
			.poll_policy = dh_poll_policy,
			.h_sched_ctx = 2,
		},
	},
};

static int uadk_wd_dh_ctx_init(struct dh_res_config *config, struct uacce_dev *dev)
{
	struct wd_sched *sched = &config->sched.wd_sched;
	struct wd_ctx_config *ctx_cfg;
	int ret, i;

	ctx_cfg = calloc(1, sizeof(struct wd_ctx_config));
	if (!ctx_cfg)
		return -ENOMEM;
	dh_res.ctx_res = ctx_cfg;

	ctx_cfg->ctx_num = CTX_NUM;
	ctx_cfg->ctxs = calloc(CTX_NUM, sizeof(struct wd_ctx));
	if (!ctx_cfg->ctxs) {
		ret = -ENOMEM;
		goto free_cfg;
	}

	for (i = 0; i < CTX_NUM; i++) {
		ctx_cfg->ctxs[i].ctx = wd_request_ctx(dev);
		if (!ctx_cfg->ctxs[i].ctx)
			goto free_ctx;
		ctx_cfg->ctxs[i].ctx_mode = (i == 0) ? CTX_SYNC : CTX_ASYNC;
	}

	ret = wd_dh_init(ctx_cfg, sched);
	if (ret)
		goto free_ctx;
	async_register_poll_fn(ASYNC_TASK_DH, uadk_dh_poll);
	return 0;

free_ctx:
	for (i = 0; i < CTX_NUM; i++) {
		if (ctx_cfg->ctxs[i].ctx) {
			wd_release_ctx(ctx_cfg->ctxs[i].ctx);
			ctx_cfg->ctxs[i].ctx = 0;
		}
	}
	free(ctx_cfg->ctxs);
free_cfg:
	free(ctx_cfg);
	return ret;
}

static void uadk_wd_dh_ctx_uninit(void)
{
	struct wd_ctx_config *ctx_cfg = dh_res.ctx_res;
	int i;

	if (dh_res.pid == getpid()) {
		wd_dh_uninit();
		for (i = 0; i < ctx_cfg->ctx_num; i++)
			wd_release_ctx(ctx_cfg->ctxs[i].ctx);
		free(ctx_cfg->ctxs);
		free(ctx_cfg);
	}
}

static void uadk_init_dh(void)
{
	struct uacce_dev *dev;

	if (dh_res.pid != getpid()) {
		dev = wd_get_accel_dev("dh");
		if (dev) {
			uadk_wd_dh_ctx_init(&dh_res_config, dev);
			free(dev);
		}
		dh_res.pid = getpid();
	}
}

static uadk_dh_sess_t *uadk_dh_new_eng_session(DH *dh_alg)
{
	uadk_dh_sess_t *dh_sess = NULL;

	dh_sess = (uadk_dh_sess_t *)OPENSSL_malloc(sizeof(uadk_dh_sess_t));
	if (dh_sess == NULL) {
		printf("\n%s, uadk engine session malloc failed.\n", __func__);
		return NULL;
	}
	memset(dh_sess, 0, sizeof(uadk_dh_sess_t));

	dh_sess->ssl_alg = dh_alg;
	return dh_sess;
}

static int uadk_dh_init_eng_session(uadk_dh_sess_t *dh_sess, int bits, bool is_g2)
{
	int key_size =  bits >> CHAR_BIT_SIZE;

	if (dh_sess->sess && dh_sess->req.x_p) {
		memset(dh_sess->req.x_p, 0, dh_sess->req.pbytes + dh_sess->req.xbytes);
		return OPENSSL_SUCCESS;
	}
	if (!dh_sess->sess) {
		if (bits == 0)
			dh_sess->key_size = DH_size(dh_sess->ssl_alg);
		else
			dh_sess->key_size = key_size;

		dh_sess->setup.key_bits = dh_sess->key_size << CHAR_BIT_SIZE;
		dh_sess->setup.is_g2 = is_g2;
		dh_sess->sess = wd_dh_alloc_sess(&dh_sess->setup);
		if (!dh_sess->sess) {
			printf("\n%s, alloc dh session failed.\n", __func__);
			return OPENSSL_FAIL;
		}
	}
	return OPENSSL_SUCCESS;
}

void uadk_dh_free_eng_session(uadk_dh_sess_t *dh_sess)
{
	if (dh_sess == NULL)
		return;
	if (dh_sess->sess != (handle_t)NULL)
		wd_dh_free_sess(dh_sess->sess);
	dh_sess->ssl_alg = NULL;
	dh_sess->req.pri = NULL;
	dh_sess->req.x_p = NULL;
	dh_sess->req.pv = NULL;
	OPENSSL_free(dh_sess);
	dh_sess = NULL;
}

uadk_dh_sess_t *uadk_dh_get_eng_session(DH *dh, int bits, bool is_g2)
{
	uadk_dh_sess_t *dh_sess = uadk_dh_new_eng_session(dh);

	if (dh_sess == NULL) {
		printf("\n%s, New engine sess failed.\n", __func__);
		return NULL;
	}
	if (uadk_dh_init_eng_session(dh_sess, bits, is_g2) == 0) {
		uadk_dh_free_eng_session(dh_sess);
		printf("\n%s, Init engine session failed.\n", __func__);
		return NULL;
	}
	return dh_sess;
}

static int check_dh_bit_useful(const int bit)
{
	switch (bit) {
	case DH768BITS:
	case DH1024BITS:
	case DH1536BITS:
	case DH2048BITS:
	case DH3072BITS:
	case DH4096BITS:
		return 1;
	default:
		break;
	}
	return 0;
}

static int prepare_dh_data(const int bits, const BIGNUM *g, DH *dh,
			   uadk_dh_sess_t **dh_sess, BIGNUM **priv_key)
{
	int ret = DH_SUCCESS;
	bool is_g2 = BN_is_word(g, DH_GENERATOR_2);

	if (!check_dh_bit_useful(bits)) {
		printf("\n%s, op size is not supported by uadk engine.\n", __func__);
		return DH_FAIL;
	}
	*dh_sess = uadk_dh_get_eng_session(dh, bits, is_g2);
	if (*dh_sess == NULL) {
		printf("\n%s, get eng ctx failed.\n", __func__);
		return DH_FAIL;
	}
	ret = uadk_dh_try_get_priv_key(dh, priv_key);
	if (ret != OPENSSL_SUCCESS || priv_key == NULL)
		return DH_FAIL;
	return ret;
}

static int uadk_dh_set_g(const BIGNUM *g, const int key_size, unsigned char *ag_bin,
			 uadk_dh_sess_t *dh_sess)
{
	struct wd_dtb g_dtb;
	__u32 gbytes;
	int ret;

	gbytes = BN_bn2bin(g, ag_bin);
	g_dtb.data = (char *)ag_bin;
	g_dtb.bsize = key_size;
	g_dtb.dsize = gbytes;
	ret = wd_dh_set_g(dh_sess->sess, &g_dtb);
	if (ret) {
		printf("wd_dh_set_g failed.\n");
		return DH_FAIL;
	}
	return DH_SUCCESS;
}

int uadk_dh_get_pubkey(uadk_dh_sess_t *dh_sess, BIGNUM **pubkey)
{
	const unsigned char *pubkey_str = (const unsigned char *)dh_sess->req.pri;

	if (pubkey_str == NULL)
		return DH_FAIL;
	*pubkey = BN_bin2bn(pubkey_str, dh_sess->req.pri_bytes, *pubkey);
	if (*pubkey == NULL)
		return DH_FAIL;
	return DH_SUCCESS;
}

/* ag_bin: The binary format of Alice's g parameter
 * ap_bin: The binary format of Alice's p parameter
 * apriv_key_bin: The binary format of Alice's private key x
 */
int uadk_dh_fill_genkey_req(const BIGNUM *g, const BIGNUM *p, const BIGNUM *priv_key,
			    uadk_dh_sess_t *dh_sess)
{
	int key_size = dh_sess->key_size;
	unsigned char *ag_bin = NULL; /* g */
	unsigned char *apriv_key_bin = NULL; /* x */
	unsigned char *ap_bin = NULL; /* p */
	unsigned char *out_pri = NULL; /* output from uadk */
	int ret;

	/* order: g, x(priv_key), p*/
	ag_bin = OPENSSL_malloc(key_size);
	apriv_key_bin =  OPENSSL_malloc(key_size * DH_PARAMS_CNT);
	ap_bin = apriv_key_bin + key_size;
	out_pri = ap_bin + key_size;
	memset(ag_bin, 0, key_size);
	memset(apriv_key_bin, 0, key_size);
	memset(ap_bin, 0, key_size);
	memset(out_pri, 0, key_size);

	/* construct data block of g */
	ret = uadk_dh_set_g(g, key_size, ag_bin, dh_sess);
	if (ret != DH_SUCCESS)
		goto err;
	dh_sess->req.xbytes = BN_bn2bin(priv_key, apriv_key_bin);
	dh_sess->req.pbytes = BN_bn2bin(p, ap_bin);
	dh_sess->req.x_p = (void *)apriv_key_bin;
	/* The output from uadk */
	dh_sess->req.pri = out_pri;
	dh_sess->req.pri_bytes = key_size;

	return DH_SUCCESS;
err:
	OPENSSL_free(ag_bin);
	OPENSSL_free(apriv_key_bin);
	return DH_FAIL;

}

int uadk_dh_fill_compkey_req(const BIGNUM *g, const BIGNUM *p, const BIGNUM *priv_key,
			     const BIGNUM *pub_key, uadk_dh_sess_t *dh_sess)
{
	int key_size = dh_sess->key_size;
	unsigned char *apriv_key_bin = NULL;
	unsigned char *ap_bin = NULL;
	unsigned char *ag_bin = NULL;
	unsigned char *out_pri = NULL;
	int ret;

	ag_bin = OPENSSL_malloc(key_size);
	apriv_key_bin = OPENSSL_malloc(key_size * DH_PARAMS_CNT);
	ap_bin = apriv_key_bin + key_size;
	out_pri = ap_bin + key_size;
	memset(ag_bin, 0, key_size);
	memset(apriv_key_bin, 0, key_size);
	memset(ap_bin, 0, key_size);
	memset(out_pri, 0, key_size);

	ret = uadk_dh_set_g(g, key_size, ag_bin, dh_sess);
	if (ret != DH_SUCCESS)
		goto err;
	dh_sess->req.x_p = apriv_key_bin;
	dh_sess->req.xbytes = BN_bn2bin(priv_key, apriv_key_bin);
	dh_sess->req.pbytes = BN_bn2bin(p, ap_bin);

	/* Phase 2:  it is PV */
	dh_sess->req.pv = ag_bin;
	dh_sess->req.pvbytes = BN_bn2bin(pub_key, ag_bin);
	dh_sess->req.pri = out_pri;
	dh_sess->req.pri_bytes = key_size;

	return DH_SUCCESS;
err:
	OPENSSL_free(ag_bin);
	OPENSSL_free(apriv_key_bin);
	return DH_FAIL;
}

static int uadk_dh_crypto(uadk_dh_sess_t *dh_sess, enum wd_dh_op_type op_type)
{
	int ret;
	struct async_op op;

	async_setup_async_event_notification(&op);
	dh_sess->req.op_type = op_type;
	if (op.job == NULL) {
		ret = wd_do_dh_sync(dh_sess->sess, &dh_sess->req);
		if (ret)
			return DH_FAIL;
	} else {
		dh_sess->req.cb = (void *)uadk_dh_cb;
		dh_sess->req.cb_param = dh_sess;
		do {
			ret = wd_do_dh_async(dh_sess->sess, &dh_sess->req);
			if (ret < 0 && ret != -EBUSY)
				goto err;
		} while (ret == -EBUSY);
		ret = async_pause_job(dh_sess, &op, ASYNC_TASK_DH);
		if (!ret)
			goto err;
	}
	return DH_SUCCESS;
err:
	(void)async_clear_async_event_notification();
	return 0;
}

void uadk_dh_soft_set_pkey(DH *dh, BIGNUM *pub_key, BIGNUM *priv_key)
{
	const BIGNUM *old_pub = DH_get0_pub_key(dh);
	const BIGNUM *old_priv = DH_get0_priv_key(dh);

	if (old_pub != pub_key && old_priv != priv_key)
		DH_set0_key(dh, pub_key, priv_key);
	else if (old_pub != pub_key)
		DH_set0_key(dh, pub_key, NULL);
	else if (old_priv != priv_key)
		DH_set0_key(dh, NULL, priv_key);
}

/* Main Phase1: Generate public key */
static int uadk_dh_generate_key(DH *dh)
{
	int bits = DH_bits(dh);
	const BIGNUM *p = NULL;
	const BIGNUM *g = NULL;
	const BIGNUM *q = NULL;
	BIGNUM *pub_key = NULL;
	BIGNUM *priv_key = NULL;
	uadk_dh_sess_t *dh_sess = NULL;
	int ret = DH_FAIL;

	uadk_init_dh();

	if (dh == NULL)
		return DH_FAIL;
	DH_get0_pqg(dh, &p, &q, &g);
	if (p == NULL || g == NULL)
		return DH_FAIL;
	if (q != NULL)
		goto end;

	/* Check whether bits exceeds the limit.
	 * The max module bits of openssl soft alg is OPENSSL_DH_MAX_MODULUS_BITS 10000.
	 * And OpenSSL speed tool supports 2048/3072/4096/6144/8192.
	 * But UADK supports 768/1024/1536/2048/3072/4096.
	 * UADK-engine will be consistent with UADK.
	 */
	if (bits != DH768BITS && bits != DH1024BITS &&
	    bits != DH1536BITS && bits != DH2048BITS &&
	    bits != DH3072BITS && bits != DH4096BITS) {
		printf("DH key size is not supported.\n"
			"Supported key size: 768/1024/1536/2048/3072/4096.\n"
			"When use speed tool, only support: 2048/3072/4096.\n");
		return DH_FAIL;
	}
	/* Get session and prepare private key */
	ret = prepare_dh_data(bits, g, dh, &dh_sess, &priv_key);
	if (ret != DH_SUCCESS) {
		printf("Prepare dh data failed.\n");
		goto end;
	}
	/* Fill request data */
	ret = uadk_dh_fill_genkey_req(g, p, priv_key, dh_sess);
	if (!ret) {
		printf("Fill req failed.\n");
		goto end;
	}
	/* Do generating key operation phase1 */
	ret = uadk_dh_crypto(dh_sess, WD_DH_PHASE1);
	if (!ret) {
		printf("Generate DH key failed.\n");
		goto end;
	}
	/* Get the generated public key from uadk(->hardware) */
	ret = uadk_dh_get_pubkey(dh_sess, &pub_key);
	if (!ret) {
		printf("Get public key failed.\n");
		goto end;
	}
	/* Set the public key and private key */
	uadk_dh_soft_set_pkey(dh, pub_key, priv_key);

	return ret;
end:
	if (pub_key != DH_get0_pub_key(dh))
		BN_free(pub_key);
	if (priv_key != DH_get0_priv_key(dh))
		BN_free(priv_key);
	uadk_dh_free_eng_session(dh_sess);
	return ret;
}

/* Main Phase2: Compute shared key */
static int uadk_dh_compute_key(unsigned char *key, const BIGNUM *pub_key, DH *dh)
{
	int bits = DH_bits(dh);
	const BIGNUM *p = NULL;
	const BIGNUM *g = NULL;
	const BIGNUM *q = NULL;
	BIGNUM *priv_key = NULL;
	uadk_dh_sess_t *dh_sess = NULL;
	int ret;
	int ret_size = 0;

	uadk_init_dh();

	if (dh == NULL || key == NULL || pub_key == NULL || DH_get0_priv_key(dh) == NULL)
		return DH_FAIL;
	DH_get0_pqg(dh, &p, &q, &g);
	if (p == NULL || g == NULL)
		return DH_FAIL;
	if (bits != DH768BITS && bits != DH1024BITS &&
	    bits != DH1536BITS && bits != DH2048BITS &&
	    bits != DH3072BITS && bits != DH4096BITS) {
		printf("DH key size is not supported.\n"
			"Supported key size: 768/1024/1536/2048/3072/4096.\n"
			"When use speed tool, only support: 2048/3072/4096.\n");
		return DH_FAIL;
	}
	ret = prepare_dh_data(bits, g, dh, &dh_sess, &priv_key);
	if (!ret) {
		printf("Prepare dh data failed.\n");
		goto end;
	}
	ret = uadk_dh_fill_compkey_req(g, p, priv_key, pub_key, dh_sess);
	if (ret != DH_SUCCESS) {
		printf("Fill req failed.\n");
		goto end;
	}
	/* Do generating shared key operation phase2 */
	ret = uadk_dh_crypto(dh_sess, WD_DH_PHASE2);
	if (!ret) {
		printf("Generate DH shared key failed. ret = %d\n", ret);
		goto end;
	}
	memcpy(key, dh_sess->req.pri, dh_sess->req.pri_bytes);
	ret_size = dh_sess->req.pri_bytes;

	return ret_size;

end:
	uadk_dh_free_eng_session(dh_sess);
	return ret_size;
}

static int uadk_dh_bn_mod_exp(const DH *dh, BIGNUM *r, const BIGNUM *a,
			      const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx,
			      BN_MONT_CTX *m_ctx)
{
	return BN_mod_exp_mont(r, a, p, m, ctx, m_ctx);
}

DH_METHOD *uadk_get_dh_methods(void)
{
	int ret;

	if (uadk_dh_method != NULL)
		return uadk_dh_method;
	uadk_dh_method = DH_meth_new("uadk hardware hpre dh method", 0);
	if (!uadk_dh_method) {
		printf("%s: allocate dh method failed\n", __func__);
		return NULL;
	}
	ret = DH_meth_set_generate_key(uadk_dh_method, uadk_dh_generate_key);
	ret = DH_meth_set_compute_key(uadk_dh_method, uadk_dh_compute_key);
	ret = DH_meth_set_bn_mod_exp(uadk_dh_method, uadk_dh_bn_mod_exp);

	if (!ret) {
		printf("%s: set DH method failed\n", __func__);
		return NULL;
	}
	return uadk_dh_method;
}

int uadk_bind_dh(ENGINE *e)
{
	return ENGINE_set_DH(e, uadk_get_dh_methods());
}

void uadk_destroy_dh(void)
{
	return uadk_wd_dh_ctx_uninit();
}
