/*
 * Copyright 2020-2022 Huawei Technologies Co.,Ltd. All rights reserved.
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
#include <uadk/wd_sched.h>
#include "uadk.h"
#include "uadk_async.h"

#define DH768BITS		768
#define DH1024BITS		1024
#define DH1536BITS		1536
#define DH2048BITS		2048
#define DH3072BITS		3072
#define DH4096BITS		4096
#define UADK_DH_MAX_MODULE_BIT	4096
#define DH_GENERATOR_2		2
#define DH_GENERATOR_5		5
#define CHAR_BIT_SIZE		3
#define DH_PARAMS_CNT		3
#define CTX_MODE_NUM		2
#define UN_SET			0
#define IS_SET			1
#define CTX_ASYNC		1
#define CTX_SYNC		0
#define CTX_NUM			2
#define UADK_DO_SOFT		(-0xE0)
#define UADK_E_SUCCESS		1
#define UADK_E_FAIL		0
#define UADK_E_POLL_SUCCESS	0
#define UADK_E_POLL_FAIL	(-1)
#define UADK_E_INIT_SUCCESS	0
#define ENV_ENABLED		1
#define KEY_GEN_BY_ENGINE	1

static DH_METHOD *uadk_dh_method;

struct bignum_st {
	BN_ULONG *d;
	int top;
	int dmax;
	int neg;
	int flags;
};

struct uadk_dh_sess {
	handle_t sess;
	struct wd_dh_sess_setup setup;
	struct wd_dh_req req;
	DH *alg;
	__u16 key_size;
	/* key_flag: 0 - key is defined by user, 1 - key is generated by engine */
	int key_flag;
};

struct dh_res {
	struct wd_ctx_config *ctx_res;
	int numa_id;
	int status;
	pthread_spinlock_t lock;
} g_dh_res;

struct dh_sched {
	int sched_type;
	struct wd_sched wd_sched;
};

struct dh_res_config {
	struct dh_sched sched;
};

static int uadk_e_dh_soft_generate_key(DH *dh)
{
	const DH_METHOD *uadk_dh_gen_soft = DH_OpenSSL();
	int (*dh_soft_generate_key)(DH *dh);
	int ret;

	if (!uadk_dh_gen_soft) {
		fprintf(stderr, "failed to get soft method\n");
		return UADK_E_FAIL;
	}

	dh_soft_generate_key = DH_meth_get_generate_key(uadk_dh_gen_soft);
	if (!dh_soft_generate_key) {
		fprintf(stderr, "failed to get soft function\n");
		return UADK_E_FAIL;
	}

	ret = dh_soft_generate_key(dh);
	if (ret < 0) {
		fprintf(stderr, "failed to do dh soft generate key\n");
		return UADK_E_FAIL;
	}

	return ret;
}

static int uadk_e_dh_soft_compute_key(unsigned char *key,
				      const BIGNUM *pub_key,
				      DH *dh)
{
	int (*dh_soft_compute_key)(unsigned char *key, const BIGNUM *pub_key,
				   DH *dh);
	const DH_METHOD *uadk_dh_comp_soft = DH_OpenSSL();
	int ret;

	if (!uadk_dh_comp_soft) {
		fprintf(stderr, "failed to get soft method.\n");
		return UADK_E_FAIL;
	}

	dh_soft_compute_key = DH_meth_get_compute_key(uadk_dh_comp_soft);
	if (!dh_soft_compute_key) {
		fprintf(stderr, "failed to get soft function.\n");
		return UADK_E_FAIL;
	}

	ret = dh_soft_compute_key(key, pub_key, dh);
	if (ret < 0) {
		fprintf(stderr, "failed to do dh soft compute key\n");
		return UADK_E_FAIL;
	}

	return ret;
}

static int dh_generate_new_priv_key(const DH *dh, BIGNUM *new_priv_key)
{
	const BIGNUM *q = DH_get0_q(dh);
	int bits;

	if (q) {
		do {
			if (!BN_priv_rand_range(new_priv_key, q))
				return UADK_E_FAIL;
		} while (BN_is_zero(new_priv_key) || BN_is_one(new_priv_key));
	} else {
		bits = DH_get_length(dh) ?
		       DH_get_length(dh) : BN_num_bits(DH_get0_p(dh)) - 1;
		if (!BN_priv_rand(new_priv_key, bits, BN_RAND_TOP_ONE,
				  BN_RAND_BOTTOM_ANY))
			return UADK_E_FAIL;
	}

	return UADK_E_SUCCESS;
}

static int dh_try_get_priv_key(struct uadk_dh_sess *dh_sess, const DH *dh, BIGNUM **priv_key)
{
	*priv_key = (BIGNUM *)DH_get0_priv_key(dh);
	if (!(*priv_key)) {
		*priv_key = BN_secure_new();
		if (!(*priv_key))
			return UADK_E_FAIL;

		if (!dh_generate_new_priv_key(dh, *priv_key))
			goto err;

		dh_sess->key_flag = KEY_GEN_BY_ENGINE;
	}

	return UADK_E_SUCCESS;

err:
	BN_free(*priv_key);
	return UADK_E_FAIL;
}

static handle_t dh_sched_init(handle_t h_sched_ctx, void *sched_param)
{
	return (handle_t)0;
}

static __u32 dh_pick_next_ctx(handle_t sched_ctx,
		void *sched_key, const int sched_mode)
{
	if (sched_mode)
		return CTX_ASYNC;
	else
		return CTX_SYNC;
}

static void uadk_e_dh_set_status(void)
{
	pthread_spin_lock(&g_dh_res.lock);
	g_dh_res.status = UADK_DEVICE_ERROR;
	pthread_spin_unlock(&g_dh_res.lock);
}

static int uadk_e_dh_poll(void *ctx)
{
	__u64 rx_cnt = 0;
	__u32 recv = 0;
	int expt = 1;
	int idx = 1;
	int ret;

	do {
		ret = wd_dh_poll_ctx(idx, expt, &recv);
		if (!ret && recv == expt) {
			return UADK_E_POLL_SUCCESS;
		} else if (ret == -EAGAIN) {
			rx_cnt++;
		} else {
			if (ret == -WD_HW_EACCESS)
				uadk_e_dh_set_status();
			return UADK_E_POLL_FAIL;
		}
	} while (rx_cnt < ENGINE_RECV_MAX_CNT);

	fprintf(stderr, "failed to recv msg: timeout!\n");

	return -ETIMEDOUT;
}

static void uadk_e_dh_cb(void *req_t)
{
	struct wd_dh_req *req_new = (struct wd_dh_req *)req_t;
	struct uadk_e_cb_info *cb_param;
	struct wd_dh_req *req_origin;
	struct async_op *op;

	if (!req_new)
		return;

	cb_param = req_new->cb_param;
	if (!cb_param)
		return;

	req_origin = cb_param->priv;
	if (!req_origin)
		return;

	req_origin->status = req_new->status;
	if (!req_origin->status)
		req_origin->pri_bytes = req_new->pri_bytes;

	op = cb_param->op;
	if (op && op->job && !op->done) {
		op->done = 1;
		async_free_poll_task(op->idx, 1);
		(void) async_wake_job(op->job);
	}
}

static int dh_poll_policy(handle_t h_sched_ctx, __u32 expect, __u32 *count)
{
	return UADK_E_POLL_SUCCESS;
}

static struct dh_res_config dh_res_config = {
	.sched = {
		.sched_type = -1,
		.wd_sched = {
			.name = "dh-sched-0",
			.sched_init = dh_sched_init,
			.pick_next_ctx = dh_pick_next_ctx,
			.poll_policy = dh_poll_policy,
			.h_sched_ctx = 2,
		},
	},
};

static int uadk_e_dh_env_poll(void *ctx)
{
	__u64 rx_cnt = 0;
	__u32 recv = 0;
	/* Poll one packet currently */
	int expt = 1;
	int ret;

	do {
		ret = wd_dh_poll(expt, &recv);
		if (ret < 0 || recv == expt) {
			if (ret == -WD_HW_EACCESS)
				uadk_e_dh_set_status();
			return ret;
		}
		rx_cnt++;
	} while (rx_cnt < ENGINE_ENV_RECV_MAX_CNT);

	fprintf(stderr, "failed to poll msg: timeout!\n");

	return -ETIMEDOUT;
}

static int uadk_e_wd_dh_env_init(struct uacce_dev *dev)
{
	int ret;

	ret = uadk_e_set_env("WD_DH_CTX_NUM", dev->numa_id);
	if (ret)
		return ret;

	ret = wd_dh_env_init(NULL);
	if (ret)
		return ret;

	async_register_poll_fn(ASYNC_TASK_DH, uadk_e_dh_env_poll);

	return 0;
}

static int uadk_e_wd_dh_init(struct dh_res_config *config, struct uacce_dev *dev)
{
	struct wd_sched *sched = &config->sched.wd_sched;
	struct wd_ctx_config *ctx_cfg;
	int ret = 0;
	__u32 i;

	ret = uadk_e_is_env_enabled("dh");
	if (ret == ENV_ENABLED)
		return uadk_e_wd_dh_env_init(dev);

	ctx_cfg = calloc(1, sizeof(struct wd_ctx_config));
	if (!ctx_cfg)
		return -ENOMEM;
	g_dh_res.ctx_res = ctx_cfg;

	ctx_cfg->ctx_num = CTX_NUM;
	ctx_cfg->ctxs = calloc(CTX_NUM, sizeof(struct wd_ctx));
	if (!ctx_cfg->ctxs) {
		ret = -ENOMEM;
		goto free_cfg;
	}

	for (i = 0; i < CTX_NUM; i++) {
		ctx_cfg->ctxs[i].ctx = wd_request_ctx(dev);
		if (!ctx_cfg->ctxs[i].ctx) {
			ret = -ENOMEM;
			goto free_ctx;
		}
		ctx_cfg->ctxs[i].ctx_mode = (i == 0) ? CTX_SYNC : CTX_ASYNC;
	}

	ret = wd_dh_init(ctx_cfg, sched);
	if (ret)
		goto free_ctx;

	async_register_poll_fn(ASYNC_TASK_DH, uadk_e_dh_poll);

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

static int uadk_e_dh_init(void)
{
	struct uacce_dev *dev;
	int ret;

	if (g_dh_res.status != UADK_UNINIT)
		return g_dh_res.status;

	pthread_spin_lock(&g_dh_res.lock);
	if (g_dh_res.status != UADK_UNINIT)
		goto unlock;

	dev = wd_get_accel_dev("dh");
	if (!dev) {
		fprintf(stderr, "no device available, switch to software!\n");
		goto err_init;
	}

	ret = uadk_e_wd_dh_init(&dh_res_config, dev);
	if (ret) {
		fprintf(stderr, "device unavailable(%d), switch to software!\n", ret);
		goto err_init;
	}

	g_dh_res.numa_id = dev->numa_id;
	g_dh_res.status = UADK_INIT_SUCCESS;
	pthread_spin_unlock(&g_dh_res.lock);
	free(dev);

	return g_dh_res.status;

err_init:
	g_dh_res.status = UADK_INIT_FAIL;
	if (dev)
		free(dev);
unlock:
	pthread_spin_unlock(&g_dh_res.lock);

	return g_dh_res.status;
}

static void uadk_e_wd_dh_uninit(void)
{
	struct wd_ctx_config *ctx_cfg = g_dh_res.ctx_res;
	__u32 i;
	int ret;

	if (g_dh_res.status == UADK_UNINIT)
		return;

	if (g_dh_res.status == UADK_INIT_FAIL)
		goto clear_status;

	ret = uadk_e_is_env_enabled("dh");
	if (ret == ENV_ENABLED) {
		wd_dh_env_uninit();
	} else {
		wd_dh_uninit();
		for (i = 0; i < ctx_cfg->ctx_num; i++)
			wd_release_ctx(ctx_cfg->ctxs[i].ctx);

		free(ctx_cfg->ctxs);
		free(ctx_cfg);
	}

clear_status:
	g_dh_res.status = UADK_UNINIT;
}

static struct uadk_dh_sess *dh_new_eng_session(DH *dh_alg)
{
	struct uadk_dh_sess *dh_sess;

	dh_sess = OPENSSL_malloc(sizeof(struct uadk_dh_sess));
	if (!dh_sess)
		return NULL;

	memset(dh_sess, 0, sizeof(struct uadk_dh_sess));

	dh_sess->alg = dh_alg;

	return dh_sess;
}

static int dh_init_eng_session(struct uadk_dh_sess *dh_sess,
			       __u16 bits, bool is_g2)
{
	__u16 key_size = bits >> CHAR_BIT_SIZE;
	struct sched_params params = {0};

	if (dh_sess->sess && dh_sess->req.x_p) {
		memset(dh_sess->req.x_p, 0, dh_sess->req.pbytes +
		       dh_sess->req.xbytes);
		return UADK_E_SUCCESS;
	}

	if (!dh_sess->sess) {
		dh_sess->key_size = key_size;
		dh_sess->setup.key_bits = bits;
		dh_sess->setup.is_g2 = is_g2;
		params.numa_id = g_dh_res.numa_id;
		dh_sess->setup.sched_param = &params;
		dh_sess->sess = wd_dh_alloc_sess(&dh_sess->setup);
		if (!dh_sess->sess)
			return UADK_E_FAIL;
	}

	return UADK_E_SUCCESS;
}

static void dh_free_eng_session(struct uadk_dh_sess *dh_sess)
{
	if (!dh_sess)
		return;

	if (dh_sess->sess)
		wd_dh_free_sess(dh_sess->sess);

	if (dh_sess->req.x_p)
		OPENSSL_free(dh_sess->req.x_p);

	if (dh_sess->req.pv)
		OPENSSL_free(dh_sess->req.pv);

	OPENSSL_free(dh_sess);
}

static struct uadk_dh_sess *dh_get_eng_session(DH *dh, __u16 bits,
					       bool is_g2)
{
	struct uadk_dh_sess *dh_sess = dh_new_eng_session(dh);
	int ret;

	if (!dh_sess)
		return NULL;

	ret = dh_init_eng_session(dh_sess, bits, is_g2);
	if (!ret) {
		dh_free_eng_session(dh_sess);
		return NULL;
	}

	return dh_sess;
}

static int check_dh_bit_useful(const __u16 bits)
{
	/*
	 * Check whether bits exceeds the limit.
	 * The max module bits of openssl soft alg is
	 * OPENSSL_DH_MAX_MODULUS_BITS, 10000 bits.
	 * OpenSSL speed tool supports 2048/3072/4096/6144/8192 bits.
	 * UADK supports 768/1024/1536/2048/3072/4096 bits.
	 * UADK-engine will be consistent with UADK.
	 */
	switch (bits) {
	case DH768BITS:
	case DH1024BITS:
	case DH1536BITS:
	case DH2048BITS:
	case DH3072BITS:
	case DH4096BITS:
		return UADK_E_SUCCESS;
	default:
		break;
	}

	return UADK_E_FAIL;
}

static int dh_prepare_data(const BIGNUM *g, DH *dh,
			   struct uadk_dh_sess **dh_sess,
			   BIGNUM **priv_key)
{
	bool is_g2 = BN_is_word(g, DH_GENERATOR_2);
	__u16 bits;
	int ret;

	/*
	 * The max module bits of DH is
	 * OPENSSL_DH_MAX_MODULUS_BITS, 10000 bits.
	 */
	bits = (__u16)DH_bits(dh);
	ret = check_dh_bit_useful(bits);
	if (!ret) {
		fprintf(stderr, "op size is not supported by uadk engine\n");
		return UADK_E_FAIL;
	}

	*dh_sess = dh_get_eng_session(dh, bits, is_g2);
	if (!(*dh_sess)) {
		fprintf(stderr, "failed to get eng ctx\n");
		return UADK_E_FAIL;
	}

	ret = dh_try_get_priv_key(*dh_sess, dh, priv_key);
	if (!ret) {
		dh_free_eng_session(*dh_sess);
		return UADK_E_FAIL;
	}

	return ret;
}

static int dh_set_g(const BIGNUM *g, const __u16 key_size,
		    unsigned char *ag_bin, struct uadk_dh_sess *dh_sess)
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
		fprintf(stderr, "failed to set dh g\n");
		return UADK_E_FAIL;
	}

	return UADK_E_SUCCESS;
}

static int dh_get_pubkey(struct uadk_dh_sess *dh_sess, BIGNUM **pubkey)
{
	const unsigned char *pubkey_str;

	pubkey_str = (const unsigned char *)dh_sess->req.pri;
	if (!pubkey_str)
		return UADK_E_FAIL;

	*pubkey = BN_bin2bn(pubkey_str, dh_sess->req.pri_bytes, *pubkey);
	if (!(*pubkey))
		return UADK_E_FAIL;

	return UADK_E_SUCCESS;
}

static int dh_fill_genkey_req(const BIGNUM *g, const BIGNUM *p,
			      const BIGNUM *priv_key,
			      struct uadk_dh_sess *dh_sess)
{
	__u16 key_size = dh_sess->key_size;
	unsigned char *apriv_key_bin;
	unsigned char *ag_bin;
	unsigned char *ap_bin;
	unsigned char *out_pri;
	int ret;

	ag_bin = OPENSSL_malloc(key_size);
	if (!ag_bin)
		return UADK_E_FAIL;

	/* Malloc a contiguous chunk of memory */
	apriv_key_bin =  OPENSSL_malloc(key_size * DH_PARAMS_CNT);
	if (!apriv_key_bin)
		goto free_ag;

	ap_bin = apriv_key_bin + key_size;
	out_pri = ap_bin + key_size;
	memset(ag_bin, 0, key_size);
	memset(apriv_key_bin, 0, key_size);
	memset(ap_bin, 0, key_size);
	memset(out_pri, 0, key_size);

	/* Construct data block of g */
	ret = dh_set_g(g, key_size, ag_bin, dh_sess);
	if (!ret)
		goto free_apriv;

	dh_sess->req.xbytes = BN_bn2bin(priv_key, apriv_key_bin);
	dh_sess->req.pbytes = BN_bn2bin(p, ap_bin);
	dh_sess->req.x_p = (void *)apriv_key_bin;
	dh_sess->req.pri = out_pri;
	dh_sess->req.pri_bytes = key_size;
	dh_sess->req.op_type = WD_DH_PHASE1;

	OPENSSL_free(ag_bin);

	return ret;

free_apriv:
	OPENSSL_free(apriv_key_bin);
free_ag:
	OPENSSL_free(ag_bin);
	return UADK_E_FAIL;
}

static int dh_fill_compkey_req(const BIGNUM *g, const BIGNUM *p,
			       const BIGNUM *priv_key, const BIGNUM *pub_key,
			       struct uadk_dh_sess *dh_sess)
{
	__u16 key_size = dh_sess->key_size;
	unsigned char *apriv_key_bin;
	unsigned char *ap_bin;
	unsigned char *ag_bin;
	unsigned char *out_pri;
	int ret;

	ag_bin = OPENSSL_malloc(key_size);
	if (!ag_bin)
		return UADK_E_FAIL;

	apriv_key_bin = OPENSSL_malloc(key_size * DH_PARAMS_CNT);
	if (!apriv_key_bin)
		goto free_ag;

	ap_bin = apriv_key_bin + key_size;
	out_pri = ap_bin + key_size;
	memset(ag_bin, 0, key_size);
	memset(apriv_key_bin, 0, key_size);
	memset(ap_bin, 0, key_size);
	memset(out_pri, 0, key_size);

	ret = dh_set_g(g, key_size, ag_bin, dh_sess);
	if (!ret)
		goto free_apriv;

	dh_sess->req.x_p = apriv_key_bin;
	dh_sess->req.xbytes = BN_bn2bin(priv_key, apriv_key_bin);
	dh_sess->req.pbytes = BN_bn2bin(p, ap_bin);

	dh_sess->req.pv = ag_bin;
	dh_sess->req.pvbytes = BN_bn2bin(pub_key, ag_bin);
	dh_sess->req.pri = out_pri;
	dh_sess->req.pri_bytes = key_size;
	dh_sess->req.op_type = WD_DH_PHASE2;

	return ret;

free_apriv:
	OPENSSL_free(apriv_key_bin);
free_ag:
	OPENSSL_free(ag_bin);
	return UADK_E_FAIL;
}

static int dh_do_sync(struct uadk_dh_sess *dh_sess)
{
	int ret;

	ret = wd_do_dh_sync(dh_sess->sess, &dh_sess->req);
	if (ret) {
		if (ret == -WD_HW_EACCESS)
			uadk_e_dh_set_status();
		return UADK_E_FAIL;
	}

	return UADK_E_SUCCESS;
}

static int dh_do_async(struct uadk_dh_sess *dh_sess, struct async_op *op)
{
	struct uadk_e_cb_info *cb_param;
	int ret = 0;
	int cnt = 0;
	int idx;

	cb_param = malloc(sizeof(struct uadk_e_cb_info));
	if (!cb_param) {
		fprintf(stderr, "failed to alloc cb_param.\n");
		return ret;
	}

	cb_param->op = op;
	cb_param->priv = &dh_sess->req;
	dh_sess->req.cb = uadk_e_dh_cb;
	dh_sess->req.cb_param = cb_param;
	dh_sess->req.status = -1;
	ret = async_get_free_task(&idx);
	if (!ret)
		goto free_cb_param;

	op->idx = idx;
	do {
		ret = wd_do_dh_async(dh_sess->sess, &dh_sess->req);
		if (unlikely(ret < 0)) {
			if (unlikely(ret == -WD_HW_EACCESS))
				uadk_e_dh_set_status();
			else if (unlikely(cnt++ > ENGINE_SEND_MAX_CNT))
				fprintf(stderr, "do dh async operation timeout.\n");
			else
				continue;

			async_free_poll_task(op->idx, 0);
			ret = UADK_E_FAIL;
			goto free_cb_param;
		}
	} while (ret == -EBUSY);

	ret = async_pause_job(dh_sess, op, ASYNC_TASK_DH);
	if (!ret)
		goto free_cb_param;

	if (dh_sess->req.status) {
		ret = UADK_E_FAIL;
		goto free_cb_param;
	}

free_cb_param:
	free(cb_param);
	dh_sess->req.cb_param = NULL;
	return ret;
}

static int dh_do_crypto(struct uadk_dh_sess *dh_sess)
{
	struct async_op op;
	int ret = 0;

	ret = async_setup_async_event_notification(&op);
	if (!ret) {
		printf("failed to setup async event notification.\n");
		return ret;
	}

	if (!op.job) {
		ret = dh_do_sync(dh_sess);
		return ret;
	}

	ret = dh_do_async(dh_sess, &op);
	(void)async_clear_async_event_notification();

	return ret;
}

static int dh_soft_set_pkey(DH *dh, BIGNUM *pub_key, BIGNUM *priv_key)
{
	const BIGNUM *old_pub = DH_get0_pub_key(dh);
	const BIGNUM *old_priv = DH_get0_priv_key(dh);

	if (old_pub != pub_key && old_priv != priv_key)
		DH_set0_key(dh, pub_key, priv_key);
	else if (old_pub != pub_key)
		DH_set0_key(dh, pub_key, NULL);
	else if (old_priv != priv_key)
		DH_set0_key(dh, NULL, priv_key);

	return UADK_E_SUCCESS;
}

static int uadk_e_dh_generate_key(DH *dh)
{
	struct uadk_dh_sess *dh_sess = NULL;
	BIGNUM *priv_key = NULL;
	BIGNUM *pub_key = NULL;
	const BIGNUM *p = NULL;
	const BIGNUM *g = NULL;
	const BIGNUM *q = NULL;
	int ret;

	if (!dh)
		return UADK_E_FAIL;

	ret = uadk_e_dh_init();
	if (ret != UADK_INIT_SUCCESS)
		goto exe_soft;

	DH_get0_pqg(dh, &p, &q, &g);
	if (!p || !g || q)
		return UADK_E_FAIL;

	/* Get session and prepare private key */
	ret = dh_prepare_data(g, dh, &dh_sess, &priv_key);
	if (!ret) {
		fprintf(stderr, "prepare dh data failed\n");
		goto soft_log;
	}

	ret = dh_fill_genkey_req(g, p, priv_key, dh_sess);
	if (!ret) {
		fprintf(stderr, "failed to fill req\n");
		goto free_data;
	}

	ret = dh_do_crypto(dh_sess);
	if (!ret) {
		fprintf(stderr, "failed to generate DH key\n");
		goto free_data;
	}

	ret = dh_get_pubkey(dh_sess, &pub_key);
	if (!ret) {
		fprintf(stderr, "failed to get public key\n");
		goto free_data;
	}

	ret = dh_soft_set_pkey(dh, pub_key, priv_key);
	dh_free_eng_session(dh_sess);

	return ret;

free_data:
	if (dh_sess->key_flag == KEY_GEN_BY_ENGINE)
		BN_clear_free(priv_key);
	dh_free_eng_session(dh_sess);
soft_log:
	fprintf(stderr, "switch to execute openssl software calculation.\n");
exe_soft:
	return uadk_e_dh_soft_generate_key(dh);
}

static int uadk_e_dh_compute_key(unsigned char *key, const BIGNUM *pub_key,
				 DH *dh)
{
	struct uadk_dh_sess *dh_sess = NULL;
	BIGNUM *priv_key = NULL;
	const BIGNUM *p = NULL;
	const BIGNUM *g = NULL;
	const BIGNUM *q = NULL;
	int ret;

	if (!dh || !key || !pub_key || !DH_get0_priv_key(dh))
		return UADK_E_FAIL;

	ret = uadk_e_dh_init();
	if (ret != UADK_INIT_SUCCESS)
		goto exe_soft;

	DH_get0_pqg(dh, &p, &q, &g);
	if (!p || !g)
		return UADK_E_FAIL;

	ret = dh_prepare_data(g, dh, &dh_sess, &priv_key);
	if (!ret) {
		fprintf(stderr, "failed to prepare dh data\n");
		goto soft_log;
	}

	ret = dh_fill_compkey_req(g, p, priv_key, pub_key, dh_sess);
	if (!ret) {
		fprintf(stderr, "failed to fill req\n");
		goto free_data;
	}

	ret = dh_do_crypto(dh_sess);
	if (!ret) {
		fprintf(stderr, "failed to generate DH shared key\n");
		goto free_data;
	}

	memcpy(key, dh_sess->req.pri, dh_sess->req.pri_bytes);
	ret = dh_sess->req.pri_bytes;
	dh_free_eng_session(dh_sess);

	return ret;

free_data:
	if (dh_sess->key_flag == KEY_GEN_BY_ENGINE)
		BN_free(priv_key);
	dh_free_eng_session(dh_sess);
soft_log:
	fprintf(stderr, "switch to execute openssl software calculation.\n");
exe_soft:
	return uadk_e_dh_soft_compute_key(key, pub_key, dh);
}

static int uadk_e_dh_bn_mod_exp(const DH *dh, BIGNUM *r, const BIGNUM *a,
				const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx,
				BN_MONT_CTX *m_ctx)
{
	return BN_mod_exp_mont(r, a, p, m, ctx, m_ctx);
}

static DH_METHOD *uadk_e_get_dh_methods(void)
{
	if (uadk_dh_method)
		return uadk_dh_method;

	uadk_dh_method = DH_meth_new("uadk hardware dh method", 0);
	if (!uadk_dh_method) {
		fprintf(stderr, "failed to allocate dh method\n");
		return NULL;
	}

	(void)DH_meth_set_generate_key(uadk_dh_method, uadk_e_dh_generate_key);
	(void)DH_meth_set_compute_key(uadk_dh_method, uadk_e_dh_compute_key);
	(void)DH_meth_set_bn_mod_exp(uadk_dh_method, uadk_e_dh_bn_mod_exp);

	return uadk_dh_method;
}

static void uadk_e_delete_dh_meth(void)
{
	if (!uadk_dh_method)
		return;

	DH_meth_free(uadk_dh_method);
	uadk_dh_method = NULL;
}

int uadk_e_bind_dh(ENGINE *e)
{
	return ENGINE_set_DH(e, uadk_e_get_dh_methods());
}

void uadk_e_destroy_dh(void)
{
	pthread_spin_destroy(&g_dh_res.lock);
	uadk_e_delete_dh_meth();
	uadk_e_wd_dh_uninit();
}

static void uadk_e_dh_clear_status(void)
{
	g_dh_res.status = UADK_UNINIT;
}

void uadk_e_dh_lock_init(void)
{
	pthread_atfork(NULL, NULL, uadk_e_dh_clear_status);
	pthread_spin_init(&g_dh_res.lock, PTHREAD_PROCESS_PRIVATE);
}
