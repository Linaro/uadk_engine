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
#include "uadk_prov_rsa.h"

#define UN_SET				0
#define IS_SET				1
#define RSA_MIN_MODULUS_BITS		512
#define RSA1024BITS			1024
#define RSA2048BITS			2048
#define RSA3072BITS			3072
#define RSA4096BITS			4096
#define OPENSSLRSA7680BITS		7680
#define OPENSSLRSA15360BITS		15360
#define UADK_P_INIT_SUCCESS		0

static struct rsa_prov g_rsa_prov;
static pthread_mutex_t rsa_mutex = PTHREAD_MUTEX_INITIALIZER;

int uadk_rsa_test_flags(const RSA *r, int flags)
{
	return r->flags & flags;
}

static int uadk_rsa_get_version(RSA *r)
{
	/* { two-prime(0), multi(1) } */
	return r->version;
}

static void uadk_rsa_get0_factors(const RSA *r, const BIGNUM **p,
				  const BIGNUM **q)
{
	if (p != NULL)
		*p = r->p;
	if (q != NULL)
		*q = r->q;
}

static void uadk_rsa_get0_crt_params(const RSA *r, const BIGNUM **dmp1,
				     const BIGNUM **dmq1, const BIGNUM **iqmp)
{
	if (dmp1 != NULL)
		*dmp1 = r->dmp1;
	if (dmq1 != NULL)
		*dmq1 = r->dmq1;
	if (iqmp != NULL)
		*iqmp = r->iqmp;
}

int check_rsa_is_crt(RSA *rsa)
{
	const BIGNUM *p = NULL;
	const BIGNUM *q = NULL;
	const BIGNUM *dmp1 = NULL;
	const BIGNUM *dmq1 = NULL;
	const BIGNUM *iqmp = NULL;
	int version;

	if (uadk_rsa_test_flags(rsa, RSA_FLAG_EXT_PKEY))
		return IS_SET;

	version = uadk_rsa_get_version(rsa);
	if (version == RSA_ASN1_VERSION_MULTI)
		return IS_SET;

	uadk_rsa_get0_factors(rsa, &p, &q);
	uadk_rsa_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);
	if ((p != NULL) && (q != NULL) && (dmp1 != NULL) &&
	    (dmq1 != NULL) && (iqmp != NULL))
		return IS_SET;

	return UN_SET;
}

int rsa_fill_prikey(RSA *rsa, struct uadk_rsa_sess *rsa_sess,
			   struct rsa_prikey_param *pri,
			   unsigned char *in_buf, unsigned char *to)
{
	struct wd_rsa_prikey *prikey = NULL;
	struct wd_dtb *wd_qinv = NULL;
	struct wd_dtb *wd_dp = NULL;
	struct wd_dtb *wd_dq = NULL;
	struct wd_dtb *wd_p = NULL;
	struct wd_dtb *wd_q = NULL;
	struct wd_dtb *wd_n = NULL;
	struct wd_dtb *wd_d = NULL;

	if (!rsa_sess->is_prikey_ready && pri->is_crt) {
		wd_rsa_get_prikey(rsa_sess->sess, &prikey);
		if (!prikey)
			return UADK_P_FAIL;

		wd_rsa_get_crt_prikey_params(prikey, &wd_dq, &wd_dp,
					     &wd_qinv, &wd_q, &wd_p);
		if (!wd_dq || !wd_dp || !wd_qinv || !wd_q || !wd_p)
			return UADK_P_FAIL;

		wd_dp->dsize = BN_bn2bin(pri->dmp1,
					 (unsigned char *)wd_dp->data);
		wd_dq->dsize = BN_bn2bin(pri->dmq1,
					 (unsigned char *)wd_dq->data);
		wd_p->dsize = BN_bn2bin(pri->p,
					(unsigned char *)wd_p->data);
		wd_q->dsize = BN_bn2bin(pri->q,
					(unsigned char *)wd_q->data);
		wd_qinv->dsize = BN_bn2bin(pri->iqmp,
					   (unsigned char *)wd_qinv->data);
	} else if (!rsa_sess->is_prikey_ready && !pri->is_crt) {
		wd_rsa_get_prikey(rsa_sess->sess, &prikey);
		if (!prikey)
			return UADK_P_FAIL;

		wd_rsa_get_prikey_params(prikey, &wd_d, &wd_n);
		if (!wd_d || !wd_n)
			return UADK_P_FAIL;

		wd_n->dsize = BN_bn2bin(pri->n,
					(unsigned char *)wd_n->data);
		wd_d->dsize = BN_bn2bin(pri->d,
					(unsigned char *)wd_d->data);
	} else {
		return UADK_P_FAIL;
	}

	rsa_sess->is_prikey_ready = IS_SET;
	rsa_sess->req.op_type = WD_RSA_SIGN;
	rsa_sess->req.src_bytes = rsa_sess->key_size;
	rsa_sess->req.dst_bytes = rsa_sess->key_size;
	rsa_sess->req.src = in_buf;
	rsa_sess->req.dst = to;

	return UADK_P_SUCCESS;
}

int rsa_fill_pubkey(struct rsa_pubkey_param *pubkey_param,
			   struct uadk_rsa_sess *rsa_sess,
			   unsigned char *in_buf, unsigned char *to)
{
	struct wd_rsa_pubkey *pubkey = NULL;
	struct wd_dtb *wd_n = NULL;
	struct wd_dtb *wd_e = NULL;

	if (!rsa_sess->is_pubkey_ready) {
		wd_rsa_get_pubkey(rsa_sess->sess, &pubkey);
		if (!pubkey)
			return UADK_P_FAIL;

		wd_rsa_get_pubkey_params(pubkey, &wd_e, &wd_n);
		if (!wd_n || !wd_e)
			return UADK_P_FAIL;

		wd_n->dsize = BN_bn2bin(pubkey_param->n,
					(unsigned char *)wd_n->data);
		wd_e->dsize = BN_bn2bin(pubkey_param->e,
					(unsigned char *)wd_e->data);
		rsa_sess->req.src_bytes = rsa_sess->key_size;
		rsa_sess->req.dst_bytes = rsa_sess->key_size;
		rsa_sess->req.op_type = WD_RSA_VERIFY;
		rsa_sess->is_pubkey_ready = IS_SET;
		rsa_sess->req.src = in_buf;
		rsa_sess->req.dst = to;

		return UADK_P_SUCCESS;
	}

	return UADK_P_FAIL;
}

static int uadk_rsa_env_poll(void *ctx)
{
	__u64 rx_cnt = 0;
	__u32 recv = 0;
	/* Poll one packet currently */
	int expt = 1;
	int ret;

	do {
		ret = wd_rsa_poll(expt, &recv);
		if (ret < 0 || recv == expt)
			return ret;
		rx_cnt++;
	} while (rx_cnt < PROV_SCH_RECV_MAX_CNT);

	UADK_ERR("failed to poll msg: timeout!\n");

	return -ETIMEDOUT;
}

static void uadk_rsa_mutex_infork(void)
{
	/* Release the replication lock of the child process */
	pthread_mutex_unlock(&rsa_mutex);
}

int uadk_prov_rsa_init(void)
{
	char alg_name[] = "rsa";
	int ret;

	pthread_atfork(NULL, NULL, uadk_rsa_mutex_infork);
	pthread_mutex_lock(&rsa_mutex);
	if (g_rsa_prov.pid != getpid()) {
		ret = wd_rsa_init2(alg_name, SCHED_POLICY_RR, TASK_MIX);
		if (unlikely(ret)) {
			pthread_mutex_unlock(&rsa_mutex);
			return ret;
		}
		g_rsa_prov.pid = getpid();
		async_register_poll_fn(ASYNC_TASK_RSA, uadk_rsa_env_poll);
	}
	pthread_mutex_unlock(&rsa_mutex);

	return UADK_P_INIT_SUCCESS;
}

void uadk_prov_destroy_rsa(void)
{
	pthread_mutex_lock(&rsa_mutex);
	if (g_rsa_prov.pid == getpid()) {
		wd_rsa_uninit2();
		g_rsa_prov.pid = 0;
	}
	pthread_mutex_unlock(&rsa_mutex);
}

static struct uadk_rsa_sess *rsa_new_eng_session(RSA *rsa)
{
	struct uadk_rsa_sess *rsa_sess;

	rsa_sess = OPENSSL_malloc(sizeof(struct uadk_rsa_sess));
	if (!rsa_sess)
		return NULL;

	memset(rsa_sess, 0, sizeof(struct uadk_rsa_sess));
	rsa_sess->alg = rsa;
	rsa_sess->is_pubkey_ready = UN_SET;
	rsa_sess->is_prikey_ready = UN_SET;

	return rsa_sess;
}

void rsa_free_eng_session(struct uadk_rsa_sess *rsa_sess)
{
	if (!rsa_sess)
		return;

	rsa_sess->alg = NULL;
	rsa_sess->is_pubkey_ready = UN_SET;
	rsa_sess->is_prikey_ready = UN_SET;

	wd_rsa_free_sess(rsa_sess->sess);
	OPENSSL_free(rsa_sess);
}

struct uadk_rsa_sess *rsa_get_eng_session(RSA *rsa, unsigned int bits,
						 int is_crt)
{
	unsigned int key_size =  bits >> BIT_BYTES_SHIFT;
	struct sched_params params = {0};
	struct uadk_rsa_sess *rsa_sess;

	rsa_sess = rsa_new_eng_session(rsa);
	if (!rsa_sess)
		return NULL;

	rsa_sess->key_size = key_size;
	rsa_sess->setup.key_bits = key_size << BIT_BYTES_SHIFT;

	/* Use the default numa parameters */
	params.numa_id = -1;
	rsa_sess->setup.sched_param = &params;
	rsa_sess->setup.is_crt = is_crt;

	rsa_sess->sess = wd_rsa_alloc_sess(&rsa_sess->setup);
	if (!rsa_sess->sess) {
		rsa_free_eng_session(rsa_sess);
		return NULL;
	}

	return rsa_sess;
}

static void uadk_e_rsa_cb(void *req_t)
{
	struct wd_rsa_req *req = (struct wd_rsa_req *)req_t;
	struct uadk_e_cb_info *cb_param;
	struct wd_rsa_req *req_origin;
	struct async_op *op;

	if (!req)
		return;

	cb_param = req->cb_param;
	if (!cb_param)
		return;

	req_origin = cb_param->priv;
	if (!req_origin)
		return;

	req_origin->status = req->status;

	op = cb_param->op;
	if (op && op->job && !op->done) {
		op->done = 1;
		async_free_poll_task(op->idx, 1);
		(void) async_wake_job(op->job);
	}
}

int rsa_do_crypto(struct uadk_rsa_sess *rsa_sess)
{
	struct uadk_e_cb_info cb_param;
	struct async_op op;
	int idx, ret;

	ret = async_setup_async_event_notification(&op);
	if (!ret) {
		UADK_ERR("failed to setup async event notification.\n");
		return UADK_P_FAIL;
	}

	if (!op.job) {
		ret = wd_do_rsa_sync(rsa_sess->sess, &(rsa_sess->req));
		if (ret)
			goto err;
		return UADK_P_SUCCESS;
	}
	cb_param.op = &op;
	cb_param.priv = &(rsa_sess->req);
	rsa_sess->req.cb = uadk_e_rsa_cb;
	rsa_sess->req.cb_param = &cb_param;
	rsa_sess->req.status = POLL_ERROR;

	ret = async_get_free_task(&idx);
	if (ret == 0)
		goto err;

	op.idx = idx;
	do {
		ret = wd_do_rsa_async(rsa_sess->sess, &(rsa_sess->req));
		if (ret < 0 && ret != -EBUSY) {
			async_free_poll_task(op.idx, 0);
			goto err;
		}
	} while (ret == -EBUSY);

	ret = async_pause_job(rsa_sess, &op, ASYNC_TASK_RSA);
	if (!ret)
		goto err;

	if (rsa_sess->req.status)
		return UADK_P_FAIL;

	return UADK_P_SUCCESS;

err:
	(void)async_clear_async_event_notification();
	return UADK_P_FAIL;
}

int uadk_rsa_bits(const RSA *r)
{
	return BN_num_bits(r->n);
}

int uadk_rsa_size(const RSA *r)
{
	return BN_num_bytes(r->n);
}

int rsa_check_bit_useful(const int bits, int flen)
{
	if (bits < RSA_MIN_MODULUS_BITS)
		return UADK_P_FAIL;
	if (flen > (bits >> BIT_BYTES_SHIFT))
		return UADK_DO_SOFT;

	switch (bits) {
	case RSA1024BITS:
	case RSA2048BITS:
	case RSA3072BITS:
	case RSA4096BITS:
		return UADK_P_SUCCESS;
	case OPENSSLRSA7680BITS:
	case OPENSSLRSA15360BITS:
	case RSA_MIN_MODULUS_BITS:
		return UADK_DO_SOFT;
	default:
		return UADK_DO_SOFT;
	}
}

int check_rsa_input_para(const int flen, const unsigned char *from,
				unsigned char *to, RSA *rsa)
{
	if (!rsa || !to || !from || flen <= 0) {
		UADK_ERR("input param invalid\n");
		return UADK_P_FAIL;
	}

	return rsa_check_bit_useful(uadk_rsa_bits(rsa), flen);
}

int rsa_pkey_param_alloc(struct rsa_pubkey_param **pub,
				struct rsa_prikey_param **pri)
{
	if (pub) {
		*pub = OPENSSL_malloc(sizeof(struct rsa_pubkey_param));
		if (!(*pub))
			return -ENOMEM;
	}

	if (pri) {
		*pri = OPENSSL_malloc(sizeof(struct rsa_prikey_param));
		if (!(*pri)) {
			if (pub)
				OPENSSL_free(*pub);
			return -ENOMEM;
		}
	}

	return UADK_P_SUCCESS;
}
void rsa_pkey_param_free(struct rsa_pubkey_param **pub,
				struct rsa_prikey_param **pri)
{
	if (pri)
		OPENSSL_free(*pri);
	if (pub)
		OPENSSL_free(*pub);
}

static void uadk_rsa_get0_key(const RSA *r, const BIGNUM **n,
			      const BIGNUM **e, const BIGNUM **d)
{
	if (n != NULL)
		*n = r->n;
	if (e != NULL)
		*e = r->e;
	if (d != NULL)
		*d = r->d;
}

int rsa_create_pub_bn_ctx(RSA *rsa, struct rsa_pubkey_param *pub,
				 unsigned char **from_buf, int *num_bytes)
{
	uadk_rsa_get0_key(rsa, &pub->n, &pub->e, NULL);
	if (!(pub->e) || !(pub->n))
		return UADK_P_FAIL;

	*num_bytes = BN_num_bytes(pub->n);
	if (!(*num_bytes))
		return UADK_P_FAIL;

	*from_buf = OPENSSL_malloc(*num_bytes);
	if (!(*from_buf))
		return -ENOMEM;

	return UADK_P_SUCCESS;
}

void rsa_free_pub_bn_ctx(unsigned char *from_buf)
{
	OPENSSL_free(from_buf);
}

int rsa_create_pri_bn_ctx(RSA *rsa, struct rsa_prikey_param *pri,
				 unsigned char **from_buf, int *num_bytes)
{
	uadk_rsa_get0_key(rsa, &pri->n, &pri->e, &pri->d);
	if (!(pri->n) || !(pri->e) || !(pri->d))
		return UADK_P_FAIL;

	uadk_rsa_get0_factors(rsa, &pri->p, &pri->q);
	if (!(pri->p) || !(pri->q))
		return UADK_P_FAIL;

	uadk_rsa_get0_crt_params(rsa, &pri->dmp1, &pri->dmq1, &pri->iqmp);
	if (!(pri->dmp1) || !(pri->dmq1) || !(pri->iqmp))
		return UADK_P_FAIL;

	*num_bytes = BN_num_bytes(pri->n);
	if (!(*num_bytes))
		return UADK_P_FAIL;

	*from_buf = OPENSSL_malloc(*num_bytes);
	if (!(*from_buf))
		return -ENOMEM;

	return UADK_P_SUCCESS;
}

void rsa_free_pri_bn_ctx(unsigned char *from_buf)
{
	OPENSSL_free(from_buf);
}
