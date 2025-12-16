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

#define PRIME_CHECK_BIT_NUM		4
#define RSA_MAX_PRIME_NUM		2
#define PRIME_RETRY_COUNT		4
#define GET_ERR_FINISH			0
#define GENCB_RETRY			3
#define GENCB_NEXT			2
#define BN_CONTINUE			1
#define BN_VALID			0

UADK_PKEY_KEYMGMT_DESCR(rsa, RSA);

struct rsa_keypair {
	struct wd_rsa_pubkey *pubkey;
	struct wd_rsa_prikey *prikey;
};

struct rsa_keygen_param {
	struct wd_dtb *wd_e;
	struct wd_dtb *wd_p;
	struct wd_dtb *wd_q;
};

struct rsa_keygen_param_bn {
	BIGNUM *e;
	BIGNUM *p;
	BIGNUM *q;
};

struct rsa_prime_param {
	BIGNUM *r1;
	BIGNUM *r2;
	BIGNUM *rsa_p;
	BIGNUM *rsa_q;
	BIGNUM *prime;
	int retries;
};

struct rsa_gen_ctx {
	OSSL_LIB_CTX *libctx;
	const char *propq;

	int rsa_type;

	size_t nbits;
	BIGNUM *pub_exp;
	size_t primes;

	/* For PSS */
	struct rsa_pss_params_30_st pss_params;
	int pss_defaults_set;

	/* For generation callback */
	OSSL_CALLBACK *cb;
	void *cbarg;
};

static void uadk_rsa_clear_flags(RSA *r, int flags)
{
	r->flags &= ~flags;
}

static void uadk_rsa_set_flags(RSA *r, int flags)
{
	r->flags |= flags;
}

static int uadk_rsa_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d)
{
	/*
	 * If the fields n and e in r are NULL, the corresponding input
	 * parameters MUST be non-NULL for n and e.  d may be
	 * left NULL (in case only the public key is used).
	 */
	if ((r->n == NULL && n == NULL)
			|| (r->e == NULL && e == NULL))
		return UADK_P_FAIL;

	if (n != NULL) {
		BN_free(r->n);
		r->n = n;
	}
	if (e != NULL) {
		BN_free(r->e);
		r->e = e;
	}
	if (d != NULL) {
		BN_clear_free(r->d);
		r->d = d;
		BN_set_flags(r->d, BN_FLG_CONSTTIME);
	}
	r->dirty_cnt++;

	return UADK_P_SUCCESS;
}

static int uadk_rsa_set0_factors(RSA *r, BIGNUM *p, BIGNUM *q)
{
	/*
	 * If the fields p and q in r are NULL, the corresponding input
	 * parameters MUST be non-NULL.
	 */
	if ((r->p == NULL && p == NULL) || (r->q == NULL && q == NULL))
		return UADK_P_FAIL;

	if (p != NULL) {
		BN_clear_free(r->p);
		r->p = p;
		BN_set_flags(r->p, BN_FLG_CONSTTIME);
	}

	if (q != NULL) {
		BN_clear_free(r->q);
		r->q = q;
		BN_set_flags(r->q, BN_FLG_CONSTTIME);
	}

	r->dirty_cnt++;

	return UADK_P_SUCCESS;
}

static int uadk_rsa_set0_crt_params(RSA *r, BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp)
{
	/*
	 * If the fields dmp1, dmq1 and iqmp in r are NULL, the corresponding input
	 * parameters MUST be non-NULL.
	 */
	if ((r->dmp1 == NULL && dmp1 == NULL)
	    || (r->dmq1 == NULL && dmq1 == NULL)
	    || (r->iqmp == NULL && iqmp == NULL))
		return UADK_P_FAIL;

	if (dmp1 != NULL) {
		BN_clear_free(r->dmp1);
		r->dmp1 = dmp1;
		BN_set_flags(r->dmp1, BN_FLG_CONSTTIME);
	}

	if (dmq1 != NULL) {
		BN_clear_free(r->dmq1);
		r->dmq1 = dmq1;
		BN_set_flags(r->dmq1, BN_FLG_CONSTTIME);
	}

	if (iqmp != NULL) {
		BN_clear_free(r->iqmp);
		r->iqmp = iqmp;
		BN_set_flags(r->iqmp, BN_FLG_CONSTTIME);
	}

	r->dirty_cnt++;

	return UADK_P_SUCCESS;
}

static int rsa_prime_mul_res(int num, struct rsa_prime_param *param,
			     BN_CTX *ctx, BN_GENCB *cb)
{
	if (num == 1) {
		if (!BN_mul(param->r1, param->rsa_p, param->rsa_q, ctx))
			return BN_ERR;
	} else {
		if (!BN_GENCB_call(cb, GENCB_RETRY, num))
			return BN_ERR;
		return BN_CONTINUE;
	}

	return BN_VALID;
}

static int check_rsa_prime_sufficient(int *num, const int *bitsr,
				      int *bitse, int * const n,
				      struct rsa_prime_param *param,
				      BN_CTX *ctx, BN_GENCB *cb)
{
	BN_ULONG bitst;
	int ret;

	ret = rsa_prime_mul_res(*num, param, ctx, cb);
	if (ret)
		return ret;

	/*
	 * If |r1|, product of factors so far, is not as long as expected
	 * (by checking the first 4 bits are less than 0x9 or greater than
	 * 0xF). If so, re-generate the last prime.
	 *
	 * NOTE: This actually can't happen in two-prime case, because of
	 * the way factors are generated.
	 *
	 * Besides, another consideration is, for multi-prime case, even the
	 * length modulus is as long as expected, the modulus could start at
	 * 0x8, which could be utilized to distinguish a multi-prime private
	 * key by using the modulus in a certificate. This is also covered
	 * by checking the length should not be less than 0x9.
	 */
	if (!BN_rshift(param->r2, param->r1, *bitse - PRIME_CHECK_BIT_NUM))
		return BN_ERR;

	bitst = BN_get_word(param->r2);
	if (bitst > 0xF || bitst < 0x9) {
	/*
	 * For keys with more than 4 primes, we attempt longer factor
	 * to meet length requirement.
	 * Otherwise, we just re-generate the prime with the same length.
	 * This strategy has the following goals:
	 * 1. 1024-bit factors are efficient when using 3072 and 4096-bit key
	 * 2. stay the same logic with normal 2-prime key
	 */
		if (*num < RSA_MAX_PRIME_NUM)
			*bitse -= bitsr[*num];
		else
			return BN_ERR;

		ret = BN_GENCB_call(cb, GENCB_NEXT, (*n)++);
		if (!ret)
			return BN_ERR;

		if (param->retries == PRIME_RETRY_COUNT) {
			param->retries = 0;
			*bitse = 0;
			*num = -1;
			return BN_CONTINUE;
		}
		param->retries++;
		return BN_REDO;
	}

	ret = BN_GENCB_call(cb, GENCB_RETRY, *num);
	if (!ret)
		return BN_ERR;
	param->retries = 0;

	return BN_VALID;
}

static void rsa_set_primes(int num, BIGNUM *rsa_p, BIGNUM *rsa_q,
			   BIGNUM **prime)
{
	if (num == 0)
		*prime = rsa_p;
	else
		*prime = rsa_q;

	/* Set BN_FLG_CONSTTIME to prime exponent */
	BN_set_flags(*prime, BN_FLG_CONSTTIME);
}

static int check_rsa_prime_equal(int num, BIGNUM *rsa_p, BIGNUM *rsa_q,
				 BIGNUM *prime)
{
	BIGNUM *prev_prime;
	int k;

	for (k = 0; k < num; k++) {
		prev_prime = NULL;
		if (k == 0)
			prev_prime = rsa_p;
		else
			prev_prime = rsa_q;

		/*
		 * BN_cmp(a,b) return -1 if a < b;
		 * return 0 if a == b;
		 * return 1 if a > b.
		 */
		if (!BN_cmp(prime, prev_prime))
			return UADK_P_FAIL;
	}

	return UADK_P_SUCCESS;
}

static int check_rsa_prime_useful(int * const n, struct rsa_prime_param *param,
				  BIGNUM *e_pub, BN_CTX *ctx, BN_GENCB *cb)
{
	unsigned long err;
	int ret;

	/*
	 * BN_sub(r, a, b) substracts b from a and place the result in r,
	 * r = a - b.
	 * BN_value_one() returns a BIGNUM constant of value 1.
	 * r2 = prime - 1.
	 */
	if (!BN_sub(param->r2, param->prime, BN_value_one()))
		return BN_ERR;
	ERR_set_mark();
	BN_set_flags(param->r2, BN_FLG_CONSTTIME);

	/*
	 * BN_mod_inverse(r, a, n, ctx) used to compute inverse modulo n.
	 * Precisely, it computes the inverse of a modulo n, and places
	 * the result in r, which means (a * r) % n == 1.
	 * If r == NULL, error. If r != NULL, success.
	 * The expected result: (r2 * r1) % e_pub == 1,
	 * the inverse of r2 exist, that is r1.
	 */
	if (BN_mod_inverse(param->r1, param->r2, e_pub, ctx))
		return UADK_P_SUCCESS;

	err = ERR_peek_last_error();
	if (ERR_GET_LIB(err) == ERR_LIB_BN &&
	    ERR_GET_REASON(err) == BN_R_NO_INVERSE)
		ERR_pop_to_mark();
	else
		return BN_ERR;

	ret = BN_GENCB_call(cb, GENCB_NEXT, (*n)++);
	if (!ret)
		return BN_ERR;

	return GET_ERR_FINISH;
}

static int get_rsa_prime_once(int num, const int *bitsr, int * const n,
			      BIGNUM *e_pub, struct rsa_prime_param *param,
			      BN_CTX *ctx, BN_GENCB *cb)
{
	int ret = -1;

	if (num >= RSA_MAX_PRIME_NUM)
		return ret;

	while (1) {
		/* Generate prime with bitsr[num] len. */
		if (!BN_generate_prime_ex(param->prime, bitsr[num],
					  0, NULL, NULL, cb))
			return BN_ERR;
		if (!check_rsa_prime_equal(num, param->rsa_p, param->rsa_q,
					   param->prime))
			continue;

		ret = check_rsa_prime_useful(n, param, e_pub, ctx, cb);
		if (ret == BN_ERR)
			return BN_ERR;
		else if (ret == UADK_P_SUCCESS)
			break;
	}

	return ret;
}

static void rsa_switch_p_q(BIGNUM *rsa_p, BIGNUM *rsa_q, BIGNUM *p, BIGNUM *q)
{
	BIGNUM *tmp;

	if (BN_cmp(rsa_p, rsa_q) < 0) {
		tmp = rsa_p;
		rsa_p = rsa_q;
		rsa_q = tmp;
	}

	BN_copy(p, rsa_p);
	BN_copy(q, rsa_q);
}

static int get_rsa_prime_param(struct rsa_prime_param *param, BN_CTX *ctx)
{
	param->r1 = BN_CTX_get(ctx);
	if (!param->r1)
		goto error;

	param->r2 = BN_CTX_get(ctx);
	if (!param->r2)
		goto error;

	param->rsa_q = BN_CTX_get(ctx);
	if (!param->rsa_q)
		goto error;

	param->rsa_p = BN_CTX_get(ctx);
	if (!param->rsa_p)
		goto error;

	return UADK_P_SUCCESS;

error:
	UADK_ERR("failed to allocate rsa prime params\n");
	return -ENOMEM;
}

static int rsa_primes_gen(int bits, BIGNUM *e_pub, BIGNUM *p,
			  BIGNUM *q, BN_GENCB *cb)
{
	int bitsr[RSA_MAX_PRIME_NUM] = {0};
	struct rsa_prime_param *param;
	int flag, quot, rmd, i;
	int ret = UADK_P_FAIL;
	BN_CTX *bnctx;
	int bitse = 0;
	/* n: modulo n, a part of public key */
	int n = 0;

	bnctx = BN_CTX_new();
	if (!bnctx)
		return ret;

	BN_CTX_start(bnctx);
	param = OPENSSL_zalloc(sizeof(struct rsa_prime_param));
	if (!param)
		goto free_ctx;

	ret = get_rsa_prime_param(param, bnctx);
	if (ret != UADK_P_SUCCESS)
		goto free_param;

	/* Divide bits into 'primes' pieces evenly */
	quot = bits / RSA_MAX_PRIME_NUM;
	rmd = bits % RSA_MAX_PRIME_NUM;
	for (i = 0; i < RSA_MAX_PRIME_NUM; i++)
		bitsr[i] = (i < rmd) ? quot + 1 : quot;

	/* Generate p, q and other primes (if any) */
	for (i = 0; i < RSA_MAX_PRIME_NUM; i++) {
		/* flag: whether primes are generated correctely. */
		flag = 1;
		/* Set flag for primes rsa_p and rsa_q separately. */
		rsa_set_primes(i, param->rsa_p, param->rsa_q, &param->prime);
		while (flag == 1) {
			ret = get_rsa_prime_once(i, bitsr, &n, e_pub, param,
						 bnctx, cb);
			if (ret == -1)
				goto free_param;
			bitse += bitsr[i];
			ret = check_rsa_prime_sufficient(&i, bitsr, &bitse, &n,
							 param, bnctx, cb);
			if (ret == BN_ERR)
				goto free_param;
			else if (ret == BN_REDO)
				continue;
			else
				flag = 0;
		}
	}
	rsa_switch_p_q(param->rsa_p, param->rsa_q, p, q);

	ret = UADK_P_SUCCESS;

free_param:
	OPENSSL_free(param);
free_ctx:
	BN_CTX_end(bnctx);
	BN_CTX_free(bnctx);
	return ret;
}

static int rsa_fill_keygen_data(struct uadk_rsa_sess *rsa_sess,
				struct rsa_keypair *key_pair,
				struct rsa_keygen_param *keygen_param,
				struct rsa_keygen_param_bn *bn_param)
{
	wd_rsa_get_pubkey(rsa_sess->sess, &key_pair->pubkey);
	if (!key_pair->pubkey)
		return UADK_P_FAIL;

	wd_rsa_get_pubkey_params(key_pair->pubkey, &keygen_param->wd_e, NULL);
	if (!keygen_param->wd_e)
		return UADK_P_FAIL;

	keygen_param->wd_e->dsize = BN_bn2bin(bn_param->e,
				    (unsigned char *)keygen_param->wd_e->data);

	wd_rsa_get_prikey(rsa_sess->sess, &key_pair->prikey);
	if (!key_pair->prikey)
		return UADK_P_FAIL;

	wd_rsa_get_crt_prikey_params(key_pair->prikey, NULL, NULL, NULL,
				     &keygen_param->wd_q, &keygen_param->wd_p);
	if (!keygen_param->wd_p || !keygen_param->wd_q)
		return UADK_P_FAIL;

	keygen_param->wd_p->dsize = BN_bn2bin(bn_param->p,
				    (unsigned char *)keygen_param->wd_p->data);
	keygen_param->wd_q->dsize = BN_bn2bin(bn_param->q,
				    (unsigned char *)keygen_param->wd_q->data);

	rsa_sess->req.src_bytes = rsa_sess->key_size;
	rsa_sess->req.dst_bytes = rsa_sess->key_size;
	rsa_sess->req.op_type = WD_RSA_GENKEY;
	rsa_sess->req.src = wd_rsa_new_kg_in(rsa_sess->sess, keygen_param->wd_e,
					     keygen_param->wd_p, keygen_param->wd_q);
	if (!rsa_sess->req.src)
		return UADK_P_FAIL;

	rsa_sess->req.dst = wd_rsa_new_kg_out(rsa_sess->sess);
	if (!rsa_sess->req.dst) {
		wd_rsa_del_kg_in(rsa_sess->sess, rsa_sess->req.src);
		return UADK_P_FAIL;
	}

	return UADK_P_SUCCESS;
}

static RSA *ossl_rsa_new_with_ctx(OSSL_LIB_CTX *libctx)
{
	RSA *rsa = OPENSSL_zalloc(sizeof(*rsa));

	if (rsa == NULL) {
		UADK_ERR("failed to zalloc rsa ret\n");
		return NULL;
	}

	rsa->references = 1;
	rsa->lock = CRYPTO_THREAD_lock_new();
	if (rsa->lock == NULL) {
		UADK_ERR("failed to malloc thread lock\n");
		OPENSSL_free(rsa);
		return NULL;
	}

	rsa->libctx = libctx;
	rsa->meth = RSA_get_default_method();

	return rsa;
}

static int rsa_gencb(int p, int n, BN_GENCB *cb)
{
	struct rsa_gen_ctx *gctx = BN_GENCB_get_arg(cb);
	OSSL_PARAM params[] = { OSSL_PARAM_END, OSSL_PARAM_END, OSSL_PARAM_END };

	params[0] = OSSL_PARAM_construct_int(OSSL_GEN_PARAM_POTENTIAL, &p);
	params[1] = OSSL_PARAM_construct_int(OSSL_GEN_PARAM_ITERATION, &n);
	return gctx->cb(params, gctx->cbarg);
}

static int rsa_get_keygen_param(struct wd_rsa_req *req, handle_t ctx, RSA *rsa,
				struct rsa_keygen_param_bn *bn_param)
{
	struct wd_rsa_kg_out *out = (struct wd_rsa_kg_out *)req->dst;
	struct wd_dtb wd_d, wd_n, wd_qinv, wd_dq, wd_dp;
	BIGNUM *dmp1, *dmq1, *iqmp, *d, *n;
	unsigned int key_bits, key_size;

	key_bits = wd_rsa_get_key_bits(ctx);
	if (!key_bits)
		return UADK_P_FAIL;

	key_size = key_bits >> BIT_BYTES_SHIFT;
	wd_rsa_get_kg_out_params(out, &wd_d, &wd_n);
	wd_rsa_get_kg_out_crt_params(out, &wd_qinv, &wd_dq, &wd_dp);

	dmq1 = BN_secure_new();
	if (!dmq1)
		return UADK_P_FAIL;

	dmp1 = BN_secure_new();
	if (!dmp1)
		goto free_bn_dq;

	iqmp = BN_new();
	if (!iqmp)
		goto free_bn_dp;

	n = BN_new();
	if (!n)
		goto free_bn_qinv;

	d = BN_secure_new();
	if (!d)
		goto free_bn_n;

	BN_bin2bn((unsigned char *)wd_n.data, key_size, n);
	BN_bin2bn((unsigned char *)wd_d.data, key_size, d);
	BN_bin2bn((unsigned char *)wd_qinv.data, wd_qinv.dsize, iqmp);
	BN_bin2bn((unsigned char *)wd_dq.data, wd_dq.dsize, dmq1);
	BN_bin2bn((unsigned char *)wd_dp.data, wd_dp.dsize, dmp1);

	if (!(uadk_rsa_set0_key(rsa, n, bn_param->e, d) &&
	    uadk_rsa_set0_factors(rsa, bn_param->p, bn_param->q) &&
	    uadk_rsa_set0_crt_params(rsa, dmp1, dmq1, iqmp)))
		goto free_bn_d;

	return UADK_P_SUCCESS;

free_bn_d:
	BN_clear_free(d);
free_bn_n:
	BN_clear_free(n);
free_bn_qinv:
	BN_clear_free(iqmp);
free_bn_dp:
	BN_clear_free(dmp1);
free_bn_dq:
	BN_clear_free(dmq1);

	return UADK_P_FAIL;
}

static void rsa_free_keygen_data(struct uadk_rsa_sess *rsa_sess)
{
	if (!rsa_sess)
		return;

	wd_rsa_del_kg_out(rsa_sess->sess, rsa_sess->req.dst);
	wd_rsa_del_kg_in(rsa_sess->sess, rsa_sess->req.src);
}

static void rsa_keygen_param_free(struct rsa_keygen_param **keygen_param,
				  struct rsa_keygen_param_bn **keygen_bn_param,
				  struct rsa_keypair **key_pair, int free_bn_ctx_tag)
{
	/*
	 * When an abnormal situation occurs, uadk engine needs to
	 * switch to software keygen function, so we need to free
	 * BN we alloced before. But in normal situation,
	 * the BN should be freed by OpenSSL tools or users.
	 * Therefore, we use a tag to distinguish these cases.
	 */
	if (free_bn_ctx_tag == UADK_DO_SOFT) {
		BN_clear_free((*keygen_bn_param)->p);
		BN_clear_free((*keygen_bn_param)->q);
		BN_clear_free((*keygen_bn_param)->e);
	}

	OPENSSL_free(*key_pair);
	OPENSSL_free(*keygen_param);
	OPENSSL_free(*keygen_bn_param);
}

static int rsa_keygen_param_alloc(struct rsa_keygen_param **keygen_param,
				  struct rsa_keygen_param_bn **keygen_bn_param,
				  struct rsa_keypair **key_pair)
{
	*keygen_param = OPENSSL_malloc(sizeof(struct rsa_keygen_param));
	if (!(*keygen_param))
		goto error;

	*keygen_bn_param = (struct rsa_keygen_param_bn *)
			   OPENSSL_malloc(sizeof(struct rsa_keygen_param_bn));
	if (!(*keygen_bn_param))
		goto free_keygen_param;

	*key_pair = OPENSSL_malloc(sizeof(struct rsa_keypair));
	if (!(*key_pair))
		goto free_keygen_bn_param;

	(*keygen_bn_param)->p = BN_secure_new();
	if (!(*keygen_bn_param)->p)
		goto free_key_pair;

	(*keygen_bn_param)->q = BN_secure_new();
	if (!(*keygen_bn_param)->q)
		goto free_p;

	(*keygen_bn_param)->e = BN_new();
	if (!(*keygen_bn_param)->e)
		goto free_q;

	return UADK_P_SUCCESS;

free_q:
	BN_clear_free((*keygen_bn_param)->q);
free_p:
	BN_clear_free((*keygen_bn_param)->p);
free_key_pair:
	OPENSSL_free(*key_pair);
free_keygen_bn_param:
	OPENSSL_free(*keygen_bn_param);
free_keygen_param:
	OPENSSL_free(*keygen_param);
error:
	return -ENOMEM;
}

static int uadk_prov_rsa_keygen(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb)
{
	struct rsa_keygen_param *keygen_param = NULL;
	struct rsa_keygen_param_bn *bn_param = NULL;
	struct rsa_keypair *key_pair = NULL;
	struct uadk_rsa_sess *rsa_sess;
	int is_crt = 1;
	int ret;

	ret = rsa_check_bit_useful(bits, 0);
	if (ret != UADK_P_SUCCESS)
		return ret;

	ret = rsa_keygen_param_alloc(&keygen_param, &bn_param, &key_pair);
	if (ret == -ENOMEM)
		return UADK_P_FAIL;

	rsa_sess = rsa_get_eng_session(rsa, bits, is_crt);
	if (!rsa_sess) {
		ret = UADK_DO_SOFT;
		goto free_keygen;
	}

	ret = rsa_primes_gen(bits, e, bn_param->p, bn_param->q, cb);
	if (!ret) {
		ret = UADK_P_FAIL;
		goto free_sess;
	}

	if (!BN_copy(bn_param->e, e)) {
		ret = UADK_P_FAIL;
		goto free_sess;
	}

	ret = rsa_fill_keygen_data(rsa_sess, key_pair, keygen_param, bn_param);
	if (!ret) {
		ret = UADK_P_FAIL;
		goto free_sess;
	}

	ret = rsa_do_crypto(rsa_sess);
	if (!ret || rsa_sess->req.status) {
		ret = UADK_DO_SOFT;
		goto free_kg_in_out;
	}

	ret = rsa_get_keygen_param(&rsa_sess->req, rsa_sess->sess, rsa, bn_param);
	if (!ret)
		ret = UADK_P_FAIL;

free_kg_in_out:
	rsa_free_keygen_data(rsa_sess);
free_sess:
	rsa_free_eng_session(rsa_sess);
free_keygen:
	rsa_keygen_param_free(&keygen_param, &bn_param, &key_pair, ret);
	return ret;
}

static const char *uadk_keymgmt_rsa_query_operation_name(int operation_id)
{
	if (!get_default_rsa_keymgmt().query_operation_name)
		return NULL;

	return get_default_rsa_keymgmt().query_operation_name(operation_id);
}

static void *uadk_keymgmt_rsa_new(void *provctx)
{
	if (!get_default_rsa_keymgmt().new_fun)
		return NULL;

	return get_default_rsa_keymgmt().new_fun(provctx);
}

static void uadk_keymgmt_rsa_free(void *keydata)
{
	if (!get_default_rsa_keymgmt().free)
		return;

	get_default_rsa_keymgmt().free(keydata);
}

static int uadk_keymgmt_rsa_has(const void *keydata, int selection)
{
	if (!get_default_rsa_keymgmt().has)
		return UADK_P_FAIL;

	return get_default_rsa_keymgmt().has(keydata, selection);
}

static int uadk_keymgmt_rsa_import(void *keydata, int selection, const OSSL_PARAM params[])
{
	if (!get_default_rsa_keymgmt().import)
		return UADK_P_FAIL;

	return get_default_rsa_keymgmt().import(keydata, selection, params);
}

static const OSSL_PARAM *uadk_keymgmt_rsa_import_types(int selection)
{
	if (!get_default_rsa_keymgmt().import_types)
		return NULL;

	return get_default_rsa_keymgmt().import_types(selection);
}

static void *uadk_keymgmt_rsa_gen_init(void *provctx, int selection,
				       const OSSL_PARAM params[])
{
	if (!get_default_rsa_keymgmt().gen_init)
		return NULL;

	return get_default_rsa_keymgmt().gen_init(provctx, selection, params);
}

static int uadk_keymgmt_rsa_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
	if (!get_default_rsa_keymgmt().gen_set_params)
		return UADK_P_FAIL;

	return get_default_rsa_keymgmt().gen_set_params(genctx, params);
}

static int uadk_keymgmt_rsa_gen_set_template(void *genctx, void *templates)
{
	if (!get_default_rsa_keymgmt().gen_set_template) {
		UADK_ERR("failed to get keymgmt gen_set_template function\n");
		return UADK_P_FAIL;
	}

	return get_default_rsa_keymgmt().gen_set_template(genctx, templates);
}

static const OSSL_PARAM *uadk_keymgmt_rsa_gen_settable_params(ossl_unused void *genctx,
							      ossl_unused void *provctx)
{
	if (!get_default_rsa_keymgmt().gen_settable_params)
		return NULL;

	return get_default_rsa_keymgmt().gen_settable_params(genctx, provctx);
}

static void *uadk_rsa_sw_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
	if (!enable_sw_offload || !get_default_rsa_keymgmt().gen)
		return NULL;

	UADK_INFO("switch to openssl software calculation in rsa key generation.\n");
	return get_default_rsa_keymgmt().gen(genctx, osslcb, cbarg);
}

static void *uadk_keymgmt_rsa_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
	struct rsa_gen_ctx *gctx = genctx;
	BN_GENCB *gencb;
	RSA *rsa;
	int ret;

	if (gctx == NULL)
		return NULL;

	ret = uadk_prov_rsa_init();
	if (ret) {
		ret = UADK_DO_SOFT;
		goto exe_soft;
	}

	rsa = ossl_rsa_new_with_ctx(gctx->libctx);
	if (rsa == NULL)
		return NULL;

	gctx->cb = osslcb;
	gctx->cbarg = cbarg;
	gencb = BN_GENCB_new();
	if (gencb != NULL)
		BN_GENCB_set(gencb, rsa_gencb, genctx);

	ret = uadk_prov_rsa_keygen(rsa, (int)gctx->nbits, gctx->pub_exp, gencb);
	if (ret == UADK_DO_SOFT || ret == UADK_P_FAIL) {
		BN_GENCB_free(gencb);
		uadk_keymgmt_rsa_free(rsa);
		goto exe_soft;
	}

	uadk_rsa_clear_flags(rsa, RSA_FLAG_TYPE_MASK);
	uadk_rsa_set_flags(rsa, gctx->rsa_type);
	BN_GENCB_free(gencb);

	return rsa;

exe_soft:
	if (ret == UADK_DO_SOFT)
		return uadk_rsa_sw_gen(genctx, osslcb, cbarg);
	return NULL;
}

static void uadk_keymgmt_rsa_gen_cleanup(void *genctx)
{
	if (!get_default_rsa_keymgmt().gen_cleanup)
		return;

	get_default_rsa_keymgmt().gen_cleanup(genctx);
}

static void *uadk_keymgmt_rsa_load(const void *reference, size_t reference_sz)
{
	if (!get_default_rsa_keymgmt().load)
		return NULL;

	return get_default_rsa_keymgmt().load(reference, reference_sz);
}

static int uadk_keymgmt_rsa_get_params(void *key, OSSL_PARAM params[])
{
	if (!get_default_rsa_keymgmt().get_params)
		return UADK_P_FAIL;

	return get_default_rsa_keymgmt().get_params(key, params);
}

static const OSSL_PARAM *uadk_keymgmt_rsa_gettable_params(void *provctx)
{
	if (!get_default_rsa_keymgmt().gettable_params)
		return NULL;

	return get_default_rsa_keymgmt().gettable_params(provctx);
}

static int uadk_keymgmt_rsa_set_params(void *key, const OSSL_PARAM params[])
{
	if (!get_default_rsa_keymgmt().set_params) {
		UADK_ERR("failed to get keymgmt set_params function\n");
		return UADK_P_FAIL;
	}

	return get_default_rsa_keymgmt().set_params(key, params);
}

static const OSSL_PARAM *uadk_keymgmt_rsa_settable_params(ossl_unused void *provctx)
{
	if (!get_default_rsa_keymgmt().settable_params) {
		UADK_ERR("failed to get keymgmt settable_params function\n");
		return NULL;
	}

	return get_default_rsa_keymgmt().settable_params(provctx);
}

static int uadk_keymgmt_rsa_match(const void *keydata1, const void *keydata2, int selection)
{
	if (!get_default_rsa_keymgmt().match)
		return UADK_P_FAIL;

	return get_default_rsa_keymgmt().match(keydata1, keydata2, selection);
}

static int uadk_keymgmt_rsa_validate(const void *keydata, int selection, int checktype)
{
	if (!get_default_rsa_keymgmt().validate)
		return UADK_P_FAIL;

	return get_default_rsa_keymgmt().validate(keydata, selection, checktype);
}

static int uadk_keymgmt_rsa_export(void *keydata, int selection,
				   OSSL_CALLBACK *param_callback, void *cbarg)
{
	if (!get_default_rsa_keymgmt().export_fun)
		return UADK_P_FAIL;

	return get_default_rsa_keymgmt().export_fun(keydata, selection, param_callback, cbarg);
}

static const OSSL_PARAM *uadk_keymgmt_rsa_export_types(int selection)
{
	if (!get_default_rsa_keymgmt().export_types)
		return NULL;

	return get_default_rsa_keymgmt().export_types(selection);
}

static void *uadk_keymgmt_rsa_dup(const void *keydata_from, int selection)
{
	if (!get_default_rsa_keymgmt().dup)
		return NULL;

	return get_default_rsa_keymgmt().dup(keydata_from, selection);
}
