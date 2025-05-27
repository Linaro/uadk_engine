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
#include <openssl/bn.h>
#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/rsa.h>
#include <openssl/types.h>
#include <uadk/wd_rsa.h>
#include <uadk/wd_sched.h>
#include "uadk_async.h"
#include "uadk_prov.h"
#include "uadk_prov_pkey.h"

#define UN_SET				0
#define IS_SET				1
#define RSA_MAX_PRIME_NUM		2
#define BIT_BYTES_SHIFT			3
#define RSA_MIN_MODULUS_BITS		512
#define RSA1024BITS			1024
#define RSA2048BITS			2048
#define RSA3072BITS			3072
#define RSA4096BITS			4096
#define OPENSSLRSA7680BITS		7680
#define OPENSSLRSA15360BITS		15360
#define CTX_SYNC			0
#define CTX_ASYNC			1
#define CTX_NUM				2
#define BN_CONTINUE			1
#define BN_VALID			0
#define BN_ERR				(-1)
#define BN_REDO				(-2)
#define GET_ERR_FINISH			0
#define UNUSED(x)			((void)(x))
#define UADK_E_FAIL			0
#define UADK_E_SUCCESS			1
#define UADK_DO_SOFT			(-0xE0)
#define UADK_E_POLL_FAIL		(-1)
#define UADK_E_POLL_SUCCESS		0
#define UADK_E_INIT_SUCCESS		0
#define CHECK_PADDING_FAIL		(-1)
#define ENV_ENABLED			1
#define PRIME_RETRY_COUNT		4
#define GENCB_NEXT			2
#define GENCB_RETRY			3
#define PRIME_CHECK_BIT_NUM		4

UADK_PKEY_KEYMGMT_DESCR(rsa, RSA);
UADK_PKEY_SIGNATURE_DESCR(rsa, RSA);
UADK_PKEY_ASYM_CIPHER_DESCR(rsa, RSA);
struct rsa_keypair {
	struct wd_rsa_pubkey *pubkey;
	struct wd_rsa_prikey *prikey;
};

struct rsa_keygen_param {
	struct wd_dtb *wd_e;
	struct wd_dtb *wd_p;
	struct wd_dtb *wd_q;
};

struct bignum_st {
	BN_ULONG *d;
	int top;
	int dmax;
	int neg;
	int flags;
};

struct rsa_keygen_param_bn {
	BIGNUM *e;
	BIGNUM *p;
	BIGNUM *q;
};

struct rsa_prikey_param {
	const BIGNUM *n;
	const BIGNUM *e;
	const BIGNUM *d;
	const BIGNUM *p;
	const BIGNUM *q;
	const BIGNUM *dmp1;
	const BIGNUM *dmq1;
	const BIGNUM *iqmp;
	int is_crt;
};

struct rsa_prime_param {
	BIGNUM *r1;
	BIGNUM *r2;
	BIGNUM *rsa_p;
	BIGNUM *rsa_q;
	BIGNUM *prime;
};

struct rsa_pubkey_param {
	const BIGNUM *e;
	const BIGNUM *n;
};

struct rsa_sched {
	int sched_type;
	struct wd_sched wd_sched;
};

struct uadk_rsa_sess {
	handle_t sess;
	struct wd_rsa_sess_setup setup;
	struct wd_rsa_req req;
	RSA *alg;
	int is_pubkey_ready;
	int is_prikey_ready;
	int key_size;
};

struct rsa_prov {
	int pid;
};
static struct rsa_prov g_rsa_prov;

static pthread_mutex_t rsa_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
	OSSL_LIB_CTX *libctx;
	char *propq;
	RSA *rsa;
	int operation;

	/*
	 * Flag to determine if the hash function can be changed (1) or not (0)
	 * Because it's dangerous to change during a DigestSign or DigestVerify
	 * operation, this flag is cleared by their Init function, and set again
	 * by their Final function.
	 */
	unsigned int flag_allow_md : 1;
	unsigned int mgf1_md_set : 1;

	/* main digest */
	EVP_MD *md;
	EVP_MD_CTX *mdctx;
	int mdnid;
	char mdname[50]; /* Purely informational */

	/* RSA padding mode */
	int pad_mode;
	/* message digest for MGF1 */
	EVP_MD *mgf1_md;
	int mgf1_mdnid;
	char mgf1_mdname[50]; /* Purely informational */
	/* PSS salt length */
	int saltlen;
	/* Minimum salt length or -1 if no PSS parameter restriction */
	int min_saltlen;

	/* Temp buffer */
	unsigned char *tbuf;

	unsigned int soft : 1;
} PROV_RSA_SIG_CTX;

typedef struct rsa_pss_params_30_st {
	int hash_algorithm_nid;
	struct {
		int algorithm_nid;       /* Currently always NID_mgf1 */
		int hash_algorithm_nid;
	} mask_gen;
	int salt_len;
	int trailer_field;
} RSA_PSS_PARAMS_30;

struct rsa_st {
	/*
	 * #legacy
	 * The first field is used to pickup errors where this is passed
	 * instead of an EVP_PKEY.  It is always zero.
	 * THIS MUST REMAIN THE FIRST FIELD.
	 */
	int dummy_zero;

	OSSL_LIB_CTX *libctx;
	int32_t version;
	const RSA_METHOD *meth;
	/* functional reference if 'meth' is ENGINE-provided */
	ENGINE *engine;
	BIGNUM *n;
	BIGNUM *e;
	BIGNUM *d;
	BIGNUM *p;
	BIGNUM *q;
	BIGNUM *dmp1;
	BIGNUM *dmq1;
	BIGNUM *iqmp;

	/*
	 * If a PSS only key this contains the parameter restrictions.
	 * There are two structures for the same thing, used in different cases.
	 */
	/* This is used uniquely by OpenSSL provider implementations. */
	RSA_PSS_PARAMS_30 pss_params;

	/* This is used uniquely by rsa_ameth.c and rsa_pmeth.c. */
	RSA_PSS_PARAMS *pss;
	/* for multi-prime RSA, defined in RFC 8017 */
	STACK_OF(RSA_PRIME_INFO) * prime_infos;
	/* Be careful using this if the RSA structure is shared */
	CRYPTO_EX_DATA ex_data;

	CRYPTO_REF_COUNT references;
	int flags;
	/* Used to cache montgomery values */
	BN_MONT_CTX *_method_mod_n;
	BN_MONT_CTX *_method_mod_p;
	BN_MONT_CTX *_method_mod_q;
	BN_BLINDING *blinding;
	BN_BLINDING *mt_blinding;
	CRYPTO_RWLOCK *lock;

	int dirty_cnt;
};

typedef struct {
	OSSL_LIB_CTX *libctx;
	RSA *rsa;
	int pad_mode;
	int operation;
	/* OAEP message digest */
	EVP_MD *oaep_md;
	/* message digest for MGF1 */
	EVP_MD *mgf1_md;
	/* OAEP label */
	unsigned char *oaep_label;
	size_t oaep_labellen;
	/* TLS padding */
	unsigned int client_version;
	unsigned int alt_version;

	unsigned int soft : 1;
} PROV_RSA_ASYM_CTX;

struct rsa_gen_ctx {
	OSSL_LIB_CTX *libctx;
	const char *propq;

	int rsa_type;

	size_t nbits;
	BIGNUM *pub_exp;
	size_t primes;

	/* For PSS */
	RSA_PSS_PARAMS_30 pss_params;
	int pss_defaults_set;

	/* For generation callback */
	OSSL_CALLBACK *cb;
	void *cbarg;
};

enum {
	INVALID = 0,
	PUB_ENC,
	PUB_DEC,
	PRI_ENC,
	PRI_DEC,
	MAX_CODE,
};

static pthread_mutex_t sig_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t asym_mutex = PTHREAD_MUTEX_INITIALIZER;

static UADK_PKEY_SIGNATURE get_default_rsa_signature(void)
{
	static UADK_PKEY_SIGNATURE s_signature;
	static int initilazed;
	pthread_mutex_lock(&sig_mutex);
	if (!initilazed) {
		UADK_PKEY_SIGNATURE *signature =
			(UADK_PKEY_SIGNATURE *)EVP_SIGNATURE_fetch(NULL, "RSA", "provider=default");

		if (signature) {
			s_signature = *signature;
			EVP_SIGNATURE_free((EVP_SIGNATURE *)signature);
			initilazed = 1;
		} else {
			fprintf(stderr, "failed to EVP_SIGNATURE_fetch default RSA provider\n");
		}
	}
	pthread_mutex_unlock(&sig_mutex);
	return s_signature;
}

static UADK_PKEY_ASYM_CIPHER get_default_rsa_asym_cipher(void)
{
	static UADK_PKEY_ASYM_CIPHER s_asym_cipher;
	static int initilazed;
	pthread_mutex_lock(&asym_mutex);
	if (!initilazed) {
		UADK_PKEY_ASYM_CIPHER *asym_cipher =
			(UADK_PKEY_ASYM_CIPHER *)EVP_ASYM_CIPHER_fetch(NULL, "RSA",
								       "provider=default");

		if (asym_cipher) {
			s_asym_cipher = *asym_cipher;
			EVP_ASYM_CIPHER_free((EVP_ASYM_CIPHER *)asym_cipher);
			initilazed = 1;
		} else {
			fprintf(stderr, "failed to EVP_ASYM_CIPHER_fetch default RSA provider\n");
		}
	}
	pthread_mutex_unlock(&asym_mutex);
	return s_asym_cipher;
}

static void uadk_rsa_clear_flags(RSA *r, int flags)
{
	r->flags &= ~flags;
}

static int uadk_rsa_test_flags(const RSA *r, int flags)
{
	return r->flags & flags;
}

static void uadk_rsa_set_flags(RSA *r, int flags)
{
	r->flags |= flags;
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

static int uadk_rsa_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d)
{
	/*
	 * If the fields n and e in r are NULL, the corresponding input
	 * parameters MUST be non-NULL for n and e.  d may be
	 * left NULL (in case only the public key is used).
	 */
	if ((r->n == NULL && n == NULL)
			|| (r->e == NULL && e == NULL))
		return UADK_E_FAIL;

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

	return UADK_E_SUCCESS;
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

static int uadk_rsa_set0_factors(RSA *r, BIGNUM *p, BIGNUM *q)
{
	/*
	 * If the fields p and q in r are NULL, the corresponding input
	 * parameters MUST be non-NULL.
	 */
	if ((r->p == NULL && p == NULL) || (r->q == NULL && q == NULL))
		return UADK_E_FAIL;

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

	return UADK_E_SUCCESS;
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
		return UADK_E_FAIL;

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

	return UADK_E_SUCCESS;
}

static int uadk_rsa_bits(const RSA *r)
{
	return BN_num_bits(r->n);
}

static int uadk_rsa_size(const RSA *r)
{
	return BN_num_bytes(r->n);
}

static int setup_tbuf(PROV_RSA_SIG_CTX *ctx)
{
	if (ctx->tbuf != NULL)
		return UADK_E_SUCCESS;

	ctx->tbuf = OPENSSL_malloc(uadk_rsa_size(ctx->rsa));
	if (ctx->tbuf == NULL) {
		ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
		return UADK_E_FAIL;
	}

	return UADK_E_SUCCESS;
}

static void clean_tbuf(PROV_RSA_SIG_CTX *ctx)
{
	if (ctx->tbuf != NULL)
		OPENSSL_cleanse(ctx->tbuf, uadk_rsa_size(ctx->rsa));
}

static void free_tbuf(PROV_RSA_SIG_CTX *ctx)
{
	clean_tbuf(ctx);
	OPENSSL_free(ctx->tbuf);
	ctx->tbuf = NULL;
}

static int rsa_check_bit_useful(const int bits, int flen)
{
	if (bits < RSA_MIN_MODULUS_BITS)
		return UADK_E_FAIL;
	if (flen > (bits >> BIT_BYTES_SHIFT))
		return UADK_DO_SOFT;

	switch (bits) {
	case RSA1024BITS:
	case RSA2048BITS:
	case RSA3072BITS:
	case RSA4096BITS:
		return UADK_E_SUCCESS;
	case OPENSSLRSA7680BITS:
	case OPENSSLRSA15360BITS:
	case RSA_MIN_MODULUS_BITS:
		return UADK_DO_SOFT;
	default:
		return UADK_DO_SOFT;
	}
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
	static int retries;
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

		if (retries == PRIME_RETRY_COUNT) {
			retries = 0;
			*bitse = 0;
			*num = -1;
			return BN_CONTINUE;
		}
		retries++;
		return BN_REDO;
	}

	ret = BN_GENCB_call(cb, GENCB_RETRY, *num);
	if (!ret)
		return BN_ERR;
	retries = 0;

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
			return UADK_E_FAIL;
	}

	return UADK_E_SUCCESS;
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
		return UADK_E_SUCCESS;

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
		else if (ret == UADK_E_SUCCESS)
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

static int check_rsa_is_crt(RSA *rsa)
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

	return UADK_E_SUCCESS;

error:
	fprintf(stderr, "failed to allocate rsa prime params\n");
	return -ENOMEM;
}

static int rsa_primes_gen(int bits, BIGNUM *e_pub, BIGNUM *p,
			  BIGNUM *q, BN_GENCB *cb)
{
	struct rsa_prime_param *param = NULL;
	int bitsr[RSA_MAX_PRIME_NUM] = {0};
	int flag, quot, rmd, i;
	BN_CTX *bnctx;
	int bitse = 0;
	int ret = 0;
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
	if (ret != UADK_E_SUCCESS)
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

	ret = UADK_E_SUCCESS;

free_param:
	OPENSSL_free(param);
free_ctx:
	BN_CTX_end(bnctx);
	BN_CTX_free(bnctx);
	return ret;
}

static int add_rsa_pubenc_padding(int flen, const unsigned char *from,
				  unsigned char *buf, int num, int padding)
{
	int ret;

	if (!buf || !num) {
		fprintf(stderr, "buf or num is invalid.\n");
		return UADK_E_FAIL;
	}

	switch (padding) {
	case RSA_PKCS1_PADDING:
		ret = RSA_padding_add_PKCS1_type_2(buf, num, from, flen);
		if (!ret)
			fprintf(stderr, "RSA_PKCS1_PADDING err.\n");
		break;
	case RSA_PKCS1_OAEP_PADDING:
		ret = RSA_padding_add_PKCS1_OAEP(buf, num, from, flen, NULL, 0);
		if (!ret)
			fprintf(stderr, "RSA_PKCS1_OAEP_PADDING err.\n");
		break;
	default:
		ret = UADK_E_FAIL;
	}

	return ret;
}

static int check_rsa_pridec_padding(unsigned char *to, int num,
				    const unsigned char *buf, int flen,
				    int padding)
{
	int ret;

	switch (padding) {
	case RSA_PKCS1_PADDING:
		ret = RSA_padding_check_PKCS1_type_2(to, num, buf, flen, num);
		if (ret == CHECK_PADDING_FAIL)
			fprintf(stderr, "RSA_PKCS1_PADDING err.\n");
		break;
	case RSA_PKCS1_OAEP_PADDING:
		ret = RSA_padding_check_PKCS1_OAEP(to, num, buf, flen, num,
						   NULL, 0);
		if (ret == CHECK_PADDING_FAIL)
			fprintf(stderr, "RSA_PKCS1_OAEP_PADDING err.\n");
		break;
	default:
		ret = UADK_E_FAIL;
	}

	if (ret == CHECK_PADDING_FAIL)
		ret = UADK_E_FAIL;

	return ret;
}

static int add_rsa_prienc_padding(int flen, const unsigned char *from,
				  unsigned char *to_buf, int tlen,
				  int padding)
{
	int ret;

	switch (padding) {
	case RSA_PKCS1_PADDING:
		ret = RSA_padding_add_PKCS1_type_1(to_buf, tlen, from, flen);
		if (!ret)
			fprintf(stderr, "RSA_PKCS1_PADDING err.\n");
		break;
	case RSA_X931_PADDING:
		ret = RSA_padding_add_X931(to_buf, tlen, from, flen);
		if (ret == -1)
			fprintf(stderr, "RSA_X931_PADDING err.\n");
		break;
	default:
		ret = UADK_E_FAIL;
	}
	if (ret <= 0)
		ret = UADK_E_FAIL;

	return ret;
}

static int check_rsa_pubdec_padding(unsigned char *to, int num,
				    const unsigned char *buf, int len,
				    int padding)
{
	int ret;

	switch (padding) {
	case RSA_PKCS1_PADDING:
		ret = RSA_padding_check_PKCS1_type_1(to, num, buf, len, num);
		if (ret == CHECK_PADDING_FAIL)
			fprintf(stderr, "RSA_PKCS1_PADDING err.\n");
		break;
	case RSA_X931_PADDING:
		ret = RSA_padding_check_X931(to, num, buf, len, num);
		if (ret == CHECK_PADDING_FAIL)
			fprintf(stderr, "RSA_X931_PADDING err.\n");
		break;
	default:
		ret = UADK_E_FAIL;
	}

	if (ret == CHECK_PADDING_FAIL)
		ret = UADK_E_FAIL;

	return ret;
}

static BN_ULONG *bn_get_words(const BIGNUM *a)
{
	return a->d;
}

static int check_rsa_input_para(const int flen, const unsigned char *from,
				unsigned char *to, RSA *rsa)
{
	if (!rsa || !to || !from || flen <= 0) {
		fprintf(stderr, "input param invalid\n");
		return UADK_E_FAIL;
	}

	return rsa_check_bit_useful(uadk_rsa_bits(rsa), flen);
}

static int rsa_get_sign_res(int padding, BIGNUM *to_bn, const BIGNUM *n,
			    BIGNUM *ret_bn, BIGNUM **res)
{
	if (padding == RSA_X931_PADDING) {
		if (!BN_sub(to_bn, n, ret_bn))
			return UADK_E_FAIL;
		if (BN_cmp(ret_bn, to_bn) > 0)
			*res = to_bn;
		else
			*res = ret_bn;
	} else {
		*res = ret_bn;
	}

	return UADK_E_SUCCESS;
}

static int rsa_get_verify_res(int padding, const BIGNUM *n, BIGNUM *ret_bn)
{
	BIGNUM *to_bn = NULL;

	if ((padding == RSA_X931_PADDING) && ((bn_get_words(ret_bn)[0] & 0xf)
	    != 0x0c)) {
		if (!BN_sub(to_bn, n, ret_bn))
			return UADK_E_FAIL;
	}

	return UADK_E_SUCCESS;
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
	} while (rx_cnt < PROV_RECV_MAX_CNT);

	fprintf(stderr, "failed to poll msg: timeout!\n");

	return -ETIMEDOUT;
}

static void uadk_rsa_mutex_infork(void)
{
	/* Release the replication lock of the child process */
	pthread_mutex_unlock(&rsa_mutex);
}

static int uadk_prov_rsa_init(void)
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

	return UADK_E_INIT_SUCCESS;
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

static void rsa_free_eng_session(struct uadk_rsa_sess *rsa_sess)
{
	if (!rsa_sess)
		return;

	rsa_sess->alg = NULL;
	rsa_sess->is_pubkey_ready = UN_SET;
	rsa_sess->is_prikey_ready = UN_SET;

	wd_rsa_free_sess(rsa_sess->sess);
	OPENSSL_free(rsa_sess);
}

static struct uadk_rsa_sess *rsa_get_eng_session(RSA *rsa, unsigned int bits,
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

static int rsa_fill_pubkey(struct rsa_pubkey_param *pubkey_param,
			   struct uadk_rsa_sess *rsa_sess,
			   unsigned char *in_buf, unsigned char *to)
{
	struct wd_rsa_pubkey *pubkey = NULL;
	struct wd_dtb *wd_n = NULL;
	struct wd_dtb *wd_e = NULL;

	if (!rsa_sess->is_pubkey_ready) {
		wd_rsa_get_pubkey(rsa_sess->sess, &pubkey);
		if (!pubkey)
			return UADK_E_FAIL;

		wd_rsa_get_pubkey_params(pubkey, &wd_e, &wd_n);
		if (!wd_n || !wd_e)
			return UADK_E_FAIL;

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

		return UADK_E_SUCCESS;
	}

	return UADK_E_FAIL;
}

static int rsa_fill_prikey(RSA *rsa, struct uadk_rsa_sess *rsa_sess,
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

	if (!(rsa_sess->is_prikey_ready) && (pri->is_crt)) {
		wd_rsa_get_prikey(rsa_sess->sess, &prikey);
		if (!prikey)
			return UADK_E_FAIL;

		wd_rsa_get_crt_prikey_params(prikey, &wd_dq, &wd_dp,
					     &wd_qinv, &wd_q, &wd_p);
		if (!wd_dq || !wd_dp || !wd_qinv || !wd_q || !wd_p)
			return UADK_E_FAIL;

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
	} else if (!(rsa_sess->is_prikey_ready) && !(pri->is_crt)) {
		wd_rsa_get_prikey(rsa_sess->sess, &prikey);
		if (!prikey)
			return UADK_E_FAIL;

		wd_rsa_get_prikey_params(prikey, &wd_d, &wd_n);
		if (!wd_d || !wd_n)
			return UADK_E_FAIL;

		wd_n->dsize = BN_bn2bin(pri->n,
					(unsigned char *)wd_n->data);
		wd_d->dsize = BN_bn2bin(pri->d,
					(unsigned char *)wd_d->data);
	} else {
		return UADK_E_FAIL;
	}

	rsa_sess->is_prikey_ready = IS_SET;
	rsa_sess->req.op_type = WD_RSA_SIGN;
	rsa_sess->req.src_bytes = rsa_sess->key_size;
	rsa_sess->req.dst_bytes = rsa_sess->key_size;
	rsa_sess->req.src = in_buf;
	rsa_sess->req.dst = to;

	return UADK_E_SUCCESS;
}

static int rsa_get_keygen_param(struct wd_rsa_req *req, handle_t ctx, RSA *rsa,
				struct rsa_keygen_param_bn *bn_param, BN_CTX **bn_ctx_in)
{
	struct wd_rsa_kg_out *out = (struct wd_rsa_kg_out *)req->dst;
	struct wd_dtb wd_d, wd_n, wd_qinv, wd_dq, wd_dp;
	BIGNUM *dmp1, *dmq1, *iqmp, *d, *n;
	unsigned int key_bits, key_size;
	BN_CTX *bn_ctx = *bn_ctx_in;

	key_bits = wd_rsa_get_key_bits(ctx);
	if (!key_bits)
		return UADK_E_FAIL;

	key_size = key_bits >> BIT_BYTES_SHIFT;
	wd_rsa_get_kg_out_params(out, &wd_d, &wd_n);
	wd_rsa_get_kg_out_crt_params(out, &wd_qinv, &wd_dq, &wd_dp);

	dmq1 = BN_CTX_get(bn_ctx);
	if (!dmq1)
		return UADK_E_FAIL;

	dmp1 = BN_CTX_get(bn_ctx);
	if (!dmp1)
		return UADK_E_FAIL;

	iqmp = BN_CTX_get(bn_ctx);
	if (!iqmp)
		return UADK_E_FAIL;

	n = BN_CTX_get(bn_ctx);
	if (!n)
		return UADK_E_FAIL;

	d = BN_CTX_get(bn_ctx);
	if (!d)
		return UADK_E_FAIL;

	BN_bin2bn((unsigned char *)wd_n.data, key_size, n);
	BN_bin2bn((unsigned char *)wd_d.data, key_size, d);
	BN_bin2bn((unsigned char *)wd_qinv.data, wd_qinv.dsize, iqmp);
	BN_bin2bn((unsigned char *)wd_dq.data, wd_dq.dsize, dmq1);
	BN_bin2bn((unsigned char *)wd_dp.data, wd_dp.dsize, dmp1);

	if (!(uadk_rsa_set0_key(rsa, n, bn_param->e, d) &&
	    uadk_rsa_set0_factors(rsa, bn_param->p, bn_param->q) &&
	    uadk_rsa_set0_crt_params(rsa, dmp1, dmq1, iqmp)))
		return UADK_E_FAIL;

	return UADK_E_SUCCESS;
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

static int rsa_do_crypto(struct uadk_rsa_sess *rsa_sess)
{
	struct uadk_e_cb_info cb_param;
	struct async_op op;
	int idx, ret;

	ret = async_setup_async_event_notification(&op);
	if (!ret) {
		fprintf(stderr, "failed to setup async event notification.\n");
		return UADK_E_FAIL;
	}

	if (!op.job) {
		ret = wd_do_rsa_sync(rsa_sess->sess, &(rsa_sess->req));
		if (ret)
			goto err;
		return UADK_E_SUCCESS;
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
		return UADK_E_FAIL;

	return UADK_E_SUCCESS;

err:
	(void)async_clear_async_event_notification();
	return UADK_E_FAIL;
}

static int rsa_fill_keygen_data(struct uadk_rsa_sess *rsa_sess,
				struct rsa_keypair *key_pair,
				struct rsa_keygen_param *keygen_param,
				struct rsa_keygen_param_bn *bn_param)
{
	wd_rsa_get_pubkey(rsa_sess->sess, &key_pair->pubkey);
	if (!key_pair->pubkey)
		return UADK_E_FAIL;

	wd_rsa_get_pubkey_params(key_pair->pubkey, &keygen_param->wd_e, NULL);
	if (!keygen_param->wd_e)
		return UADK_E_FAIL;

	keygen_param->wd_e->dsize = BN_bn2bin(bn_param->e,
				    (unsigned char *)keygen_param->wd_e->data);

	wd_rsa_get_prikey(rsa_sess->sess, &key_pair->prikey);
	if (!key_pair->prikey)
		return UADK_E_FAIL;

	wd_rsa_get_crt_prikey_params(key_pair->prikey, NULL, NULL, NULL,
				     &keygen_param->wd_q, &keygen_param->wd_p);
	if (!keygen_param->wd_p || !keygen_param->wd_q)
		return UADK_E_FAIL;

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
		return UADK_E_FAIL;

	rsa_sess->req.dst = wd_rsa_new_kg_out(rsa_sess->sess);
	if (!rsa_sess->req.dst) {
		wd_rsa_del_kg_in(rsa_sess->sess, rsa_sess->req.src);
		return UADK_E_FAIL;
	}

	return UADK_E_SUCCESS;
}

static void rsa_free_keygen_data(struct uadk_rsa_sess *rsa_sess)
{
	if (!rsa_sess)
		return;

	wd_rsa_del_kg_out(rsa_sess->sess, rsa_sess->req.dst);
	wd_rsa_del_kg_in(rsa_sess->sess, rsa_sess->req.src);
}

static int rsa_keygen_param_alloc(struct rsa_keygen_param **keygen_param,
				  struct rsa_keygen_param_bn **keygen_bn_param,
				  struct rsa_keypair **key_pair, BN_CTX **bn_ctx_in)
{
	BN_CTX *bn_ctx;

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

	bn_ctx = BN_CTX_new();
	if (!bn_ctx)
		goto free_key_pair;

	BN_CTX_start(bn_ctx);
	*bn_ctx_in = bn_ctx;

	(*keygen_bn_param)->p = BN_CTX_get(bn_ctx);
	if (!(*keygen_bn_param)->p)
		goto free_bn_ctx;

	(*keygen_bn_param)->q = BN_CTX_get(bn_ctx);
	if (!(*keygen_bn_param)->q)
		goto free_bn_ctx;

	(*keygen_bn_param)->e = BN_CTX_get(bn_ctx);
	if (!(*keygen_bn_param)->e)
		goto free_bn_ctx;

	return UADK_E_SUCCESS;

free_bn_ctx:
	BN_CTX_end(bn_ctx);
	BN_CTX_free(bn_ctx);
free_key_pair:
	OPENSSL_free(*key_pair);
free_keygen_bn_param:
	OPENSSL_free(*keygen_bn_param);
free_keygen_param:
	OPENSSL_free(*keygen_param);
error:
	return -ENOMEM;
}

static void rsa_keygen_param_free(struct rsa_keygen_param **keygen_param,
				  struct rsa_keygen_param_bn **keygen_bn_param,
				  struct rsa_keypair **key_pair, BN_CTX **bn_ctx,
				  int free_bn_ctx_tag)
{
	/*
	 * When an abnormal situation occurs, uadk engine needs to
	 * switch to software keygen function, so we need to free
	 * BN ctx we alloced before. But in normal situation,
	 * the BN ctx should be freed by OpenSSL tools or users.
	 * Therefore, we use a tag to distinguish these cases.
	 */
	if (free_bn_ctx_tag == UADK_DO_SOFT) {
		BN_CTX_end(*bn_ctx);
		BN_CTX_free(*bn_ctx);
	}

	OPENSSL_free(*key_pair);
	OPENSSL_free(*keygen_param);
	OPENSSL_free(*keygen_bn_param);
}

static int rsa_pkey_param_alloc(struct rsa_pubkey_param **pub,
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

	return UADK_E_SUCCESS;
}

static void rsa_pkey_param_free(struct rsa_pubkey_param **pub,
				struct rsa_prikey_param **pri)
{
	if (pri)
		OPENSSL_free(*pri);
	if (pub)
		OPENSSL_free(*pub);
}

static int rsa_create_pub_bn_ctx(RSA *rsa, struct rsa_pubkey_param *pub,
				 unsigned char **from_buf, int *num_bytes)
{
	uadk_rsa_get0_key(rsa, &pub->n, &pub->e, NULL);
	if (!(pub->e) || !(pub->n))
		return UADK_E_FAIL;

	*num_bytes = BN_num_bytes(pub->n);
	if (!(*num_bytes))
		return UADK_E_FAIL;

	*from_buf = OPENSSL_malloc(*num_bytes);
	if (!(*from_buf))
		return -ENOMEM;

	return UADK_E_SUCCESS;
}

static void rsa_free_pub_bn_ctx(unsigned char **from_buf)
{
	OPENSSL_free(*from_buf);
}

static int rsa_create_pri_bn_ctx(RSA *rsa, struct rsa_prikey_param *pri,
				 unsigned char **from_buf, int *num_bytes)
{
	uadk_rsa_get0_key(rsa, &pri->n, &pri->e, &pri->d);
	if (!(pri->n) || !(pri->e) || !(pri->d))
		return UADK_E_FAIL;

	uadk_rsa_get0_factors(rsa, &pri->p, &pri->q);
	if (!(pri->p) || !(pri->q))
		return UADK_E_FAIL;

	uadk_rsa_get0_crt_params(rsa, &pri->dmp1, &pri->dmq1, &pri->iqmp);
	if (!(pri->dmp1) || !(pri->dmq1) || !(pri->iqmp))
		return UADK_E_FAIL;

	*num_bytes = BN_num_bytes(pri->n);
	if (!(*num_bytes))
		return UADK_E_FAIL;

	*from_buf = OPENSSL_malloc(*num_bytes);
	if (!(*from_buf))
		return -ENOMEM;

	return UADK_E_SUCCESS;
}

static void rsa_free_pri_bn_ctx(unsigned char **from_buf)
{
	OPENSSL_free(*from_buf);
}

static int uadk_prov_rsa_keygen(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb)
{
	struct rsa_keygen_param *keygen_param = NULL;
	struct rsa_keygen_param_bn *bn_param = NULL;
	struct uadk_rsa_sess *rsa_sess = NULL;
	struct rsa_keypair *key_pair = NULL;
	BN_CTX *bn_ctx = NULL;
	int is_crt = 1;
	int ret;

	ret = rsa_check_bit_useful(bits, 0);
	if (ret != UADK_E_SUCCESS)
		return ret;

	ret = rsa_keygen_param_alloc(&keygen_param, &bn_param, &key_pair, &bn_ctx);
	if (ret == -ENOMEM)
		return UADK_E_FAIL;

	rsa_sess = rsa_get_eng_session(rsa, bits, is_crt);
	if (!rsa_sess) {
		ret = UADK_DO_SOFT;
		goto free_keygen;
	}

	ret = rsa_primes_gen(bits, e, bn_param->p, bn_param->q, cb);
	if (!ret) {
		ret = UADK_E_FAIL;
		goto free_sess;
	}

	if (!BN_copy(bn_param->e, e)) {
		ret = UADK_E_FAIL;
		goto free_sess;
	}

	ret = rsa_fill_keygen_data(rsa_sess, key_pair, keygen_param, bn_param);
	if (!ret) {
		ret = UADK_E_FAIL;
		goto free_sess;
	}

	ret = rsa_do_crypto(rsa_sess);
	if (!ret || rsa_sess->req.status) {
		ret = UADK_DO_SOFT;
		goto free_kg_in_out;
	}

	ret = rsa_get_keygen_param(&rsa_sess->req, rsa_sess->sess, rsa, bn_param, &bn_ctx);
	if (!ret)
		ret = UADK_E_FAIL;

free_kg_in_out:
	rsa_free_keygen_data(rsa_sess);
free_sess:
	rsa_free_eng_session(rsa_sess);
free_keygen:
	rsa_keygen_param_free(&keygen_param, &bn_param, &key_pair, &bn_ctx, ret);
	return ret;
}

static int crypt_trans_bn(struct uadk_rsa_sess *rsa_sess, unsigned char *buf, int num_bytes)
{
	BIGNUM *bn = NULL;
	int ret;

	bn = BN_bin2bn((const unsigned char *)rsa_sess->req.dst,
			   rsa_sess->req.dst_bytes, NULL);
	if (!bn)
		return UADK_E_FAIL;

	ret = BN_bn2binpad(bn, buf, num_bytes);
	if (ret == BN_ERR)
		ret = UADK_E_FAIL;

	BN_free(bn);

	return ret;
}

static int uadk_prov_rsa_public_encrypt(int flen, const unsigned char *from,
				     unsigned char *to, RSA *rsa, int padding)
{
	struct rsa_pubkey_param *pub_enc = NULL;
	struct uadk_rsa_sess *rsa_sess = NULL;
	unsigned char *from_buf = NULL;
	int num_bytes, is_crt, ret;

	ret = check_rsa_input_para(flen, from, to, rsa);
	if (ret != UADK_E_SUCCESS)
		return ret;

	ret = rsa_pkey_param_alloc(&pub_enc, NULL);
	if (ret == -ENOMEM)
		return UADK_E_FAIL;

	is_crt = check_rsa_is_crt(rsa);

	rsa_sess = rsa_get_eng_session(rsa, uadk_rsa_bits(rsa), is_crt);
	if (!rsa_sess) {
		ret = UADK_DO_SOFT;
		goto free_pkey;
	}

	ret = rsa_create_pub_bn_ctx(rsa, pub_enc, &from_buf, &num_bytes);
	if (ret <= 0) {
		ret = UADK_E_FAIL;
		goto free_sess;
	}

	ret = add_rsa_pubenc_padding(flen, from, from_buf, num_bytes, padding);
	if (!ret) {
		ret = UADK_E_FAIL;
		goto free_buf;
	}

	ret = rsa_fill_pubkey(pub_enc, rsa_sess, from_buf, to);
	if (!ret) {
		ret = UADK_E_FAIL;
		goto free_buf;
	}

	ret = rsa_do_crypto(rsa_sess);
	if (!ret || rsa_sess->req.status) {
		ret = UADK_DO_SOFT;
		goto free_buf;
	}

	ret = crypt_trans_bn(rsa_sess, to, num_bytes);

free_buf:
	rsa_free_pub_bn_ctx(&from_buf);
free_sess:
	rsa_free_eng_session(rsa_sess);
free_pkey:
	rsa_pkey_param_free(&pub_enc, NULL);
	return ret;
}

static int uadk_prov_rsa_private_decrypt(int flen, const unsigned char *from,
				      unsigned char *to, RSA *rsa, int padding)
{
	struct rsa_prikey_param *pri = NULL;
	unsigned char *from_buf = NULL;
	struct uadk_rsa_sess *rsa_sess;
	int num_bytes, ret;

	ret = check_rsa_input_para(flen, from, to, rsa);
	if (ret != UADK_E_SUCCESS)
		return ret;

	ret = rsa_pkey_param_alloc(NULL, &pri);
	if (ret == -ENOMEM)
		return UADK_E_FAIL;

	pri->is_crt = check_rsa_is_crt(rsa);

	rsa_sess = rsa_get_eng_session(rsa, uadk_rsa_bits(rsa), pri->is_crt);
	if (!rsa_sess) {
		ret = UADK_DO_SOFT;
		goto free_pkey;
	}

	ret = rsa_create_pri_bn_ctx(rsa, pri, &from_buf, &num_bytes);
	if (ret <= 0) {
		ret = UADK_E_FAIL;
		goto free_sess;
	}

	if (flen != num_bytes) {
		ret = UADK_E_FAIL;
		goto free_buf;
	}

	ret = rsa_fill_prikey(rsa, rsa_sess, pri, from_buf, to);
	if (!ret) {
		ret = UADK_E_FAIL;
		goto free_buf;
	}

	memcpy(rsa_sess->req.src, from, rsa_sess->req.src_bytes);

	ret = rsa_do_crypto(rsa_sess);
	if (!ret || rsa_sess->req.status) {
		ret = UADK_DO_SOFT;
		goto free_buf;
	}

	ret = crypt_trans_bn(rsa_sess, from_buf, num_bytes);
	if (!ret)
		goto free_buf;

	ret = check_rsa_pridec_padding(to, num_bytes, from_buf, flen, padding);
	if (!ret)
		ret = UADK_E_FAIL;

free_buf:
	rsa_free_pri_bn_ctx(&from_buf);
free_sess:
	rsa_free_eng_session(rsa_sess);
free_pkey:
	rsa_pkey_param_free(NULL, &pri);
	return ret;
}

static int sign_trans_bn(struct uadk_rsa_sess *rsa_sess, unsigned char *from_buf,
			 struct rsa_prikey_param *pri, int padding,
			 unsigned char *to, int num_bytes)
{
	BIGNUM *sign_bn = NULL;
	BIGNUM *to_bn = NULL;
	BIGNUM *res = NULL;
	int ret;

	sign_bn = BN_bin2bn((const unsigned char *)rsa_sess->req.dst,
			   rsa_sess->req.dst_bytes, NULL);
	if (!sign_bn)
		return UADK_E_FAIL;

	to_bn = BN_bin2bn(from_buf, num_bytes, NULL);
	if (!to_bn) {
		BN_free(sign_bn);

		return UADK_E_FAIL;
	}

	ret = rsa_get_sign_res(padding, to_bn, pri->n, sign_bn, &res);
	if (!ret) {
		BN_free(to_bn);
		BN_free(sign_bn);

		return UADK_E_FAIL;
	}

	ret = BN_bn2binpad(res, to, num_bytes);

	return ret;
}

static int uadk_prov_rsa_private_sign(int flen, const unsigned char *from,
				   unsigned char *to, RSA *rsa, int padding)
{
	struct uadk_rsa_sess *rsa_sess = NULL;
	struct rsa_prikey_param *prik = NULL;
	unsigned char *from_buf = NULL;
	int ret, num_bytes;

	ret = check_rsa_input_para(flen, from, to, rsa);
	if (ret != UADK_E_SUCCESS)
		return ret;

	ret = rsa_pkey_param_alloc(NULL, &prik);
	if (ret == -ENOMEM)
		return UADK_E_FAIL;

	prik->is_crt = check_rsa_is_crt(rsa);

	rsa_sess = rsa_get_eng_session(rsa, uadk_rsa_bits(rsa), prik->is_crt);
	if (!rsa_sess) {
		ret = UADK_DO_SOFT;
		goto free_pkey;
	}

	ret = rsa_create_pri_bn_ctx(rsa, prik, &from_buf, &num_bytes);
	if (ret <= 0 || flen > num_bytes) {
		ret = UADK_E_FAIL;
		goto free_sess;
	}

	ret = add_rsa_prienc_padding(flen, from, from_buf, num_bytes, padding);
	if (!ret) {
		ret = UADK_E_FAIL;
		goto free_buf;
	}

	ret = rsa_fill_prikey(rsa, rsa_sess, prik, from_buf, to);
	if (!ret) {
		ret = UADK_E_FAIL;
		goto free_buf;
	}

	ret = rsa_do_crypto(rsa_sess);
	if (!ret || rsa_sess->req.status) {
		ret = UADK_DO_SOFT;
		goto free_buf;
	}

	ret = sign_trans_bn(rsa_sess, from_buf, prik, padding, to, num_bytes);

free_buf:
	rsa_free_pri_bn_ctx(&from_buf);
free_sess:
	rsa_free_eng_session(rsa_sess);
free_pkey:
	rsa_pkey_param_free(NULL, &prik);
	return ret;
}

static int verify_trans_bn(struct uadk_rsa_sess *rsa_sess, unsigned char *from_buf,
			   int num_bytes, struct rsa_pubkey_param *pub,
			   int padding, int *len)
{
	BIGNUM *verify_bn = NULL;
	int ret;

	verify_bn = BN_bin2bn((const unsigned char *)rsa_sess->req.dst,
			    rsa_sess->req.dst_bytes, NULL);
	if (!verify_bn)
		return UADK_E_FAIL;

	ret = rsa_get_verify_res(padding, pub->n, verify_bn);
	if (!ret) {
		BN_free(verify_bn);
		return UADK_E_FAIL;
	}

	*len = BN_bn2binpad(verify_bn, from_buf, num_bytes);
	if (*len == 0) {
		BN_free(verify_bn);
		return UADK_E_FAIL;
	}

	return ret;
}

static int uadk_prov_rsa_public_verify(int flen, const unsigned char *from,
				    unsigned char *to, RSA *rsa, int padding)
{
	struct uadk_rsa_sess *rsa_sess = NULL;
	struct rsa_pubkey_param *pub = NULL;
	int num_bytes, is_crt, len, ret;
	unsigned char *from_buf = NULL;

	ret = check_rsa_input_para(flen, from, to, rsa);
	if (ret != UADK_E_SUCCESS)
		return ret;

	ret = rsa_pkey_param_alloc(&pub, NULL);
	if (ret == -ENOMEM)
		return UADK_E_FAIL;

	is_crt = check_rsa_is_crt(rsa);

	rsa_sess = rsa_get_eng_session(rsa, uadk_rsa_bits(rsa), is_crt);
	if (!rsa_sess) {
		ret = UADK_DO_SOFT;
		goto free_pkey;
	}

	ret = rsa_create_pub_bn_ctx(rsa, pub, &from_buf, &num_bytes);
	if (ret <= 0 || flen > num_bytes) {
		ret = UADK_E_FAIL;
		goto free_sess;
	}

	ret = rsa_fill_pubkey(pub, rsa_sess, from_buf, to);
	if (!ret) {
		ret = UADK_E_FAIL;
		goto free_buff;
	}

	memcpy(rsa_sess->req.src, from, rsa_sess->req.src_bytes);
	ret = rsa_do_crypto(rsa_sess);
	if (!ret || rsa_sess->req.status) {
		ret = UADK_DO_SOFT;
		goto free_buff;
	}

	ret = verify_trans_bn(rsa_sess, from_buf, num_bytes, pub, padding, &len);
	if (!ret)
		goto free_buff;

	ret = check_rsa_pubdec_padding(to, num_bytes, from_buf, len, padding);

free_buff:
	rsa_free_pub_bn_ctx(&from_buf);
free_sess:
	rsa_free_eng_session(rsa_sess);
free_pkey:
	rsa_pkey_param_free(&pub, NULL);
	return ret;
}

static int uadk_rsa_asym_init(void *vprsactx, void *vrsa,
			      const OSSL_PARAM params[], int operation)
{
	PROV_RSA_ASYM_CTX *priv = (PROV_RSA_ASYM_CTX *)vprsactx;

	priv->rsa = vrsa;
	priv->operation = operation;

	switch (uadk_rsa_test_flags(priv->rsa, RSA_FLAG_TYPE_MASK)) {
	case RSA_FLAG_TYPE_RSA:
		priv->pad_mode = RSA_PKCS1_PADDING;
		break;
	case RSA_FLAG_TYPE_RSASSAPSS:
		priv->pad_mode = RSA_PKCS1_PSS_PADDING;
		break;
	default:
		ERR_raise(ERR_LIB_RSA, PROV_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
		return UADK_E_FAIL;
	}

	if (uadk_prov_rsa_init())
		priv->soft = 1;

	return UADK_E_SUCCESS;
}

static int uadk_rsa_init(void *vprsactx, void *vrsa,
			 const OSSL_PARAM params[], int operation)
{
	PROV_RSA_SIG_CTX *ctx = (PROV_RSA_SIG_CTX *)vprsactx;

	if (ctx == NULL || vrsa == NULL)
		return UADK_E_FAIL;

	ctx->rsa = vrsa;
	ctx->operation = operation;

	/* Maximum for sign, auto for verify */
	ctx->saltlen = RSA_PSS_SALTLEN_AUTO;
	ctx->min_saltlen = -1;

	switch (uadk_rsa_test_flags(ctx->rsa, RSA_FLAG_TYPE_MASK)) {
	case RSA_FLAG_TYPE_RSA:
		ctx->pad_mode = RSA_PKCS1_PADDING;
		break;
	case RSA_FLAG_TYPE_RSASSAPSS:
		ctx->pad_mode = RSA_PKCS1_PSS_PADDING;
		break;
	default:
		ERR_raise(ERR_LIB_RSA, PROV_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE);
		return UADK_E_FAIL;
	}

	if (uadk_prov_rsa_init())
		ctx->soft = 1;

	return UADK_E_SUCCESS;
}

static int uadk_signature_rsa_verify_recover_init(void *vprsactx, void *vrsa,
						  const OSSL_PARAM params[])
{
	return UADK_E_SUCCESS;
}

static int uadk_signature_rsa_verify_recover(void *vprsactx, unsigned char *rout,
					     size_t *routlen, size_t routsize,
					     const unsigned char *sig, size_t siglen)
{
	return UADK_E_SUCCESS;
}

static int uadk_signature_rsa_verify_init(void *vprsactx, void *vrsa,
				const OSSL_PARAM params[])
{
	return uadk_rsa_init(vprsactx, vrsa, params, EVP_PKEY_OP_VERIFY);
}

static int uadk_rsa_sw_verify(void *vprsactx, const unsigned char *sig,
			      size_t siglen, const unsigned char *tbs,
			      size_t tbslen)
{
	if (!enable_sw_offload || !get_default_rsa_signature().verify)
		return UADK_E_FAIL;

	fprintf(stderr, "switch to openssl software calculation in verifaction.\n");
	return get_default_rsa_signature().verify(vprsactx, sig, siglen, tbs, tbslen);
}

static int uadk_signature_rsa_verify(void *vprsactx, const unsigned char *sig,
			   size_t siglen, const unsigned char *tbs,
			   size_t tbslen)
{
	PROV_RSA_SIG_CTX *priv = (PROV_RSA_SIG_CTX *)vprsactx;
	size_t rslen = 0;

	if (priv->soft) {
		rslen = UADK_DO_SOFT;
		goto exe_soft;
	}

	/* todo call public_verify */
	if (priv->md != NULL) {
		/* todo */
	} else {
		if (!setup_tbuf(priv))
			return UADK_E_FAIL;
		rslen = uadk_prov_rsa_public_verify(siglen, sig, priv->tbuf,
						 priv->rsa, priv->pad_mode);
		if (rslen == UADK_DO_SOFT || rslen == UADK_E_FAIL)
			goto exe_soft;
	}

	if ((rslen != tbslen) || memcmp(tbs, priv->tbuf, rslen))
		return UADK_E_FAIL;

	return UADK_E_SUCCESS;

exe_soft:
	if (rslen == UADK_DO_SOFT)
		return uadk_rsa_sw_verify(vprsactx, sig, siglen, tbs, tbslen);
	return UADK_E_FAIL;
}

static int uadk_rsa_sw_sign(void *vprsactx, unsigned char *sig,
			    size_t *siglen, size_t sigsize,
			    const unsigned char *tbs, size_t tbslen)
{
	if (!enable_sw_offload || !get_default_rsa_signature().sign)
		return UADK_E_FAIL;

	fprintf(stderr, "switch to openssl software calculation in rsa signature.\n");
	return get_default_rsa_signature().sign(vprsactx, sig, siglen, sigsize, tbs, tbslen);
}

static int uadk_signature_rsa_sign(void *vprsactx, unsigned char *sig,
			 size_t *siglen, size_t sigsize,
			 const unsigned char *tbs, size_t tbslen)
{
	PROV_RSA_SIG_CTX *priv = (PROV_RSA_SIG_CTX *)vprsactx;
	size_t rsasize = uadk_rsa_size(priv->rsa);
	int ret;

	if (priv->soft) {
		ret = UADK_DO_SOFT;
		goto exe_soft;
	}

	if (sig == NULL) {
		*siglen = rsasize;
		return UADK_E_SUCCESS;
	}

	if (sigsize < rsasize) {
		ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_SIGNATURE_SIZE,
			       "is %zu, should be at least %zu", sigsize, rsasize);
		return UADK_E_FAIL;
	}

	ret = uadk_prov_rsa_private_sign(tbslen, tbs, sig, priv->rsa, priv->pad_mode);
	if (ret == UADK_DO_SOFT || ret == UADK_E_FAIL)
		goto exe_soft;

	if (ret < 0)
		return ret;

	*siglen = ret;

	return UADK_E_SUCCESS;
exe_soft:
	if (ret == UADK_DO_SOFT)
		return uadk_rsa_sw_sign(vprsactx, sig, siglen, sigsize, tbs, tbslen);
	return UADK_E_FAIL;
}

static int uadk_signature_rsa_sign_init(void *vprsactx, void *vrsa, const OSSL_PARAM params[])
{
	return uadk_rsa_init(vprsactx, vrsa, params, EVP_PKEY_OP_SIGN);
}

static void *uadk_signature_rsa_newctx(void *provctx, const char *propq)
{
	PROV_RSA_SIG_CTX *priv = OPENSSL_zalloc(sizeof(PROV_RSA_SIG_CTX));
	char *propq_copy = NULL;

	if (priv == NULL)
		goto err;

	if  (propq != NULL) {
		propq_copy = OPENSSL_strdup(propq);
		if (propq_copy == NULL)
			goto err;
	}

	priv->libctx = prov_libctx_of(provctx);
	priv->flag_allow_md = 1;
	priv->propq = propq_copy;
	return priv;

err:
	OPENSSL_free(priv);
	fprintf(stderr, "%s failed.\n", __func__);
	return NULL;
}

static void uadk_signature_rsa_freectx(void *vprsactx)
{
	PROV_RSA_SIG_CTX *priv = (PROV_RSA_SIG_CTX *)vprsactx;

	if (priv == NULL)
		return;

	free_tbuf(priv);
	OPENSSL_clear_free(priv, sizeof(*priv));
}

static void *uadk_asym_cipher_rsa_newctx(void *provctx)
{
	PROV_RSA_ASYM_CTX *priv = NULL;

	priv = OPENSSL_zalloc(sizeof(*priv));
	if (priv == NULL)
		return NULL;
	priv->libctx = prov_libctx_of(provctx);

	return priv;
}

static void uadk_asym_cipher_rsa_freectx(void *vprsactx)
{
	PROV_RSA_ASYM_CTX *priv = (PROV_RSA_ASYM_CTX *)vprsactx;

	if (priv == NULL)
		return;

	OPENSSL_free(priv);
}

static int uadk_signature_rsa_set_ctx_params(void *vprsactx, const OSSL_PARAM params[])
{
	PROV_RSA_SIG_CTX *priv = (PROV_RSA_SIG_CTX *)vprsactx;

	if (priv == NULL)
		return UADK_E_FAIL;
	if (params == NULL)
		return UADK_E_SUCCESS;

	/* todo */

	return UADK_E_SUCCESS;
}

static const OSSL_PARAM settable_ctx_params[] = {
	OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
	OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PROPERTIES, NULL, 0),
	OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
	OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, NULL, 0),
	OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_PROPERTIES, NULL, 0),
	OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL, 0),
	OSSL_PARAM_END
};

static const OSSL_PARAM settable_ctx_params_no_digest[] = {
	OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
	OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, NULL, 0),
	OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_PROPERTIES, NULL, 0),
	OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL, 0),
	OSSL_PARAM_END
};

static const OSSL_PARAM *uadk_signature_rsa_settable_ctx_params(void *vprsactx,
							       void *provctx)
{
	PROV_RSA_SIG_CTX *priv = (PROV_RSA_SIG_CTX *)vprsactx;

	if (priv != NULL && !priv->flag_allow_md)
		return settable_ctx_params_no_digest;

	return settable_ctx_params;
}

static int uadk_signature_rsa_digest_sign_init(void *vprsactx, const char *mdname,
					      void *vrsa, const OSSL_PARAM params[])
{
	if (!get_default_rsa_signature().digest_sign_init)
		return UADK_E_FAIL;

	return get_default_rsa_signature().digest_sign_init(vprsactx, mdname, vrsa, params);
}

static int uadk_signature_rsa_digest_sign_update(void *vprsactx,
					     const unsigned char *data,
					     size_t datalen)
{
	PROV_RSA_SIG_CTX *priv = (PROV_RSA_SIG_CTX *)vprsactx;

	if (priv == NULL || priv->mdctx == NULL)
		return UADK_E_FAIL;

	return EVP_DigestUpdate(priv->mdctx, data, datalen);
}

static int uadk_signature_rsa_digest_sign_final(void *vprsactx, unsigned char *sig,
					       size_t *siglen, size_t sigsize)
{
	PROV_RSA_SIG_CTX *priv = (PROV_RSA_SIG_CTX *)vprsactx;
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int dlen = 0;

	if (priv == NULL)
		return UADK_E_FAIL;
	priv->flag_allow_md = 1;

	if (priv->mdctx == NULL)
		return UADK_E_FAIL;
	/*
	 * If sig is NULL then we're just finding out the sig size. Other fields
	 * are ignored. Defer to rsa_sign.
	 */
	if (sig != NULL) {
		/*
		 * The digests used here are all known (see rsa_get_md_nid()), so they
		 * should not exceed the internal buffer size of EVP_MAX_MD_SIZE.
		 */
		if (!EVP_DigestFinal_ex(priv->mdctx, digest, &dlen))
			return UADK_E_FAIL;
	}

	return uadk_signature_rsa_sign(vprsactx, sig, siglen, sigsize,
				       digest, (size_t)dlen);
}

static int uadk_signature_rsa_digest_verify_init(void *vprsactx, const char *mdname,
				       void *vrsa, const OSSL_PARAM params[])
{
	if (!get_default_rsa_signature().digest_verify_init)
		return UADK_E_FAIL;

	return get_default_rsa_signature().digest_verify_init(vprsactx, mdname, vrsa, params);
}

static int uadk_signature_rsa_digest_verify_update(void *vprsactx, const unsigned char *data,
						   size_t datalen)
{
	if (!get_default_rsa_signature().digest_verify_update)
		return UADK_E_FAIL;

	return get_default_rsa_signature().digest_verify_update(vprsactx, data, datalen);
}

static int uadk_signature_rsa_digest_verify_final(void *vprsactx, const unsigned char *sig,
					size_t siglen)
{
	PROV_RSA_SIG_CTX *priv = (PROV_RSA_SIG_CTX *)vprsactx;
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int dlen = 0;

	if (priv == NULL)
		return UADK_E_FAIL;
	priv->flag_allow_md = 1;
	if (priv->mdctx == NULL)
		return UADK_E_FAIL;

	/*
	 * The digests used here are all known (see rsa_get_md_nid()), so they
	 * should not exceed the internal buffer size of EVP_MAX_MD_SIZE.
	 */
	if (!EVP_DigestFinal_ex(priv->mdctx, digest, &dlen))
		return UADK_E_FAIL;

	return uadk_signature_rsa_verify(vprsactx, sig, siglen, digest, (size_t)dlen);
}

static void *uadk_signature_rsa_dupctx(void *vprsactx)
{
	if (!get_default_rsa_signature().dupctx)
		return NULL;

	return get_default_rsa_signature().dupctx(vprsactx);
}

static int uadk_signature_rsa_get_ctx_params(void *vprsactx, OSSL_PARAM *params)
{
	if (!get_default_rsa_signature().get_ctx_params)
		return UADK_E_FAIL;

	return get_default_rsa_signature().get_ctx_params(vprsactx, params);
}

static const OSSL_PARAM *uadk_signature_rsa_gettable_ctx_md_params(void *vprsactx)
{
	if (!get_default_rsa_signature().gettable_ctx_md_params)
		return NULL;

	return get_default_rsa_signature().gettable_ctx_md_params(vprsactx);
}

static int uadk_signature_rsa_set_ctx_md_params(void *vprsactx, const OSSL_PARAM params[])
{
	if (!get_default_rsa_signature().set_ctx_md_params)
		return UADK_E_FAIL;

	return get_default_rsa_signature().set_ctx_md_params(vprsactx, params);
}

static const OSSL_PARAM *uadk_signature_rsa_settable_ctx_md_params(void *vprsactx)
{
	if (!get_default_rsa_signature().settable_ctx_md_params)
		return NULL;

	return get_default_rsa_signature().settable_ctx_md_params(vprsactx);
}

static const OSSL_PARAM *uadk_signature_rsa_gettable_ctx_params(ossl_unused void *vprsactx,
						      ossl_unused void *provctx)
{
	if (!get_default_rsa_signature().gettable_ctx_params)
		return NULL;

	return get_default_rsa_signature().gettable_ctx_params(vprsactx, provctx);
}

static int uadk_signature_rsa_get_ctx_md_params(void *vprsactx, OSSL_PARAM *params)
{
	if (!get_default_rsa_signature().get_ctx_md_params)
		return UADK_E_FAIL;

	return get_default_rsa_signature().get_ctx_md_params(vprsactx, params);
}

static int uadk_asym_cipher_rsa_encrypt_init(void *vprsactx, void *vrsa,
				      const OSSL_PARAM params[])
{
	return uadk_rsa_asym_init(vprsactx, vrsa, params, EVP_PKEY_OP_ENCRYPT);
}

static int uadk_asym_cipher_rsa_decrypt_init(void *vprsactx, void *vrsa,
				      const OSSL_PARAM params[])
{
	return uadk_rsa_asym_init(vprsactx, vrsa, params, EVP_PKEY_OP_DECRYPT);
}

static int uadk_rsa_sw_encrypt(void *vprsactx, unsigned char *out,
			       size_t *outlen, size_t outsize,
			       const unsigned char *in, size_t inlen)
{
	if (!enable_sw_offload || !get_default_rsa_asym_cipher().encrypt)
		return UADK_E_FAIL;

	fprintf(stderr, "switch to openssl software calculation	in rsa encryption.\n");
	return get_default_rsa_asym_cipher().encrypt(vprsactx, out, outlen, outsize, in, inlen);
}

static int uadk_asym_cipher_rsa_encrypt(void *vprsactx, unsigned char *out,
				 size_t *outlen, size_t outsize,
				 const unsigned char *in, size_t inlen)
{
	PROV_RSA_ASYM_CTX *priv = (PROV_RSA_ASYM_CTX *)vprsactx;
	size_t len;
	int ret;

	if (priv->soft) {
		ret = UADK_DO_SOFT;
		goto exe_soft;
	}

	if (out == NULL) {
		len = uadk_rsa_size(priv->rsa);
		if (len == 0) {
			ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
			return UADK_E_FAIL;
		}
		*outlen = len;
		return UADK_E_SUCCESS;
	}

	ret = uadk_prov_rsa_public_encrypt(inlen, in, out, priv->rsa, priv->pad_mode);
	if (ret == UADK_DO_SOFT || ret == UADK_E_FAIL)
		goto exe_soft;

	*outlen = ret;

	return UADK_E_SUCCESS;
exe_soft:
	if (ret == UADK_DO_SOFT)
		return uadk_rsa_sw_encrypt(vprsactx, out, outlen, outsize, in, inlen);
	return UADK_E_FAIL;
}

static int uadk_rsa_sw_decrypt(void *vprsactx, unsigned char *out,
			       size_t *outlen, size_t outsize,
			       const unsigned char *in, size_t inlen)
{
	if (!enable_sw_offload || !get_default_rsa_asym_cipher().decrypt)
		return UADK_E_FAIL;

	fprintf(stderr, "switch to openssl software calculation in rsa decryption.\n");
	return get_default_rsa_asym_cipher().decrypt(vprsactx, out, outlen, outsize, in, inlen);
}

static int uadk_asym_cipher_rsa_decrypt(void *vprsactx, unsigned char *out,
				 size_t *outlen, size_t outsize,
				 const unsigned char *in, size_t inlen)
{
	PROV_RSA_ASYM_CTX *priv = (PROV_RSA_ASYM_CTX *)vprsactx;
	size_t len = uadk_rsa_size(priv->rsa);
	int ret;

	if (priv->soft) {
		ret = UADK_DO_SOFT;
		goto exe_soft;
	}

	if (out == NULL) {
		if (len == 0) {
			ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
			return UADK_E_FAIL;
		}
		*outlen = len;
		return UADK_E_SUCCESS;
	}

	if (outsize < len) {
		ERR_raise(ERR_LIB_PROV, PROV_R_BAD_LENGTH);
		return UADK_E_FAIL;
	}

	ret = uadk_prov_rsa_private_decrypt(inlen, in, out, priv->rsa, priv->pad_mode);
	if (ret == UADK_DO_SOFT || ret == UADK_E_FAIL)
		goto exe_soft;

	*outlen = ret;

	return UADK_E_SUCCESS;
exe_soft:
	if (ret == UADK_DO_SOFT)
		return uadk_rsa_sw_decrypt(vprsactx, out, outlen, outsize, in, inlen);
	return UADK_E_FAIL;
}

static int uadk_asym_cipher_rsa_get_ctx_params(void *vprsactx, OSSL_PARAM *params)
{
	if (!get_default_rsa_asym_cipher().get_ctx_params)
		return UADK_E_FAIL;

	return get_default_rsa_asym_cipher().get_ctx_params(vprsactx, params);
}

static const OSSL_PARAM *uadk_asym_cipher_rsa_gettable_ctx_params(void *vprsactx,
							   void *provctx)
{
	if (!get_default_rsa_asym_cipher().gettable_ctx_params)
		return NULL;

	return get_default_rsa_asym_cipher().gettable_ctx_params(vprsactx, provctx);
}

static int uadk_asym_cipher_rsa_set_ctx_params(void *vprsactx, const OSSL_PARAM params[])
{
	if (!get_default_rsa_asym_cipher().set_ctx_params)
		return UADK_E_FAIL;

	return get_default_rsa_asym_cipher().set_ctx_params(vprsactx, params);
}

static const OSSL_PARAM *uadk_asym_cipher_rsa_settable_ctx_params(void *vprsactx,
							   void *provctx)
{
	if (!get_default_rsa_asym_cipher().settable_ctx_params)
		return NULL;

	return get_default_rsa_asym_cipher().settable_ctx_params(vprsactx, provctx);
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
		return UADK_E_FAIL;

	return get_default_rsa_keymgmt().has(keydata, selection);
}

static int uadk_keymgmt_rsa_import(void *keydata, int selection, const OSSL_PARAM params[])
{
	if (!get_default_rsa_keymgmt().import)
		return UADK_E_FAIL;

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
		return UADK_E_FAIL;

	return get_default_rsa_keymgmt().gen_set_params(genctx, params);
}

static int uadk_keymgmt_rsa_gen_set_template(void *genctx, void *templates)
{
	if (!get_default_rsa_keymgmt().gen_set_template) {
		fprintf(stderr, "failed to get keymgmt gen_set_template function\n");
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

static int rsa_gencb(int p, int n, BN_GENCB *cb)
{
	struct rsa_gen_ctx *gctx = BN_GENCB_get_arg(cb);
	OSSL_PARAM params[] = { OSSL_PARAM_END, OSSL_PARAM_END, OSSL_PARAM_END };

	params[0] = OSSL_PARAM_construct_int(OSSL_GEN_PARAM_POTENTIAL, &p);
	params[1] = OSSL_PARAM_construct_int(OSSL_GEN_PARAM_ITERATION, &n);
	return gctx->cb(params, gctx->cbarg);
}

static RSA *ossl_rsa_new_with_ctx(OSSL_LIB_CTX *libctx)
{
	RSA *ret = OPENSSL_zalloc(sizeof(*ret));

	if (ret == NULL) {
		ERR_raise(ERR_LIB_RSA, ERR_R_MALLOC_FAILURE);
		return NULL;
	}

	ret->references = 1;
	ret->lock = CRYPTO_THREAD_lock_new();
	if (ret->lock == NULL) {
		ERR_raise(ERR_LIB_RSA, ERR_R_MALLOC_FAILURE);
		OPENSSL_free(ret);
		return NULL;
	}

	ret->libctx = libctx;
	ret->meth = RSA_get_default_method();

	return ret;
}

static void *uadk_rsa_sw_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
	if (!enable_sw_offload || !get_default_rsa_keymgmt().gen)
		return NULL;

	fprintf(stderr, "switch to openssl software calculation in rsa key generation.\n");
	return get_default_rsa_keymgmt().gen(genctx, osslcb, cbarg);
}

static void *uadk_keymgmt_rsa_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
	struct rsa_gen_ctx *gctx = genctx;
	RSA *rsa = NULL;
	BN_GENCB *gencb = NULL;
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
	if (ret == UADK_DO_SOFT || ret == UADK_E_FAIL) {
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
		return UADK_E_FAIL;

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
		fprintf(stderr, "failed to get keymgmt set_params function\n");
		return UADK_P_FAIL;
	}

	return get_default_rsa_keymgmt().set_params(key, params);
}

static const OSSL_PARAM *uadk_keymgmt_rsa_settable_params(ossl_unused void *provctx)
{
	if (!get_default_rsa_keymgmt().settable_params) {
		fprintf(stderr, "failed to get keymgmt settable_params function\n");
		return NULL;
	}

	return get_default_rsa_keymgmt().settable_params(provctx);
}

static int uadk_keymgmt_rsa_match(const void *keydata1, const void *keydata2, int selection)
{
	if (!get_default_rsa_keymgmt().match)
		return UADK_E_FAIL;

	return get_default_rsa_keymgmt().match(keydata1, keydata2, selection);
}

static int uadk_keymgmt_rsa_validate(const void *keydata, int selection, int checktype)
{
	if (!get_default_rsa_keymgmt().validate)
		return UADK_E_FAIL;

	return get_default_rsa_keymgmt().validate(keydata, selection, checktype);
}

static int uadk_keymgmt_rsa_export(void *keydata, int selection,
				   OSSL_CALLBACK *param_callback, void *cbarg)
{
	if (!get_default_rsa_keymgmt().export_fun)
		return UADK_E_FAIL;

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

static void *uadk_asym_cipher_rsa_dupctx(void *vprsactx)
{
	if (!get_default_rsa_asym_cipher().dupctx)
		return NULL;
	return get_default_rsa_asym_cipher().dupctx(vprsactx);
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
