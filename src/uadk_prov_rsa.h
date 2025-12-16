/* SPDX-License-Identifier: Apache-2.0 */
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
#ifndef UADK_PROV_RSA_H
#define UADK_PROV_RSA_H
#include <openssl/bn.h>
#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/types.h>
#include <uadk/wd_rsa.h>
#include <uadk/wd_sched.h>
#include "uadk_async.h"
#include "uadk_prov.h"
#include "uadk_prov_pkey.h"
#include "uadk_utils.h"

#define BN_ERR				(-1)
#define BN_REDO				(-2)
#define CHECK_PADDING_FAIL		(-1)
#define BIT_BYTES_SHIFT			3

struct bignum_st {
	BN_ULONG *d;
	int top;
	int dmax;
	int neg;
	int flags;
};

struct rsa_prov {
	int pid;
};

struct rsa_pss_params_30_st {
	int hash_algorithm_nid;
	struct {
		int algorithm_nid;       /* Currently always NID_mgf1 */
		int hash_algorithm_nid;
	} mask_gen;
	int salt_len;
	int trailer_field;
};

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
	struct rsa_pss_params_30_st pss_params;

	/* This is used uniquely by rsa_ameth.c and rsa_pmeth.c. */
	RSA_PSS_PARAMS *pss;
	/* for multi-prime RSA, defined in RFC 8017 */
	STACK_OF(RSA_PRIME_INFO) * prime_infos;
	/* Be careful using this if the RSA structure is shared */
	CRYPTO_EX_DATA ex_data;

	int references;
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

struct rsa_pubkey_param {
	const BIGNUM *e;
	const BIGNUM *n;
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

enum {
	INVALID = 0,
	PUB_ENC,
	PUB_DEC,
	PRI_ENC,
	PRI_DEC,
	MAX_CODE,
};

int uadk_rsa_test_flags(const RSA *r, int flags);
int check_rsa_is_crt(RSA *rsa);
int rsa_fill_prikey(RSA *rsa, struct uadk_rsa_sess *rsa_sess,
			   struct rsa_prikey_param *pri,
			   unsigned char *in_buf, unsigned char *to);
int rsa_fill_pubkey(struct rsa_pubkey_param *pubkey_param,
			   struct uadk_rsa_sess *rsa_sess,
			   unsigned char *in_buf, unsigned char *to);
int uadk_prov_rsa_init(void);
void rsa_free_eng_session(struct uadk_rsa_sess *rsa_sess);
struct uadk_rsa_sess *rsa_get_eng_session(RSA *rsa, unsigned int bits,
						 int is_crt);
int rsa_do_crypto(struct uadk_rsa_sess *rsa_sess);
int uadk_rsa_bits(const RSA *r);
int uadk_rsa_size(const RSA *r);
int rsa_check_bit_useful(const int bits, int flen);
int check_rsa_input_para(const int flen, const unsigned char *from,
				unsigned char *to, RSA *rsa);
int rsa_pkey_param_alloc(struct rsa_pubkey_param **pub,
				struct rsa_prikey_param **pri);
void rsa_pkey_param_free(struct rsa_pubkey_param **pub,
				struct rsa_prikey_param **pri);
int rsa_create_pub_bn_ctx(RSA *rsa, struct rsa_pubkey_param *pub,
				 unsigned char **from_buf, int *num_bytes);
void rsa_free_pub_bn_ctx(unsigned char *from_buf);
int rsa_create_pri_bn_ctx(RSA *rsa, struct rsa_prikey_param *pri,
				 unsigned char **from_buf, int *num_bytes);
void rsa_free_pri_bn_ctx(unsigned char *from_buf);

#endif
