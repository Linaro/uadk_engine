/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2015-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#ifndef UADK_PROV_FFC_H
#define UADK_PROV_FFC_H

#include <openssl/core_names.h>
#include <openssl/dh.h>
#include <openssl/obj_mac.h>
#include <openssl/proverr.h>

/* Default value for gindex when canonical generation of g is not used */
#define FFC_UNVERIFIABLE_GINDEX			-1
#define FFC_PARAM_FLAG_VALIDATE_PQ		0x01
#define FFC_PARAM_FLAG_VALIDATE_G		0x02
#define FFC_PARAM_FLAG_VALIDATE_PQG \
	(FFC_PARAM_FLAG_VALIDATE_PQ | FFC_PARAM_FLAG_VALIDATE_G)
#define FFC_PARAM_FLAG_VALIDATE_LEGACY		0x04

/* The different types of FFC keys */
#define FFC_PARAM_TYPE_DSA			0
#define FFC_PARAM_TYPE_DH			1

/*
 * The mode used by functions that share code for both generation and
 * verification. See ossl_ffc_params_FIPS186_4_gen_verify().
 */
#define FFC_PARAM_MODE_VERIFY			0
#define FFC_PARAM_MODE_GENERATE			1

/* Return codes for generation and validation of FFC parameters */
#define FFC_PARAM_RET_STATUS_FAILED		0
#define FFC_PARAM_RET_STATUS_SUCCESS		1
/* Returned if validating and g is only partially verifiable */
#define FFC_PARAM_RET_STATUS_UNVERIFIABLE_G	2

/*
 * NB: These values must align with the equivalently named macros in
 * openssl/dh.h. We cannot use those macros here in case DH has been disabled.
 */
#define FFC_CHECK_P_NOT_PRIME                0x00001
#define FFC_CHECK_P_NOT_SAFE_PRIME           0x00002
#define FFC_CHECK_UNKNOWN_GENERATOR          0x00004
#define FFC_CHECK_NOT_SUITABLE_GENERATOR     0x00008
#define FFC_CHECK_Q_NOT_PRIME                0x00010
#define FFC_CHECK_INVALID_Q_VALUE            0x00020
#define FFC_CHECK_INVALID_J_VALUE            0x00040

#define FFC_CHECK_BAD_LN_PAIR                0x00080
#define FFC_CHECK_INVALID_SEED_SIZE          0x00100
#define FFC_CHECK_MISSING_SEED_OR_COUNTER    0x00200
#define FFC_CHECK_INVALID_G                  0x00400
#define FFC_CHECK_INVALID_PQ                 0x00800
#define FFC_CHECK_INVALID_COUNTER            0x01000
#define FFC_CHECK_P_MISMATCH                 0x02000
#define FFC_CHECK_Q_MISMATCH                 0x04000
#define FFC_CHECK_G_MISMATCH                 0x08000
#define FFC_CHECK_COUNTER_MISMATCH           0x10000

/* Validation Return codes */
#define FFC_ERROR_PUBKEY_TOO_SMALL		0x01
#define FFC_ERROR_PUBKEY_TOO_LARGE		0x02
#define FFC_ERROR_PUBKEY_INVALID		0x04
#define FFC_ERROR_NOT_SUITABLE_GENERATOR	0x08
#define FFC_ERROR_PRIVKEY_TOO_SMALL		0x10
#define FFC_ERROR_PRIVKEY_TOO_LARGE		0x20
#define FFC_ERROR_PASSED_NULL_PARAM		0x40

/* How many bignums are in each "pool item"; */
#define BN_CTX_POOL_SIZE			16

/* The size of prime p and prime q */
#define L_P_512BITS			512
#define L_P_1024BITS			1024
#define L_P_2048BITS			2048
#define L_P_3072BITS			3072
#define N_Q_160BITS			160
#define N_Q_224BITS			224
#define N_Q_256BITS			256

/* Security strength of DH or DSA */
#define SECURITY_STR_80BITS		80
#define SECURITY_STR_112BITS		112
#define SECURITY_STR_128BITS		128

#define GENCB_NEXT			2
#define GENCB_RETRY			3

#define TRANS_BYTES_TO_BITS(bytes)		((bytes) << 3)
#define TRANS_BITS_TO_BYTES(bits)		((bits) >> 3)
#define PADDING_LEN(len)			((len + 63) / 64 * 64)

#define OSSL_NELEM(x)    (sizeof(x)/sizeof((x)[0]))
/* Macro to make a BIGNUM from static data */
#define make_dh_bn(x)				\
	const BIGNUM ossl_bignum_##x = {	\
			(BN_ULONG *) x,			\
			OSSL_NELEM(x),			\
			OSSL_NELEM(x),			\
			0, BN_FLG_STATIC_DATA		\
	}					\

/*
 * Finite field cryptography (FFC) domain parameters are used by DH and DSA.
 * Refer to FIPS186_4 Appendix A & B.
 */
typedef struct ffc_params_st {
	/* Primes */
	BIGNUM *p;
	BIGNUM *q;
	/* Generator */
	BIGNUM *g;
	/* DH X9.42 Optional Subgroup factor j >= 2 where p = j * q + 1 */
	BIGNUM *j;

	/* Required for FIPS186_4 validation of p, q and optionally canonical g */
	unsigned char *seed;
	/* If this value is zero the hash size is used as the seed length */
	size_t seedlen;
	/* Required for FIPS186_4 validation of p and q */
	int pcounter;
	/* The identity of a named group */
	int nid;

	/*
	 * Required for FIPS186_4 generation & validation of canonical g.
	 * It uses unverifiable g if this value is -1.
	 */
	int gindex;
	/* loop counter for unverifiable g */
	int h;

	unsigned int flags;
	/*
	 * The digest to use for generation or validation. If this value is NULL,
	 * then the digest is chosen using the value of N.
	 */
	const char *mdname;
	const char *mdprops;
#if OPENSSL_VERSION_NUMBER >= 0x30000060
	/* Default key length for known named groups according to RFC7919 */
	int keylength;
#endif
} FFC_PARAMS;

struct bignum_st {
	/* Pointer to an array of 'BN_BITS2' bit chunks. */
	BN_ULONG *d;
	/* Index of last used d +1. */
	int top;
	/* The next are internal book keeping for bn_expand. */
		/* Size of the d array. */
	int dmax;
	/* one if the number is negative */
	int neg;
	int flags;
};

/* A wrapper to manage the "stack frames" */
typedef struct bignum_ctx_stack {
	/* Array of indexes into the bignum stack */
	unsigned int *indexes;
	/* Number of stack frames, and the size of the allocated array */
	unsigned int depth, size;
} BN_STACK;

/* A bundle of bignums that can be linked with other bundles */
typedef struct bignum_pool_item {
	/* The bignum values */
	BIGNUM vals[BN_CTX_POOL_SIZE];
	/* Linked-list admin */
	struct bignum_pool_item *prev, *next;
} BN_POOL_ITEM;

/* A linked-list of bignums grouped in bundles */
typedef struct bignum_pool {
	/* Linked-list admin */
	BN_POOL_ITEM *head, *current, *tail;
	/* Stack depth and allocation size */
	unsigned int used, size;
} BN_POOL;

/* The opaque BN_CTX type */
struct bignum_ctx {
	/* The bignum bundles */
	BN_POOL pool;
	/* The "stack frames", if you will */
	BN_STACK stack;
	/* The number of bignums currently assigned */
	unsigned int used;
	/* Depth of stack overflow */
	int err_stack;
	/* Block "gets" until an "end" (compatibility behaviour) */
	int too_many;
	/* Flags. */
	int flags;
	/* The library context */
	OSSL_LIB_CTX *libctx;
};

static const BN_ULONG value_2 = 2;
static const BIGNUM ossl_bignum_const_2 = {
	(BN_ULONG *)&value_2, 1, 1, 0, BN_FLG_STATIC_DATA
};

#define declare_dh_bn(x)	\
	extern const BIGNUM ossl_bignum_dh##x##_p;		\
	extern const BIGNUM ossl_bignum_dh##x##_q;		\
	extern const BIGNUM ossl_bignum_dh##x##_g		\

declare_dh_bn(1024_160);
declare_dh_bn(2048_224);
declare_dh_bn(2048_256);

extern const BIGNUM ossl_bignum_ffdhe2048_p;
extern const BIGNUM ossl_bignum_ffdhe3072_p;
extern const BIGNUM ossl_bignum_ffdhe4096_p;
extern const BIGNUM ossl_bignum_ffdhe2048_q;
extern const BIGNUM ossl_bignum_ffdhe3072_q;
extern const BIGNUM ossl_bignum_ffdhe4096_q;

extern const BIGNUM ossl_bignum_modp_1536_p;
extern const BIGNUM ossl_bignum_modp_2048_p;
extern const BIGNUM ossl_bignum_modp_3072_p;
extern const BIGNUM ossl_bignum_modp_4096_p;

extern const BIGNUM ossl_bignum_modp_1536_q;
extern const BIGNUM ossl_bignum_modp_2048_q;
extern const BIGNUM ossl_bignum_modp_3072_q;
extern const BIGNUM ossl_bignum_modp_4096_q;

#define FFDHE(sz, keylength) {                                             \
	SN_ffdhe##sz, NID_ffdhe##sz,                                        \
	sz,                                                                 \
	keylength,                                                          \
	&ossl_bignum_ffdhe##sz##_p, &ossl_bignum_ffdhe##sz##_q,             \
	&ossl_bignum_const_2,                                               \
	}

#define MODP(sz, keylength)  {                                             \
	SN_modp_##sz, NID_modp_##sz,                                        \
	sz,                                                                 \
	keylength,                                                          \
	&ossl_bignum_modp_##sz##_p, &ossl_bignum_modp_##sz##_q,             \
	&ossl_bignum_const_2                                                \
	}

#define RFC5114(name, uid, sz, tag) {                                      \
	name, uid,                                                          \
	sz,                                                                 \
	0,                                                                  \
	&ossl_bignum_dh##tag##_p, &ossl_bignum_dh##tag##_q,                 \
	&ossl_bignum_dh##tag##_g                                            \
	}

struct dh_named_group_st {
	const char *name;
	int uid;
#ifndef OPENSSL_NO_DH
	int32_t nbits;
	int keylength;
	const BIGNUM *p;
	const BIGNUM *q;
	const BIGNUM *g;
#endif
};
typedef struct dh_named_group_st DH_NAMED_GROUP;
/*
 * The private key length values are taken from RFC7919 with the values for
 * MODP primes given the same lengths as the equivalent FFDHE.
 * The MODP 1536 value is approximated.
 */
static const DH_NAMED_GROUP dh_named_groups[] = {
	FFDHE(2048, 225),
	FFDHE(3072, 275),
	FFDHE(4096, 325),
#ifndef FIPS_MODULE
	MODP(1536, 200),
#endif
	MODP(2048, 225),
	MODP(3072, 275),
	MODP(4096, 325),
    /*
     * Additional dh named groups from RFC 5114 that have a different g.
     * The uid can be any unique identifier.
     */
#ifndef FIPS_MODULE
	RFC5114("dh_1024_160", 1, 1024, 1024_160),
	RFC5114("dh_2048_224", 2, 2048, 2048_224),
	RFC5114("dh_2048_256", 3, 2048, 2048_256),
#endif
};

int ossl_ffc_params_set_seed(FFC_PARAMS *params,
				    const unsigned char *seed, size_t seedlen);
int ossl_ffc_params_copy(FFC_PARAMS *dst, const FFC_PARAMS *src);
void ossl_ffc_params_get0_pqg(const FFC_PARAMS *d, const BIGNUM **p,
				     const BIGNUM **q, const BIGNUM **g);
const DH_NAMED_GROUP *ossl_ffc_uid_to_dh_named_group(int uid);
void ossl_ffc_params_set0_pqg(FFC_PARAMS *d, BIGNUM *p, BIGNUM *q, BIGNUM *g);
int ossl_ffc_named_group_set(FFC_PARAMS *ffc, const DH_NAMED_GROUP *group);
int ossl_ffc_named_group_get_uid(const DH_NAMED_GROUP *group);
void ossl_ffc_params_set_gindex(FFC_PARAMS *params, int index);
void ossl_ffc_params_set_pcounter(FFC_PARAMS *params, int index);
void ossl_ffc_params_set_h(FFC_PARAMS *params, int index);
int ossl_ffc_set_digest(FFC_PARAMS *params, const char *alg, const char *props);
void ossl_ffc_params_enable_flags(FFC_PARAMS *params, unsigned int flags,
				  int enable);
int ossl_ffc_params_cmp(const FFC_PARAMS *a, const FFC_PARAMS *b, int ignore_q);
void ossl_ffc_params_init(FFC_PARAMS *params);
void ossl_ffc_params_cleanup(FFC_PARAMS *params);
int ossl_ffc_params_FIPS186_2_generate(OSSL_LIB_CTX *libctx, FFC_PARAMS *params,
				       int type, size_t L, size_t N,
				       int *res, BN_GENCB *cb);
int ossl_ffc_params_FIPS186_2_gen_verify(OSSL_LIB_CTX *libctx,
					 FFC_PARAMS *params, int mode, int type,
					 size_t L, size_t N, int *res,
					 BN_GENCB *cb);
int ossl_ffc_params_FIPS186_4_generate(OSSL_LIB_CTX *libctx, FFC_PARAMS *params,
				       int type, size_t L, size_t N,
				       int *res, BN_GENCB *cb);

#endif
