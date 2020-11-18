#include <openssl/bn.h>
#include <openssl/engine.h>
#include <openssl/ossl_typ.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <uadk/wd_rsa.h>
#include "uadk.h"
#include "uadk_async.h"

#define UN_SET				0
#define IS_SET				1
#define BIT_BYTES_SHIFT			3

#define HPRE_CRYPTO_SUCC		1
#define HPRE_CRYPTO_FAIL		0

#define OPENSSL_SUCCESS			(1)
#define OPENSSL_FAIL			(0)
#define KAE_SUCCESS			(0)
#define KAE_FAIL			(-1)

#define RSA_MIN_MODULUS_BITS		512
#define RSA1024BITS			1024
#define RSA2048BITS			2048
#define RSA3072BITS			3072
#define RSA4096BITS			4096

#define PKEY_METHOD_TYPE_NUM		1
#define RSA_MAX_DEV_NUM			16

#define CTX_ASYNC	1
#define CTX_SYNC	0
#define CTX_NUM		2

struct bignum_st {
	BN_ULONG *d;
	int top;
	int dmax;
	int neg;
	int flags;
};


struct uadk_rsa_sess {
	handle_t sess;
	struct wd_rsa_sess_setup setup;
	struct wd_rsa_req req;
	RSA *ssl_alg;
	int is_pubkey_ready;
	int is_privkey_ready;
	/* fix me: move this as already has key_bits in sess_setup */
	int key_size;
};

typedef struct uadk_rsa_sess uadk_rsa_sess_t;

struct rsa_res_per_dev {
	int numa_id;
	int sync_ctx_num;
	int async_ctx_num;
};

struct rsa_sched {
	int sched_type;
	struct wd_sched wd_sched;
};

struct rsa_res_config {
	int dev_num;
	struct rsa_res_per_dev dev_res[RSA_MAX_DEV_NUM];
	struct rsa_sched sched;
};

/* rsa global hardware resource is saved here */
struct rsa_res {
	struct wd_ctx_config *ctx_res;
} rsa_res;

enum {
	INVALID = 0,
	PUB_ENC,
	PUB_DEC,
	PRI_ENC,
	PRI_DEC,
	MAX_CODE,
};

static RSA_METHOD *uadk_rsa_method;

int check_bit_useful(const int bit)
{
	switch (bit) {
	case RSA1024BITS:
	case RSA2048BITS:
	case RSA3072BITS:
	case RSA4096BITS:
		return 1;
	default:
		break;
	}
	return 0;
}

static int prime_mul_res(int i, BIGNUM *rsa_p, BIGNUM *rsa_q, BIGNUM *r1,
			BN_CTX *ctx, BN_GENCB *cb)
{
	if (i == 1) {
		if (!BN_mul(r1, rsa_p, rsa_q, ctx))
			goto err;
	} else {
		if (!BN_GENCB_call(cb, 3, i))
			goto err;
		goto cont;
	}
	return 0;
err:
	return -1;
cont:
	return 1;
}

static int check_prime_sufficient(int *i, int *bitsr, int *bitse, int *n,
				BIGNUM *rsa_p, BIGNUM *rsa_q, BIGNUM *r1,
				BIGNUM *r2, BN_CTX *ctx, BN_GENCB *cb)
{
	BN_ULONG bitst;
	static int retries;
	int ret;

	ret = prime_mul_res(*i, rsa_p, rsa_q, r1, ctx, cb);
	if (ret)
		return ret;
	if (!BN_rshift(r2, r1, *bitse - 4))
		goto err;
	bitst = BN_get_word(r2);
	if (bitst < 0x9 || bitst > 0xF) {
		*bitse -= bitsr[*i];
		if (!BN_GENCB_call(cb, 2, *n++))
			goto err;
		if (retries == 4) {
			*i = -1;
			*bitse = 0;
			retries = 0;
			goto cont;
		}
		retries++;
		goto redo;
	}
	if (!BN_GENCB_call(cb, 3, *i))
		goto err;
	retries = 0;
	return 0;
err:
	return -1;
redo:
	return -2;
cont:
	return 1;

}

static void set_primes(int i, BIGNUM *rsa_p, BIGNUM *rsa_q, BIGNUM **prime)
{
	if (i == 0)
		*prime = rsa_p;
	else
		*prime = rsa_q;
	BN_set_flags(*prime, BN_FLG_CONSTTIME);
}

static int check_prime_equal(int i, BIGNUM *rsa_p, BIGNUM *rsa_q, BIGNUM *prime)
{
	int j;
	BIGNUM *prev_prime = NULL;

	for (j = 0; j < i; j++) {
		prev_prime = NULL;
		if (j == 0)
			prev_prime = rsa_p;
		else
			prev_prime = rsa_q;
		if (!BN_cmp(prime, prev_prime))
			return KAE_FAIL;
	}
	return KAE_SUCCESS;
}

static int check_prime_useful(int *n, BIGNUM *prime, BIGNUM *r1, BIGNUM *r2,
			BIGNUM *e_value, BN_CTX *ctx, BN_GENCB *cb)
{
	if (!BN_sub(r2, prime, BN_value_one()))
		goto err;
	ERR_set_mark();
	BN_set_flags(r2, BN_FLG_CONSTTIME);
	if (BN_mod_inverse(r1, r2, e_value, ctx) != NULL)
		goto br;
	unsigned long error = ERR_peek_last_error();

	if (ERR_GET_LIB(error) == ERR_LIB_BN && ERR_GET_REASON(error) == BN_R_NO_INVERSE)
		ERR_pop_to_mark();
	else
		goto err;
	if (!BN_GENCB_call(cb, 2, *n++))
		goto err;
	return 0;
err:
	return -1;
br:
	return 1;
}

static int hpre_get_prime_once(int i, const int *bitsr, int *n, BIGNUM *prime,
			BIGNUM *rsa_p, BIGNUM *rsa_q, BIGNUM *r1,
			BIGNUM *r2, BIGNUM *e_value, BN_CTX *ctx,
			BN_GENCB *cb)
{
	int adj = 0;
	int ret = KAE_FAIL;

	for (;;) {
redo:
		if (!BN_generate_prime_ex(prime, bitsr[i] + adj, 0, (const
		BIGNUM *)NULL, (const BIGNUM *)NULL, cb))
			goto err;
		if (check_prime_equal(i, rsa_p, rsa_q, prime) == KAE_FAIL)
			goto redo;
		ret = check_prime_useful(n, prime, r1, r2, e_value, ctx, cb);
		if (ret == KAE_FAIL)
			goto err;
		else if (ret == 1)
			break;
	}
	return ret;
err:
	return KAE_FAIL;
}

static void switch_p_q(BIGNUM *rsa_p, BIGNUM *rsa_q, BIGNUM *p, BIGNUM *q)
{
	BIGNUM *tmp = (BIGNUM *)NULL;

	if (BN_cmp(rsa_p, rsa_q) < 0) {
		tmp = rsa_p;
		rsa_p = rsa_q;
		rsa_q = tmp;
	}
	BN_copy(q, rsa_q);
	BN_copy(p, rsa_p);
}

static int hpre_rsa_primegen(int bits, BIGNUM *e_value, BIGNUM *p, BIGNUM *q,
			BN_GENCB *cb)
{
	int ok = -1;
	int primes = 2;
	int n = 0;
	int bitse = 0;
	int i;
	int bitsr[2];
	int quo;
	int ret;
	BN_CTX *ctx = (BN_CTX *)NULL;
	BIGNUM *r1 = (BIGNUM *)NULL;
	BIGNUM *r2 = (BIGNUM *)NULL;
	BIGNUM *prime = (BIGNUM *)NULL;
	BIGNUM *rsa_p, *rsa_q;

	ctx = BN_CTX_new();
	if (ctx == NULL)
		goto err;
	BN_CTX_start(ctx);
	r1 = BN_CTX_get(ctx);
	r2 = BN_CTX_get(ctx);
	rsa_p = BN_CTX_get(ctx);
	rsa_q = BN_CTX_get(ctx);
	if (rsa_q == NULL)
		goto err;
	/* divide bits into 'primes' pieces evenly */
	quo = bits / primes;

	bitsr[0] = quo;
	bitsr[1] = quo;
	/* generate p, q and other primes (if any) */
	for (i = 0; i < primes; i++) {
		set_primes(i, rsa_p, rsa_q, &prime);
redo:
	if (hpre_get_prime_once(i, bitsr, &n, prime, rsa_p, rsa_q, r1,
	r2, e_value, ctx, cb) == KAE_FAIL)
		goto err;
	bitse += bitsr[i];
	ret = check_prime_sufficient(&i, bitsr, &bitse, &n, rsa_p, rsa_q, r1,
	r2, ctx, cb);
	if (ret == -1)
		goto err;
	else if (ret == -2)
		goto redo;
	else if (ret == 1)
		continue;
	}
	switch_p_q(rsa_p, rsa_q, p, q);
	ok = 1;
err:
	if (ok == -1)
		ok = 0;
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	return ok;
}

static int hpre_rsa_iscrt(RSA *rsa)
{
	int version = 0;
	const BIGNUM *p = NULL;
	const BIGNUM *q = NULL;
	const BIGNUM *dmp1 = NULL;
	const BIGNUM *dmq1 = NULL;
	const BIGNUM *iqmp = NULL;

	if (RSA_test_flags(rsa, RSA_FLAG_EXT_PKEY))
		return 1;
	version = RSA_get_version(rsa);

	if (version == RSA_ASN1_VERSION_MULTI)
		return 1;

	RSA_get0_factors(rsa, &p, &q);
	RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);
	if ((p != NULL) && (q != NULL) && (dmp1 != NULL) && (dmq1 != NULL) &&
			(iqmp != NULL)) {
		return 1;
	}
	return 0;
}


static int hpre_pubenc_padding(int flen, const unsigned char *from,
			unsigned char *buf, int num, int padding)
{
	int ret = HPRE_CRYPTO_FAIL;

	switch (padding) {
	case RSA_PKCS1_PADDING:
		ret = RSA_padding_add_PKCS1_type_2(buf, num, from, flen);
		break;
	case RSA_PKCS1_OAEP_PADDING:
		ret = RSA_padding_add_PKCS1_OAEP(buf, num, from, flen, NULL, 0);
		break;
	case RSA_SSLV23_PADDING:
		ret = RSA_padding_add_SSLv23(buf, num, from, flen);
		break;
	case RSA_NO_PADDING:
		ret = RSA_padding_add_none(buf, num, from, flen);
		break;
	default:
		ret = HPRE_CRYPTO_FAIL;
	}
	if (ret <= 0)
		ret = HPRE_CRYPTO_FAIL;
	else
		ret = HPRE_CRYPTO_SUCC;
	return ret;
}

static int hpre_prienc_padding(int flen, const unsigned char *from,
			unsigned char *buf, int num, int padding)
{
	int ret = HPRE_CRYPTO_FAIL;

	switch (padding) {
	case RSA_PKCS1_PADDING:
		ret =  RSA_padding_add_PKCS1_type_1(buf, num, from, flen);
		break;
	case RSA_X931_PADDING:
		ret = RSA_padding_add_X931(buf, num, from, flen);
		break;
	case RSA_NO_PADDING:
		ret = RSA_padding_add_none(buf, num, from, flen);
		break;
	default:
		ret = HPRE_CRYPTO_FAIL;
	}
	if (ret <= 0)
		ret = HPRE_CRYPTO_FAIL;
	else
		ret = HPRE_CRYPTO_SUCC;
	return ret;
}

static int hpre_rsa_padding(int flen, const unsigned char *from,
			unsigned char *buf, int num, int padding, int type)
{
	int ret = HPRE_CRYPTO_FAIL;

	if (type == PUB_ENC)
		return hpre_pubenc_padding(flen, from, buf, num, padding);
	else if (type == PRI_ENC)
		return hpre_prienc_padding(flen, from, buf, num, padding);
	return ret;
}

static int hpre_check_pubdec_padding(unsigned char *to, int num,
				const unsigned char *buf, int len,
				int padding)
{
	int ret;

	switch (padding) {
	case RSA_PKCS1_PADDING:
		ret = RSA_padding_check_PKCS1_type_1(to, num, buf, len, num);
		break;
	case RSA_X931_PADDING:
		ret = RSA_padding_check_X931(to, num, buf, len, num);
		break;
	case RSA_NO_PADDING:
		memcpy(to, buf, len);
		ret = len;
		break;
	default:
		ret = HPRE_CRYPTO_FAIL;
	}

	if (ret == -1)
		ret = HPRE_CRYPTO_FAIL;
	return ret;
}

static int hpre_check_pridec_padding(unsigned char *to, int num,
				const unsigned char *buf, int len,
				int padding)
{
	int ret;

	switch (padding) {
	case RSA_PKCS1_PADDING:
		ret = RSA_padding_check_PKCS1_type_2(to, num, buf, len, num);
		break;
	case RSA_PKCS1_OAEP_PADDING:
		ret = RSA_padding_check_PKCS1_OAEP(to, num, buf, len, num,
		NULL, 0);
		break;
	case RSA_SSLV23_PADDING:
		ret = RSA_padding_check_SSLv23(to, num, buf, len, num);
		break;
	case RSA_NO_PADDING:
		memcpy(to, buf, len);
		ret = len;
		break;
	default:
		ret = HPRE_CRYPTO_FAIL;
	}

	if (ret == -1)
		ret = HPRE_CRYPTO_FAIL;
	return ret;
}

static int check_rsa_padding(unsigned char *to, int num,
			const unsigned char *buf, int len, int padding,
			int type)
{
	int ret = HPRE_CRYPTO_FAIL;

	if (type == PUB_DEC)
		return hpre_check_pubdec_padding(to, num, buf, len, padding);
	else if (type == PRI_DEC)
		return hpre_check_pridec_padding(to, num, buf, len, padding);
	return ret;
}

int check_pubkey_param(const BIGNUM *n, const BIGNUM *e)
{
	if (BN_num_bits(n) > OPENSSL_RSA_MAX_MODULUS_BITS)
		return HPRE_CRYPTO_FAIL;
	if (BN_ucmp(n, e) <= 0)
		return HPRE_CRYPTO_FAIL;
	return HPRE_CRYPTO_SUCC;
}


static int hpre_rsa_check_para(int flen, const unsigned char *from,
			unsigned char *to, RSA *rsa)
{
	if ((rsa == NULL || from == NULL || to == NULL || flen <= 0))
		return 1;
}

static int hpre_rsa_check(const int flen, const BIGNUM *n, const BIGNUM *e,
			int *num_bytes, RSA *rsa)
{
	int key_bits;

	if (n == NULL || e == NULL)
		return HPRE_CRYPTO_FAIL;
	if (check_pubkey_param(n, e) != HPRE_CRYPTO_SUCC)
		return HPRE_CRYPTO_FAIL;
	*num_bytes = BN_num_bytes(n);
	if (flen > *num_bytes)
		return HPRE_CRYPTO_FAIL;
	key_bits = RSA_bits(rsa);
	if (!check_bit_useful(key_bits))
		return HPRE_CRYPTO_FAIL;

	return HPRE_CRYPTO_SUCC;
}

int hpre_get_prienc_res(int padding, BIGNUM *f, const BIGNUM *n, BIGNUM
			*bn_ret, BIGNUM **res)
{
	if (padding == RSA_X931_PADDING) {
		if (!BN_sub(f, n, bn_ret))
			return HPRE_CRYPTO_FAIL;
		if (BN_cmp(bn_ret, f) > 0)
			*res = f;
		else
			*res = bn_ret;
	} else {
		*res = bn_ret;
	}
	return HPRE_CRYPTO_SUCC;
}


static BN_ULONG *bn_get_words(const BIGNUM *a)
{
	return a->d;
}

static __u32 rsa_pick_next_ctx(handle_t sched_ctx, const void *req,
			const struct sched_key *key)
{
	const struct wd_rsa_req *rsa_req = req;
	
	if (rsa_req->cb)
		return CTX_ASYNC;
	else
		return CTX_SYNC;
}

static int rsa_poll_policy(handle_t h_sched_ctx, __u32 expect, __u32 *count)
{
	return 0;
}

int uadk_rsa_poll(void *ctx)
{
	int ret = 0;
	int expt = 1;
	int recv;

	do {
		ret = wd_rsa_poll_ctx(CTX_ASYNC, expt, &recv);
		if (recv >= expt)
			return 0;
		else if (ret < 0 && ret != -EAGAIN)
			return ret;
	} while (ret == -EAGAIN);

	return ret;
}

/* make resource configure static */
struct rsa_res_config rsa_res_config = {
	.dev_num = 2,
	.dev_res[0] = {
		.numa_id = 0,
		.sync_ctx_num = 1,
		.async_ctx_num = 1,
	},
	.dev_res[1] = {
		.numa_id = 2,
		.sync_ctx_num = 1,
		.async_ctx_num = 1,
	},
	.sched = {
		.sched_type = -1,
		.wd_sched = {
			.name = "RSA RR",
			.pick_next_ctx = rsa_pick_next_ctx,
			.poll_policy = rsa_poll_policy,
			.h_sched_ctx = 0,
		},
	},
};

static struct uacce_dev *get_uacce_dev(struct rsa_res_per_dev *dev_res,
				struct uacce_dev_list *list)
{
	struct uacce_dev *dev = NULL;

	while (list) {
		if (list->dev->numa_id == dev_res->numa_id) {
			dev = list->dev;
			break;
		}
		list = list->next;
	}
	return dev;
}

static int init_ctx_cfg(struct wd_ctx_config *ctx_cfg,
			struct rsa_res_config *config)
{
	struct rsa_res_per_dev *dev_res;
	struct uacce_dev *uacce_dev;
	struct uacce_dev_list *list;
	struct wd_ctx *ctx;
	int i, j, k, ret, ctx_num, ctx_index = 0;

	list = wd_get_accel_list("rsa");
	if (!list)
		return -ENODEV;
	for (i = 0; i < config->dev_num; i++) {
		dev_res = &config->dev_res[i];
		uacce_dev = get_uacce_dev(dev_res, list);
		if (!uacce_dev)
			continue;
		for (k = 0; k < 2; k++) {
			ctx_num = (k == 0) ? dev_res->sync_ctx_num :
			dev_res->async_ctx_num;
			for (j = 0; j < ctx_num; j++) {
				ctx = ctx_cfg->ctxs + ctx_index;
				ctx->ctx = wd_request_ctx(uacce_dev);
				if (!ctx->ctx) {
					ret = -ENODEV;
					goto release_ctx;
				}
				ctx->ctx_mode = (k == 0) ? CTX_SYNC :
				CTX_ASYNC;
				ctx->op_type = 0;
				ctx_index++;
			}
		}
	}
	wd_free_list_accels(list);
	return 0;

release_ctx:
	ctx = ctx_cfg->ctxs;
	while (ctx->ctx) {
		wd_release_ctx(ctx->ctx);
		ctx->ctx = 0;
		ctx->op_type = 0;
		ctx->ctx_mode = 0;
		ctx++;
	}
	wd_free_list_accels(list);
	return ret;
}

static void uninit_ctx_cfg(struct wd_ctx_config *ctx_cfg)
{
	struct wd_ctx *ctx = ctx_cfg->ctxs;
	int i;

	for (i = 0; i < ctx_cfg->ctx_num; i++) {
		wd_release_ctx(ctx->ctx);
		ctx->ctx = 0;
		ctx->op_type = 0;
		ctx->ctx_mode = 0;
		ctx++;
	}
}

static int uadk_wd_rsa_init(struct rsa_res_config *config)
{
	struct wd_sched *sched = &config->sched.wd_sched;
	struct rsa_res_per_dev *dev_res;
	struct wd_ctx_config *ctx_cfg;
	int ctx_num = 0;
	int ret, i;

	ctx_cfg = calloc(1, sizeof(struct wd_ctx_config));
	if (!ctx_cfg)
		return -ENOMEM;
	rsa_res.ctx_res = ctx_cfg;

	for (i = 0; i < config->dev_num; i++) {
		dev_res = &config->dev_res[i];
		ctx_num += dev_res->sync_ctx_num + dev_res->async_ctx_num;
	}
	ctx_cfg->ctxs = calloc(ctx_num, sizeof(struct wd_ctx));
	if (!ctx_cfg->ctxs) {
		ret = -ENOMEM;
		goto free_cfg;
	}
	ctx_cfg->ctx_num = ctx_num;
	ret = init_ctx_cfg(ctx_cfg, config);
	if (ret)
		goto free_ctx;
	ret = wd_rsa_init(ctx_cfg, sched);
	if (ret)
		goto unit_ctx;
	async_register_poll_fn(ASYNC_TASK_RSA, uadk_rsa_poll);
	return 0;
unit_ctx:
	uninit_ctx_cfg(ctx_cfg);
free_ctx:
	free(ctx_cfg->ctxs);
free_cfg:
	free(ctx_cfg);
	return ret;
}

static void uadk_wd_rsa_uninit(void)
{
	struct wd_ctx_config *ctx_cfg = rsa_res.ctx_res;

	wd_rsa_uninit();
	uninit_ctx_cfg(ctx_cfg);
	free(ctx_cfg->ctxs);
	free(ctx_cfg);
}

static uadk_rsa_sess_t *uadk_new_eng_session(RSA *rsa_alg)
{
	uadk_rsa_sess_t *rsa_sess = NULL;

	rsa_sess = (uadk_rsa_sess_t *)OPENSSL_malloc(sizeof(uadk_rsa_sess_t));
	if (rsa_sess == NULL)
		return NULL;
	memset(rsa_sess, 0, sizeof(uadk_rsa_sess_t));
	rsa_sess->ssl_alg = rsa_alg;
	rsa_sess->is_privkey_ready = UN_SET;
	rsa_sess->is_pubkey_ready = UN_SET;

	return rsa_sess;
}

static int uadk_init_eng_session(uadk_rsa_sess_t *rsa_sess, int bits, int is_crt)
{
	int key_size =  bits >> BIT_BYTES_SHIFT;

	if (rsa_sess->sess && rsa_sess->req.src) {
		memset(rsa_sess->req.src, 0, rsa_sess->req.src_bytes);
		return OPENSSL_SUCCESS;
	}
	if (!rsa_sess->sess) {
		if (bits == 0)
			rsa_sess->key_size = RSA_size(rsa_sess->ssl_alg);
		else
			rsa_sess->key_size = key_size;
		rsa_sess->setup.key_bits = rsa_sess->key_size << BIT_BYTES_SHIFT;
		if (is_crt)
			rsa_sess->setup.is_crt = IS_SET;
		else
			rsa_sess->setup.is_crt = UN_SET;
	}
	rsa_sess->sess = wd_rsa_alloc_sess(&rsa_sess->setup);
	if (!rsa_sess->sess) {
		printf("\n%s: create rsa session failed.", __func__);
		return OPENSSL_FAIL;
	}
	return OPENSSL_SUCCESS;
}

static void uadk_free_eng_session(uadk_rsa_sess_t *rsa_sess)
{
	if (rsa_sess == NULL) {
		printf("\n%s: no rsa_sess to free.", __func__);
		return;
	}
	wd_rsa_del_kg_in(rsa_sess->sess, rsa_sess->req.src);
	wd_rsa_del_kg_out(rsa_sess->sess, rsa_sess->req.dst);
	rsa_sess->ssl_alg = NULL;
	rsa_sess->sess = 0;
	rsa_sess->req.src = NULL;
	rsa_sess->req.dst = NULL;
	rsa_sess->is_privkey_ready = UN_SET;
	rsa_sess->is_pubkey_ready = UN_SET;
	OPENSSL_free(rsa_sess);
	rsa_sess = NULL;
}

static uadk_rsa_sess_t *uadk_get_eng_session(RSA *rsa, int bits, int is_crt)
{
	uadk_rsa_sess_t *rsa_sess =  uadk_new_eng_session(rsa);

	if (rsa_sess == NULL) {
		printf("\n%s: new eng ctx failed.", __func__);
		return HPRE_CRYPTO_FAIL;
	}
	if (uadk_init_eng_session(rsa_sess, bits, is_crt) == 0) {
		uadk_free_eng_session(rsa_sess);
		printf("\n%s: init eng ctx failed.", __func__);
		return HPRE_CRYPTO_FAIL;
	}
	return rsa_sess;
}

static int uadk_rsa_fill_pubkey(const BIGNUM *e, const BIGNUM *n,
			uadk_rsa_sess_t *rsa_sess)
{
	struct wd_rsa_pubkey *pubkey = NULL;
	struct wd_dtb *wd_e = NULL;
	struct wd_dtb *wd_n = NULL;

	wd_rsa_get_pubkey(rsa_sess->sess, &pubkey);
	wd_rsa_get_pubkey_params(pubkey, &wd_e, &wd_n);
	if (!rsa_sess->is_pubkey_ready) {
		wd_e->dsize = BN_bn2bin(e, (unsigned char *)wd_e->data);
		wd_n->dsize = BN_bn2bin(n, (unsigned char *)wd_n->data);
		rsa_sess->is_pubkey_ready = IS_SET;
	}
	return HPRE_CRYPTO_SUCC;
}

static int uadk_rsa_fill_prikey(RSA *rsa, uadk_rsa_sess_t *rsa_sess,
			const BIGNUM *d, const BIGNUM *n)
{
	struct wd_rsa_prikey *prikey = NULL;
	struct wd_dtb *wd_d = NULL;
	struct wd_dtb *wd_n = NULL;

	wd_rsa_get_prikey(rsa_sess->sess, &prikey);
	wd_rsa_get_prikey_params(prikey, &wd_d, &wd_n);
	if (!rsa_sess->is_privkey_ready) {
		wd_d->dsize = BN_bn2bin(d, (unsigned char *)wd_d->data);
		wd_n->dsize = BN_bn2bin(n, (unsigned char *)wd_n->data);
		rsa_sess->is_privkey_ready = IS_SET;
	}
	return HPRE_CRYPTO_SUCC;
}

static int uadk_rsa_fill_prikey_crt(RSA *rsa, uadk_rsa_sess_t *rsa_sess, const
				BIGNUM *p, const BIGNUM *q, const BIGNUM
				*dmp1, const BIGNUM *dmq1, const BIGNUM *iqmp)
{
	struct wd_rsa_prikey *prikey = NULL;
	struct wd_dtb *wd_dq, *wd_dp, *wd_q, *wd_p, *wd_qinv;

	wd_rsa_get_prikey(rsa_sess->sess, &prikey);
	wd_rsa_get_crt_prikey_params(prikey, &wd_dq, &wd_dp, &wd_qinv, &wd_q, &wd_p);
	if (!rsa_sess->is_privkey_ready) {
		wd_dq->dsize = BN_bn2bin(dmq1, (unsigned char *)wd_dq->data);
		wd_dp->dsize = BN_bn2bin(dmp1, (unsigned char *)wd_dp->data);
		wd_q->dsize = BN_bn2bin(q, (unsigned char *)wd_q->data);
		wd_p->dsize = BN_bn2bin(p, (unsigned char *)wd_p->data);
		wd_qinv->dsize = BN_bn2bin(iqmp, (unsigned char *)wd_qinv->data);
		rsa_sess->is_privkey_ready = IS_SET;
	}
	return HPRE_CRYPTO_SUCC;
}


static int uadk_rsa_fill_keygen_data(handle_t ctx, struct wd_rsa_req *req,
				struct wd_dtb *wd_e, struct wd_dtb *wd_p,
				struct wd_dtb *wd_q)
{
	struct wd_rsa_pubkey *pubkey = NULL;
	struct wd_rsa_prikey *prikey = NULL;

	req->src = wd_rsa_new_kg_in(ctx, wd_e, wd_p, wd_q);
	if (!req->src) {
		printf("%s: create rsa-key-gen request input data failed.\n",
				__func__);
		return HPRE_CRYPTO_FAIL;
	}
	req->dst = wd_rsa_new_kg_out(ctx);
	if (!req->dst) {
		/* fix me: call wd_ras_del_kg_in here */
		printf("%s: create rsa-key-gen receive output data failed.\n",
				__func__);
		return HPRE_CRYPTO_FAIL;
	}
	return HPRE_CRYPTO_SUCC;
}

static int uadk_rsa_get_keygen_param(struct wd_rsa_req *req, handle_t ctx, RSA *rsa,
				BIGNUM *e_value, BIGNUM *p, BIGNUM *q)
{
	BIGNUM *n = BN_new();
	BIGNUM *d = BN_new();
	BIGNUM *dmp1 = BN_new();
	BIGNUM *dmq1 = BN_new();
	BIGNUM *iqmp = BN_new();
	struct wd_dtb wd_d;
	struct wd_dtb wd_n;
	struct wd_dtb wd_qinv;
	struct wd_dtb wd_dq;
	struct wd_dtb wd_dp;
	unsigned int key_bits, key_size;
	struct wd_rsa_kg_out *out = (struct wd_rsa_kg_out *)req->dst;

	key_bits = wd_rsa_key_bits(ctx);
	key_size = key_bits >> BIT_BYTES_SHIFT;
	wd_rsa_get_kg_out_params(out, &wd_d, &wd_n);
	wd_rsa_get_kg_out_crt_params(out, &wd_qinv, &wd_dq, &wd_dp);

	BN_bin2bn((unsigned char *)wd_d.data, key_size, d);
	BN_bin2bn((unsigned char *)wd_n.data, key_size, n);
	BN_bin2bn((unsigned char *)wd_qinv.data, wd_qinv.dsize, iqmp);
	BN_bin2bn((unsigned char *)wd_dq.data, wd_dq.dsize, dmq1);
	BN_bin2bn((unsigned char *)wd_dp.data, wd_dp.dsize, dmp1);

	if (!(RSA_set0_key(rsa, n, e_value, d) && RSA_set0_factors(rsa, p, q) &&
				RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp)))
		return OPENSSL_FAIL;
	else
		return OPENSSL_SUCCESS;
}

static int uadk_rsa_sync(handle_t ctx, struct wd_rsa_req *req)
{
	int ret = wd_do_rsa_sync(ctx, req);
	return ret;
}

void uadk_rsa_sync_free(handle_t ctx, struct wd_rsa_req *req)
{
	return;
}

static void uadk_rsa_cb(void)
{
}

int uadk_rsa_crypto(handle_t ctx, struct wd_rsa_req *req)
{
	int ret;
	struct async_op op;
	uadk_rsa_sess_t *rsa_sess = (uadk_rsa_sess_t *)ctx;

	async_setup_async_event_notification(&op);
	if (op.job == NULL) {
		ret = wd_do_rsa_sync(ctx, req);
		if (ret)
			return 0;
	} else {
		req->cb = (void *)uadk_rsa_cb;
		req->cb_param = req;
		do {
			ret = wd_do_rsa_async(ctx, req);
			if (ret < 0 && ret != -EBUSY)
				goto err;
		} while (ret == -EBUSY);

		ret = async_pause_job(rsa_sess, &op, ASYNC_TASK_RSA);
		if (!ret)
			goto err;
	}
	return HPRE_CRYPTO_SUCC; 
err:
	(void)async_clear_async_event_notification();
	return HPRE_CRYPTO_FAIL;
}

static int uadk_rsa_prepare_req(const BIGNUM *n, int flen,
			const unsigned char *from,
			BN_CTX **bn_ctx,
			BIGNUM **bn_ret, BIGNUM **f_ret)
{
	BN_CTX *bn_ctx_tmp;
	BIGNUM *bn_ret_tmp = NULL;
	BIGNUM *f = NULL;

	bn_ctx_tmp = BN_CTX_new();
	BN_CTX_start(bn_ctx_tmp);
	bn_ret_tmp = BN_CTX_get(bn_ctx_tmp);
	f = BN_CTX_get(bn_ctx_tmp);
	BN_bin2bn(from, flen, f);
	BN_ucmp(f, n);
	*bn_ctx = bn_ctx_tmp;
	*bn_ret = bn_ret_tmp;
	*f_ret = f;
	return 1;
}

static int uadk_rsa_keygen(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb)
{
	uadk_rsa_sess_t *rsa_sess = NULL;
	struct wd_rsa_pubkey *pubkey = NULL;
	struct wd_rsa_prikey *prikey = NULL;
	struct wd_dtb *wd_e = NULL;
	struct wd_dtb *wd_p = NULL;
	struct wd_dtb *wd_q = NULL;
	BIGNUM *e_value = NULL;
	BIGNUM *p = NULL;
	BIGNUM *q = NULL;
	int ret = 0;
	int key_size = 0;
	int is_crt = 1; /* default mode: crt*/

	/* Check bits from two aspects: size and supports.*/
	if (bits < RSA_MIN_MODULUS_BITS) {
		printf("\n%s: RSA key size too small.\n", __func__);
		return HPRE_CRYPTO_FAIL;
	}
	if (check_bit_useful(bits)) {
		key_size = bits >> BYTE_BITS_SHIFT;
	} else {
		printf("\n%s: %d is not supported by rsa engine.\n", __func__,
		bits);
		return HPRE_CRYPTO_FAIL;
	}
	/* Get session from uadk for openssl engine.*/
	rsa_sess = uadk_get_eng_session(rsa, bits, is_crt);
	if (rsa_sess == NULL) {
		printf("\n%s: get engine session failed.\n", __func__);
		return HPRE_CRYPTO_FAIL;
	}
	/* Allocate and initialize BIGNUM structure for p,q.*/
	e_value = BN_new();
	p = BN_new();
	q = BN_new();
	if (!e || !p || !q) {
		printf("\n%s: e, or p, or q malloc failed.\n", __func__);
		return OPENSSL_FAIL;
	}
	/* Generate primes.*/
	if (hpre_rsa_primegen(bits, e, p, q, NULL) == OPENSSL_FAIL) {
		printf("\n%s: rsa primes generate failed.\n", __func__);
		return HPRE_CRYPTO_FAIL;
	}
	if (!BN_copy(e_value, e))
		return OPENSSL_FAIL;
	/* Get addresses of public key and public key params.*/
	wd_rsa_get_pubkey(rsa_sess->sess, &pubkey);
	wd_rsa_get_pubkey_params(pubkey, &wd_e, NULL);
	wd_e->dsize = BN_bn2bin(e_value, (unsigned char *)wd_e->data);
	/* Get addresses of private key and private key params.*/
	wd_rsa_get_prikey(rsa_sess->sess, &prikey);
	wd_rsa_get_crt_prikey_params(prikey, NULL, NULL, NULL, &wd_q, &wd_p);
	wd_q->dsize = BN_bn2bin(q, (unsigned char *)wd_q->data);
	wd_p->dsize = BN_bn2bin(p, (unsigned char *)wd_p->data);
	/* Fill rsa session for uadk.*/
	rsa_sess->req.src_bytes = key_size;
	rsa_sess->req.op_type = WD_RSA_GENKEY;
	rsa_sess->req.dst_bytes = key_size;
	ret = uadk_rsa_fill_keygen_data(rsa_sess->sess, &rsa_sess->req, wd_e,
			wd_p, wd_q);
	if (!ret) {
		printf("\n%s: rsa fill keygen data failed.\n", __func__);
		return HPRE_CRYPTO_FAIL;
	}

	/* Do sync RSA key pair generation.*/
	ret = uadk_rsa_sync(rsa_sess->sess, &rsa_sess->req);
	if (ret || rsa_sess->req.status) {
		printf("\n%s: do rsa sync failed.\n", __func__);
		return HPRE_CRYPTO_FAIL;
	}
	ret = uadk_rsa_get_keygen_param(&rsa_sess->req, rsa_sess->sess, rsa,
			e_value, p, q);
	return ret;
}

static int uadk_rsa_public_encrypt(int flen, const unsigned char *from,
				unsigned char *to, RSA *rsa, int Padding)
{
	const BIGNUM *n = NULL;
	const BIGNUM *e = NULL;
	const BIGNUM *d = NULL;
	BIGNUM *ret_bn  = NULL;
	uadk_rsa_sess_t *rsa_sess = NULL;
	unsigned char *in_buf = NULL;
	int num_bytes = 0;
	int ret = 0;
	BN_CTX *bn_ctx = NULL;
	int key_bits = 0;

	/* Check bits. */
	key_bits = RSA_bits(rsa);
	if (!check_bit_useful(key_bits)) {
		printf("\n%s: %d is not supported by rsa engine.\n",
				__func__, key_bits);
		return HPRE_CRYPTO_FAIL;
	}
	rsa_sess = uadk_get_eng_session(rsa, 0, 1);
	if (rsa_sess == NULL) {
		printf("\n%s: get engine session failed.\n", __func__);
		return HPRE_CRYPTO_FAIL;
	}
	RSA_get0_key(rsa, &n, &e, &d);
	//TODO check e and n with check_pubkey_param()
	bn_ctx = BN_CTX_new();
	if (!bn_ctx) {
		printf("\n%s: bn_ctx malloc failed.\n", __func__);
		return HPRE_CRYPTO_FAIL;
	}
	BN_CTX_start(bn_ctx);
	ret_bn = BN_CTX_get(bn_ctx);
	num_bytes = BN_num_bytes(n);
	in_buf = (unsigned char *)OPENSSL_malloc(num_bytes);
	if (!ret_bn || !in_buf) {
		printf("\n%s: pulic encrypt malloc failed.\n", __func__);
		return OPENSSL_FAIL;
	}
	ret = hpre_rsa_padding(flen, from, in_buf, num_bytes, Padding, PUB_ENC);
	if (!ret) {
		printf("\n%s: rsa padding failed.\n", __func__);
		return HPRE_CRYPTO_FAIL;
	}
	ret = uadk_rsa_fill_pubkey(e, n, rsa_sess);
	if (!ret) {
		printf("\n%s: rsa fill pubkey failed.\n", __func__);
		return HPRE_CRYPTO_FAIL;
	}
	rsa_sess->req.src_bytes = rsa_sess->key_size;
	rsa_sess->req.op_type = WD_RSA_VERIFY;
	rsa_sess->req.src = in_buf;
	rsa_sess->req.dst = to;
	rsa_sess->req.dst_bytes = rsa_sess->key_size;
	memcpy(rsa_sess->req.src, in_buf, rsa_sess->req.src_bytes);
	ret = uadk_rsa_sync(rsa_sess->sess, &rsa_sess->req);
	if (ret || rsa_sess->req.status) {
		printf("\n%s: do rsa encrypt failed.\n", __func__);
		return HPRE_CRYPTO_FAIL;
	}
	BN_bin2bn((const unsigned char *)rsa_sess->req.dst,
			rsa_sess->req.dst_bytes, ret_bn);
	ret = BN_bn2binpad(ret_bn, to, num_bytes);
	return ret;
}

static int uadk_rsa_private_decrypt(int flen, const unsigned char *from,
				unsigned char *to, RSA *rsa, int padding)
{
	const BIGNUM *n = (const BIGNUM *)NULL;
	const BIGNUM *e = (const BIGNUM *)NULL;
	const BIGNUM *d = (const BIGNUM *)NULL;
	const BIGNUM *p = (const BIGNUM *)NULL;
	const BIGNUM *q = (const BIGNUM *)NULL;
	const BIGNUM *dmp1 = (const BIGNUM *)NULL;
	const BIGNUM *dmq1 = (const BIGNUM *)NULL;
	const BIGNUM *iqmp = (const BIGNUM *)NULL;
	BIGNUM *bn_ret = (BIGNUM *)NULL;
	BIGNUM *f = (BIGNUM *)NULL;
	unsigned char *in_buf = (unsigned char *)NULL;
	uadk_rsa_sess_t *rsa_sess = NULL;
	BN_CTX *bn_ctx = NULL;
	int ret = 0;
	int len = 0;
	int key_bits = 0;
	int num_bytes = 0;

	hpre_rsa_check_para(flen, from, to, rsa);
	RSA_get0_key(rsa, &n, &e, &d);
	num_bytes = BN_num_bytes(n);
	if (flen > num_bytes) {
		printf("\n%s: decrypt data greater than mod len.\n",
				__func__);
		return HPRE_CRYPTO_FAIL;
	}
	key_bits = RSA_bits(rsa);
	if (!check_bit_useful(key_bits)) {
		printf("\n%s: %d is not supported by rsa engine.\n", __func__,
				key_bits);
		return HPRE_CRYPTO_FAIL;
	}
	rsa_sess = uadk_get_eng_session(rsa, 0, 1);
	if (rsa_sess == NULL) {
		printf("\n%s: get engine session failed.\n", __func__);
		return HPRE_CRYPTO_FAIL;
	}
	bn_ctx = BN_CTX_new();
	if (!bn_ctx) {
		printf("\n%s: bn_ctx malloc failed.\n", __func__);
		return HPRE_CRYPTO_FAIL;
	}
	BN_CTX_start(bn_ctx);
	f = BN_CTX_get(bn_ctx);
	bn_ret = BN_CTX_get(bn_ctx);
	RSA_get0_factors(rsa, &p, &q);
	RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);
	in_buf = (unsigned char *)OPENSSL_malloc(num_bytes);
	if (!bn_ret || !in_buf) {
		printf("\n%s: pulic decrypt malloc failed.\n", __func__);
		return OPENSSL_FAIL;
	}
	BN_bin2bn(from, (int)flen, f);
	BN_ucmp(f, n);
	ret = uadk_rsa_fill_pubkey(e, n, rsa_sess);
	if (!ret) {
		printf("\n%s: rsa fill pubkey failed.\n", __func__);
		return HPRE_CRYPTO_FAIL;
	}
	if (hpre_rsa_iscrt(rsa)) {
		ret = uadk_rsa_fill_prikey_crt(rsa, rsa_sess, p, q,
				dmp1, dmq1, iqmp);
		if (!ret) {
			printf("\n%s: rsa fill pubkey failed.\n", __func__);
			return HPRE_CRYPTO_FAIL;
		}
	} else {
		ret = uadk_rsa_fill_prikey(rsa, rsa_sess, d, n);
		if (!ret) {
			printf("\n%s: rsa fill prikey failed.\n", __func__);
			return HPRE_CRYPTO_FAIL;
		}
	}
	rsa_sess->req.src_bytes = rsa_sess->key_size;
	rsa_sess->req.op_type = WD_RSA_SIGN;
	rsa_sess->req.dst_bytes = rsa_sess->key_size;
	rsa_sess->req.src = in_buf;
	rsa_sess->req.dst = to;
	memcpy(rsa_sess->req.src, from, rsa_sess->req.src_bytes);
	ret = uadk_rsa_sync(rsa_sess->sess, &rsa_sess->req);
	if (ret || rsa_sess->req.status) {
		printf("\n%s: do rsa sync failed.\n", __func__);
		return HPRE_CRYPTO_FAIL;
	}
	BN_bin2bn((const unsigned char *)rsa_sess->req.dst,
			rsa_sess->req.dst_bytes, bn_ret);
	len = BN_bn2binpad(bn_ret, in_buf, num_bytes);
	ret = check_rsa_padding(to, num_bytes, in_buf, len, padding, PRI_DEC);
	if (!ret) {
		printf("\n%s: rsa padding failed.\n", __func__);
		return HPRE_CRYPTO_FAIL;
	}
	return ret;
}

static int uadk_rsa_private_sign(int flen, const unsigned char *from,
				unsigned char *to, RSA *rsa, int padding)
{
	int ret = 0;
	uadk_rsa_sess_t *rsa_sess = NULL;
	BIGNUM *f = (BIGNUM *)NULL;
	BIGNUM *bn_ret = (BIGNUM *)NULL;
	BIGNUM *res = (BIGNUM *)NULL;
	const BIGNUM *n = (const BIGNUM *)NULL;
	const BIGNUM *e = (const BIGNUM *)NULL;
	const BIGNUM *d = (const BIGNUM *)NULL;
	const BIGNUM *p = (const BIGNUM *)NULL;
	const BIGNUM *q = (const BIGNUM *)NULL;
	const BIGNUM *dmp1 = (const BIGNUM *)NULL;
	const BIGNUM *dmq1 = (const BIGNUM *)NULL;
	const BIGNUM *iqmp = (const BIGNUM *)NULL;
	unsigned char *in_buf = (unsigned char *)NULL;
	int key_bits = 0;
	int version = 0;
	int num_bytes = 0;
	BN_CTX *bn_ctx = NULL;

	hpre_rsa_check_para(flen, from, to, rsa);
	key_bits = RSA_bits(rsa);
	if (!check_bit_useful(key_bits)) {
		printf("\n%s: %d is not supported by rsa engine.\n",
				__func__, key_bits);
		return HPRE_CRYPTO_FAIL;
	}
	rsa_sess = uadk_get_eng_session(rsa, key_bits, 1);
	if (rsa_sess == NULL) {
		printf("\n%s: get engine session failed.\n", __func__);
		return HPRE_CRYPTO_FAIL;
	}
	bn_ctx = BN_CTX_new();
	if (!bn_ctx) {
		printf("\n%s: bn_ctx malloc failed.\n", __func__);
		return HPRE_CRYPTO_FAIL;
	}
	BN_CTX_start(bn_ctx);
	f = BN_CTX_get(bn_ctx);
	bn_ret = BN_CTX_get(bn_ctx);
	RSA_get0_factors(rsa, &p, &q);
	RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);
	version = RSA_get_version(rsa);
	RSA_get0_key(rsa, &n, &e, &d);
	num_bytes = BN_num_bytes(n);
	in_buf = (unsigned char *)OPENSSL_malloc(num_bytes);
	if (!bn_ret || !in_buf) {
		printf("\n%s: sign malloc failed.\n", __func__);
		return OPENSSL_FAIL;
	}
	ret = hpre_rsa_padding(flen, from, in_buf, num_bytes, padding,
	PRI_ENC);
	if (!ret) {
		printf("\n%s: rsa padding failed.\n", __func__);
		return HPRE_CRYPTO_FAIL;
	}
	BN_bin2bn(in_buf, num_bytes, f);
	BN_ucmp(f, n);
	ret = uadk_rsa_fill_pubkey(e, n, rsa_sess);
	if (!ret) {
		printf("\n%s: rsa fill pubkey failed.\n", __func__);
		return HPRE_CRYPTO_FAIL;
	}
	if (hpre_rsa_iscrt(rsa)) {
		ret = uadk_rsa_fill_prikey_crt(rsa, rsa_sess, p, q, dmp1,
		dmq1, iqmp);
		if (!ret) {
			printf("\n%s: rsa fill crt prikey failed.\n",
			__func__);
			return HPRE_CRYPTO_FAIL;
		}
	} else {
		ret = uadk_rsa_fill_prikey(rsa, rsa_sess, d, n);
		if (!ret) {
			printf("\n%s: rsa fill prikey failed.\n", __func__);
			return HPRE_CRYPTO_FAIL;
		}
	}
	rsa_sess->req.src_bytes = rsa_sess->key_size;
	rsa_sess->req.op_type = WD_RSA_SIGN;
	rsa_sess->req.src = in_buf;
	rsa_sess->req.dst = to;
	rsa_sess->req.dst_bytes = rsa_sess->key_size;
	memcpy(rsa_sess->req.src, in_buf, rsa_sess->req.src_bytes);
	ret = uadk_rsa_crypto(rsa_sess->sess, &rsa_sess->req);
	if (!ret || rsa_sess->req.status) {
		printf("\n%s: do rsa sign failed. ret = %d\n", __func__, ret);
		return HPRE_CRYPTO_FAIL;
	}
	BN_bin2bn((const unsigned char *)rsa_sess->req.dst,
			rsa_sess->req.dst_bytes, bn_ret);
	hpre_get_prienc_res(padding, f, n, bn_ret, &res);
	ret = BN_bn2binpad(res, to, num_bytes);
	return ret;
}

static int uadk_rsa_public_verify(int flen, const unsigned char *from,
				unsigned char *to, RSA *rsa, int padding)
{
	uadk_rsa_sess_t *rsa_sess = NULL;
	BIGNUM *bn_ret = NULL;
	BIGNUM *f = NULL;
	BN_CTX *bn_ctx = NULL;
	const BIGNUM *n = NULL;
	const BIGNUM *e = NULL;
	const BIGNUM *d = NULL;
	int num_bytes = 0;
	unsigned char *in_buf = NULL;
	int ret = 0;
	int len = 0;

	if (hpre_rsa_check_para(flen, from, to, rsa) != HPRE_CRYPTO_SUCC) {
		printf("\n%s: hpre rsa check para failed.\n", __func__);
		return HPRE_CRYPTO_FAIL;
	}
	RSA_get0_key(rsa, &n, &e, &d);
	ret = hpre_rsa_check(flen, n, e, &num_bytes, rsa);
	if (!ret) {
		printf("\n%s: hpre rsa check e n failed.\n", __func__);
		return HPRE_CRYPTO_FAIL;
	}
	rsa_sess = uadk_get_eng_session(rsa, 0, 1);
	if (rsa_sess == NULL) {
		printf("\n%s: get engine session failed.\n", __func__);
		return HPRE_CRYPTO_FAIL;
	}
	in_buf = (unsigned char *)OPENSSL_malloc(num_bytes);
	if (in_buf == NULL)
		return HPRE_CRYPTO_FAIL;
	uadk_rsa_prepare_req(n, flen, from, &bn_ctx, &bn_ret, &f);
	ret = uadk_rsa_fill_pubkey(e, n, rsa_sess);
	if (!ret) {
		printf("\n%s: rsa fill pubkey failed.\n", __func__);
		return HPRE_CRYPTO_FAIL;
	}
	rsa_sess->req.src_bytes = rsa_sess->key_size;
	rsa_sess->req.op_type = WD_RSA_VERIFY;
	rsa_sess->req.src = in_buf;
	rsa_sess->req.dst = to;
	rsa_sess->req.dst_bytes = rsa_sess->key_size;
	memcpy(rsa_sess->req.src, from, rsa_sess->req.src_bytes);
	ret = uadk_rsa_crypto(rsa_sess->sess, &rsa_sess->req);
	if (!ret || rsa_sess->req.status) {
		printf("\n%s: do rsa verify failed.\n", __func__);
		return HPRE_CRYPTO_FAIL;
	}
	BN_bin2bn((const unsigned char *)rsa_sess->req.dst,
			rsa_sess->req.dst_bytes, bn_ret);
	if ((padding == RSA_X931_PADDING) && ((bn_get_words(bn_ret)[0] & 0xf)
				!= 12)) {
		if (!BN_sub(bn_ret, n, bn_ret))
			return HPRE_CRYPTO_FAIL;
	}
	len = BN_bn2binpad(bn_ret, in_buf, num_bytes);
	ret = check_rsa_padding(to, num_bytes, in_buf, len, padding, PUB_DEC);
	return ret;
}

static int uadk_rsa_mod_exp(void)
{
	return 1;
}
static int uadk_rsa_bn_mod_exp(void)
{
	return 1;
}

int uadk_init_rsa(void)
{
	return uadk_wd_rsa_init(&rsa_res_config);
}

void uadk_destroy_rsa(void)
{
	return uadk_wd_rsa_uninit();
}

RSA_METHOD *uadk_get_rsa_methods(void)
{
	int ret;

	if (uadk_rsa_method != NULL)
		return uadk_rsa_method;
	/* New rsa method. */
	uadk_rsa_method = RSA_meth_new("uadk hardware hpre rsa method", 0);
	if (!uadk_rsa_method) {
		printf("%s: allocate rsa method failed\n", __func__);
		return NULL;
	}
	/* Set RSA methods. */
	ret = RSA_meth_set_keygen(uadk_rsa_method, uadk_rsa_keygen);
	ret = RSA_meth_set_pub_enc(uadk_rsa_method, uadk_rsa_public_encrypt);
	ret = RSA_meth_set_priv_dec(uadk_rsa_method, uadk_rsa_private_decrypt);
	ret = RSA_meth_set_priv_enc(uadk_rsa_method, uadk_rsa_private_sign);
	ret = RSA_meth_set_pub_dec(uadk_rsa_method, uadk_rsa_public_verify);
	if (!ret) {
		printf("%s: set RSA method failed\n", __func__);
		return NULL;
	}
	return uadk_rsa_method;
}

static void uadk_free_rsa_methods(void)
{
	if (uadk_rsa_method) {
		RSA_meth_free(uadk_rsa_method);
		uadk_rsa_method = NULL;
	}
}
