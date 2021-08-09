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
#include <openssl/engine.h>
#include <uadk/wd.h>
#include <uadk/wd_ecc.h>
#include "uadk_pkey.h"
#include "uadk_async.h"

#define ECC_MAX_DEV_NUM			16
#define CTX_ASYNC	1
#define CTX_SYNC	0
#define CTX_NUM		2
#define GET_RAND_MAX_CNT		100

static int pkey_nids[] = {
	EVP_PKEY_EC,
	EVP_PKEY_SM2,
	0
};

struct ecc_sched {
	int sched_type;
	struct wd_sched wd_sched;
};

struct ecc_res_config {
	struct ecc_sched sched;
};

typedef struct uadk_ecc_sess {
	handle_t sess;
	struct wd_ecc_sess_setup setup;
	struct wd_ecc_req req;
	int is_pubkey_ready;
	int is_privkey_ready;
	int key_size;
} uadk_ecc_sess_t;

/* ecc global hardware resource is saved here */
struct ecc_res {
	struct wd_ctx_config *ctx_res;
} ecc_res;

static struct uadk_pkey_meth pkey_meth;

static __u32 ecc_pick_next_ctx(handle_t sched_ctx, const void *req,
			       const struct sched_key *key)
{
	const struct wd_ecc_req *ecc_req = req;

	if (ecc_req->cb)
		return CTX_ASYNC;
	else
		return CTX_SYNC;
}

static int ecc_poll_policy(handle_t h_sched_ctx, __u32 expect, __u32 *count)
{
	return 0;
}

void uadk_ecc_cb(void)
{
	;
}

int uadk_ecc_poll(void *ctx)
{
	unsigned int recv = 0;
	int expt = 1;
	int ret;

	do {
		ret = wd_ecc_poll_ctx(CTX_ASYNC, expt, &recv);
		if (recv >= expt)
			return 0;
		else if (ret < 0 && ret != -EAGAIN)
			return ret;
	} while (ret == -EAGAIN);

	return ret;
}

/* make resource configure static */
struct ecc_res_config ecc_res_config = {
	.sched = {
		.sched_type = -1,
		.wd_sched = {
			.name = "ECC RR",
			.pick_next_ctx = ecc_pick_next_ctx,
			.poll_policy = ecc_poll_policy,
			.h_sched_ctx = 0,
		},
	},
};

static int uadk_wd_ecc_init(struct ecc_res_config *config)
{
	struct wd_sched *sched = &config->sched.wd_sched;
	struct wd_ctx_config *ctx_cfg;
	struct uacce_dev *dev;
	int ret, i;

	if (ecc_res.ctx_res)
		return 0;

	ctx_cfg = calloc(1, sizeof(struct wd_ctx_config));
	if (!ctx_cfg)
		return -ENOMEM;
	ecc_res.ctx_res = ctx_cfg;

	ctx_cfg->ctx_num = CTX_NUM;
	ctx_cfg->ctxs = calloc(CTX_NUM, sizeof(struct wd_ctx));
	if (!ctx_cfg->ctxs) {
		ret = -ENOMEM;
		goto free_cfg;
	}

	ret = -EINVAL;
	/* ctx is no difference for sm2/ecdsa/ecdh/x25519/x448 */
	dev = wd_get_accel_dev("ecdsa");
	for (i = 0; i < CTX_NUM; i++) {
		ctx_cfg->ctxs[i].ctx = wd_request_ctx(dev);
		if (!ctx_cfg->ctxs[i].ctx)
			goto free_ctx;
		ctx_cfg->ctxs[i].ctx_mode = (i == 0) ? CTX_SYNC : CTX_ASYNC;
	}
	free(dev);

	ret = wd_ecc_init(ctx_cfg, sched);
	if (ret)
		goto free_ctx;

	async_register_poll_fn(ASYNC_TASK_ECC, uadk_ecc_poll);
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
	ecc_res.ctx_res = NULL;
	return ret;
}

static void uadk_wd_ecc_uninit(void)
{
	struct wd_ctx_config *ctx_cfg = ecc_res.ctx_res;
	int i;

	if (!ctx_cfg)
		return;

	wd_ecc_uninit();
	for (i = 0; i < ctx_cfg->ctx_num; i++)
		wd_release_ctx(ctx_cfg->ctxs[i].ctx);
	free(ctx_cfg->ctxs);
	free(ctx_cfg);
	ecc_res.ctx_res = NULL;
}

int uadk_ecc_crypto(handle_t sess,
		    struct wd_ecc_req *req, void *usr)
{
	struct async_op op;
	int ret;

	async_setup_async_event_notification(&op);
	if (op.job != NULL) {
		req->cb = (void *)uadk_ecc_cb;
		req->cb_param = req;
		do {
			ret = wd_do_ecc_async(sess, req);
			if (ret < 0 && ret != -EBUSY)
				goto err;
		} while (ret == -EBUSY);

		ret = async_pause_job((void *)usr, &op, ASYNC_TASK_ECC);
		if (!ret)
			goto err;
		if (op.ret)
			return op.ret;

	} else {
		ret = wd_do_ecc_sync(sess, req);
		if (ret < 0)
			return ret;
	}
	return 1;
err:
	(void)async_clear_async_event_notification();
	return 0;
}

int uadk_ecc_set_public_key(handle_t sess, EC_KEY *eckey)
{
	unsigned char *point_bin = NULL;
	struct wd_ecc_point pubkey;
	struct wd_ecc_key *ecc_key;
	unsigned int key_bytes;
	const EC_POINT *point;
	const EC_GROUP *group;
	int ret, len;

	point = EC_KEY_get0_public_key(eckey);
	if (!point) {
		printf("pubkey not set!\n");
		return -EINVAL;
	}

	group = EC_KEY_get0_group(eckey);
	key_bytes = (EC_GROUP_order_bits(group) + 7) / 8;
	len = EC_POINT_point2buf(group, point, 4, &point_bin, NULL);
	if (len != 2 * key_bytes + 1) {
		printf("EC_POINT_point2buf err.\n");
		return -EINVAL;
	}

	pubkey.x.data = (char *)point_bin + 1;
	pubkey.x.dsize = key_bytes;
	pubkey.y.data = pubkey.x.data + key_bytes;
	pubkey.y.dsize = key_bytes;
	ecc_key = wd_ecc_get_key(sess);
	ret = wd_ecc_set_pubkey(ecc_key, &pubkey);
	if (ret) {
		printf("failed to set ecc pubkey\n");
		ret = UADK_DO_SOFT;
	}

	free(point_bin);

	return ret;
}

int uadk_ecc_set_private_key(handle_t sess, EC_KEY *eckey)
{
	unsigned char bin[UADK_ECC_MAX_KEY_BYTES];
	struct wd_ecc_key *ecc_key;
	struct wd_dtb prikey;
	const BIGNUM *d;
	int ret;

	d = EC_KEY_get0_private_key(eckey);
	if (!d) {
		printf("private key not set\n");
		return -EINVAL;
	}

	ecc_key = wd_ecc_get_key(sess);
	prikey.data = (void *)bin;
	prikey.dsize = BN_bn2bin(d, bin);
	ret = wd_ecc_set_prikey(ecc_key, &prikey);
	if (ret) {
		printf("failed to set ecc prikey, ret = %d\n", ret);
		ret = UADK_DO_SOFT;
	}

	return ret;
}

int uadk_ecc_get_rand(char *out, size_t out_len, void *usr)
{
	int count = GET_RAND_MAX_CNT;
	BIGNUM *k;
	int ret;

	if (!out) {
		printf("out is NULL\n");
		return -1;
	}

	k = BN_new();
	if (!k)
		return -ENOMEM;

	do {
		ret = RAND_priv_bytes((void *)out, out_len);
		if (ret != 1) {
			printf("failed to BN_rand_range\n");
			ret = -EINVAL;
			goto err;
		}

		if (!BN_bin2bn((void *)out, out_len, k)) {
			ret = -EINVAL;
			printf("failed to BN_rand_range\n");
			goto err;
		}
	} while (--count >= 0 && (BN_is_zero(k) || BN_ucmp(k, usr) >= 0));

	ret = 0;
	if (count < 0)
		ret = -1;
err:
	BN_free(k);

	return ret;
}

bool uadk_prime_field(const EC_GROUP *group)
{
	int type = EC_METHOD_get_field_type(EC_GROUP_method_of(group));

	return type == NID_X9_62_prime_field;
}

int uadk_get_curve(const EC_GROUP *group, BIGNUM *p, BIGNUM *a,
		     BIGNUM *b, BN_CTX *ctx)
{
# if OPENSSL_VERSION_NUMBER > 0x10101000L
	if (!EC_GROUP_get_curve(group, p, a, b, ctx))
		return -1;
# else
	if (!EC_GROUP_get_curve_GFp(group, p, a, b, ctx))
		return -1;
# endif
	return 0;
}

int uadk_get_affine_coordinates(const EC_GROUP *group, const EC_POINT *p,
				BIGNUM *x, BIGNUM *y, BN_CTX *ctx)
{
# if OPENSSL_VERSION_NUMBER > 0x10101000L
	if (!EC_POINT_get_affine_coordinates(group, p, x, y, ctx))
		return -1;
# else
	if (!EC_POINT_get_affine_coordinates_GFp(group, p, x, y, ctx))
		return -1;
# endif
	return 0;
}

void uadk_ecc_fill_req(struct wd_ecc_req *req, unsigned int op,
		       void *in, void *out)
{
	req->op_type = op;
	req->src = in;
	req->dst = out;
}

bool uadk_support_algorithm(char *alg)
{
	struct uacce_dev_list *list = wd_get_accel_list(alg);

	if (list) {
		wd_free_list_accels(list);
		return true;
	}

	return false;
}

int uadk_init_ecc(void)
{
	if (uadk_support_algorithm("sm2") ||
	    uadk_support_algorithm("ecdsa") ||
	    uadk_support_algorithm("ecdh") ||
	    uadk_support_algorithm("x25519") ||
	    uadk_support_algorithm("x448"))
		return uadk_wd_ecc_init(&ecc_res_config);

	return -EINVAL;
}

static void uadk_uninit_ecc(void)
{
	uadk_wd_ecc_uninit();
}

const EVP_PKEY_METHOD *get_openssl_pkey_meth(int nid)
{
	size_t count = EVP_PKEY_meth_get_count();
	const EVP_PKEY_METHOD *pmeth;
	int pkey_id = -1;
	int i;

	for (i = 0; i < count; i++) {
		pmeth = EVP_PKEY_meth_get0(i);
		EVP_PKEY_meth_get0_info(&pkey_id, NULL, pmeth);
		if (nid == pkey_id)
			return pmeth;
	}

	printf("not find openssl method %d\n", nid);
	return NULL;
}

static int get_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth,
			  const int **nids, int nid)
{
	if (!pmeth) {
		*nids = pkey_nids;
		return 2;
	}

	switch (nid) {
	case EVP_PKEY_SM2:
		*pmeth = pkey_meth.sm2;
		break;
	case EVP_PKEY_EC:
		*pmeth = pkey_meth.ec;
		break;
	default:
		printf("not find nid %d\n", nid);
		return 0;
	}

	return 1;
}

static int uadk_ecc_bind_pmeth(ENGINE *e)
{
	int ret = 0;

	if (!uadk_sm2_create_pmeth(&pkey_meth)) {
		printf("Failed to register sm2 pmeth");
		return 0;
	}

	if (!uadk_ec_create_pmeth(&pkey_meth)) {
		printf("Failed to register ec pmeth");
		goto del_sm2_meth;
	}

	ret = ENGINE_set_pkey_meths(e, get_pkey_meths);
	if (!ret) {
		printf("Failed to engine set pkey meths, ret = %d\n", ret);
		goto del_ec_meth;
	}

	return 1;

del_ec_meth:
	uadk_ec_delete_pmeth(&pkey_meth);
del_sm2_meth:
	uadk_sm2_delete_pmeth(&pkey_meth);

	return ret;
}

static void uadk_ecc_delete_pmeth(void)
{
	uadk_ec_delete_pmeth(&pkey_meth);
	uadk_sm2_delete_pmeth(&pkey_meth);
}


int uadk_bind_ecc(ENGINE *e)
{
	int ret;

	ret = uadk_ecc_bind_pmeth(e);
	if (!ret) {
		printf("failed to bind ecc pmeth\n");
		return ret;
	}

	ret = uadk_bind_ec(e);
	if (!ret) {
		printf("failed to bind ec\n");
		uadk_ecc_delete_pmeth();
		return ret;
	}

	return ret;
}

void uadk_destroy_ecc(void)
{
	uadk_ecc_delete_pmeth();
	uadk_ec_delete_meth();
	uadk_uninit_ecc();
}

