#include <openssl/bn.h>
#include <openssl/asn1t.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/engine.h>
#include <openssl/ossl_typ.h>
#include <openssl/err.h>
#include <uadk/wd_ecc.h>
#include "uadk.h"
#include "uadk_pkey.h"
#include "uadk_async.h"

#define BIT_BYTES_SHIFT			3
#define ECC_MAX_KEY_BITS		521
#define ECC_MAX_KEY_BYTES		((ECC_MAX_KEY_BITS + 7) >> BIT_BYTES_SHIFT)
#define SM2_KEY_BYTES			32

#define ECC_MAX_DEV_NUM			16
#define CTX_ASYNC	1
#define CTX_SYNC	0

#define ECC_DEBUG(fmt, args...)	printf(fmt, ##args)

static EVP_PKEY_METHOD *sm2_pmeth;
static EVP_PKEY_METHOD *ecc_pmeth;

struct sm2_ctx {
	handle_t sess;
	const BIGNUM *prikey;
	const EC_POINT *pubkey;
	/* Key and paramgen group */
	EC_GROUP *gen_group;
	/* message digest */
	const EVP_MD *md;
	/* Distinguishing Identifier, ISO/IEC
	 * 15946-3
	 */
	uint8_t *id;
	size_t id_len;
	/* id_set indicates if the
	 * 'id' field is set (1) or
	 * not (0)
	 */
	int id_set;
};

struct ecc_res_per_dev {
	int numa_id;
	int sync_ctx_num;
	int async_ctx_num;
};

struct ecc_sched {
	int sched_type;
	struct wd_sched wd_sched;
};

struct ecc_res_config {
	int dev_num;
	struct ecc_res_per_dev dev_res[ECC_MAX_DEV_NUM];
	struct ecc_sched sched;
};

/* ecc global hardware resource is saved here */
struct ecc_res {
	struct wd_ctx_config *ctx_res;
	int pid;
} ecc_res;

typedef struct uadk_ecc_sess {
	handle_t sess;
	struct wd_ecc_sess_setup setup;
	struct wd_ecc_req req;
	int is_pubkey_ready;
	int is_privkey_ready;
	int key_size;
} uadk_ecc_sess_t;

typedef struct sm2_ciphertext {
	BIGNUM *C1x;
	BIGNUM *C1y;
	ASN1_OCTET_STRING *C3;
	ASN1_OCTET_STRING *C2;
} SM2_Ciphertext;

DECLARE_ASN1_FUNCTIONS(SM2_Ciphertext)

ASN1_SEQUENCE(SM2_Ciphertext) = {
	ASN1_SIMPLE(SM2_Ciphertext, C1x, BIGNUM),
	ASN1_SIMPLE(SM2_Ciphertext, C1y, BIGNUM),
	ASN1_SIMPLE(SM2_Ciphertext, C3, ASN1_OCTET_STRING),
	ASN1_SIMPLE(SM2_Ciphertext, C2, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(SM2_Ciphertext)

IMPLEMENT_ASN1_FUNCTIONS(SM2_Ciphertext)

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

int uadk_ecc_poll(void *ctx)
{
	int ret = 0;
	int expt = 1;
	int recv;

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
	.dev_num = 2,
	.dev_res[0] = {
		.numa_id = 0,
		.sync_ctx_num = 1,
		.async_ctx_num = 1,
	},
	.dev_res[1] = {
		.numa_id = -1,
		.sync_ctx_num = 1,
		.async_ctx_num = 1,
	},
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

static struct uacce_dev *get_uacce_dev(struct ecc_res_per_dev *dev_res,
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
			struct ecc_res_config *config,
			struct uacce_dev_list *list)
{
	struct ecc_res_per_dev *dev_res;
	struct uacce_dev *uacce_dev;
	struct wd_ctx *ctx;
	int i, j, k, ret, ctx_num, ctx_index = 0;

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

static int uadk_wd_ecc_init(struct ecc_res_config *config,
			    struct uacce_dev_list *list)
{
	struct wd_sched *sched = &config->sched.wd_sched;
	struct ecc_res_per_dev *dev_res;
	struct wd_ctx_config *ctx_cfg;
	struct uacce_dev *uacce_dev;
	int ctx_num = 0;
	int ret, i;

	ctx_cfg = calloc(1, sizeof(struct wd_ctx_config));
	if (!ctx_cfg)
		return -ENOMEM;
	ecc_res.ctx_res = ctx_cfg;

	for (i = 0; i < config->dev_num; i++) {
		dev_res = &config->dev_res[i];
		uacce_dev = get_uacce_dev(dev_res, list);
		if (!uacce_dev)
			continue;
		ctx_num += dev_res->sync_ctx_num + dev_res->async_ctx_num;
	}

	if (!ctx_num) {
		printf("not find dev\n");
		goto free_cfg;
	}

	ctx_cfg->ctxs = calloc(ctx_num, sizeof(struct wd_ctx));
	if (!ctx_cfg->ctxs) {
		ret = -ENOMEM;
		goto free_cfg;
	}
	ctx_cfg->ctx_num = ctx_num;
	ret = init_ctx_cfg(ctx_cfg, config, list);
	if (ret)
		goto free_ctx;
	ret = wd_ecc_init(ctx_cfg, sched);
	if (ret)
		goto uninit_ctx;
	async_register_poll_fn(ASYNC_TASK_ECC, uadk_ecc_poll);
	return 0;
uninit_ctx:
	uninit_ctx_cfg(ctx_cfg);
free_ctx:
	free(ctx_cfg->ctxs);
free_cfg:
	free(ctx_cfg);
	return ret;
}

static void uadk_wd_ecc_uninit(void)
{
	struct wd_ctx_config *ctx_cfg = ecc_res.ctx_res;

	if (ecc_res.pid == getpid()) {
		wd_ecc_uninit();
		uninit_ctx_cfg(ctx_cfg);
		free(ctx_cfg->ctxs);
		free(ctx_cfg);
	}
}

void uadk_destroy_ecc(void)
{
	return uadk_wd_ecc_uninit();
}

static void uadk_ecc_cb(void)
{
}

static int uadk_ecc_crypto(struct sm2_ctx *ctx, struct wd_ecc_req *req)
{
	int ret;
	struct async_op op;

	async_setup_async_event_notification(&op);
	if (op.job != NULL) {
		req->cb = (void *)uadk_ecc_cb;
		req->cb_param = req;
		do {
			ret = wd_do_ecc_async(ctx->sess, req);
			if (ret < 0 && ret != -EBUSY)
				goto err;
		} while (ret == -EBUSY);

		ret = async_pause_job((void *)ctx, &op, ASYNC_TASK_ECC);
		if (!ret)
			goto err;
	} else {
		ret = wd_do_ecc_sync(ctx->sess, req);
		if (ret < 0)
			return ret;
	}
	return 1;
err:
	(void)async_clear_async_event_notification();
	return 0;
}

void uadk_init_ecc(void)
{

	struct uacce_dev_list *list;

	if (ecc_res.pid != getpid()) {
		list = wd_get_accel_list("rsa");
		if (list) {
			uadk_wd_ecc_init(&ecc_res_config, list);
			wd_free_list_accels(list);
		}
		ecc_res.pid = getpid();
	}
}

static int get_rand(char *out, size_t out_len, void *usr)
{
	int ret;

	if (!out)
		return -1;

	ret = RAND_priv_bytes((void *)out, out_len);
	if (ret != 1) {
		printf("RAND_priv_bytes fail = %d\n", ret);
		return -1;
	}

		return 0;
}

static int get_hash_type(int nid_hash)
{
	switch (nid_hash) {
	case NID_sha1:
		return WD_HASH_SHA1;
	case NID_sha224:
		return WD_HASH_SHA224;
	case NID_sha256:
		return WD_HASH_SHA256;
	case NID_sha384:
		return WD_HASH_SHA384;
	case NID_sha512:
		return WD_HASH_SHA512;
	case NID_md4:
		return WD_HASH_MD4;
	case NID_md5:
		return WD_HASH_MD5;
	case NID_sm3:
		return WD_HASH_SM3;
	default:
		return -1;
	}
}

static int compute_hash(const char *in, size_t in_len,
		       char *out, size_t out_len, void *usr)
{
	const EVP_MD *digest = (const EVP_MD *)usr;
	EVP_MD_CTX *hash = EVP_MD_CTX_new();
	int ret = 0;

	if (EVP_DigestInit(hash, digest) == 0 ||
		EVP_DigestUpdate(hash, in, in_len) == 0 ||
		EVP_DigestFinal(hash, (void *)out, NULL) == 0) {
		printf("compute hash failed\n");
		ret = -1;
	}

	EVP_MD_CTX_free(hash);

	return ret;
}

static int sm2_update_sess(struct sm2_ctx *smctx)
{
	int nid_hash = smctx->md ? EVP_MD_type(smctx->md) : NID_sm3;
	struct wd_ecc_sess_setup setup;
	handle_t sess;
	int type;

	if (smctx->sess)
		wd_ecc_free_sess(smctx->sess);
	smctx->prikey = NULL;
	smctx->pubkey = NULL;

	memset(&setup, 0, sizeof(setup));
	setup.alg = "sm2";
	setup.rand.cb = get_rand;
	if (smctx->md) {
		setup.hash.cb = compute_hash;
		setup.hash.usr = (void *)smctx->md;
		type = get_hash_type(nid_hash);
		if (type < 0) {
			printf("uadk not support hash nid %d\n", nid_hash);
			return -EINVAL;
		}
		setup.hash.type = type;
	}

	smctx->sess = wd_ecc_alloc_sess(&setup);
	if (!smctx->sess) {
		printf("Failed to alloc sess\n");
		return -EINVAL;
	}

	return 0;

}

static int update_public_key(EVP_PKEY_CTX *ctx)
{
	struct sm2_ctx *smctx = EVP_PKEY_CTX_get_data(ctx);
	EVP_PKEY *p_key = EVP_PKEY_CTX_get0_pkey(ctx);
	EC_KEY *ec = EVP_PKEY_get0(p_key);
	unsigned char *point_bin = NULL;
	struct wd_ecc_key *ecc_key;
	struct wd_ecc_point pubkey;
	unsigned int key_bytes;
	const EC_POINT *point;
	const EC_GROUP *group;
	int ret, len;

	point = EC_KEY_get0_public_key(ec);
	if (!point) {
		printf("pubkey not set!\n");
		return -EINVAL;
	}

	group = EC_KEY_get0_group(ec);
	if (smctx->pubkey) {
		ret = EC_POINT_cmp(group, (void *)smctx->pubkey, point, NULL);
		if (!ret)
			return 0;
	}

	key_bytes = (EC_GROUP_order_bits(group) + 7) / 8;
	len = EC_POINT_point2buf(group, point, 4, &point_bin, NULL);
	if (len != 2 * key_bytes + 1) {
		printf("EC_POINT_point2buf err.\n");
		return -EINVAL;
	}

	pubkey.x.data = point_bin + 1;
	pubkey.x.dsize = key_bytes;
	pubkey.y.data = pubkey.x.data + key_bytes;
	pubkey.y.dsize = key_bytes;
	ecc_key = wd_ecc_get_key(smctx->sess);
	ret = wd_ecc_set_pubkey(ecc_key, &pubkey);
	if (ret) {
		free(point_bin);
		return ret;
	}

	smctx->pubkey = point;
	return 0;
}

static int update_private_key(EVP_PKEY_CTX *ctx)
{
	struct sm2_ctx *smctx = EVP_PKEY_CTX_get_data(ctx);
	EVP_PKEY *p_key = EVP_PKEY_CTX_get0_pkey(ctx);
	unsigned char bin[ECC_MAX_KEY_BYTES];
	EC_KEY *ec = EVP_PKEY_get0(p_key);
	struct wd_ecc_key *ecc_key;
	struct wd_dtb prikey;
	const BIGNUM *d;
	int ret;

	d = EC_KEY_get0_private_key(ec);
	if (!d) {
		printf("private key not set\n");
		return -EINVAL;
	}

	if (smctx->prikey && !BN_cmp(d, smctx->prikey))
		return 0;

	ecc_key = wd_ecc_get_key(smctx->sess);
	prikey.data = bin;
	prikey.dsize = BN_bn2bin(d, bin);
	ret = wd_ecc_set_prikey(ecc_key, &prikey);
	if (ret)
		return ret;

	smctx->prikey = d;
	return 0;
}

static int sm2_sign_init(EVP_PKEY_CTX *ctx)
{
	return 1;
}

static int sign_bin_to_ber(EC_KEY *ec, struct wd_dtb *r, struct wd_dtb *s,
			   unsigned char *sig, size_t *siglen)
{
	unsigned int sltmp;
	ECDSA_SIG *e_sig;
	BIGNUM *br, *bs;
	int ret;

	e_sig = ECDSA_SIG_new();
	if (!e_sig) {
		printf("Failed to ECDSA_SIG_new\n");
		return 0;
	}

	br = BN_bin2bn(r->data, r->dsize, NULL);
	if (!br) {
		printf("Failed to BN_bin2bn r\n");
		goto free_sig;
	}

	bs = BN_bin2bn(s->data, s->dsize, NULL);
	if (!bs) {
		printf("Failed to BN_bin2bn s\n");
		goto free_r;
	}

	ret = ECDSA_SIG_set0(e_sig, br, bs);
	if (ret != 1) {
		printf("Failed to ECDSA_SIG_set0\n");
		goto free_s;
	}

	sltmp = i2d_ECDSA_SIG(e_sig, &sig);
	if (sltmp < 0) {
		printf("Failed to i2d_ECDSA_SIG\n");
		goto free_s;
	}
	*siglen = (size_t)sltmp;
	return 1;

free_s:
	BN_free(bs);
free_r:
	BN_free(br);
free_sig:
	ECDSA_SIG_free(e_sig);

	return 0;
}

static int sig_ber_to_bin(EC_KEY *ec, unsigned char *sig, size_t sig_len,
			  struct wd_dtb *r, struct wd_dtb *s)
{
	const unsigned char *p = sig;
	BIGNUM *b_r, *b_s = NULL;
	unsigned char *der = NULL;
	ECDSA_SIG *e_sig = NULL;
	int ret, len1, len2;

	e_sig = ECDSA_SIG_new();
	if (!e_sig) {
		printf("Failed to ECDSA_SIG_new\n");
		return -ENOMEM;
	}

	if (d2i_ECDSA_SIG(&e_sig, &p, sig_len) == NULL) {
		printf("d2i_ECDSA_SIG error\n");
		ret = -EINVAL;
		goto free_sig;
	}

	/* Ensure signature uses DER and doesn't have trailing garbage */
	len1 = i2d_ECDSA_SIG(e_sig, &der);
	if (len1 != sig_len || memcmp(sig, der, len1) != 0) {
		printf("sig data error, derlen(%d), sig_len(%lu)\n",
		len1, sig_len);
		ret = -EINVAL;
		goto free_der;
	}

	b_r = (void *)ECDSA_SIG_get0_r((const ECDSA_SIG *)e_sig);
	if (!b_r) {
		printf("failed to get r\n");
		ret = -EINVAL;
		goto free_der;
	}

	b_s = (void *)ECDSA_SIG_get0_s((const ECDSA_SIG *)e_sig);
	if (!b_r) {
		printf("failed to get s\n");
		ret = -EINVAL;
		goto free_der;
	}

	len1 = BN_num_bytes(b_r);
	len2 = BN_num_bytes(b_s);
	if (len1 > ECC_MAX_KEY_BYTES || len2 > ECC_MAX_KEY_BYTES) {
		printf("r or s bytes = (%d, %d) error\n", len1, len2);
		ret = -EINVAL;
		goto free_der;
	}
	r->dsize = BN_bn2bin(b_r, r->data);
	s->dsize = BN_bn2bin(b_s, s->data);
	ret = 0;
free_der:
	OPENSSL_free(der);
free_sig:
	ECDSA_SIG_free(e_sig);

	return ret;
}

static int cipher_bin_to_ber(EVP_MD *md, struct wd_ecc_point *c1,
			     struct wd_dtb *c2, struct wd_dtb *c3,
			     unsigned char *ber, size_t *ber_len)
{
	struct sm2_ciphertext ctext_struct;
	const int C3_size = EVP_MD_size(md);
	int ciphertext_leni, ret;
	BIGNUM *x1, *y1;

	x1 = BN_bin2bn(c1->x.data, c1->x.dsize, NULL);
	if (!x1) {
		printf("Failed to BN_bin2bn x1\n");
		return -ENOMEM;
	}

	y1 = BN_bin2bn(c1->y.data, c1->y.dsize, NULL);
	if (!y1) {
		printf("Failed to BN_bin2bn y1\n");
		goto free_x1;
	}

	ctext_struct.C1x = x1;
	ctext_struct.C1y = y1;
	ctext_struct.C3 = ASN1_OCTET_STRING_new();
	if (!ctext_struct.C3) {
		ret = -ENOMEM;
		goto free_y1;
	}

	ctext_struct.C2 = ASN1_OCTET_STRING_new();
	if (!ctext_struct.C2) {
		ret = -ENOMEM;
		goto free_y1;
	}

	if (!ASN1_OCTET_STRING_set(ctext_struct.C3, c3->data, c3->dsize)
		|| !ASN1_OCTET_STRING_set(ctext_struct.C2, c2->data, c2->dsize)) {
		printf("Failed to ASN1_OCTET_STRING_set\n");
		ret = -EINVAL;
		goto free_y1;
	}

	ciphertext_leni = i2d_SM2_Ciphertext(&ctext_struct, (unsigned char **)&ber);
	/* Ensure cast to size_t is safe */
	if (ciphertext_leni < 0)
		goto free_y1;
	*ber_len = (size_t)ciphertext_leni;
	ret = 1;
free_y1:
	BN_free(y1);
free_x1:
	BN_free(x1);

	return ret;

}

static int cipher_ber_to_bin(EVP_MD *md, unsigned char *ber, size_t ber_len,
			     struct wd_ecc_point *c1,
			     struct wd_dtb *c2,
			     struct wd_dtb *c3)
{
	struct sm2_ciphertext *ctext_struct;
	int md_size = EVP_MD_size(md);
	int ret, len, len1;

	ctext_struct = d2i_SM2_Ciphertext(NULL, (const unsigned char **)&ber, ber_len);
	if (!ctext_struct) {
		printf("Failed to d2i_SM2_Ciphertext\n");
		return -ENOMEM;
	}

	len = BN_num_bytes(ctext_struct->C1x);
	len1 = BN_num_bytes(ctext_struct->C1y);
	c1->x.data = malloc(len + len1 + ctext_struct->C2->length +
		ctext_struct->C3->length);
	if (!c1->x.data) {
		ret = -ENOMEM;
		goto free_ctext;
	}
	c1->y.data = c1->x.data + len;
	c3->data = c1->y.data + len1;
	c2->data = c3->data + ctext_struct->C3->length;
	memcpy(c2->data, ctext_struct->C2->data, ctext_struct->C2->length);
	memcpy(c3->data, ctext_struct->C3->data, ctext_struct->C3->length);
	c2->dsize = ctext_struct->C2->length;
	c3->dsize = ctext_struct->C3->length;
	c1->x.dsize = BN_bn2bin(ctext_struct->C1x, c1->x.data);
	c1->y.dsize = BN_bn2bin(ctext_struct->C1y, c1->y.data);

	return 0;
free_ctext:
	SM2_Ciphertext_free(ctext_struct);
	return ret;
}

static void fill_req(struct wd_ecc_req *req, unsigned int op, void *in, void *out)
{
	req->op_type = op;
	req->src = in;
	req->dst = out;
}

static size_t ec_field_size(const EC_GROUP *group)
{
	/* Is there some simpler way to do this? */
	BIGNUM *p = BN_new();
	BIGNUM *a = BN_new();
	BIGNUM *b = BN_new();
	size_t field_size = 0;

	if (p == NULL || a == NULL || b == NULL)
		goto done;

	if (!EC_GROUP_get_curve(group, p, a, b, NULL))
		goto done;
	field_size = (BN_num_bits(p) + 7) / 8;

done:
	BN_free(p);
	BN_free(a);
	BN_free(b);

	return field_size;
}

static int sm2_ciphertext_size(const EC_KEY *key, const EVP_MD *digest, size_t msg_len,
			       size_t *ct_size)
{
	const size_t field_size = ec_field_size(EC_KEY_get0_group(key));
	const int md_size = EVP_MD_size(digest);
	size_t sz;

	if (field_size == 0 || md_size < 0)
		return 0;

	/* Integer and string are
	 * simple type; set
	 * constructed = 0, means
	 * primitive and definite
	 * length encoding.
	 */
	sz = 2 * ASN1_object_size(0, field_size + 1, V_ASN1_INTEGER)
		+ ASN1_object_size(0, md_size, V_ASN1_OCTET_STRING)
		+ ASN1_object_size(0, msg_len, V_ASN1_OCTET_STRING);
	*ct_size = ASN1_object_size(1, sz, V_ASN1_SEQUENCE);
	return 1;
}

static int sm2_sign_init_iot(handle_t sess, struct wd_ecc_req *req,
			     unsigned char *digest, size_t digest_len)
{
	struct wd_ecc_out *ecc_out;
	struct wd_ecc_in *ecc_in;
	struct wd_dtb e = { 0 };

	ecc_out = wd_sm2_new_sign_out(sess);
	if (!ecc_out) {
		printf("Failed to new sign out\n");
		return -ENOMEM;
	}

	e.data = (void *)digest;
	e.dsize = digest_len;
	ecc_in = wd_sm2_new_sign_in(sess, &e, NULL, NULL, 1);
	if (!ecc_in) {
		printf("Failed to new sign in\n");
		wd_ecc_del_out(sess, ecc_out);
		return -ENOMEM;
	}

	fill_req(req, WD_SM2_SIGN, ecc_in, ecc_out);

	return 0;
}

static int sm2_sign_check(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
		  const unsigned char *tbs, size_t tbslen)
{
	struct sm2_ctx *smctx = EVP_PKEY_CTX_get_data(ctx);
	EVP_PKEY *p_key = EVP_PKEY_CTX_get0_pkey(ctx);
	EC_KEY *ec = EVP_PKEY_get0(p_key);
	const int sig_sz = ECDSA_size(ec);

	if (!smctx || !smctx->sess) {
		printf("smctx or sess NULL\n");
		return -EINVAL;
	}

	if (sig_sz <= 0) {
		printf("sig_sz error\n");
		return -EINVAL;
	}

	if (sig == NULL) {
		*siglen = (size_t)sig_sz;
		return 1;
	}

	if (*siglen < (size_t)sig_sz) {
		printf("siglen(%lu) < sig_sz(%lu)\n", *siglen, (size_t)sig_sz);
		return -EINVAL;
	}

	return 0;
}

static int sm2_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
		  const unsigned char *tbs, size_t tbslen)
{
	struct sm2_ctx *smctx = EVP_PKEY_CTX_get_data(ctx);
	EVP_PKEY *p_key = EVP_PKEY_CTX_get0_pkey(ctx);
	struct wd_dtb *r = NULL;
	struct wd_dtb *s = NULL;
	struct wd_ecc_req req;
	int ret;

	ret = sm2_sign_check(ctx, sig, siglen, tbs, tbslen);
	if (ret)
		return ret;

	memset(&req, 0, sizeof(req));
	ret = sm2_sign_init_iot(smctx->sess, &req, (void *)tbs, tbslen);
	if (ret)
		return ret;

	ret = update_private_key(ctx);
	if (ret)
		goto uninit_iot;

	ret = uadk_ecc_crypto(smctx, &req);
	if (ret != 1) {
		printf("Failed to uadk_ecc_crypto, ret = %d\n", ret);
		goto uninit_iot;
	}

	wd_sm2_get_sign_out_params(req.dst, &r, &s);
	ret = sign_bin_to_ber(NULL, r, s, sig, siglen);
	if (ret)
		goto uninit_iot;

	ret = 1;

uninit_iot:
	wd_ecc_del_in(smctx->sess, req.src);
	wd_ecc_del_out(smctx->sess, req.dst);

	return ret;
}

static int sm2_verify_init(EVP_PKEY_CTX *ctx)
{
	return 1;
}

static int sm2_verify_init_iot(handle_t sess, struct wd_ecc_req *req,
			       struct wd_dtb *e,
			       struct wd_dtb *r,
			       struct wd_dtb *s)
{
	struct wd_ecc_in *ecc_in;

	ecc_in = wd_sm2_new_verf_in(sess, e, r, s, NULL, 1);
	if (!ecc_in) {
		printf("Failed to new verf in\n");
		return -ENOMEM;
	}

	fill_req(req, WD_SM2_VERIFY, ecc_in, NULL);

	return 0;
}

static int sm2_verify_check(EVP_PKEY_CTX *ctx, const unsigned char *sig, size_t siglen,
		    const unsigned char *tbs, size_t tbslen)
{
	return 0;
}

static int sm2_verify(EVP_PKEY_CTX *ctx, const unsigned char *sig, size_t siglen,
		      const unsigned char *tbs, size_t tbslen)
{
	struct sm2_ctx *smctx = EVP_PKEY_CTX_get_data(ctx);
	EVP_PKEY *p_key = EVP_PKEY_CTX_get0_pkey(ctx);
	EC_KEY *ec = EVP_PKEY_get0(p_key);
	unsigned char buf_r[ECC_MAX_KEY_BYTES] = { 0 };
	unsigned char buf_s[ECC_MAX_KEY_BYTES] = { 0 };
	struct wd_dtb e = { 0 };
	struct wd_dtb r = { 0 };
	struct wd_dtb s = { 0 };
	struct wd_ecc_req req;
	int ret;

	r.data = buf_r;
	s.data = buf_s;
	r.bsize = ECC_MAX_KEY_BYTES;
	s.bsize = ECC_MAX_KEY_BYTES;
	ret = sig_ber_to_bin(ec, (void *)sig, siglen, &r, &s);
	if (ret)
		return ret;

	e.data = (void *)tbs;
	e.dsize = tbslen;
	memset(&req, 0, sizeof(req));
	ret = sm2_verify_init_iot(smctx->sess, &req, &e, &r, &s);
	if (ret)
		return ret;

	ret = update_public_key(ctx);
	if (ret)
		goto uninit_iot;

	ret = uadk_ecc_crypto(smctx, &req);
	if (ret != 1) {
		printf("Failed to uadk_ecc_crypto, ret = %d\n", ret);
		goto uninit_iot;
	}

uninit_iot:
	wd_ecc_del_in(smctx->sess, req.src);

	return ret;
}

static int sm2_encrypt_init_iot(handle_t sess, struct wd_ecc_req *req,
				unsigned char *in, size_t inlen)
{
	struct wd_ecc_out *ecc_out;
	struct wd_ecc_in *ecc_in;
	struct wd_dtb e = { 0 };
	int ret;

	ecc_out = wd_sm2_new_enc_out(sess, inlen);
	if (!ecc_out) {
		printf("Failed to new enc out\n");
		return -ENOMEM;
	}

	e.data = (void *)in;
	e.dsize = inlen;
	ecc_in = wd_sm2_new_enc_in(sess, NULL, &e);
	if (!ecc_in) {
		printf("Failed to new enc in\n");
		wd_ecc_del_out(sess, ecc_out);
		return -ENOMEM;
	}

	fill_req(req, WD_SM2_ENCRYPT, ecc_in, ecc_out);
	return 0;
}

static int sm2_encrypt_check(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
		  const unsigned char *in, size_t inlen)
{
	struct sm2_ctx *smctx = EVP_PKEY_CTX_get_data(ctx);
	EVP_PKEY *p_key = EVP_PKEY_CTX_get0_pkey(ctx);
	EC_KEY *ec = EVP_PKEY_get0(p_key);
	const EVP_MD *md = (smctx->md == NULL) ? EVP_sm3() : smctx->md;
	int c3_size = EVP_MD_size(md);

	if (!smctx || !smctx->sess) {
		printf("smctx or sess NULL\n");
		return 0;
	}

	if (c3_size <= 0) {
		printf("c3 size error\n");
		return 0;
	}

	if (!out) {
		if (!sm2_ciphertext_size(ec, md, inlen, outlen))
			return -1;
		else
			return 1;
	}

	return 0;
}
static int sm2_encrypt_init(EVP_PKEY_CTX *ctx)
{
	return 1;
}

static int sm2_encrypt(EVP_PKEY_CTX *ctx,
		       unsigned char *out, size_t *outlen,
		       const unsigned char *in, size_t inlen)
{
	struct sm2_ctx *smctx = EVP_PKEY_CTX_get_data(ctx);
	EVP_PKEY *p_key = EVP_PKEY_CTX_get0_pkey(ctx);
	EC_KEY *ec = EVP_PKEY_get0(p_key);
	struct wd_ecc_out *ecc_out;
	struct wd_ecc_in *ecc_in;
	struct wd_ecc_point *c1 = NULL;
	struct wd_dtb *c2 = NULL;
	struct wd_dtb *c3 = NULL;
	struct wd_ecc_req req;
	struct wd_dtb e, k;
	EVP_MD *md;
	int ret;

	ret = sm2_encrypt_check(ctx, out, outlen, in, inlen);
	if (ret)
		return ret;

	memset(&req, 0, sizeof(req));
	ret = sm2_encrypt_init_iot(smctx->sess, &req, (void *)in, inlen);
	if (ret)
		return ret;

	ret = update_public_key(ctx);
	if (ret)
		goto uninit_iot;

	ret = uadk_ecc_crypto(smctx, &req);
	if (ret != 1) {
		printf("Failed to uadk_ecc_crypto, ret = %d\n", ret);
		goto uninit_iot;
	}

	wd_sm2_get_enc_out_params(req.dst, &c1, &c2, &c3);
	ret = cipher_bin_to_ber(md, c1, c2, c3, out, outlen);
	if (ret)
		goto uninit_iot;

	ret = 1;
uninit_iot:
	wd_ecc_del_in(smctx->sess, req.src);
	wd_ecc_del_out(smctx->sess, req.dst);

	return ret;
}

static int sm2_decrypt_init(EVP_PKEY_CTX *ctx)
{
	return 1;
}

static int sm2_decrypt_check(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
			     const unsigned char *in, size_t inlen)
{
	struct sm2_ctx *smctx = EVP_PKEY_CTX_get_data(ctx);
	EVP_PKEY *p_key = EVP_PKEY_CTX_get0_pkey(ctx);
	EC_KEY *ec = EVP_PKEY_get0(p_key);
	const EVP_MD *md;
	int hash_size;

	if (!smctx || !smctx->sess) {
		printf("smctx or sess NULL\n");
		return -EINVAL;
	}

	md = (smctx->md == NULL) ? EVP_sm3() : smctx->md;
	hash_size = EVP_MD_size(md);
	if (hash_size <= 0) {
		printf("hash size = %d error\n", hash_size);
		return 0;
	}

	if (!out) {
		if (!sm2_ciphertext_size(ec, md, inlen, outlen))
			return -1;
		else
			return 1;
	}

	return 0;
}

static int sm2_decrypt_init_iot(handle_t sess,
			  struct wd_ecc_req *req,
			  struct wd_ecc_point *c1,
			  struct wd_dtb *c2,
			  struct wd_dtb *c3)
{
	struct wd_ecc_out *ecc_out;
	struct wd_ecc_in *ecc_in;

	ecc_out = wd_sm2_new_dec_out(sess, c2->dsize);
	if (!ecc_out) {
		printf("Failed to new dec out\n");
		return -ENOMEM;
	}

	ecc_in = wd_sm2_new_dec_in(sess, c1, c2, c3);
	if (!ecc_in) {
		printf("Failed to new dec in\n");
		wd_ecc_del_out(sess, ecc_out);
		return -ENOMEM;
	}

	fill_req(req, WD_SM2_DECRYPT, ecc_in, ecc_out);

	return 0;
}

static void sm2_decrypt_uninit_iot(handle_t sess, struct wd_ecc_req *req)
{
	wd_ecc_del_in(sess, req->src);
	wd_ecc_del_out(sess, req->dst);
}

static int sm2_get_plaintext(struct wd_ecc_req *req,
			     unsigned char *out, size_t *outlen)
{

	struct wd_dtb *ptext = NULL;

	wd_sm2_get_dec_out_params(req->dst, &ptext);
	if (*outlen < ptext->dsize) {
		printf("outlen(%lu) < (%u)\n", *outlen, ptext->dsize);
		return -EINVAL;
	}
	memcpy(out, ptext->data, ptext->dsize);
	*outlen = ptext->dsize;
	return 0;
}

static int sm2_decrypt(EVP_PKEY_CTX *ctx,
		       unsigned char *out, size_t *outlen,
		       const unsigned char *in, size_t inlen)
{
	struct sm2_ctx *smctx = EVP_PKEY_CTX_get_data(ctx);
	EVP_PKEY *p_key = EVP_PKEY_CTX_get0_pkey(ctx);
	EC_KEY *ec = EVP_PKEY_get0(p_key);
	struct wd_ecc_point c1;
	struct wd_dtb c2, c3;
	struct wd_ecc_req req;
	const EVP_MD *md;
	int ret;

	ret = sm2_decrypt_check(ctx, out, outlen, in, inlen);
	if (ret)
		return ret;

	md = (smctx->md == NULL) ? EVP_sm3() : smctx->md;
	ret = cipher_ber_to_bin((void *)md, (void *)in, inlen, &c1, &c2, &c3);
	if (ret)
		return ret;

	if (c3.dsize != EVP_MD_size(md)) {
		printf("c3 dsize != hash_size\n");
		goto free_bin;
	}

	memset(&req, 0, sizeof(req));
	ret = sm2_decrypt_init_iot(smctx->sess, &req, &c1, &c2, &c3);
	if (ret)
		goto free_bin;

	ret = update_private_key(ctx);
	if (ret)
		goto uninit_iot;

	ret = uadk_ecc_crypto(smctx, &req);
	if (ret != 1) {
		printf("Failed to uadk_ecc_crypto, ret = %d\n", ret);
		goto uninit_iot;
	}

	ret = sm2_get_plaintext(&req, out, outlen);
	if (ret)
		goto uninit_iot;

	ret = 1;
uninit_iot:
	sm2_decrypt_uninit_iot(smctx->sess, &req);
free_bin:
	free(c1.x.data);
	return ret;
}

static int sm2_keygen_init_iot(handle_t sess, struct wd_ecc_req *req)
{
	struct wd_ecc_out *ecc_out;

	ecc_out = wd_sm2_new_kg_out(sess);
	if (!ecc_out) {
		printf("Failed to new sign out\n");
		return -ENOMEM;
	}

	fill_req(req, WD_SM2_KG, NULL, ecc_out);

	return 0;
}

static int set_key_to_ec_key(EC_KEY *ec, struct wd_ecc_req *req)
{
	unsigned char buff[SM2_KEY_BYTES * 2 + 1] = { 0x4 };
	struct wd_ecc_point *pubkey = NULL;
	struct wd_dtb *privkey = NULL;
	const EC_GROUP *group;
	EC_POINT *point, *ptr;
	BIGNUM *tmp;
	int ret;

	wd_sm2_get_kg_out_params(req->dst, &privkey, &pubkey);

	tmp = BN_bin2bn((unsigned char *)privkey->data, privkey->dsize, NULL);
	ret = EC_KEY_set_private_key(ec, tmp);
	BN_free(tmp);
	if (ret != 1) {
		printf("Failed to EC KEY set private key\n");
		return ret;
	}

	group = EC_KEY_get0_group(ec);
	point = EC_POINT_new(group);
	if (!point) {
		printf("Failed to EC POINT new\n");
		return -ENOMEM;
	}

	memcpy(buff + 1, pubkey->x.data, SM2_KEY_BYTES * 2);
	tmp = BN_bin2bn(buff, SM2_KEY_BYTES * 2 + 1, NULL);
	ptr = EC_POINT_bn2point(group, tmp, point, NULL);
	BN_free(tmp);
	if (!ptr) {
		printf("EC_POINT_bn2point failed\n");
		EC_POINT_free(point);
		return -EINVAL;
	}

	ret = EC_KEY_set_public_key(ec, point);
	EC_POINT_free(point);
	if (ret != 1) {
		printf("EC_KEY_set_public_key failed\n");
		return -EINVAL;
	}

	return 0;
}

static int sm2_keygen_init(EVP_PKEY_CTX *ctx)
{
	return 1;
}

static int sm2_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *ppkey)
{
	struct sm2_ctx *smctx = EVP_PKEY_CTX_get_data(ctx);
	EVP_PKEY *p_key = EVP_PKEY_CTX_get0_pkey(ctx);
	struct wd_ecc_req req;
	EC_KEY *ec;
	int ret;

	if (p_key == NULL && smctx->gen_group == NULL) {
		printf("no parameters set\n");
		return 0;
	}

	ec = EC_KEY_new();
	if (ec == NULL) {
		printf("Failed to EC KEY new\n");
		return -ENOMEM;
	}
	EVP_PKEY_set1_EC_KEY(p_key, ec);

	if (!EVP_PKEY_assign_EC_KEY(ppkey, ec)) {
		printf("Failed to EVP PKEY assign EC KEY\n");
		EC_KEY_free(ec);
		return 0;
	}
	/* Note: if error is returned, we count on caller to free
	 * pkey->pkey.ec
	 */
	if (p_key != NULL)
		ret = EVP_PKEY_copy_parameters(ppkey, p_key);
	else
		ret = EC_KEY_set_group(ec, smctx->gen_group);
	if (ret != 1) {
		printf("Failed to set group\n");
		return ret;
	}

	memset(&req, 0, sizeof(req));
	ret = sm2_keygen_init_iot(smctx->sess, &req);
	if (ret)
		return ret;

	ret = uadk_ecc_crypto(smctx, &req);
	if (ret != 1) {
		printf("Failed to uadk_ecc_crypto, ret = %d\n", ret);
		goto uninit_iot;
	}

	ret = set_key_to_ec_key(ec, &req);
	if (ret)
		goto uninit_iot;

	ret = 1;
uninit_iot:
	wd_ecc_del_out(smctx->sess, req.dst);
	return ret;
}

static void sm2_cleanup(EVP_PKEY_CTX *ctx)
{
	struct sm2_ctx *smctx = EVP_PKEY_CTX_get_data(ctx);

	if (!smctx)
		return;

	EC_GROUP_free(smctx->gen_group);
	OPENSSL_free(smctx->id);

	if (smctx->sess)
		wd_ecc_free_sess(smctx->sess);
	free(smctx);
	EVP_PKEY_CTX_set_data(ctx, NULL);
}

static int sm2_init(EVP_PKEY_CTX *ctx)
{
	struct sm2_ctx *smctx;
	int ret;

	smctx = malloc(sizeof(*smctx));
	if (!smctx) {
		printf("Failed to alloc sm2 ctx\n");
		return 0;
	}

	memset(smctx, 0, sizeof(*smctx));

	ret = sm2_update_sess(smctx);
	if (ret) {
		printf("Failed to update sess\n");
		free(smctx);
		return 0;
	}

	EVP_PKEY_CTX_set_data(ctx, smctx);
	EVP_PKEY_CTX_set0_keygen_info(ctx, NULL, 0);

	return 1;
}

static int sm2_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
	struct sm2_ctx *smctx = EVP_PKEY_CTX_get_data(ctx);
	EC_GROUP *group;
	uint8_t *tmp_id;

	switch (type) {
	case EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID:
		group = EC_GROUP_new_by_curve_name(p1);
		if (group == NULL) {
			printf("invalid curve %d\n", p1);
			return 0;
		}
		EC_GROUP_free(smctx->gen_group);
		smctx->gen_group = group;
		return 1;
	case EVP_PKEY_CTRL_EC_PARAM_ENC:
		if (smctx->gen_group == NULL) {
			printf("no parameters set\n");
			return 0;
		}
		EC_GROUP_set_asn1_flag(smctx->gen_group, p1);
		return 1;
	case EVP_PKEY_CTRL_MD:
		smctx->md = p2;
		if (sm2_update_sess(smctx))
			return 0;
		return 1;
	case EVP_PKEY_CTRL_GET_MD:
		*(const EVP_MD **)p2 = smctx->md;
		return 1;
	case EVP_PKEY_CTRL_SET1_ID:
		if (p1 > 0) {
			tmp_id = OPENSSL_malloc(p1);
			if (tmp_id == NULL) {
				printf("Failed to malloc\n");
				return 0;
			}
			memcpy(tmp_id, p2, p1);
			OPENSSL_free(smctx->id);
			smctx->id = tmp_id;
		} else {
			/* set null-ID */
			OPENSSL_free(smctx->id);
			smctx->id = NULL;
		}
		smctx->id_len = (size_t)p1;
		smctx->id_set = 1;
		return 1;
	case EVP_PKEY_CTRL_GET1_ID:
		memcpy(p2, smctx->id, smctx->id_len);
		return 1;
	case EVP_PKEY_CTRL_GET1_ID_LEN:
		*(size_t *)p2 = smctx->id_len;
		return 1;
	case EVP_PKEY_CTRL_DIGESTINIT:
		/* nothing to be inited, this is to suppress the error... */
		return 1;
	default:
		printf("sm2 ctrl type = %d error\n", type);
		return -2;
	}
}

static int sm2_ctrl_str(EVP_PKEY_CTX *ctx,
			const char *type, const char *value)
{
	if (strcmp(type, "ec_paramgen_curve") == 0) {
		int nid;

		if ((EC_curve_nist2nid(value) == NID_undef)
			&& (OBJ_sn2nid(value) == NID_undef)
			&& (OBJ_ln2nid(value) == NID_undef)) {
			printf("invalid curve\n");
			return 0;
		}

		nid = EC_curve_nist2nid(value);
		if (nid == NID_undef) {
			nid = OBJ_sn2nid(value);
			if (nid == NID_undef)
				nid = OBJ_ln2nid(value);
		}
		return EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid);
	} else if (strcmp(type, "ec_param_enc") == 0) {
		int param_enc;

		if (strcmp(value, "explicit") == 0)
			param_enc = 0;
		else if (strcmp(value, "named_curve") == 0)
			param_enc = OPENSSL_EC_NAMED_CURVE;
		else
			return -2;
		return EVP_PKEY_CTX_set_ec_param_enc(ctx, param_enc);
	}

	return -2;
}

static int sm2_compute_z_digest(uint8_t *out,
				const EVP_MD *digest,
				const uint8_t *id,
				const size_t id_len,
				const EC_KEY *key)
{
	int rc = 0;
	const EC_GROUP *group = EC_KEY_get0_group(key);
	BN_CTX *ctx = NULL;
	EVP_MD_CTX *hash = NULL;
	BIGNUM *p = NULL;
	BIGNUM *a = NULL;
	BIGNUM *b = NULL;
	BIGNUM *xG = NULL;
	BIGNUM *yG = NULL;
	BIGNUM *xA = NULL;
	BIGNUM *yA = NULL;
	int p_bytes = 0;
	uint8_t *buf = NULL;
	uint16_t entl = 0;
	uint8_t e_byte = 0;

	hash = EVP_MD_CTX_new();
	ctx = BN_CTX_new();
	if (hash == NULL || ctx == NULL) {
		printf("Failed to EVP_CTX_new\n");
		goto done;
	}

	p = BN_CTX_get(ctx);
	a = BN_CTX_get(ctx);
	b = BN_CTX_get(ctx);
	xG = BN_CTX_get(ctx);
	yG = BN_CTX_get(ctx);
	xA = BN_CTX_get(ctx);
	yA = BN_CTX_get(ctx);

	if (yA == NULL) {
		printf("Failed to malloc\n");
		goto done;
	}

	if (!EVP_DigestInit(hash, digest)) {
		printf("error evp lib\n");
		goto done;
	}

	/* Z = h(ENTL || ID || a || b || xG || yG || xA || yA) */

	if (id_len >= (UINT16_MAX / 8)) {
		/* too large */
		printf("id too large\n");
		goto done;
	}

	entl = (uint16_t)(8 * id_len);

	e_byte = entl >> 8;
		if (!EVP_DigestUpdate(hash, &e_byte, 1)) {
			printf("error evp lib\n");
			goto done;
		}
	e_byte = entl & 0xFF;
	if (!EVP_DigestUpdate(hash, &e_byte, 1)) {
		printf("error evp lib\n");
		goto done;
	}

	if (id_len > 0 && !EVP_DigestUpdate(hash, id, id_len)) {
		printf("error evp lib\n");
		goto done;
	}

	if (!EC_GROUP_get_curve(group, p, a, b, ctx)) {
		printf("error ec lib\n");
		goto done;
	}

	p_bytes = BN_num_bytes(p);
	buf = OPENSSL_zalloc(p_bytes);
	if (buf == NULL) {
		printf("Failed to malloc\n");
		goto done;
	}

	if (BN_bn2binpad(a, buf, p_bytes) < 0
	    || !EVP_DigestUpdate(hash, buf, p_bytes)
	    || BN_bn2binpad(b, buf, p_bytes) < 0
	    || !EVP_DigestUpdate(hash, buf, p_bytes)
	    || !EC_POINT_get_affine_coordinates(group,
						EC_GROUP_get0_generator(group),
						xG, yG, ctx)
	    || BN_bn2binpad(xG, buf, p_bytes) < 0
	    || !EVP_DigestUpdate(hash, buf, p_bytes)
	    || BN_bn2binpad(yG, buf, p_bytes) < 0
	    || !EVP_DigestUpdate(hash, buf, p_bytes)
	    || !EC_POINT_get_affine_coordinates(group,
						EC_KEY_get0_public_key(key),
						xA, yA, ctx)
	    || BN_bn2binpad(xA, buf, p_bytes) < 0
	    || !EVP_DigestUpdate(hash, buf, p_bytes)
	    || BN_bn2binpad(yA, buf, p_bytes) < 0
	    || !EVP_DigestUpdate(hash, buf, p_bytes)
	    || !EVP_DigestFinal(hash, out, NULL)) {
		printf("internal error\n");
		goto done;
	}

	rc = 1;

done:
	OPENSSL_free(buf);
	BN_CTX_free(ctx);
	EVP_MD_CTX_free(hash);
	return rc;
}

static int sm2_digest_custom(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx)
{
	struct sm2_ctx *smctx = EVP_PKEY_CTX_get_data(ctx);
	EVP_PKEY *p_key = EVP_PKEY_CTX_get0_pkey(ctx);
	const EVP_MD *md = EVP_MD_CTX_md(mctx);
	EC_KEY *ec = EVP_PKEY_get0(p_key);
	uint8_t z[EVP_MAX_MD_SIZE];
	int mdlen = EVP_MD_size(md);

	if (!smctx->id_set) {
		/*
		 * An ID value must be set. The specifications are not clear whether a
		 * NULL is allowed. We only allow it if set explicitly for maximum
		 * flexibility.
		 */
		printf("id not set\n");
		return 0;
	}

	if (mdlen < 0) {
		printf("invalid digest size %d\n", mdlen);
		return 0;
	}

	/* get hashed prefix 'z' of tbs message */
	if (!sm2_compute_z_digest(z, md, smctx->id, smctx->id_len, ec))
		return 0;

	return EVP_DigestUpdate(mctx, z, (size_t)mdlen);
}

static int sm2_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{
	struct sm2_ctx *dctx, *sctx;

	if (!sm2_init(dst))
		return 0;
	sctx = EVP_PKEY_CTX_get_data(src);
	dctx = EVP_PKEY_CTX_get_data(dst);
	if (sctx->gen_group != NULL) {
		dctx->gen_group = EC_GROUP_dup(sctx->gen_group);
		if (dctx->gen_group == NULL) {
			printf("Failed to EC GROUP dup\n");
			sm2_cleanup(dst);
			return 0;
		}
	}

	if (sctx->id != NULL) {
		dctx->id = OPENSSL_malloc(sctx->id_len);
		if (dctx->id == NULL) {
			printf("Failed to malloc\n");
			sm2_cleanup(dst);
			return 0;
		}
		memcpy(dctx->id, sctx->id, sctx->id_len);
	}
	dctx->id_len = sctx->id_len;
	dctx->id_set = sctx->id_set;
	dctx->md = sctx->md;

	return 1;
}

int uadk_sm2_create_pmeth(struct uadk_pkey_meth *pkey_meth)
{
	EVP_PKEY_METHOD *meth;

	meth = EVP_PKEY_meth_new(EVP_PKEY_SM2, 0);
	if (meth == NULL)
		return 0;

	EVP_PKEY_meth_set_init(meth, sm2_init);
	EVP_PKEY_meth_set_copy(meth, sm2_copy);
	EVP_PKEY_meth_set_ctrl(meth, sm2_ctrl, sm2_ctrl_str);
	EVP_PKEY_meth_set_digest_custom(meth, sm2_digest_custom);
	EVP_PKEY_meth_set_cleanup(meth, sm2_cleanup);
	EVP_PKEY_meth_set_encrypt(meth, sm2_encrypt_init, sm2_encrypt);
	EVP_PKEY_meth_set_decrypt(meth, sm2_decrypt_init, sm2_decrypt);
	EVP_PKEY_meth_set_sign(meth, sm2_sign_init, sm2_sign);
	EVP_PKEY_meth_set_verify(meth, sm2_verify_init, sm2_verify);

	pkey_meth->sm2 = meth;
	return 1;
}

void uadk_sm2_delete_pmeth(struct uadk_pkey_meth *pkey_meth)
{
	if (!pkey_meth->sm2)
		return;

	EVP_PKEY_meth_free(pkey_meth->sm2);
	pkey_meth->sm2 = NULL;
}

int uadk_ec_create_pmeth(struct uadk_pkey_meth *pkey_meth)
{
	EVP_PKEY_METHOD *meth;

	meth = EVP_PKEY_meth_new(EVP_PKEY_EC, 0);
	if (meth == NULL)
		return 0;

	EVP_PKEY_meth_set_init(meth, sm2_init);
	EVP_PKEY_meth_set_copy(meth, sm2_copy);
	EVP_PKEY_meth_set_ctrl(meth, sm2_ctrl, sm2_ctrl_str);
	EVP_PKEY_meth_set_cleanup(meth, sm2_cleanup);
	EVP_PKEY_meth_set_keygen(meth, sm2_keygen_init, sm2_keygen);

	pkey_meth->ec = meth;
	return 1;
}

void uadk_ec_delete_pmeth(struct uadk_pkey_meth *pkey_meth)
{
	if (!pkey_meth->ec)
		return;

	EVP_PKEY_meth_free(pkey_meth->ec);
	pkey_meth->ec = NULL;
}
