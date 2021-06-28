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
#include <errno.h>
#include <openssl/bn.h>
#include <openssl/engine.h>
#include <openssl/crypto.h>
#include <openssl/ossl_typ.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <string.h>
#include "uadk_pkey.h"
#include <uadk/wd_ecc.h>

typedef ECDSA_SIG *(*PFUNC_SIGN_SIG)(const unsigned char *,
                                     int,
                                     const BIGNUM *,
                                     const BIGNUM *,
                                     EC_KEY *);

typedef int (*PFUNC_VERIFY_SIG)(const unsigned char *,
                                int,
                                const ECDSA_SIG *,
                                EC_KEY *eckey);

typedef int (*PFUNC_GEN_KEY)(EC_KEY *);

static EC_KEY_METHOD *uadk_ec_method = NULL;

static void init_dtb_param(void *dtb, char *start,
			   __u32 dsz, __u32 bsz, __u32 num)
{
	struct wd_dtb *tmp = dtb;
	int i = 0;

	while (i++ < num) {
		tmp->data = start;
		tmp->dsize = dsz;
		tmp->bsize = bsz;
		tmp += 1;
		start += bsz;
	}
}

static int set_sess_setup_cv(const EC_GROUP *group,
			     struct wd_ecc_curve_cfg *cv)
{
	struct wd_ecc_curve *pparam = cv->cfg.pparam;
	BIGNUM *p, *a, *b, *xg, *yg, *order;
	const EC_POINT *g;
	int ret = -1;
	BN_CTX *ctx;

	ctx = BN_CTX_new();
	if (!ctx)
		return -ENOMEM;

	BN_CTX_start(ctx);
	p = BN_CTX_get(ctx);
	a = BN_CTX_get(ctx);
	b = BN_CTX_get(ctx);
	xg = BN_CTX_get(ctx);
	yg = BN_CTX_get(ctx);

	ret = uadk_get_curve(group, p, a, b, ctx);
	if (ret)
		goto err;

	g = EC_GROUP_get0_generator(group);
	ret = uadk_get_affine_coordinates(group, g, xg, yg, ctx);
	if (ret)
		goto err;

	order = (BIGNUM *)EC_GROUP_get0_order(group);
	pparam->p.dsize = BN_bn2bin(p, (void *)pparam->p.data);
	pparam->a.dsize = BN_bn2bin(a, (void *)pparam->a.data);
	pparam->b.dsize = BN_bn2bin(b, (void *)pparam->b.data);
	pparam->g.x.dsize = BN_bn2bin(xg, (void *)pparam->g.x.data);
	pparam->g.y.dsize = BN_bn2bin(yg, (void *)pparam->g.y.data);
	pparam->n.dsize = BN_bn2bin(order, (void *)pparam->n.data);
	cv->type = WD_CV_CFG_PARAM;
	ret = 0;
err:
	if(ctx) {
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
	}

	return ret;
}

static handle_t ecc_alloc_sess(EC_KEY *eckey, const char *alg)
{
	char buff[UADK_ECC_MAX_KEY_BYTES * UADK_ECC_CV_PARAM_NUM];
	struct wd_ecc_sess_setup sp;
	struct wd_ecc_curve param;
	const EC_GROUP *group;
	const BIGNUM *order;
	handle_t sess;
	int ret;

	init_dtb_param(&param, buff, 0, UADK_ECC_MAX_KEY_BYTES,
		       UADK_ECC_CV_PARAM_NUM);

	memset(&sp, 0, sizeof(sp));
	sp.cv.cfg.pparam = &param;
	group = EC_KEY_get0_group(eckey);
	ret = set_sess_setup_cv(group, &sp.cv);
	if (ret)
		return (handle_t)0;

	order = EC_GROUP_get0_order(group);
	sp.alg = alg;
	sp.key_bits = BN_num_bits(order);
	sp.rand.cb = uadk_ecc_get_rand;
	sp.rand.usr = (void *)order;
	sess = wd_ecc_alloc_sess(&sp);
	if (!sess)
		printf("failed to alloc ecc sess\n");

	return sess;
}

static int eckey_check(EC_KEY *eckey)
{
	const EC_GROUP *group;
	const BIGNUM *order;
	const EC_POINT *g;

	if (!eckey) {
		printf("eckey is NULL\n");
		return -1;
	}

	group = EC_KEY_get0_group(eckey);
	if (!group) {
		printf("group is NULL\n");
		return -1;
	}

	order = EC_GROUP_get0_order(group);
	g = EC_GROUP_get0_generator(group);
	if (!order || !g) {
		printf("order or g is NULL\n");
		return -1;
	}

	if (!uadk_prime_field(group))
		return UADK_DO_SOFT;

	return 0;
}

static int ecdsa_do_sign_check(EC_KEY *eckey,
		const unsigned char *dgst, int dlen,
		const BIGNUM *k, const BIGNUM *r)
{
	const EC_POINT *pub_key;
	const BIGNUM *priv_key;
	int ret;

	if (!dgst) {
		printf("eckey or dgst NULL\n");
		return -1;
	}

	if (dlen <= 0) {
		printf("dlen error, dlen = %d", dlen);
		return -1;
	}

	if (k || r)
		return UADK_DO_SOFT;

	ret = eckey_check(eckey);
	if (ret)
		return ret;

	priv_key = EC_KEY_get0_private_key(eckey);
	pub_key = EC_KEY_get0_public_key(eckey);
	if (!priv_key || !pub_key) {
		printf("priv_key or pub_key is NULL\n");
		return -1;
	}

	return 0;
}

static int set_digest(handle_t sess, struct wd_dtb *e,
		      const unsigned char *dgst, int dlen)
{
	int key_bits;
	BIGNUM *m;

	key_bits = wd_ecc_get_key_bits(sess);
	if (dlen << UADK_BITS_2_BYTES_SHIFT > key_bits) {
		m = BN_new();

		/* Need to truncate digest if it is too long: first truncate whole bytes */
		dlen = (key_bits + 7) >> UADK_BITS_2_BYTES_SHIFT;
		if (!BN_bin2bn(dgst, dlen, m)) {
			printf("failed to BN_bin2bn digest\n");
			BN_free(m);
			return -1;
		}

		/* If still too long, truncate remaining bits with a shift */
		if (dlen << UADK_BITS_2_BYTES_SHIFT > key_bits &&
		    !BN_rshift(m, m, 8 - (key_bits & 0x7))) {
			printf("failed to truncate input digest\n");
			BN_free(m);
			return -1;
		}
		e->dsize = BN_bn2bin(m, (void *)e->data);
		BN_free(m);
	} else {
		e->data = (void *)dgst;
		e->dsize = dlen;
	}

	return 0;
}

static int ecdsa_sign_init_iot(handle_t sess, struct wd_ecc_req *req,
			       const unsigned char *dgst, int dlen)
{
	char buff[UADK_ECC_MAX_KEY_BYTES];
	struct wd_ecc_out *ecc_out;
	struct wd_ecc_in *ecc_in;
	struct wd_dtb e = { 0 };
	int ret;

	ecc_out = wd_ecdsa_new_sign_out(sess);
	if (!ecc_out) {
		printf("Failed to new sign out\n");
		return UADK_DO_SOFT;
	}

	e.data = buff;
	ret = set_digest(sess, &e, dgst, dlen);
	if (ret)
		goto err;

	ecc_in = wd_ecdsa_new_sign_in(sess, &e, NULL);
	if (!ecc_in) {
		printf("Failed to new ecdsa sign in\n");
		ret = UADK_DO_SOFT;
		goto err;
	}

	uadk_ecc_fill_req(req, WD_ECDSA_SIGN, ecc_in, ecc_out);
	return 0;
err:
	wd_ecc_del_out(sess, ecc_out);

	return ret;
}

static ECDSA_SIG *openssl_do_sign(const unsigned char *dgst, int dlen,
				  const BIGNUM *in_kinv, const BIGNUM *in_r,
				  EC_KEY *eckey)
{
	PFUNC_SIGN_SIG sign_sig_pfunc = NULL;
	EC_KEY_METHOD *openssl_meth;

	openssl_meth = (EC_KEY_METHOD *)EC_KEY_OpenSSL();
	EC_KEY_METHOD_get_sign(openssl_meth, NULL, NULL,
			       &sign_sig_pfunc);
	if (!sign_sig_pfunc) {
		printf("sign_sig_pfunc is NULL\n");
		return NULL;
	}

	return (*sign_sig_pfunc)(dgst, dlen, in_kinv, in_r, eckey);
}

static ECDSA_SIG *create_ecdsa_sig(struct wd_ecc_req *req,
				   int *do_soft)
{
	struct wd_dtb *r = NULL;
	struct wd_dtb *s = NULL;
	BIGNUM *br, *bs;
	ECDSA_SIG *sig;
	int ret;

	sig = ECDSA_SIG_new();
	if (!sig) {
		printf("failed to ECDSA_SIG_new\n");
		return NULL;
	}

	br = BN_new();
	bs = BN_new();
	if (!br || !bs) {
		printf("failed to BN_new r or s\n");
		goto err;
	}

	ret = ECDSA_SIG_set0(sig, br, bs);
	if (!ret) {
		printf("failed to ECDSA_SIG_set0\n");
		goto err;
	}

	wd_ecdsa_get_sign_out_params(req->dst, &r, &s);
	if (!BN_bin2bn((void *)r->data, r->dsize, br) ||
	    !BN_bin2bn((void *)s->data, s->dsize, bs)) {
		printf("failed to BN_bin2bn r or s\n");
		*do_soft = UADK_DO_SOFT;
		goto err;
	}

	return sig;
err:
	ECDSA_SIG_free(sig);
	BN_free(br);
	BN_free(bs);
	return NULL;
}

static ECDSA_SIG *ecdsa_do_sign(const unsigned char *dgst, int dlen,
				const BIGNUM *in_kinv, const BIGNUM *in_r,
				EC_KEY *eckey)
{
	struct wd_ecc_req req;
	ECDSA_SIG *sig = NULL;
	handle_t sess;
	int ret;

	ret = ecdsa_do_sign_check(eckey, dgst, dlen, in_kinv, in_r);
	if (ret)
		goto do_soft;

	ret = UADK_DO_SOFT;
	sess = ecc_alloc_sess(eckey, "ecdsa");
	if (!sess)
		goto do_soft;

	memset(&req, 0, sizeof(req));
	ret = ecdsa_sign_init_iot(sess, &req, (void *)dgst, dlen);
	if (ret)
		goto free_sess;

	ret =  uadk_ecc_set_private_key(sess, eckey);
	if (ret)
		goto free_sess;

	ret = uadk_init_ecc();
	if (ret) {
		ret = UADK_DO_SOFT;
		goto free_sess;
	}

	ret = uadk_ecc_crypto(sess, &req, (void *)sess);
	if (ret != 1) {
		ret = UADK_DO_SOFT;
		goto uninit_iot;
	}

	sig = create_ecdsa_sig(&req, &ret);
uninit_iot:
	wd_ecc_del_in(sess, req.src);
	wd_ecc_del_out(sess, req.dst);
free_sess:
	wd_ecc_free_sess(sess);
do_soft:
	if (!sig && ret == UADK_DO_SOFT)
		sig = openssl_do_sign(dgst, dlen, in_kinv,
				      in_r, eckey);

	return sig;
}

static int ecdsa_sign(int type, const unsigned char *dgst, int dlen,
		      unsigned char *sig, unsigned int *siglen,
		      const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey)
{
	ECDSA_SIG *s;

	if (!dgst || dlen <= 0) {
		printf("input param error, dlen = %d\n", dlen);
		goto err;
	}

	s = ecdsa_do_sign(dgst, dlen, kinv, r, eckey);
	if (!s) {
		printf("failed to ecdsa do sign\n");
		goto err;
	}

	*siglen = i2d_ECDSA_SIG(s, &sig);
	ECDSA_SIG_free(s);
	return 1;

err:
	if (siglen)
		*siglen = 0;

	return 0;
}

static int ecdsa_do_verify_check(EC_KEY *eckey,
				 const unsigned char *dgst, int dlen,
				 const ECDSA_SIG *sig)
{
	const BIGNUM *sig_r = NULL;
	const BIGNUM *sig_s = NULL;
	const EC_POINT *pub_key;
	const BIGNUM *priv_key;
	const EC_GROUP *group;
	const BIGNUM *order;
	int ret;

	if (!dgst) {
		printf("dgst is NULL\n");
		return -1;
	}

	if (dlen <= 0) {
		printf("digest len error, dlen = %d", dlen);
		return -1;
	}

	ret = eckey_check(eckey);
	if (ret)
		return ret;

	priv_key = EC_KEY_get0_private_key(eckey);
	pub_key = EC_KEY_get0_public_key(eckey);
	if (!priv_key || !pub_key) {
		printf("priv_key or pub_key is NULL\n");
		return -1;
	}

	ECDSA_SIG_get0((ECDSA_SIG *)sig, &sig_r, &sig_s);
	if (BN_num_bytes(sig_r) > UADK_ECC_MAX_KEY_BYTES ||
	    BN_num_bytes(sig_s) > UADK_ECC_MAX_KEY_BYTES) {
		printf("ECDSA_SIG len error: rlen = %d, slen = %d\n",
			BN_num_bytes(sig_r), BN_num_bytes(sig_s));
		return -1;
	}

	group = EC_KEY_get0_group(eckey);
	order = EC_GROUP_get0_order(group);
	if (BN_is_zero(sig_r) ||
	    BN_is_negative(sig_r) ||
	    BN_ucmp(sig_r, order) >= 0 ||
	    BN_is_zero(sig_s) ||
	    BN_is_negative(sig_s) ||
	    BN_ucmp(sig_s, order) >= 0) {
		printf("ECDSA_SIG is invalid\n");
		return -1;
	}

	return 0;
}

static int ecdsa_verify_init_iot(handle_t sess, struct wd_ecc_req *req,
				 const unsigned char *dgst, int dlen,
				 const ECDSA_SIG *sig)
{
	char buf_r[UADK_ECC_MAX_KEY_BYTES] = { 0 };
	char buf_s[UADK_ECC_MAX_KEY_BYTES] = { 0 };
	char buf_e[UADK_ECC_MAX_KEY_BYTES] = { 0 };
	const BIGNUM *sig_r = NULL;
	const BIGNUM *sig_s = NULL;
	struct wd_ecc_in *ecc_in;
	struct wd_dtb e = { 0 };
	struct wd_dtb r = { 0 };
	struct wd_dtb s = { 0 };
	int ret;

	e.data = buf_e;
	ret = set_digest(sess, &e, dgst, dlen);
	if (ret)
		return ret;

	r.data = buf_r;
	s.data = buf_s;
	ECDSA_SIG_get0(sig, &sig_r, &sig_s);
	r.dsize = BN_bn2bin(sig_r, (void *)r.data);
	s.dsize = BN_bn2bin(sig_s, (void *)s.data);
	ecc_in = wd_ecdsa_new_verf_in(sess, &e, &r, &s);
	if (!ecc_in) {
		printf("failed to new ecdsa verf in\n");
		return UADK_DO_SOFT;
	}

	uadk_ecc_fill_req(req, WD_ECDSA_VERIFY, ecc_in, NULL);

	return 0;
}

static int openssl_do_verify(const unsigned char *dgst, int dlen,
			     const ECDSA_SIG *sig, EC_KEY *eckey)
{

	PFUNC_VERIFY_SIG verify_sig_pfunc = NULL;
	EC_KEY_METHOD *openssl_meth;

	openssl_meth = (EC_KEY_METHOD *)EC_KEY_OpenSSL();
	EC_KEY_METHOD_get_verify(openssl_meth, NULL,
				 &verify_sig_pfunc);
	if (!verify_sig_pfunc) {
		printf("verify_sig_pfunc is NULL\n");
		return -1;
	}

	return (*verify_sig_pfunc)(dgst, dlen, sig, eckey);

}

static int ecdsa_do_verify(const unsigned char *dgst, int dlen,
			   const ECDSA_SIG *sig, EC_KEY *eckey)
{
	struct wd_ecc_req req;
	handle_t sess;
	int ret;

	ret = ecdsa_do_verify_check(eckey, dgst, dlen, sig);
	if (ret)
		goto do_soft;

	ret = UADK_DO_SOFT;
	sess = ecc_alloc_sess(eckey, "ecdsa");
	if (!sess)
		goto do_soft;

	memset(&req, 0, sizeof(req));
	ret = ecdsa_verify_init_iot(sess, &req, dgst, dlen, sig);
	if (ret) {
		goto free_sess;
	}

	ret =  uadk_ecc_set_public_key(sess, eckey);
	if (ret)
		goto free_sess;

	ret = uadk_init_ecc();
	if (ret) {
		ret = UADK_DO_SOFT;
		goto free_sess;
	}

	ret = uadk_ecc_crypto(sess, &req, (void *)sess);
	if (ret != 1){
		if (ret == WD_VERIFY_ERR) {
			ret = 0;
		} else {
			ret = UADK_DO_SOFT;
		}
		goto uninit_iot;
	}
uninit_iot:
	wd_ecc_del_in(sess, req.src);
free_sess:
	wd_ecc_free_sess(sess);
do_soft:
	if (ret == UADK_DO_SOFT)
		return openssl_do_verify(dgst, dlen, sig, eckey);

	return ret;
}

static int ecdsa_verify(int type, const unsigned char *dgst, int dlen,
			const unsigned char *sig, int siglen, EC_KEY *eckey)
{
	const unsigned char *p = sig;
	unsigned char *der = NULL;
	int ret = -1;
	ECDSA_SIG *s;
	int derlen;

	s = ECDSA_SIG_new();
	if (!s) {
		printf("failed to ECDSA_SIG_new\n");
		return ret;
	}

	if (!d2i_ECDSA_SIG(&s, &p, siglen)) {
		printf("failed to d2i_ECDSA_SIG: siglen = %d\n", siglen);
		goto err;
	}

	/* Ensure signature uses DER and doesn't have trailing garbage */
	derlen = i2d_ECDSA_SIG(s, &der);
	if (derlen != siglen || memcmp(sig, der, derlen) != 0) {
		printf("ECDSA_SIG s have trailing garbage\n");
		goto err;
	}

	ret = ecdsa_do_verify(dgst, dlen, s, eckey);
err:
	OPENSSL_free(der);
	ECDSA_SIG_free(s);
	return ret;
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
		printf("failed to EC KEY set private key\n");
		return -EINVAL;
	}

	group = EC_KEY_get0_group(ec);
	point = EC_POINT_new(group);
	if (!point) {
		printf("failed to EC POINT new\n");
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

static int openssl_do_generate(EC_KEY *eckey)
{
	PFUNC_GEN_KEY gen_key_pfunc = NULL;
	EC_KEY_METHOD *openssl_meth;

	openssl_meth = (EC_KEY_METHOD *)EC_KEY_OpenSSL();
	EC_KEY_METHOD_get_keygen(openssl_meth, &gen_key_pfunc);
	if (!gen_key_pfunc) {
		printf("gen_key_pfunc is NULL\n");
		return -1;
	}

	return (*gen_key_pfunc)(eckey);

}
static int sm2_genkey_check(EC_KEY *eckey)
{
	BIGNUM *priv_key;
	int ret;

	ret = eckey_check(eckey);
	if (ret)
		return ret;

	priv_key = (BIGNUM *)EC_KEY_get0_private_key(eckey);
	if (priv_key)
		return UADK_DO_SOFT;

	return 0;
}

static int sm2_keygen_init_iot(handle_t sess, struct wd_ecc_req *req)
{
	struct wd_ecc_out *ecc_out;

	ecc_out = wd_sm2_new_kg_out(sess);
	if (!ecc_out) {
		printf("failed to new sign out\n");
		return UADK_DO_SOFT;
	}

	uadk_ecc_fill_req(req, WD_SM2_KG, NULL, ecc_out);

	return 0;
}

static int eckey_create_key(EC_KEY *eckey)
{
	const EC_GROUP *group;
	EC_POINT *pub_key;
	BIGNUM *priv_key;

	group = EC_KEY_get0_group(eckey);
	pub_key = (EC_POINT *)EC_KEY_get0_public_key(eckey);
	if (!pub_key) {
		pub_key = EC_POINT_new(group);
		if (!pub_key) {
			printf("failed to new pub_key\n");
			return -1;
		}
		EC_KEY_set_public_key(eckey, pub_key);
	}

	priv_key = BN_new();
	if (!priv_key) {
		printf("failed to BN_new priv_key\n");
		return -1;
	}
	EC_KEY_set_private_key(eckey, priv_key);

	return 0;
}

static int sm2_generate_key(EC_KEY *eckey)
{
	struct wd_ecc_req req;
	handle_t sess;
	int ret;

	ret = sm2_genkey_check(eckey);
	if (ret)
		goto do_soft;

	ret = eckey_create_key(eckey);
	if (ret)
		return ret;

	sess = ecc_alloc_sess(eckey, "sm2");
	if (!sess)
		goto do_soft;

	memset(&req, 0, sizeof(req));
	ret = sm2_keygen_init_iot(sess, &req);
	if (ret)
		goto free_sess;

	ret = uadk_init_ecc();
	if (ret) {
		ret = UADK_DO_SOFT;
		goto uninit_iot;
	}

	ret = uadk_ecc_crypto(sess, &req, (void *)sess);
	if (ret != 1) {
		ret = UADK_DO_SOFT;
		goto uninit_iot;
	}

	ret = set_key_to_ec_key(eckey, &req);
	if (ret)
		goto uninit_iot;

	ret = 1;
uninit_iot:
	wd_ecc_del_out(sess, req.dst);
free_sess:
	wd_ecc_free_sess(sess);
do_soft:
	if (ret == UADK_DO_SOFT)
		return openssl_do_generate(eckey);

	return ret;
}

static int ecc_generate_key(EC_KEY *eckey)
{
	int cv_nid;

	cv_nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(eckey));
	if (cv_nid == NID_sm2)
		return sm2_generate_key(eckey);

	return openssl_do_generate(eckey);
}

static void ec_key_meth_set_ecdsa(EC_KEY_METHOD *meth)
{
	if (!uadk_support_algorithm("ecdsa"))
		return;

	EC_KEY_METHOD_set_sign(meth,
			       ecdsa_sign,
			       NULL,
			       ecdsa_do_sign);
	EC_KEY_METHOD_set_verify(meth,
				 ecdsa_verify,
				 ecdsa_do_verify);
}

static void ec_key_meth_set_ecdh(EC_KEY_METHOD *meth)
{
	if (!uadk_support_algorithm("ecdh") &&
	    !uadk_support_algorithm("sm2"))
		return;

	EC_KEY_METHOD_set_keygen(meth, ecc_generate_key);
}

static EC_KEY_METHOD *uadk_get_ec_methods(void)
{
	EC_KEY_METHOD *def_ec_method;

	if (uadk_ec_method != NULL)
		return uadk_ec_method;

	def_ec_method = (EC_KEY_METHOD *)EC_KEY_get_default_method();
	uadk_ec_method = EC_KEY_METHOD_new(def_ec_method);
	if (!uadk_ec_method) {
		printf("failed to EC_KEY_METHOD_new\n");
		return NULL;
	}

	ec_key_meth_set_ecdsa(uadk_ec_method);
	ec_key_meth_set_ecdh(uadk_ec_method);

	return uadk_ec_method;
}

void uadk_ec_delete_meth(void)
{
	if (!uadk_ec_method)
		return;

	EC_KEY_METHOD_free(uadk_ec_method);
	uadk_ec_method = NULL;
}

int uadk_ec_create_pmeth(struct uadk_pkey_meth *pkey_meth)
{
	const EVP_PKEY_METHOD *openssl_meth;
	EVP_PKEY_METHOD *meth;

	meth = EVP_PKEY_meth_new(EVP_PKEY_EC, 0);
	if (meth == NULL) {
		printf("failed to EVP_PKEY_meth_new\n");
		return 0;
	}

	openssl_meth = get_openssl_pkey_meth(EVP_PKEY_EC);
	EVP_PKEY_meth_copy(meth, openssl_meth);

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

int uadk_bind_ec(ENGINE *e)
{
	return ENGINE_set_EC(e, uadk_get_ec_methods());
}

