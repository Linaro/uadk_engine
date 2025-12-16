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
#include <string.h>
#include <openssl/bn.h>
#include <openssl/engine.h>
#include <openssl/crypto.h>
#include <openssl/ossl_typ.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <uadk/wd_ecc.h>
#include <uadk/wd_sched.h>
#include "uadk_pkey.h"
#include "uadk.h"

#define X25519_KEYLEN		32
#define X448_KEYLEN		56
#define X25519_KEYBITS		256
#define X448_KEYBITS		448
#define ECX_MAX_KEYLEN		57
#define UADK_E_SUCCESS		1
#define UADK_E_FAIL		0

#if OPENSSL_VERSION_NUMBER >= 0x30000000
enum ECX_KEY_TYPE {
	ECX_KEY_TYPE_X25519,
	ECX_KEY_TYPE_X448,
	ECX_KEY_TYPE_ED25519,
	ECX_KEY_TYPE_ED448
};

struct ecx_key {
	OSSL_LIB_CTX *libctx;
	char *propq;
	unsigned int haspubkey:1;
	unsigned char pubkey[ECX_MAX_KEYLEN];
	unsigned char *privkey;
	size_t keylen;
	enum ECX_KEY_TYPE type;
	int references;
	CRYPTO_RWLOCK *lock;
};

struct evp_pkey_ctx_st {
	/* Actual operation */
	int operation;

	/*
	 * Library context, property query, keytype and keymgmt associated with
	 * this context
	 */
	OSSL_LIB_CTX *libctx;
	char *propquery;
	const char *keytype;
	/* If |pkey| below is set, this field is always a reference to its keymgmt */
	EVP_KEYMGMT *keymgmt;

	union {
		struct {
			void *genctx;
		} keymgmt;

		struct {
			EVP_KEYEXCH *exchange;
			/*
			 * Opaque ctx returned from a providers exchange algorithm
			 * implementation OSSL_FUNC_keyexch_newctx()
			 */
			void *algctx;
		} kex;

		struct {
			EVP_SIGNATURE *signature;
			/*
			 * Opaque ctx returned from a providers signature algorithm
			 * implementation OSSL_FUNC_signature_newctx()
			 */
			void *algctx;
		} sig;

		struct {
			EVP_ASYM_CIPHER *cipher;
			/*
			 * Opaque ctx returned from a providers asymmetric cipher algorithm
			 * implementation OSSL_FUNC_asym_cipher_newctx()
			 */
			void *algctx;
		} ciph;
		struct {
			EVP_KEM *kem;
			/*
			 * Opaque ctx returned from a providers KEM algorithm
			 * implementation OSSL_FUNC_kem_newctx()
			 */
			void *algctx;
		} encap;
	} op;

	/*
	 * Cached parameters. Inits of operations that depend on these should
	 * call evp_pkey_ctx_use_delayed_data() when the operation has been set
	 * up properly.
	 */
	struct {
		/* Distinguishing Identifier, ISO/IEC 15946-3, FIPS 196 */
		char *dist_id_name; /* The name used with EVP_PKEY_CTX_ctrl_str() */
		void *dist_id;      /* The distinguishing ID itself */
		size_t dist_id_len; /* The length of the distinguishing ID */

		/* Indicators of what has been set.  Keep them together! */
		unsigned int dist_id_set : 1;
	} cached_parameters;

	/* Application specific data, usually used by the callback */
	void *app_data;
	/* Keygen callback */
	EVP_PKEY_gen_cb *pkey_gencb;
	/* implementation specific keygen data */
	int *keygen_info;
	int keygen_info_count;

	/* Legacy fields below */

	/* EVP_PKEY identity */
	int legacy_keytype;
	/* Method associated with this operation */
	const EVP_PKEY_METHOD *pmeth;
	/* Engine that implements this method or NULL if builtin */
	ENGINE *engine;
	/* Key: may be NULL */
	EVP_PKEY *pkey;
	/* Peer key for key agreement, may be NULL */
	EVP_PKEY *peerkey;
	/* Algorithm specific data */
	void *data;
	/* Indicator if digest_custom needs to be called */
	unsigned int flag_call_digest_custom:1;
	/*
	 * Used to support taking custody of memory in the case of a provider being
	 * used with the deprecated EVP_PKEY_CTX_set_rsa_keygen_pubexp() API. This
	 * member should NOT be used for any other purpose and should be removed
	 * when said deprecated API is excised completely.
	 */
	BIGNUM *rsa_pubexp;
};
#else
struct ecx_key {
	unsigned char pubkey[ECX_MAX_KEYLEN];
	unsigned char *privkey;
};

struct evp_pkey_ctx_st {
	/* Method associated with this operation */
	const EVP_PKEY_METHOD *pmeth;
	/* Engine that implements this method or NULL if builtin */
	ENGINE *engine;
	/* Key: may be NULL */
	EVP_PKEY *pkey;
	/* Peer key for key agreement, may be NULL */
	EVP_PKEY *peerkey;
	/* Actual operation */
	int operation;
	/* Algorithm specific data */
	void *data;
	/* Application specific data */
	void *app_data;
	/* Keygen callback */
	EVP_PKEY_gen_cb *pkey_gencb;
	/* implementation specific keygen data */
	int *keygen_info;
	int keygen_info_count;
};
#endif

struct ecx_ctx {
	handle_t sess;
	__u32 key_size;
	int nid;
};

static int reverse_bytes(unsigned char *to_buf, __u32 size)
{
	unsigned char *tmp_buf;
	unsigned char tmp;

	if (!size) {
		fprintf(stderr, "invalid size, size = %u\n", size);
		return UADK_E_FAIL;
	}

	if (!to_buf) {
		fprintf(stderr, "to_buf is NULL\n");
		return UADK_E_FAIL;
	}

	tmp_buf = to_buf + size - 1;
	while (to_buf < tmp_buf) {
		tmp = *tmp_buf;
		*tmp_buf-- = *to_buf;
		*to_buf++ = tmp;
	}

	return UADK_E_SUCCESS;
}

static int x25519_init(EVP_PKEY_CTX *ctx)
{
	struct wd_ecc_sess_setup setup = {0};
	struct sched_params params = {0};
	struct ecx_ctx *x25519_ctx;
	int ret;

	ret = uadk_e_ecc_get_support_state(X25519_SUPPORT);
	if (!ret) {
		fprintf(stderr, "x25519 is not supported\n");
		return UADK_E_FAIL;
	}

	ret = uadk_init_ecc();
	if (ret != UADK_INIT_SUCCESS)
		return UADK_E_FAIL;

	x25519_ctx = calloc(1, sizeof(struct ecx_ctx));
	if (!x25519_ctx) {
		fprintf(stderr, "failed to alloc x25519 ctx\n");
		return UADK_E_FAIL;
	}

	setup.alg = "x25519";
	setup.key_bits = X25519_KEYBITS;
	params.numa_id = uadk_e_ecc_get_numa_id();
	setup.sched_param = &params;
	x25519_ctx->sess = wd_ecc_alloc_sess(&setup);
	if (!x25519_ctx->sess) {
		fprintf(stderr, "failed to alloc sess\n");
		free(x25519_ctx);
		return UADK_E_FAIL;
	}

	EVP_PKEY_CTX_set_data(ctx, x25519_ctx);

	return UADK_E_SUCCESS;
}

static int x448_init(EVP_PKEY_CTX *ctx)
{
	struct wd_ecc_sess_setup setup = {0};
	struct sched_params params = {0};
	struct ecx_ctx *x448_ctx;
	int ret;

	ret = uadk_e_ecc_get_support_state(X448_SUPPORT);
	if (!ret) {
		fprintf(stderr, "x448 is not supported\n");
		return UADK_E_FAIL;
	}

	ret = uadk_init_ecc();
	if (ret != UADK_INIT_SUCCESS)
		return UADK_E_FAIL;

	x448_ctx = calloc(1, sizeof(struct ecx_ctx));
	if (!x448_ctx) {
		fprintf(stderr, "failed to alloc x448 ctx\n");
	        return UADK_E_FAIL;
	}

	setup.alg = "x448";
	setup.key_bits = X448_KEYBITS;
	params.numa_id = uadk_e_ecc_get_numa_id();
	setup.sched_param = &params;
	x448_ctx->sess = wd_ecc_alloc_sess(&setup);
	if (!x448_ctx->sess) {
		fprintf(stderr, "failed to alloc sess\n");
		free(x448_ctx);
		return UADK_E_FAIL;
	}

	EVP_PKEY_CTX_set_data(ctx, x448_ctx);

	return UADK_E_SUCCESS;
}

static int ecx_get_nid(EVP_PKEY_CTX *ctx)
{
	const EVP_PKEY_METHOD *pmeth_from_ctx;
	int nid;

	pmeth_from_ctx = (const EVP_PKEY_METHOD *)(ctx->pmeth);

	EVP_PKEY_meth_get0_info(&nid, NULL, pmeth_from_ctx);
	if (nid != EVP_PKEY_X25519 && nid != EVP_PKEY_X448)
		return UADK_E_FAIL;

	return nid;
}

static int ecx_init(EVP_PKEY_CTX *ctx)
{
	int nid = ecx_get_nid(ctx);

	switch (nid) {
	case EVP_PKEY_X25519:
		return x25519_init(ctx);
	case EVP_PKEY_X448:
		return x448_init(ctx);
	default:
		fprintf(stderr, "failed to init ecx\n");
	}

	return UADK_E_FAIL;
}

static void ecx_uninit(EVP_PKEY_CTX *ctx)
{
	struct ecx_ctx *ecx_ctx = EVP_PKEY_CTX_get_data(ctx);

	if (!ecx_ctx)
		return;

	if (ecx_ctx->sess)
		wd_ecc_free_sess(ecx_ctx->sess);

	free(ecx_ctx);

	EVP_PKEY_CTX_set_data(ctx, NULL);
}

static int ecx_set_ctx(EVP_PKEY_CTX *ctx, struct ecx_ctx *ecx_ctx)
{
	int nid = ecx_get_nid(ctx);

	switch (nid) {
	case EVP_PKEY_X25519:
		ecx_ctx->nid = EVP_PKEY_X25519;
		ecx_ctx->key_size = X25519_KEYLEN;
		return UADK_E_SUCCESS;
	case EVP_PKEY_X448:
		ecx_ctx->nid = EVP_PKEY_X448;
		ecx_ctx->key_size = X448_KEYLEN;
		return UADK_E_SUCCESS;
	default:
		fprintf(stderr, "failed to set ecx ctx\n");
	}

	return UADK_E_FAIL;
}

static int ecx_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
	if (type == EVP_PKEY_CTRL_PEER_KEY)
		return UADK_E_SUCCESS;

	return UADK_E_INVALID;
}

static int ecx_genkey_check(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
	if (!ctx) {
		fprintf(stderr, "ctx is NULL\n");
		return UADK_E_FAIL;
	}

	if (!pkey) {
		fprintf(stderr, "pkey is NULL\n");
		return UADK_E_FAIL;
	}

	return UADK_E_SUCCESS;
}

static int ecx_keygen_init_iot(handle_t sess, struct wd_ecc_req *req)
{
	struct wd_ecc_out *ecx_out;

	ecx_out = wd_ecxdh_new_out(sess);
	if (!ecx_out) {
		fprintf(stderr, "failed to new sign out\n");
		return UADK_E_FAIL;
	}

	uadk_ecc_fill_req(req, WD_ECXDH_GEN_KEY, NULL, ecx_out);

	return UADK_E_SUCCESS;
}

static int ecx_create_privkey(struct ecx_key **ecx_key, __u32 key_size)
{
	unsigned char *privkey;
	int ret;

	*ecx_key = OPENSSL_zalloc(sizeof(struct ecx_key));
	if (!(*ecx_key)) {
		fprintf(stderr, "failed to alloc ecx_key\n");
		return UADK_E_FAIL;
	}

	privkey = OPENSSL_secure_malloc(key_size);
	if (!privkey) {
		fprintf(stderr, "failed to alloc private key\n");
		goto free_ecx_key;
	}

	ret = RAND_priv_bytes(privkey, key_size);
	if (ret <= 0) {
		fprintf(stderr, "failed to gen private key\n");
		goto free_pri;
	}

	(*ecx_key)->privkey = privkey;

	return UADK_E_SUCCESS;

free_pri:
	OPENSSL_secure_free(privkey);
free_ecx_key:
	OPENSSL_free(*ecx_key);

	return UADK_E_FAIL;
}

static int ecx_keygen_set_private_key(struct ecx_ctx *ecx_ctx,
				      struct ecx_key *ecx_key)
{
	handle_t sess = ecx_ctx->sess;
	struct wd_ecc_key *ecc_key;
	struct wd_dtb prikey;
	int ret;

	prikey.data = (char *)ecx_key->privkey;
	prikey.dsize = ecx_ctx->key_size;

	ecc_key = wd_ecc_get_key(sess);
	ret = wd_ecc_set_prikey(ecc_key, &prikey);
	if (ret) {
		fprintf(stderr, "failed to set ecc prikey, ret = %d\n", ret);
		return UADK_E_FAIL;
	}

	return UADK_E_SUCCESS;
}

static int ecx_keygen_set_pkey(EVP_PKEY *pkey, struct ecx_ctx *ecx_ctx,
			       struct wd_ecc_req *req, struct ecx_key *ecx_key)
{
	struct wd_ecc_point *pubkey = NULL;
	int ret;

	wd_ecxdh_get_out_params(req->dst, &pubkey);
	if (!pubkey) {
		fprintf(stderr, "failed to get pubkey\n");
		return UADK_E_FAIL;
	}

	if (pubkey->x.dsize >= ECX_MAX_KEYLEN) {
		fprintf(stderr, "invalid key size, pubkey->x.dsize = %u\n",
			pubkey->x.dsize);
		return UADK_E_FAIL;
	}

	memcpy(ecx_key->pubkey, (const unsigned char *)pubkey->x.data, pubkey->x.dsize);
	/* Trans public key from big-endian to little-endian */
	ret = reverse_bytes(ecx_key->pubkey, pubkey->x.dsize);
	if (!ret) {
		fprintf(stderr, "failed to trans public key\n");
		return UADK_E_FAIL;
	}
	/* Trans private key from big-endian to little-endian */
	ret = reverse_bytes(ecx_key->privkey, ecx_ctx->key_size);
	if (!ret) {
		fprintf(stderr, "failed to trans private key\n");
		return UADK_E_FAIL;
	}
	/*
	 * This is a pretreatment of X25519/X448 described in RFC 7748.
	 * In order to decode the random bytes as an integer scaler, there
	 * are some special data processing. And use little-endian mode for
	 * decoding.
	 */
	if (ecx_ctx->nid == EVP_PKEY_X25519) {
		/* Set the three LSB of the first byte to 0 */
		ecx_key->privkey[0] &= 0xF8;

		/* Set the MSB of the last byte to 0 */
		ecx_key->privkey[X25519_KEYLEN - 1] &= 0x7F;

		/* Set the second MSB of the last byte to 1 */
		ecx_key->privkey[X25519_KEYLEN - 1] |= 0x40;
	} else if (ecx_ctx->nid == EVP_PKEY_X448) {
		/* Set the two LSB of the first byte to 0 */
		ecx_key->privkey[0] &= 0xFC;

		/* Set the MSB of the last byte to 1 */
		ecx_key->privkey[X448_KEYLEN - 1] |= 0x80;
	}

	ret = EVP_PKEY_assign(pkey, ecx_ctx->nid, ecx_key);

	return ret;
}

static int openssl_do_derive(EVP_PKEY_CTX *ctx, unsigned char *key,
			     size_t *keylen)
{
	int (*sw_fn_ptr)(EVP_PKEY_CTX *, unsigned char *, size_t *) = NULL;
	const EVP_PKEY_METHOD *sw_ecx_method;
	int nid = ecx_get_nid(ctx);

	sw_ecx_method = EVP_PKEY_meth_find(nid);
	if (!sw_ecx_method) {
		fprintf(stderr, "failed to get software method\n");
		return UADK_E_FAIL;
	}

	EVP_PKEY_meth_get_derive((EVP_PKEY_METHOD *)sw_ecx_method, NULL,
				 &sw_fn_ptr);

	return (*sw_fn_ptr)(ctx, key, keylen);
}

static int openssl_do_ecx_genkey(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
	int (*sw_fn_ptr)(EVP_PKEY_CTX *, EVP_PKEY *) = NULL;
	const EVP_PKEY_METHOD *sw_ecx_method;
	int nid = ecx_get_nid(ctx);

	sw_ecx_method = EVP_PKEY_meth_find(nid);
	if (!sw_ecx_method) {
                fprintf(stderr, "failed to get software method\n");
                return UADK_E_FAIL;
	}

	EVP_PKEY_meth_get_keygen((EVP_PKEY_METHOD *)sw_ecx_method, NULL,
				 &sw_fn_ptr);

	return (*sw_fn_ptr)(ctx, pkey);
}

static int ecx_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
	struct ecx_key *ecx_key = NULL;
	struct wd_ecc_req req = {0};
	struct ecx_ctx *keygen_ctx;
	int ret;

	ret = ecx_genkey_check(ctx, pkey);
	if (!ret)
		goto do_soft;

	ret = ecx_init(ctx);
	if (!ret)
		goto do_soft;

	keygen_ctx = EVP_PKEY_CTX_get_data(ctx);
	if (!keygen_ctx)
		goto uninit_ctx;

	ret = ecx_set_ctx(ctx, keygen_ctx);
	if (!ret)
		goto uninit_ctx;

	ret = ecx_create_privkey(&ecx_key, keygen_ctx->key_size);
	if (!ret)
		goto uninit_ctx;

	ret = ecx_keygen_init_iot(keygen_ctx->sess, &req);
	if (!ret)
		goto free_key;

	ret = ecx_keygen_set_private_key(keygen_ctx, ecx_key);
	if (!ret)
		goto uninit_iot;

	ret = uadk_ecc_crypto(keygen_ctx->sess, &req, (void *)keygen_ctx->sess);
	if (!ret)
		goto uninit_iot;

	ret = ecx_keygen_set_pkey(pkey, keygen_ctx, &req, ecx_key);
	if (!ret)
		goto uninit_iot;

	wd_ecc_del_out(keygen_ctx->sess, req.dst);
	ecx_uninit(ctx);

	return ret;

uninit_iot:
	wd_ecc_del_out(keygen_ctx->sess, req.dst);
free_key:
	OPENSSL_secure_free(ecx_key->privkey);
	OPENSSL_free(ecx_key);
uninit_ctx:
	ecx_uninit(ctx);
do_soft:
	fprintf(stderr, "switch to execute openssl software calculation.\n");
	return openssl_do_ecx_genkey(ctx, pkey);
}

static int ecx_compkey_init_iot(struct ecx_ctx *ecx_ctx, struct wd_ecc_req *req,
				struct ecx_key *peer_ecx_key,
				struct ecx_key *ecx_key)
{
	__u32 key_size = ecx_ctx->key_size;
	char buf_y[ECX_MAX_KEYLEN] = {0};
	handle_t sess = ecx_ctx->sess;
	struct wd_ecc_point in_pubkey;
	struct wd_ecc_out *ecx_out;
	struct wd_ecc_in *ecx_in;
	int ret;

	/* Trans public key from little-endian to big-endian */
	ret = reverse_bytes(peer_ecx_key->pubkey, key_size);
	if(!ret) {
		fprintf(stderr, "failed to trans public key\n");
		return UADK_E_FAIL;
	}

	in_pubkey.x.data = (char *)peer_ecx_key->pubkey;
	in_pubkey.x.dsize = key_size;
	in_pubkey.y.data = buf_y;
	in_pubkey.y.dsize = 1;

	ecx_in = wd_ecxdh_new_in(sess, &in_pubkey);
	if (!ecx_in) {
		fprintf(stderr, "failed to new ecxdh in\n");
		return UADK_E_FAIL;
	}

	ecx_out = wd_ecxdh_new_out(sess);
	if (!ecx_out) {
		fprintf(stderr, "failed to new ecxdh out\n");
		ret = UADK_E_FAIL;
		goto del_in;
	}

	uadk_ecc_fill_req(req, WD_ECXDH_COMPUTE_KEY, ecx_in, ecx_out);

	/* Trans public key from big-endian to little-endian */
	ret = reverse_bytes(peer_ecx_key->pubkey, key_size);
	if (!ret) {
		fprintf(stderr, "failed to trans public key\n");
		goto del_out;
	}

	return ret;

del_out:
	wd_ecc_del_out(sess, ecx_out);
del_in:
	wd_ecc_del_in(sess, ecx_in);

	return ret;
}

static void ecx_compkey_uninit_iot(handle_t sess, struct wd_ecc_req *req)
{
	wd_ecc_del_out(sess, req->dst);
	wd_ecc_del_in(sess, req->src);
}

static int ecx_derive_set_private_key(struct ecx_ctx *ecx_ctx,
				      struct ecx_key *ecx_key)
{
	int key_size = ecx_ctx->key_size;
	handle_t sess = ecx_ctx->sess;
	struct wd_ecc_key *ecc_key;
	struct wd_dtb prikey;
	int ret;

	/* Trans private key from little-endian to big-endian */
	ret = reverse_bytes(ecx_key->privkey, key_size);
	if (!ret) {
		fprintf(stderr, "failed to trans private key\n");
		return UADK_E_FAIL;
	}

	prikey.data = (char *)ecx_key->privkey;
	prikey.dsize = ecx_ctx->key_size;
	ecc_key = wd_ecc_get_key(sess);
	ret = wd_ecc_set_prikey(ecc_key, &prikey);
	if (ret) {
		fprintf(stderr, "failed to set ecc prikey, ret = %d\n", ret);
		return UADK_E_FAIL;
	}

	/* Trans private key from big-endian to little-endian */
	ret = reverse_bytes(ecx_key->privkey, key_size);
	if (!ret) {
		fprintf(stderr, "failed to trans private key\n");
		return UADK_E_FAIL;
	}

	return UADK_E_SUCCESS;
}

static int ecx_get_key(EVP_PKEY_CTX *ctx, struct ecx_key **ecx_key,
		       struct ecx_key **peer_ecx_key)
{
	EVP_PKEY *pkey, *peer_key;

	pkey = EVP_PKEY_CTX_get0_pkey(ctx);
	if (!pkey)
		return UADK_E_FAIL;

	peer_key = EVP_PKEY_CTX_get0_peerkey(ctx);
	if (!peer_key)
		return UADK_E_FAIL;

	*peer_ecx_key = EVP_PKEY_get0(peer_key);
	if (!(*peer_ecx_key))
		return UADK_E_FAIL;

	*ecx_key = EVP_PKEY_get0(pkey);
	if (!(*ecx_key))
		return UADK_E_FAIL;

	return UADK_E_SUCCESS;
}

static void x25519_pad_out_key(unsigned char *dst_key, unsigned char *src_key,
			       size_t len)
{
	unsigned char x25519_pad_key[X25519_KEYLEN] = {0};

	if (len != X25519_KEYLEN) {
		memcpy(x25519_pad_key, src_key, len);
		memcpy(dst_key, x25519_pad_key, X25519_KEYLEN);
	} else {
		memcpy(dst_key, src_key, X25519_KEYLEN);
	}
}

static void x448_pad_out_key(unsigned char *dst_key, unsigned char *src_key,
			     size_t len)
{
	unsigned char x448_pad_key[X448_KEYLEN] = {0};

	if (len != X448_KEYLEN) {
		memcpy(x448_pad_key, src_key, len);
		memcpy(dst_key, x448_pad_key, X448_KEYLEN);
	} else {
		memcpy(dst_key, src_key, X448_KEYLEN);
	}
}

static void ecx_pad_out_key(unsigned char *dst_key, unsigned char *src_key,
			     size_t len, int nid)
{
	if (nid == EVP_PKEY_X25519) {
		x25519_pad_out_key(dst_key, src_key, len);
		return;
	}

	if (nid == EVP_PKEY_X448) {
		x448_pad_out_key(dst_key, src_key, len);
		return;
	}
}

/**
 * ecx_derive: generate shared key.
 * @ctx: the ecx key ctx, contain own private key,
 * public key and peer public key.
 * @key: the output shared key.
 * @keylen: the length of output shared key.
 */
static int ecx_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen)
{
	struct ecx_key *peer_ecx_key = NULL;
	struct wd_ecc_point *s_key = NULL;
	struct ecx_key *ecx_key = NULL;
	struct wd_ecc_req req = {0};
	struct ecx_ctx *derive_ctx;
	int ret;

	if (!ctx) {
		fprintf(stderr, "invalid: ctx is NULL\n");
		goto do_soft;
	}

	ret = ecx_init(ctx);
	if (!ret)
		goto do_soft;

	derive_ctx = EVP_PKEY_CTX_get_data(ctx);
	if (!derive_ctx)
		goto uninit_ctx;

	ret = ecx_set_ctx(ctx, derive_ctx);
	if (!ret)
		goto uninit_ctx;

	if (!key || !(*keylen)) {
		*keylen = (size_t)derive_ctx->key_size;
		return UADK_E_SUCCESS;
	}

	ret = ecx_get_key(ctx, &ecx_key, &peer_ecx_key);
	if (!ret)
		goto uninit_ctx;

	ret = ecx_compkey_init_iot(derive_ctx, &req, peer_ecx_key, ecx_key);
	if (!ret)
		goto uninit_ctx;

	ret = ecx_derive_set_private_key(derive_ctx, ecx_key);
	if (!ret)
		goto uninit_iot;

	ret = uadk_ecc_crypto(derive_ctx->sess, &req, (void *)derive_ctx);
	if (!ret)
		goto uninit_iot;

	wd_ecxdh_get_out_params(req.dst, &s_key);
	if (!s_key)
		goto uninit_iot;

	ret = reverse_bytes((unsigned char *)s_key->x.data, s_key->x.dsize);
	if (!ret)
		goto uninit_iot;

	ecx_pad_out_key(key, (unsigned char *)s_key->x.data, s_key->x.dsize, derive_ctx->nid);

	ecx_compkey_uninit_iot(derive_ctx->sess, &req);
	ecx_uninit(ctx);

	return ret;

uninit_iot:
	ecx_compkey_uninit_iot(derive_ctx->sess, &req);
uninit_ctx:
	ecx_uninit(ctx);
do_soft:
	fprintf(stderr, "switch to execute openssl software calculation.\n");
	return openssl_do_derive(ctx, key, keylen);
}

int uadk_x25519_create_pmeth(struct uadk_pkey_meth *pkey_meth)
{
	const EVP_PKEY_METHOD *openssl_meth;
	EVP_PKEY_METHOD *meth;

	if (pkey_meth->x25519)
		return UADK_E_SUCCESS;

	meth = EVP_PKEY_meth_new(EVP_PKEY_X25519, 0);
	if (!meth) {
		fprintf(stderr, "failed to EVP_PKEY_meth_new\n");
		return UADK_E_FAIL;
	}

	openssl_meth = get_openssl_pkey_meth(EVP_PKEY_X25519);
	if (!openssl_meth) {
		fprintf(stderr, "failed to get x25519 pkey methods\n");
		EVP_PKEY_meth_free(meth);
		return UADK_E_FAIL;
	}

	EVP_PKEY_meth_copy(meth, openssl_meth);

	if (!uadk_e_ecc_get_support_state(X25519_SUPPORT)) {
		pkey_meth->x25519 = meth;
		return UADK_E_SUCCESS;
	}

	EVP_PKEY_meth_set_ctrl(meth, ecx_ctrl, NULL);
	EVP_PKEY_meth_set_keygen(meth, NULL, ecx_keygen);
	EVP_PKEY_meth_set_derive(meth, NULL, ecx_derive);

	pkey_meth->x25519 = meth;

	return UADK_E_SUCCESS;
}

int uadk_x448_create_pmeth(struct uadk_pkey_meth *pkey_meth)
{
	const EVP_PKEY_METHOD *openssl_meth;
	EVP_PKEY_METHOD *meth;

	if (pkey_meth->x448)
		return UADK_E_SUCCESS;

	meth = EVP_PKEY_meth_new(EVP_PKEY_X448, 0);
	if (!meth) {
		fprintf(stderr, "failed to EVP_PKEY_meth_new\n");
		return UADK_E_FAIL;
	}

	openssl_meth = get_openssl_pkey_meth(EVP_PKEY_X448);
	if (!openssl_meth) {
		fprintf(stderr, "failed to get x448 pkey methods\n");
		EVP_PKEY_meth_free(meth);
		return UADK_E_FAIL;
	}

	EVP_PKEY_meth_copy(meth, openssl_meth);

	if (!uadk_e_ecc_get_support_state(X448_SUPPORT)) {
		pkey_meth->x448 = meth;
		return UADK_E_SUCCESS;
	}

	EVP_PKEY_meth_set_ctrl(meth, ecx_ctrl, NULL);
	EVP_PKEY_meth_set_keygen(meth, NULL, ecx_keygen);
	EVP_PKEY_meth_set_derive(meth, NULL, ecx_derive);

	pkey_meth->x448 = meth;

	return UADK_E_SUCCESS;
}
