// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2024 Huawei Technologies Co.,Ltd. All rights reserved.
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

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#include <openssl/proverr.h>
#include <openssl/rand.h>
#include <openssl/trace.h>
#include <uadk/wd_ecc.h>
#include <uadk/wd_sched.h>
#include "uadk_async.h"
#include "uadk_prov.h"
#include "uadk_prov_pkey.h"

#define X448_KEYLEN		56
#define X448_KEYBITS		448
#define ECX_MAX_KEYLEN		57
#define X448_SECURITY_BITS	224

#define ECX_POSSIBLE_SELECTIONS (OSSL_KEYMGMT_SELECT_KEYPAIR)

#define UADK_CRYPTO_UP_REF(val, ret, lock) CRYPTO_atomic_add(val, 1, ret, lock)

static inline int UADK_CRYPTO_DOWN_REF(int *val, int *ret,
				  ossl_unused void *lock)
{
	*ret = __atomic_fetch_sub(val, 1, __ATOMIC_RELAXED) - 1;
	if (*ret == 0)
		__atomic_thread_fence(__ATOMIC_ACQUIRE);
	return 1;
}

UADK_PKEY_KEYMGMT_DESCR(x448, X448);
UADK_PKEY_KEYEXCH_DESCR(x448, X448);

typedef enum {
	ECX_KEY_TYPE_X25519 = 0x0,
	ECX_KEY_TYPE_X448 = 0x1,
} ECX_KEY_TYPE;

typedef struct {
	OSSL_LIB_CTX *libctx;
	char *propq;
	unsigned int haspubkey:1;
	unsigned char pubkey[ECX_MAX_KEYLEN];
	unsigned char *privkey;
	size_t keylen;
	ECX_KEY_TYPE type;
	int references;
	void *lock;
} ECX_KEY;

typedef struct {
	OSSL_LIB_CTX *libctx;
	char *propq;
	ECX_KEY_TYPE type;
	int selection;
	size_t keylen;
	/* uadk sesssion */
	handle_t sess;
} PROV_ECX_KEYMGMT_CTX;

typedef struct {
	size_t keylen;
	ECX_KEY *key;
	ECX_KEY *peerkey;
	OSSL_LIB_CTX *libctx;
	char *propq;
	/* uadk sesssion */
	handle_t sess;
} PROV_ECX_KEYEXCH_CTX;

struct x448_res {
	int pid;
} g_x448_prov;

static void *uadk_keymgmt_x448_new(void *provctx)
{
	if (get_default_x448_keymgmt().new_fun == NULL)
		return NULL;

	return get_default_x448_keymgmt().new_fun(provctx);
}

void uadk_keymgmt_x448_free(void *keydata)
{
	if (get_default_x448_keymgmt().free == NULL)
		return;

	get_default_x448_keymgmt().free(keydata);
}

static int uadk_keymgmt_x448_has(const void *keydata, int selection)
{
	if (get_default_x448_keymgmt().has == NULL)
		return UADK_P_FAIL;

	return get_default_x448_keymgmt().has(keydata, selection);
}

static int uadk_keymgmt_x448_match(const void *keydata1, const void *keydata2, int selection)
{
	if (get_default_x448_keymgmt().match == NULL)
		return UADK_P_FAIL;

	return get_default_x448_keymgmt().match(keydata1, keydata2, selection);
}

static int uadk_keymgmt_x448_import(void *keydata, int selection, const OSSL_PARAM params[])
{
	if (get_default_x448_keymgmt().import == NULL)
		return UADK_P_FAIL;

	return get_default_x448_keymgmt().import(keydata, selection, params);
}

static int uadk_keymgmt_x448_export(void *keydata, int selection,
				    OSSL_CALLBACK *cb, void *cb_params)
{
	if (get_default_x448_keymgmt().export_fun == NULL)
		return UADK_P_FAIL;

	return get_default_x448_keymgmt().export_fun(keydata, selection, cb, cb_params);
}

static const OSSL_PARAM *uadk_keymgmt_x448_import_types(int selection)
{
	if (get_default_x448_keymgmt().import_types == NULL)
		return NULL;

	return get_default_x448_keymgmt().import_types(selection);
}

static const OSSL_PARAM *uadk_keymgmt_x448_export_types(int selection)
{
	if (get_default_x448_keymgmt().export_types == NULL)
		return NULL;

	return get_default_x448_keymgmt().export_types(selection);
}

void *uadk_keymgmt_x448_load(const void *reference, size_t reference_sz)
{
	if (get_default_x448_keymgmt().load == NULL)
		return NULL;

	return get_default_x448_keymgmt().load(reference, reference_sz);
}

static void *uadk_keymgmt_x448_dup(const void *keydata_from, int selection)
{
	if (get_default_x448_keymgmt().dup == NULL)
		return NULL;

	return get_default_x448_keymgmt().dup(keydata_from, selection);
}

static int uadk_keymgmt_x448_validate(const void *keydata, int selection, int checktype)
{
	if (get_default_x448_keymgmt().validate == NULL)
		return UADK_P_FAIL;

	return get_default_x448_keymgmt().validate(keydata, selection, checktype);
}

static const OSSL_PARAM *uadk_keymgmt_x448_gettable_params(void *provctx)
{
	if (get_default_x448_keymgmt().gettable_params == NULL)
		return NULL;

	return get_default_x448_keymgmt().gettable_params(provctx);
}

static int uadk_keymgmt_x448_set_params(void *key, const OSSL_PARAM params[])
{
	if (get_default_x448_keymgmt().set_params == NULL)
		return UADK_P_FAIL;

	return get_default_x448_keymgmt().set_params(key, params);
}

static const OSSL_PARAM *uadk_keymgmt_x448_settable_params(void *provctx)
{
	if (get_default_x448_keymgmt().settable_params == NULL)
		return NULL;

	return get_default_x448_keymgmt().settable_params(provctx);
}

static int uadk_keymgmt_x448_gen_set_params(void *genctx,
					  const OSSL_PARAM params[])
{
	if (get_default_x448_keymgmt().gen_set_params == NULL)
		return UADK_P_FAIL;

	return get_default_x448_keymgmt().gen_set_params(genctx, params);
}

static const OSSL_PARAM *uadk_keymgmt_x448_gen_settable_params(ossl_unused void *genctx,
						ossl_unused void *provctx)
{
	if (get_default_x448_keymgmt().gen_settable_params == NULL)
		return NULL;

	return get_default_x448_keymgmt().gen_settable_params(genctx, provctx);
}

static int uadk_keymgmt_x448_gen_set_template(void *genctx, void *templ)
{
	if (get_default_x448_keymgmt().gen_set_template == NULL)
		return UADK_P_FAIL;

	return get_default_x448_keymgmt().gen_set_template(genctx, templ);
}

static const char *uadk_keymgmt_x448_query_operation_name(int operation_id)
{
	if (get_default_x448_keymgmt().query_operation_name == NULL)
		return NULL;

	return get_default_x448_keymgmt().query_operation_name(operation_id);
}

static int ossl_param_build_set_octet_string(OSSL_PARAM_BLD *bld, OSSL_PARAM *p, const char *key,
					     const unsigned char *data, size_t data_len)
{
	if (bld != NULL)
		return OSSL_PARAM_BLD_push_octet_string(bld, key, data, data_len);

	p = OSSL_PARAM_locate(p, key);
	if (p != NULL)
		return OSSL_PARAM_set_octet_string(p, data, data_len);

	return UADK_P_SUCCESS;
}

static int uadk_prov_key_to_params(ECX_KEY *key, OSSL_PARAM_BLD *tmpl,
				   OSSL_PARAM params[], int include_private)
{
	if (!ossl_param_build_set_octet_string(tmpl, params,
					       OSSL_PKEY_PARAM_PUB_KEY,
					       key->pubkey, key->keylen))
		return UADK_P_FAIL;

	if (include_private && key->privkey != NULL
	    && !ossl_param_build_set_octet_string(tmpl, params,
						  OSSL_PKEY_PARAM_PRIV_KEY,
						  key->privkey, key->keylen))
		return UADK_P_FAIL;

	return UADK_P_SUCCESS;
}

static int uadk_prov_ecx_get_params(void *key, OSSL_PARAM params[],
				    int bits, int secbits, int size)
{
	ECX_KEY *ecx = key;
	OSSL_PARAM *p;

	if (ecx == NULL)
		return UADK_P_FAIL;

	p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
	if (p && !OSSL_PARAM_set_int(p, bits))
		return UADK_P_FAIL;

	p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
	if (p && !OSSL_PARAM_set_int(p, secbits))
		return UADK_P_FAIL;

	p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
	if (p && !OSSL_PARAM_set_int(p, size))
		return UADK_P_FAIL;

	p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
	if (p && (ecx->type == ECX_KEY_TYPE_X25519 || ecx->type == ECX_KEY_TYPE_X448)) {
		if (!OSSL_PARAM_set_octet_string(p, ecx->pubkey, ecx->keylen))
			return UADK_P_FAIL;
	}

	return uadk_prov_key_to_params(ecx, NULL, params, 1);
}

static int uadk_keymgmt_x448_get_params(void *key, OSSL_PARAM params[])
{
	return uadk_prov_ecx_get_params(key, params, X448_KEYBITS, X448_SECURITY_BITS,
					X448_KEYLEN);
}

static int ossl_ecx_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
	PROV_ECX_KEYMGMT_CTX *gctx = (PROV_ECX_KEYMGMT_CTX *)genctx;
	const char *groupname = NULL;
	const OSSL_PARAM *p;

	p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME);
	if (p != NULL) {
		/*
		 * We optionally allow setting a group name - but each algorithm only
		 * support one such name, so all we do is verify that it is the one we
		 * expected.
		 */
		switch (gctx->type) {
		case ECX_KEY_TYPE_X25519:
			groupname = "x25519";
			break;
		case ECX_KEY_TYPE_X448:
			groupname = "x448";
			break;
		default:
			/* We only support this for key exchange at the moment */
			break;
		}
		if (p->data_type != OSSL_PARAM_UTF8_STRING || groupname == NULL ||
		    OPENSSL_strcasecmp(p->data, groupname) != 0) {
			fprintf(stderr, "invalid ecx params\n");
			return UADK_P_FAIL;
		}
	}
	p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_PROPERTIES);
	if (p != NULL) {
		if (p->data_type != OSSL_PARAM_UTF8_STRING)
			return UADK_P_FAIL;

		OPENSSL_free(gctx->propq);
		gctx->propq = OPENSSL_strdup(p->data);
		if (gctx->propq == NULL)
			return UADK_P_FAIL;
	}

	return UADK_P_SUCCESS;
}

static handle_t uadk_prov_x448_alloc_sess(void)
{
	struct wd_ecc_sess_setup setup = {0};
	struct sched_params params = {0};

	setup.alg = "x448";
	setup.key_bits = X448_KEYBITS;
	params.numa_id = -1;
	setup.sched_param = &params;

	return wd_ecc_alloc_sess(&setup);
}

static void uadk_prov_x448_free_sess(handle_t sess)
{
	if (sess)
		wd_ecc_free_sess(sess);
}

static void *ossl_ecx_gen_init(void *provctx, int selection, const OSSL_PARAM params[],
				    ECX_KEY_TYPE type)
{
	OSSL_LIB_CTX *libctx = prov_libctx_of(provctx);
	PROV_ECX_KEYMGMT_CTX *gctx = NULL;
	int ret;

	gctx = OPENSSL_zalloc(sizeof(PROV_ECX_KEYMGMT_CTX));
	if (gctx == NULL) {
		fprintf(stderr, "failed to alloc ecx gctx\n");
		return NULL;
	}

	gctx->libctx = libctx;
	gctx->type = type;
	gctx->selection = selection;

	ret = ossl_ecx_gen_set_params(gctx, params);
	if (ret == UADK_P_FAIL) {
		fprintf(stderr, "failed to set ecx params\n");
		OPENSSL_free(gctx);
		gctx = NULL;
	}

	return gctx;
}

static void uadk_keymgmt_x448_gen_cleanup(void *genctx)
{
	/* genctx will be freed in cleanup function */
	if (get_default_x448_keymgmt().gen_cleanup == NULL)
		return;

	get_default_x448_keymgmt().gen_cleanup(genctx);
}

static void *uadk_keymgmt_x448_gen_init(void *provctx, int selection,
					const OSSL_PARAM params[])
{
	if (provctx == NULL) {
		fprintf(stderr, "invalid: provctx is NULL\n");
		return NULL;
	}

	return ossl_ecx_gen_init(provctx, selection, params, ECX_KEY_TYPE_X448);
}

static ECX_KEY *uadk_prov_ecx_key_new(OSSL_LIB_CTX *libctx, ECX_KEY_TYPE type, int haspubkey,
				      const char *propq)
{
	ECX_KEY *ecx_key = OPENSSL_zalloc(sizeof(ECX_KEY));

	if (ecx_key == NULL) {
		fprintf(stderr, "failed to alloc ecx key");
		return NULL;
	}

	ecx_key->libctx = libctx;
	ecx_key->haspubkey = haspubkey;

	switch (type) {
	case ECX_KEY_TYPE_X448:
		ecx_key->keylen = X448_KEYLEN;
		ecx_key->type = type;
		ecx_key->references = 1;
		break;
	default:
		fprintf(stderr, "invalid: unsupported ecx type\n");
		goto free_ecx_key;
	}

	if (propq) {
		ecx_key->propq = OPENSSL_strdup(propq);
		if (ecx_key->propq == NULL)
			goto free_ecx_key;
	}

	ecx_key->lock = CRYPTO_THREAD_lock_new();
	if (ecx_key->lock == NULL)
		goto err;

	return ecx_key;

err:
	if (propq)
		OPENSSL_free(ecx_key->propq);
free_ecx_key:
	OPENSSL_free(ecx_key);
	return NULL;
}

static void uadk_prov_ecx_key_free(ECX_KEY *ecx_key)
{
	int i = 0;

	if (ecx_key == NULL)
		return;

	UADK_CRYPTO_DOWN_REF(&ecx_key->references, &i, ecx_key->lock);
	if (i > 0)
		return;

	if (ecx_key->propq)
		OPENSSL_free(ecx_key->propq);

	if (ecx_key->privkey)
		OPENSSL_secure_free(ecx_key->privkey);

	if (ecx_key->lock)
		CRYPTO_THREAD_lock_free(ecx_key->lock);

	OPENSSL_free(ecx_key);
}

static ECX_KEY *uadk_prov_ecx_create_prikey(PROV_ECX_KEYMGMT_CTX *gctx)
{
	unsigned char *prikey = NULL;
	ECX_KEY *ecx_key = NULL;
	int ret;

	ecx_key = uadk_prov_ecx_key_new(gctx->libctx, gctx->type, 0, gctx->propq);
	if (ecx_key == NULL) {
		fprintf(stderr, "failed to new ecx_key\n");
		return UADK_P_FAIL;
	}
	gctx->keylen = X448_KEYLEN;

	/* If we're doing parameter generation then we just return a blank key */
	if ((gctx->selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
		return ecx_key;

	prikey = OPENSSL_secure_malloc(ecx_key->keylen);
	if (prikey == NULL) {
		fprintf(stderr, "failed to alloc prikey\n");
		goto free_ecx_key;
	}

	ret = RAND_priv_bytes(prikey, ecx_key->keylen);
	if (ret <= 0) {
		fprintf(stderr, "failed to set rand bytes to prikey\n");
		goto free_pri;
	}
	ecx_key->privkey = prikey;

	return ecx_key;

free_pri:
	OPENSSL_secure_free(prikey);
free_ecx_key:
	uadk_prov_ecx_key_free(ecx_key);

	return NULL;
}

static void uadk_prov_ecx_free_prikey(ECX_KEY *ecx_key)
{
	if (ecx_key == NULL)
		return;

	if (ecx_key->privkey) {
		OPENSSL_secure_free(ecx_key->privkey);
		ecx_key->privkey = NULL;
	}

	uadk_prov_ecx_key_free(ecx_key);
}

static int uadk_prov_ecx_keygen_init_iot(handle_t sess, struct wd_ecc_req *req)
{
	struct wd_ecc_out *ecx_out;

	ecx_out = wd_ecxdh_new_out(sess);
	if (ecx_out == NULL) {
		fprintf(stderr, "failed to new sign out\n");
		return UADK_P_FAIL;
	}

	uadk_prov_ecc_fill_req(req, WD_ECXDH_GEN_KEY, NULL, ecx_out);

	return UADK_P_SUCCESS;
}

static void uadk_prov_ecx_keygen_uninit_iot(handle_t sess, struct wd_ecc_req *req)
{
	wd_ecc_del_out(sess, req->dst);
}

static int uadk_prov_reverse_bytes(unsigned char *to_buf, __u32 size)
{
	unsigned char *tmp_buf = NULL;
	unsigned char tmp;

	if (size == 0) {
		fprintf(stderr, "invalid size, size = %u\n", size);
		return UADK_P_FAIL;
	}

	if (to_buf == NULL) {
		fprintf(stderr, "to_buf is NULL\n");
		return UADK_P_FAIL;
	}

	tmp_buf = to_buf + size - 1;
	while (to_buf < tmp_buf) {
		tmp = *tmp_buf;
		*tmp_buf-- = *to_buf;
		*to_buf++ = tmp;
	}

	return UADK_P_SUCCESS;
}

static int uadk_prov_reverse_bytes_ex(unsigned char *src_buf, unsigned char *dst_buf, __u32 size)
{
	__u32 i;

	if (size == 0) {
		fprintf(stderr, "invalid size, size = %u\n", size);
		return UADK_P_FAIL;
	}

	if (src_buf == NULL) {
		fprintf(stderr, "src_buf is NULL\n");
		return UADK_P_FAIL;
	}

	if (dst_buf == NULL) {
		fprintf(stderr, "dst_buf is NULL\n");
		return UADK_P_FAIL;
	}

	for (i = 0; i < size; i++)
		dst_buf[i] = src_buf[size - i - 1];

	return UADK_P_SUCCESS;
}

static int uadk_prov_ecx_set_pkey(PROV_ECX_KEYMGMT_CTX *gctx, struct wd_ecc_req *req,
				  ECX_KEY *ecx_key)
{
	struct wd_ecc_point *pubkey = NULL;
	int ret;

	wd_ecxdh_get_out_params(req->dst, &pubkey);
	if (pubkey == NULL) {
		fprintf(stderr, "failed to get pubkey\n");
		return UADK_P_FAIL;
	}

	if (pubkey->x.dsize >= ECX_MAX_KEYLEN) {
		fprintf(stderr, "invalid: pubkey->x.dsize = %u\n",
			pubkey->x.dsize);
		return UADK_P_FAIL;
	}

	/* Trans public key from big-endian to little-endian */
	ret = uadk_prov_reverse_bytes_ex((unsigned char *)pubkey->x.data,
					 ecx_key->pubkey, pubkey->x.dsize);
	if (ret == UADK_P_FAIL) {
		fprintf(stderr, "failed to transform pubkey\n");
		return ret;
	}
	/* Trans private key from big-endian to little-endian */
	ret = uadk_prov_reverse_bytes(ecx_key->privkey, gctx->keylen);
	if (ret == UADK_P_FAIL) {
		fprintf(stderr, "failed to transform prikey\n");
		return ret;
	}
	/*
	 * This is a pretreatment of X448 described in RFC 7748.
	 * In order to decode the random bytes as an integer scaler, there
	 * are some special data processing. And use little-endian mode for
	 * decoding.
	 */
	if (gctx->type == ECX_KEY_TYPE_X448) {
		/* Set the two LSB of the first byte to 0 */
		ecx_key->privkey[0] &= 0xFC;

		/* Set the MSB of the last byte to 1 */
		ecx_key->privkey[X448_KEYLEN - 1] |= 0x80;
	} else {
		fprintf(stderr, "invalid: unsupported ecx type\n");
		return UADK_P_FAIL;
	}

	return ret;
}

static int uadk_prov_ecx_keygen_set_prikey(PROV_ECX_KEYMGMT_CTX *gctx, ECX_KEY *ecx_key)
{
	struct wd_ecc_key *ecc_key = NULL;
	struct wd_dtb prikey = {0};
	handle_t sess = gctx->sess;
	int ret;

	prikey.data = (char *)ecx_key->privkey;
	prikey.dsize = ecx_key->keylen;

	ecc_key = wd_ecc_get_key(sess);
	ret = wd_ecc_set_prikey(ecc_key, &prikey);
	if (ret) {
		fprintf(stderr, "failed to set ecc prikey, ret = %d\n", ret);
		return UADK_P_FAIL;
	}

	return UADK_P_SUCCESS;
}

static void *uadk_prov_ecx_keygen(PROV_ECX_KEYMGMT_CTX *gctx)
{
	struct wd_ecc_req req = {0};
	ECX_KEY *ecx_key = NULL;
	int ret;

	ecx_key = uadk_prov_ecx_create_prikey(gctx);
	if (ecx_key == NULL)
		return NULL;

	ret = uadk_prov_ecx_keygen_init_iot(gctx->sess, &req);
	if (ret == UADK_P_FAIL)
		goto free_prikey;

	ret = uadk_prov_ecx_keygen_set_prikey(gctx, ecx_key);
	if (ret == UADK_P_FAIL)
		goto uninit_iot;

	ret = uadk_prov_ecc_crypto(gctx->sess, &req, (void *)gctx->sess);
	if (ret == UADK_P_FAIL)
		goto uninit_iot;

	ret = uadk_prov_ecx_set_pkey(gctx, &req, ecx_key);
	if (ret == UADK_P_FAIL)
		goto uninit_iot;

	ecx_key->haspubkey = 1;

	uadk_prov_ecx_keygen_uninit_iot(gctx->sess, &req);

	return ecx_key;

uninit_iot:
	uadk_prov_ecx_keygen_uninit_iot(gctx->sess, &req);
free_prikey:
	uadk_prov_ecx_free_prikey(ecx_key);

	return NULL;
}

static void *uadk_keymgmt_x448_gen(void *genctx, OSSL_CALLBACK *cb, void *cb_params)
{
	PROV_ECX_KEYMGMT_CTX *gctx = (PROV_ECX_KEYMGMT_CTX *)genctx;
	ECX_KEY *ecx_key = NULL;
	int ret;

	if (gctx == NULL) {
		fprintf(stderr, "invalid: ecx keygen ctx is NULL\n");
		return NULL;
	}

	if (gctx->type != ECX_KEY_TYPE_X448) {
		fprintf(stderr, "invalid: unsupported ecx type\n");
		return NULL;
	}

	ret = uadk_prov_keymgmt_get_support_state(KEYMGMT_X448);
	if (ret == UADK_P_FAIL) {
		fprintf(stderr, "failed to get hardware x448 keygen support\n");
		return NULL;
	}

	ret = uadk_prov_ecc_init("x448");
	if (ret != UADK_P_SUCCESS) {
		fprintf(stderr, "failed to init x448\n");
		return NULL;
	}

	gctx->sess = uadk_prov_x448_alloc_sess();
	if (gctx->sess == (handle_t)0) {
		fprintf(stderr, "failed to alloc x448 sess\n");
		return NULL;
	}

	ecx_key = uadk_prov_ecx_keygen(gctx);
	if (ecx_key == NULL)
		fprintf(stderr, "failed to generate x448 key\n");

	uadk_prov_x448_free_sess(gctx->sess);

	return ecx_key;
}

static UADK_PKEY_KEYEXCH get_default_x448_keyexch(void)
{
	static UADK_PKEY_KEYEXCH s_keyexch;
	static int initilazed;

	if (!initilazed) {
		UADK_PKEY_KEYEXCH *keyexch =
			(UADK_PKEY_KEYEXCH *)EVP_KEYEXCH_fetch(NULL, "X448", "provider=default");
		if (keyexch) {
			s_keyexch = *keyexch;
			EVP_KEYEXCH_free((EVP_KEYEXCH *)keyexch);
			initilazed = 1;
		} else {
			fprintf(stderr, "failed to EVP_KEYEXCH_fetch default X448 provider\n");
		}
	}
	return s_keyexch;
}

static void *uadk_keyexch_x448_newctx(void *provctx)
{
	PROV_ECX_KEYEXCH_CTX *ecxctx = NULL;

	ecxctx = OPENSSL_zalloc(sizeof(PROV_ECX_KEYEXCH_CTX));
	if (ecxctx == NULL) {
		ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
		return NULL;
	}

	ecxctx->keylen = X448_KEYLEN;

	return ecxctx;
}

static void uadk_keyexch_x448_freectx(void *vecxctx)
{
	PROV_ECX_KEYEXCH_CTX *ecxctx = (PROV_ECX_KEYEXCH_CTX *)vecxctx;

	if (ecxctx == NULL)
		return;

	OPENSSL_free(ecxctx);
	ecxctx = NULL;
}

static int uadk_keyexch_x448_set_ctx_params(void *ecxctx, const OSSL_PARAM params[])
{
	if (get_default_x448_keyexch().set_ctx_params == NULL)
		return UADK_P_FAIL;

	return get_default_x448_keyexch().set_ctx_params(ecxctx, params);
}

static const OSSL_PARAM *uadk_keyexch_x448_settable_ctx_params(ossl_unused void *ecxctx,
						ossl_unused void *provctx)
{
	if (get_default_x448_keyexch().settable_ctx_params == NULL)
		return NULL;

	return get_default_x448_keyexch().settable_ctx_params(ecxctx, provctx);
}

static const OSSL_PARAM *uadk_keyexch_x448_gettable_ctx_params(ossl_unused void *ecxctx,
						ossl_unused void *provctx)
{
	if (get_default_x448_keyexch().gettable_ctx_params == NULL)
		return NULL;

	return get_default_x448_keyexch().gettable_ctx_params(ecxctx, provctx);
}

static int uadk_keyexch_x448_get_ctx_params(void *ecxctx, OSSL_PARAM params[])
{
	if (get_default_x448_keyexch().get_ctx_params == NULL)
		return UADK_P_FAIL;

	return get_default_x448_keyexch().get_ctx_params(ecxctx, params);
}

static int uadk_keyexch_x448_init(void *vecxctx, void *vkey,
				  ossl_unused const OSSL_PARAM params[])
{
	PROV_ECX_KEYEXCH_CTX *ecxctx = (PROV_ECX_KEYEXCH_CTX *)vecxctx;
	ECX_KEY *key = vkey;

	if (ecxctx == NULL) {
		fprintf(stderr, "invalid: ecxctx is NULL\n");
		return UADK_P_FAIL;
	}

	if (key == NULL) {
		fprintf(stderr, "invalid: key is NULL\n");
		return UADK_P_FAIL;
	}

	if (key->keylen != ecxctx->keylen) {
		fprintf(stderr, "invalid: key->keylen(%zu) != ecxctx->keylen(%zu)\n",
			key->keylen, ecxctx->keylen);
		return UADK_P_FAIL;
	}

	uadk_prov_ecx_key_free(ecxctx->key);
	ecxctx->key = key;

	return UADK_P_SUCCESS;
}

static int ossl_ecx_key_up_ref(ECX_KEY *key)
{
	int i = 0;

	if (UADK_CRYPTO_UP_REF(&key->references, &i, key->lock) <= 0)
		return UADK_P_FAIL;

	return ((i > 1) ? UADK_P_SUCCESS : UADK_P_FAIL);
}

static int uadk_keyexch_x448_set_peer(void *vecxctx, void *vkey)
{
	PROV_ECX_KEYEXCH_CTX *ecxctx = (PROV_ECX_KEYEXCH_CTX *)vecxctx;
	ECX_KEY *key = vkey;

	if (ecxctx == NULL) {
		fprintf(stderr, "invalid: ecxctx is NULL\n");
		return UADK_P_FAIL;
	}

	if (key == NULL) {
		fprintf(stderr, "invalid: key is NULL\n");
		return UADK_P_FAIL;
	}

	if (key->keylen != ecxctx->keylen || !ossl_ecx_key_up_ref(key)) {
		fprintf(stderr, "invalid: key->keylen(%zu) != ecxctx->keylen(%zu)\n",
			key->keylen, ecxctx->keylen);
		return UADK_P_FAIL;
	}

	uadk_prov_ecx_key_free(ecxctx->peerkey);
	ecxctx->peerkey = key;

	return UADK_P_SUCCESS;
}

static int uadk_prov_ecx_compkey_init_iot(PROV_ECX_KEYEXCH_CTX *ecxctx, struct wd_ecc_req *req)
{
	char buffer_y[ECX_MAX_KEYLEN] = {0};
	handle_t sess = ecxctx->sess;
	struct wd_ecc_point in_pubkey;
	struct wd_ecc_out *ecx_out;
	struct wd_ecc_in *ecx_in;
	int ret;

	/* Trans public key from little-endian to big-endian */
	ret = uadk_prov_reverse_bytes(ecxctx->peerkey->pubkey, ecxctx->keylen);
	if (ret == UADK_P_FAIL) {
		fprintf(stderr, "failed to trans public key\n");
		return UADK_P_FAIL;
	}

	in_pubkey.x.data = (char *)ecxctx->peerkey->pubkey;
	in_pubkey.x.dsize = ecxctx->keylen;
	in_pubkey.y.data = buffer_y;
	in_pubkey.y.dsize = 1;

	ecx_in = wd_ecxdh_new_in(sess, &in_pubkey);
	if (ecx_in == NULL) {
		fprintf(stderr, "failed to new ecxdh in\n");
		return UADK_P_FAIL;
	}

	ecx_out = wd_ecxdh_new_out(sess);
	if (ecx_out == NULL) {
		fprintf(stderr, "failed to new ecxdh out\n");
		ret = UADK_P_FAIL;
		goto del_in;
	}

	uadk_prov_ecc_fill_req(req, WD_ECXDH_COMPUTE_KEY, ecx_in, ecx_out);

	/* Trans public key from big-endian to little-endian */
	ret = uadk_prov_reverse_bytes(ecxctx->peerkey->pubkey, ecxctx->keylen);
	if (ret == UADK_P_FAIL) {
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

static void uadk_prov_ecx_compkey_uninit_iot(PROV_ECX_KEYEXCH_CTX *ecxctx, struct wd_ecc_req *req)
{
	wd_ecc_del_in(ecxctx->sess, req->src);
	wd_ecc_del_out(ecxctx->sess, req->dst);
}

static int uadk_prov_ecx_derive_set_prikey(PROV_ECX_KEYEXCH_CTX *ecxctx)
{
	handle_t sess = ecxctx->sess;
	struct wd_ecc_key *ecc_key;
	struct wd_dtb prikey;
	int ret;

	/* Trans private key from little-endian to big-endian */
	ret = uadk_prov_reverse_bytes(ecxctx->key->privkey, ecxctx->keylen);
	if (!ret) {
		fprintf(stderr, "failed to trans private key\n");
		return UADK_P_FAIL;
	}

	prikey.data = (char *)ecxctx->key->privkey;
	prikey.dsize = ecxctx->keylen;
	ecc_key = wd_ecc_get_key(sess);
	ret = wd_ecc_set_prikey(ecc_key, &prikey);
	if (ret) {
		fprintf(stderr, "failed to set ecc prikey, ret = %d\n", ret);
		return UADK_P_FAIL;
	}

	/* Trans private key from big-endian to little-endian */
	ret = uadk_prov_reverse_bytes(ecxctx->key->privkey, ecxctx->keylen);
	if (ret == UADK_P_FAIL) {
		fprintf(stderr, "failed to trans private key\n");
		return UADK_P_FAIL;
	}

	return UADK_P_SUCCESS;
}

static void uadk_prov_x448_pad_out_key(unsigned char *dst_key, unsigned char *src_key,
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

static void uadk_prov_ecx_pad_out_key(unsigned char *dst_key, unsigned char *src_key,
				      size_t len, int type)
{
	if (type == ECX_KEY_TYPE_X448) {
		uadk_prov_x448_pad_out_key(dst_key, src_key, len);
		return;
	}
}

static int uadk_prov_ecx_derive(PROV_ECX_KEYEXCH_CTX *ecxctx, unsigned char *key, size_t *keylen)
{
	struct wd_ecc_point *s_key = NULL;
	ECX_KEY *peer_ecx_key = NULL;
	struct wd_ecc_req req = {0};
	ECX_KEY *ecx_key = NULL;
	int ret;

	if (ecxctx == NULL) {
		fprintf(stderr, "invalid: ctx is NULL\n");
		return UADK_P_FAIL;
	}

	peer_ecx_key = ecxctx->peerkey;
	ecx_key = ecxctx->key;
	if (peer_ecx_key == NULL || ecx_key == NULL) {
		fprintf(stderr, "invalid: peer_ecx_key or ecx_key is NULL\n");
		return UADK_P_FAIL;
	}

	if (key == NULL || *keylen == 0) {
		*keylen = (size_t)ecxctx->keylen;
		return UADK_P_SUCCESS;
	}

	ret = uadk_prov_ecx_compkey_init_iot(ecxctx, &req);
	if (ret == UADK_P_FAIL)
		return UADK_P_FAIL;

	ret = uadk_prov_ecx_derive_set_prikey(ecxctx);
	if (ret == UADK_P_FAIL)
		goto uninit_iot;

	ret = uadk_prov_ecc_crypto(ecxctx->sess, &req, (void *)ecxctx);
	if (ret == UADK_P_FAIL)
		goto uninit_iot;

	wd_ecxdh_get_out_params(req.dst, &s_key);
	if (!s_key)
		goto uninit_iot;

	ret = uadk_prov_reverse_bytes((unsigned char *)s_key->x.data, s_key->x.dsize);
	if (ret == UADK_P_FAIL)
		goto uninit_iot;

	uadk_prov_ecx_pad_out_key(key, (unsigned char *)s_key->x.data,
				  s_key->x.dsize, ecx_key->type);

uninit_iot:
	uadk_prov_ecx_compkey_uninit_iot(ecxctx, &req);

	return ret;
}

static int uadk_keyexch_x448_derive(void *vecxctx, unsigned char *secret, size_t *secretlen,
				    size_t outlen)
{
	PROV_ECX_KEYEXCH_CTX *ecxctx = (PROV_ECX_KEYEXCH_CTX *)vecxctx;
	int ret;

	if (ecxctx == NULL) {
		fprintf(stderr, "invalid: ecxctx is NULL in derive op\n");
		return UADK_P_FAIL;
	}

	if (ecxctx->key == NULL || ecxctx->key->privkey == NULL ||
	    ecxctx->peerkey == NULL) {
		ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
		return UADK_P_FAIL;
	}

	if (ecxctx->keylen != X448_KEYLEN) {
		ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
		return UADK_P_FAIL;
	}

	if (secret == NULL) {
		*secretlen = ecxctx->keylen;
		return UADK_P_SUCCESS;
	}

	if (outlen < ecxctx->keylen) {
		ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
		return UADK_P_FAIL;
	}

	ret = uadk_prov_keyexch_get_support_state(KEYEXCH_X448);
	if (ret == UADK_P_FAIL) {
		fprintf(stderr, "failed to get hardware x448 keyexch support\n");
		return UADK_P_FAIL;
	}

	ret = uadk_prov_ecc_init("x448");
	if (ret != UADK_P_SUCCESS) {
		fprintf(stderr, "failed to init x448\n");
		return UADK_P_FAIL;
	}

	ecxctx->sess = uadk_prov_x448_alloc_sess();
	if (ecxctx->sess == (handle_t)0) {
		fprintf(stderr, "failed to alloc sess\n");
		return UADK_P_FAIL;
	}

	ret = uadk_prov_ecx_derive(ecxctx, secret, &ecxctx->keylen);
	if (ret == UADK_P_FAIL)
		fprintf(stderr, "failed to do x448 derive\n");

	*secretlen = ecxctx->keylen;

	uadk_prov_x448_free_sess(ecxctx->sess);

	return ret;
}

static void *uadk_keyexch_x448_dupctx(void *vecxctx)
{
	PROV_ECX_KEYEXCH_CTX *srcctx = (PROV_ECX_KEYEXCH_CTX *)vecxctx;
	PROV_ECX_KEYEXCH_CTX *dstctx;

	if (srcctx == NULL)
		return NULL;

	dstctx = OPENSSL_zalloc(sizeof(PROV_ECX_KEYEXCH_CTX));
	if (dstctx == NULL) {
		ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
		return NULL;
	}

	*dstctx = *srcctx;
	if (dstctx->key != NULL && !ossl_ecx_key_up_ref(dstctx->key)) {
		ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
		OPENSSL_free(dstctx);
		return NULL;
	}

	if (dstctx->peerkey != NULL && !ossl_ecx_key_up_ref(dstctx->peerkey)) {
		ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
		uadk_prov_ecx_key_free(dstctx->key);
		OPENSSL_free(dstctx);
		return NULL;
	}

	return dstctx;
}
