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

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <uadk/wd_ecc.h>
#include "uadk_async.h"
#include "uadk_prov.h"
#include "uadk_prov_pkey.h"
#include "uadk_utils.h"

#define UADK_PROV_ECC_PADDING		7
#define UADK_PROV_RAND_MAX_CNT		1000
#define UADK_EC_DEFAULT_FLAGS		0
#define UADK_EC_FLAGS_ERROR		(-1)

static const OSSL_ITEM check_group_type_nameid_map[] = {
	{0, OSSL_PKEY_EC_GROUP_CHECK_DEFAULT},
	{EC_FLAG_CHECK_NAMED_GROUP, OSSL_PKEY_EC_GROUP_CHECK_NAMED},
	{EC_FLAG_CHECK_NAMED_GROUP_NIST, OSSL_PKEY_EC_GROUP_CHECK_NAMED_NIST},
};

UADK_PKEY_KEYMGMT_DESCR(ec, EC);
static UADK_PKEY_KEYMGMT s_keymgmt;

static UADK_PKEY_KEYMGMT get_default_ec_keymgmt(void)
{
	return s_keymgmt;
}

void set_default_ec_keymgmt(void)
{
	UADK_PKEY_KEYMGMT *keymgmt;

	keymgmt = (UADK_PKEY_KEYMGMT *)EVP_KEYMGMT_fetch(NULL, "EC", "provider=default");
	if (keymgmt) {
		s_keymgmt = *keymgmt;
		EVP_KEYMGMT_free((EVP_KEYMGMT *)keymgmt);
	} else {
		UADK_INFO("failed to EVP_KEYMGMT_fetch EC default provider\n");
	}
}

static int ec_param_check(struct ec_gen_ctx *gctx, EC_KEY *ec)
{
	const EC_GROUP *group;
	int type, ret;

	ret = uadk_prov_ecc_genctx_check(gctx, ec);
	if (!ret) {
		UADK_ERR("failed to check genctx!\n");
		return ret;
	}

	group = EC_KEY_get0_group(ec);
	/* Field GF(2m) is not supported by uadk */
	type = EC_METHOD_get_field_type(EC_GROUP_method_of(group));
	if (type != NID_X9_62_prime_field) {
		UADK_ERR("invalid: uadk unsupport Field GF(2m)!\n");
		return UADK_DO_SOFT;
	}

	ret = uadk_prov_ecc_bit_check(group);

	return ret;
}

static int ec_set_public_key(EC_KEY *ec, struct wd_ecc_out *ec_out)
{
	int key_size_std, key_size_x, key_size_y;
	struct wd_ecc_point *pubkey = NULL;
	int ret = UADK_P_FAIL;
	const EC_GROUP *group;
	int x_shift, y_shift;
	unsigned char *buff;
	EC_POINT *point;
	int buff_size;

	wd_ecxdh_get_out_params(ec_out, &pubkey);
	if (!pubkey) {
		UADK_ERR("failed to get pubkey!\n");
		return ret;
	}

	group = EC_KEY_get0_group(ec);
	point = EC_POINT_new(group);
	if (!point) {
		UADK_ERR("failed to new ec point!\n");
		return ret;
	}

	key_size_std = (unsigned int)(EC_GROUP_get_degree(group) +
			UADK_PROV_ECC_PADDING) >> TRANS_BITS_BYTES_SHIFT;
	key_size_x = pubkey->x.dsize;
	key_size_y = pubkey->y.dsize;
	if (key_size_x > key_size_std || key_size_y > key_size_std) {
		UADK_ERR("invalid: key size is error!\n");
		goto free_point;
	}

	/*
	 * The public key is composed as: tag + point_x + point_y
	 * tag - 1 byte
	 * point_x - [key_size_std] bytes
	 * point_y - [key_size_std] bytes
	 */
	buff_size = ECC_POINT_SIZE(key_size_std) + 1;
	x_shift = key_size_std - key_size_x + 1;
	y_shift = buff_size - key_size_y;
	buff = (unsigned char *)OPENSSL_zalloc(buff_size);
	if (!buff) {
		UADK_ERR("failed to alloc buf, buff_size = %d!\n",
			 buff_size);
		goto free_point;
	}

	buff[0] = UADK_OCTET_STRING;
	memcpy(buff + x_shift, pubkey->x.data, key_size_x);
	memcpy(buff + y_shift, pubkey->y.data, key_size_y);

	ret = EC_POINT_oct2point(group, point, buff, buff_size, NULL);
	if (!ret) {
		UADK_ERR("failed to do EC_POINT_oct2point!\n");
		goto free_buf;
	}

	ret = EC_KEY_set_public_key(ec, point);
	if (!ret)
		UADK_ERR("failed to do EC_KEY_set_public_key!\n");

free_buf:
	OPENSSL_free(buff);
free_point:
	EC_POINT_free(point);

	return ret;
}

static handle_t ec_alloc_sess(EC_KEY *ec, struct wd_ecc_out **ec_out)
{
	handle_t sess;
	int ret;

	ret = uadk_prov_keymgmt_get_support_state(KEYMGMT_ECDH);
	if (!ret) {
		UADK_ERR("failed to get hardware ecdh keygen support!\n");
		return ret;
	}

	ret = uadk_prov_ecc_init("ecdh");
	if (!ret) {
		UADK_ERR("failed to init ecdh!\n");
		return ret;
	}

	sess = uadk_prov_ecc_alloc_sess(ec, "ecdh");
	if (!sess) {
		UADK_ERR("failed to alloc ec sess!\n");
		return ret;
	}

	*ec_out = wd_ecxdh_new_out(sess);
	if (!(*ec_out)) {
		UADK_ERR("failed to new sign out\n");
		wd_ecc_free_sess(sess);
		return UADK_P_FAIL;
	}

	return sess;
}

static void ec_free_sess(handle_t sess, struct wd_ecc_out *ec_out)
{
	wd_ecc_del_out(sess, ec_out);
	wd_ecc_free_sess(sess);
}

static int ec_set_private_key(EC_KEY *ec, BIGNUM *priv_key)
{
	BIGNUM *priv_k = priv_key;
	int ret = UADK_P_FAIL;
	const EC_GROUP *group;
	const BIGNUM *order;
	int cnt = 0;

	if (priv_k)
		goto set_key;

	priv_k = BN_new();
	if (!priv_k) {
		UADK_ERR("failed to BN_new priv_k!\n");
		return UADK_P_FAIL;
	}

	group = EC_KEY_get0_group(ec);
	order = EC_GROUP_get0_order(group);

	do {
		cnt++;
		if (cnt > UADK_PROV_RAND_MAX_CNT) {
			UADK_ERR("failed to get appropriate prikey, timeout\n");
			goto free_priv_k;
		}

		if (!BN_priv_rand_range(priv_k, order)) {
			UADK_ERR("failed to get rand data!\n");
			goto free_priv_k;
		}
	} while (BN_is_zero(priv_k) || BN_is_one(priv_k));

set_key:
	ret = EC_KEY_set_private_key(ec, priv_k);
	if (!ret)
		UADK_ERR("failed to set private key!\n");

free_priv_k:
	if (!priv_key)
		BN_clear_free(priv_k);
	return ret;
}

static int ec_update_private_key(EC_KEY *ec, handle_t sess, BIGNUM *priv_key)
{
	int ret;

	ret = ec_set_private_key(ec, priv_key);
	if (!ret)
		return ret;

	return uadk_prov_ecc_set_private_key(sess, ec);
}

static int ec_hw_keygen(EC_KEY *ec, BIGNUM *priv_key)
{
	struct wd_ecc_out *ec_out = NULL;
	struct wd_ecc_req req = {0};
	handle_t sess;
	int ret;

	sess = ec_alloc_sess(ec, &ec_out);
	if (!sess) {
		UADK_ERR("failed to alloc sess!\n");
		return UADK_DO_SOFT;
	}

	ret = ec_update_private_key(ec, sess, priv_key);
	if (!ret) {
		UADK_ERR("failed to update private key!\n");
		goto free_sess;
	}

	uadk_prov_ecc_fill_req(&req, WD_ECXDH_GEN_KEY, NULL, ec_out);
	ret = uadk_prov_ecc_crypto(sess, &req, (void *)sess);
	if (ret != UADK_P_SUCCESS) {
		UADK_ERR("failed to generate key!\n");
		ret = UADK_DO_SOFT;
		goto free_sess;
	}

	ret = ec_set_public_key(ec, ec_out);

free_sess:
	ec_free_sess(sess, ec_out);
	return ret;
}

static int ec_set_cofactor_mode(EC_KEY *ec, int mode)
{
	const EC_GROUP *group = EC_KEY_get0_group(ec);
	const BIGNUM *cofactor;
	/*
	 * mode can be only 0 for disable, or 1 for enable here.
	 *
	 * This is in contrast with the same parameter on an ECDH EVP_PKEY_CTX that
	 * also supports mode == -1 with the meaning of "reset to the default for
	 * the associated key".
	 */
	if (mode < COFACTOR_MODE_DISABLED || mode > COFACTOR_MODE_ENABLED)
		return UADK_P_FAIL;

	cofactor = EC_GROUP_get0_cofactor(group);
	if (!cofactor)
		return UADK_P_FAIL;

	/* ECDH cofactor mode has no effect if cofactor is 1 */
	if (BN_is_one(cofactor))
		return UADK_P_SUCCESS;

	if (mode == COFACTOR_MODE_ENABLED)
		EC_KEY_set_flags(ec, EC_FLAG_COFACTOR_ECDH);
	else
		EC_KEY_clear_flags(ec, EC_FLAG_COFACTOR_ECDH);

	return UADK_P_SUCCESS;
}

static int ec_check_group_type_name2id(const char *name)
{
	size_t size = OSSL_NELEM(check_group_type_nameid_map);
	size_t i;

	/* Return the default value if there is no name */
	if (!name)
		return UADK_EC_DEFAULT_FLAGS;

	for (i = 0; i < size; i++) {
		if (!OPENSSL_strcasecmp(name, check_group_type_nameid_map[i].ptr))
			return check_group_type_nameid_map[i].id;
	}

	return UADK_EC_FLAGS_ERROR;
}

static int ec_set_check_group_type(EC_KEY *ec, const char *name)
{
	int flags;

	flags = ec_check_group_type_name2id(name);
	if (flags == UADK_EC_FLAGS_ERROR)
		return UADK_P_FAIL;

	EC_KEY_clear_flags(ec, EC_FLAG_CHECK_NAMED_GROUP_MASK);
	EC_KEY_set_flags(ec, flags);

	return UADK_P_SUCCESS;
}

static void *uadk_ec_sw_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
	if (!enable_sw_offload || !get_default_ec_keymgmt().gen)
		return NULL;

	UADK_INFO("switch to openssl software calculation in ecx generation.\n");

	return get_default_ec_keymgmt().gen(genctx, osslcb, cbarg);
}

static void *uadk_keymgmt_ec_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
	struct ec_gen_ctx *gctx = genctx;
	EC_KEY *ec;
	int ret;

	if (!gctx) {
		UADK_ERR("invalid: gctx is NULL to ec gen!\n");
		return NULL;
	}

	ec = EC_KEY_new_ex(gctx->libctx, NULL);
	if (!ec) {
		UADK_ERR("failed to new ec key!\n");
		return NULL;
	}

	ret = ec_param_check(genctx, ec);
	if (ret != UADK_P_SUCCESS) {
		UADK_ERR("failed to check genctx!\n");
		goto free_ec_key;
	}

	/* Whether you want it or not, you get a keypair, not just one half */
	if ((gctx->selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
		ret = ec_hw_keygen(ec, gctx->priv_key);
		if (ret != UADK_P_SUCCESS) {
			UADK_ERR("failed to gen public key!\n");
			goto free_ec_key;
		}
	}

	if (gctx->ecdh_mode != COFACTOR_MODE_USE_KEY) {
		ret = ec_set_cofactor_mode(ec, gctx->ecdh_mode);
		if (!ret)
			goto free_ec_key;
	}

	if (gctx->group_check) {
		ret = ec_set_check_group_type(ec, gctx->group_check);
		if (!ret)
			goto free_ec_key;
	}

	return ec;

free_ec_key:
	EC_KEY_free(ec);

	if (ret == UADK_DO_SOFT)
		return uadk_ec_sw_gen(genctx, osslcb, cbarg);
	return NULL;
}

static void uadk_keymgmt_ec_gen_cleanup(void *genctx)
{
	struct ec_gen_ctx *gctx = genctx;

	if (!gctx)
		return;

	EC_GROUP_free(gctx->gen_group);
	BN_free(gctx->p);
	BN_free(gctx->a);
	BN_free(gctx->b);
	BN_free(gctx->order);
	BN_free(gctx->cofactor);
	BN_clear_free(gctx->priv_key);
	OPENSSL_free(gctx->group_name);
	OPENSSL_free(gctx->field_type);
	OPENSSL_free(gctx->pt_format);
	OPENSSL_free(gctx->encoding);
	OPENSSL_free(gctx->seed);
	OPENSSL_free(gctx->gen);
	OPENSSL_free(gctx);
}

static void *uadk_keymgmt_ec_gen_init(void *provctx, int selection,
				      const OSSL_PARAM params[])
{
	struct ec_gen_ctx *gctx;
	int ret;

	if (!provctx)
		return NULL;

	if (!(selection & OSSL_KEYMGMT_SELECT_ALL))
		return NULL;

	gctx = OPENSSL_zalloc(sizeof(*gctx));
	if (!gctx)
		return NULL;

	gctx->libctx = prov_libctx_of(provctx);
	gctx->selection = selection;

	ret = uadk_keymgmt_ec_gen_set_params(gctx, params);
	if (!ret) {
		OPENSSL_free(gctx);
		return NULL;
	}

	return gctx;
}

static int uadk_keymgmt_ec_gen_set_template(void *genctx, void *templ)
{
	struct ec_gen_ctx *gctx = genctx;
	const EC_GROUP *src_group;
	EC_GROUP *dst_group;
	EC_KEY *ec = templ;

	if (!gctx || !ec) {
		UADK_ERR("invalid: genctx or templ is NULL!\n");
		return UADK_P_FAIL;
	}

	src_group = EC_KEY_get0_group(ec);
	if (!src_group) {
		UADK_ERR("failed to get source group!\n");
		return UADK_P_FAIL;
	}

	dst_group = EC_GROUP_dup(src_group);
	if (!dst_group) {
		UADK_ERR("failed to copy group!\n");
		return UADK_P_FAIL;
	}

	EC_GROUP_free(gctx->gen_group);
	gctx->gen_group = dst_group;

	return UADK_P_SUCCESS;
}

static int ec_set_int_param(const char *key, int *val, const OSSL_PARAM params[])
{
	const OSSL_PARAM *p;

	p = OSSL_PARAM_locate_const(params, key);
	if (!p)
		return UADK_P_SUCCESS;

	return OSSL_PARAM_get_int(p, val);
}

static int ec_set_utf8_param(const char *key, char **val, const OSSL_PARAM params[])
{
	const OSSL_PARAM *p;

	p = OSSL_PARAM_locate_const(params, key);
	if (!p)
		return UADK_P_SUCCESS;

	if (p->data_type != OSSL_PARAM_UTF8_STRING)
		return UADK_P_FAIL;

	OPENSSL_free(*val);
	*val = OPENSSL_strdup(p->data);
	if (!(*val))
		return UADK_P_FAIL;

	return UADK_P_SUCCESS;
}

static int ec_set_bn_param(const char *key, BIGNUM **val, const OSSL_PARAM params[])
{
	const OSSL_PARAM *p;

	p = OSSL_PARAM_locate_const(params, key);
	if (!p)
		return UADK_P_SUCCESS;

	if (!(*val))
		*val = BN_new();

	if (!(*val))
		return UADK_P_FAIL;

	return OSSL_PARAM_get_BN(p, val);
}

static int ec_set_octet_param(const char *key, unsigned char **val,
			      size_t *val_len, const OSSL_PARAM params[])
{
	const OSSL_PARAM *p;

	p = OSSL_PARAM_locate_const(params, key);
	if (!p)
		return UADK_P_SUCCESS;

	if (p->data_type != OSSL_PARAM_OCTET_STRING)
		return UADK_P_FAIL;

	OPENSSL_free(*val);
	*val = OPENSSL_memdup(p->data, p->data_size);
	if (!(*val))
		return UADK_P_FAIL;

	*val_len = p->data_size;

	return UADK_P_SUCCESS;
}

static int uadk_keymgmt_ec_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
	struct ec_gen_ctx *gctx = genctx;
	int ret;

	if (!gctx) {
		UADK_ERR("invalid: gctx is NULL to set params!\n");
		return UADK_P_FAIL;
	}

	ret = ec_set_int_param(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, &gctx->ecdh_mode, params);
	if (!ret)
		return ret;

	ret = ec_set_utf8_param(OSSL_PKEY_PARAM_GROUP_NAME, &gctx->group_name, params);
	if (!ret)
		return ret;

	ret = ec_set_utf8_param(OSSL_PKEY_PARAM_EC_FIELD_TYPE, &gctx->field_type, params);
	if (!ret)
		return ret;

	ret = ec_set_utf8_param(OSSL_PKEY_PARAM_EC_ENCODING, &gctx->encoding, params);
	if (!ret)
		return ret;

	ret = ec_set_utf8_param(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT,
				&gctx->pt_format, params);
	if (!ret)
		return ret;

	ret = ec_set_utf8_param(OSSL_PKEY_PARAM_EC_GROUP_CHECK_TYPE,
				&gctx->group_check, params);
	if (!ret)
		return ret;

	ret = ec_set_bn_param(OSSL_PKEY_PARAM_EC_P, &gctx->p, params);
	if (!ret)
		return ret;

	ret = ec_set_bn_param(OSSL_PKEY_PARAM_EC_A, &gctx->a, params);
	if (!ret)
		return ret;

	ret = ec_set_bn_param(OSSL_PKEY_PARAM_EC_B, &gctx->b, params);
	if (!ret)
		return ret;

	ret = ec_set_bn_param(OSSL_PKEY_PARAM_EC_ORDER, &gctx->order, params);
	if (!ret)
		return ret;

	ret = ec_set_bn_param(OSSL_PKEY_PARAM_PRIV_KEY, &gctx->priv_key, params);
	if (!ret)
		return ret;

	ret = ec_set_bn_param(OSSL_PKEY_PARAM_EC_COFACTOR, &gctx->cofactor, params);
	if (!ret)
		return ret;

	ret = ec_set_octet_param(OSSL_PKEY_PARAM_EC_SEED, &gctx->seed,
				 &gctx->seed_len, params);
	if (!ret)
		return ret;

	return ec_set_octet_param(OSSL_PKEY_PARAM_EC_GENERATOR,
				  &gctx->gen, &gctx->gen_len, params);
}

static const OSSL_PARAM *uadk_keymgmt_ec_gen_settable_params(ossl_unused void *genctx,
							     ossl_unused void *provctx)
{
	static const OSSL_PARAM settable[] = {
		OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
		OSSL_PARAM_int(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, NULL),
		OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING, NULL, 0),
		OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT,
				       NULL, 0),
		OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_FIELD_TYPE, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_P, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_A, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_B, NULL, 0),
		OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_EC_GENERATOR, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_ORDER, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_EC_COFACTOR, NULL, 0),
		OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
		OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_EC_SEED, NULL, 0),
		OSSL_PARAM_END
	};

	return settable;
}

static void *uadk_keymgmt_ec_new(void *provctx)
{
	if (!get_default_ec_keymgmt().new_fun)
		return NULL;

	return get_default_ec_keymgmt().new_fun(provctx);
}

static void uadk_keymgmt_ec_free(void *keydata)
{
	if (!get_default_ec_keymgmt().free)
		return;

	return get_default_ec_keymgmt().free(keydata);
}

static int uadk_keymgmt_ec_get_params(void *key, OSSL_PARAM params[])
{
	if (!get_default_ec_keymgmt().get_params)
		return UADK_P_FAIL;

	return get_default_ec_keymgmt().get_params(key, params);
}

static const OSSL_PARAM *uadk_keymgmt_ec_gettable_params(void *provctx)
{
	if (!get_default_ec_keymgmt().gettable_params)
		return NULL;

	return get_default_ec_keymgmt().gettable_params(provctx);
}

static int uadk_keymgmt_ec_set_params(void *key, const OSSL_PARAM params[])
{
	if (!get_default_ec_keymgmt().set_params)
		return UADK_P_FAIL;

	return get_default_ec_keymgmt().set_params(key, params);
}

static const OSSL_PARAM *uadk_keymgmt_ec_settable_params(void *provctx)
{
	if (!get_default_ec_keymgmt().settable_params)
		return NULL;

	return get_default_ec_keymgmt().settable_params(provctx);
}

static void *uadk_keymgmt_ec_load(const void *reference, size_t reference_sz)
{
	if (!get_default_ec_keymgmt().load)
		return NULL;

	return get_default_ec_keymgmt().load(reference, reference_sz);
}

static int uadk_keymgmt_ec_has(const void *keydata, int selection)
{
	if (!get_default_ec_keymgmt().has)
		return UADK_P_FAIL;

	return get_default_ec_keymgmt().has(keydata, selection);
}

static int uadk_keymgmt_ec_validate(const void *keydata,
				    int selection, int checktype)
{
	if (!get_default_ec_keymgmt().validate)
		return UADK_P_FAIL;

	return get_default_ec_keymgmt().validate(keydata, selection, checktype);
}

static int uadk_keymgmt_ec_match(const void *keydata1,
				 const void *keydata2, int selection)
{
	if (!get_default_ec_keymgmt().match)
		return UADK_P_FAIL;

	return get_default_ec_keymgmt().match(keydata1, keydata2, selection);
}

static int uadk_keymgmt_ec_import(void *keydata, int selection,
				  const OSSL_PARAM params[])
{
	if (!get_default_ec_keymgmt().import)
		return UADK_P_FAIL;

	return get_default_ec_keymgmt().import(keydata, selection, params);
}

static const OSSL_PARAM *uadk_keymgmt_ec_import_types(int selection)
{
	if (!get_default_ec_keymgmt().import_types)
		return NULL;

	return get_default_ec_keymgmt().import_types(selection);
}

static int uadk_keymgmt_ec_export(void *keydata, int selection,
				  OSSL_CALLBACK *param_cb, void *cbarg)
{
	if (!get_default_ec_keymgmt().export_fun)
		return UADK_P_FAIL;

	return get_default_ec_keymgmt().export_fun(keydata, selection, param_cb, cbarg);
}

static const OSSL_PARAM *uadk_keymgmt_ec_export_types(int selection)
{
	if (!get_default_ec_keymgmt().export_types)
		return NULL;

	return get_default_ec_keymgmt().export_types(selection);
}

static void *uadk_keymgmt_ec_dup(const void *keydata_from, int selection)
{
	if (!get_default_ec_keymgmt().dup)
		return NULL;

	return get_default_ec_keymgmt().dup(keydata_from, selection);
}

static const char *uadk_keymgmt_ec_query_operation_name(int operation_id)
{
	if (!get_default_ec_keymgmt().query_operation_name)
		return NULL;

	return get_default_ec_keymgmt().query_operation_name(operation_id);
}
