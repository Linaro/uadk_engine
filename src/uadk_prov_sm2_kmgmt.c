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

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/engine.h>
#include <uadk/wd_ecc.h>
#include "uadk_prov.h"
#include "uadk_prov_pkey.h"
#include "uadk_utils.h"

#define SM2_KEY_BYTES		32

UADK_PKEY_KEYMGMT_DESCR(sm2, SM2);
static UADK_PKEY_KEYMGMT s_keymgmt;

static UADK_PKEY_KEYMGMT get_default_sm2_keymgmt(void)
{
	return s_keymgmt;
}

void set_default_sm2_keymgmt(void)
{
	UADK_PKEY_KEYMGMT *keymgmt;

	keymgmt = (UADK_PKEY_KEYMGMT *)EVP_KEYMGMT_fetch(NULL, "SM2", "provider=default");
	if (keymgmt) {
		s_keymgmt = *keymgmt;
		EVP_KEYMGMT_free((EVP_KEYMGMT *)keymgmt);
	} else {
		UADK_INFO("failed to EVP_KEYMGMT_fetch sm2 default provider\n");
	}
}

static const char *uadk_keymgmt_sm2_query_operation_name(int operation_id)
{
	if (!get_default_sm2_keymgmt().query_operation_name) {
		UADK_ERR("failed to get keymgmt query_operation_name function\n");
		return NULL;
	}

	return get_default_sm2_keymgmt().query_operation_name(operation_id);
}

/**
 * Create an uadk provider side sm2 key object.
 *
 * @param provctx The provider context.
 * @return Return created key object if success, return NULL if failed.
 */
static void *uadk_keymgmt_sm2_new(void *provctx)
{
	if (!get_default_sm2_keymgmt().new_fun) {
		UADK_ERR("failed to get keymgmt new function\n");
		return NULL;
	}

	return get_default_sm2_keymgmt().new_fun(provctx);
}

/**
 * Release an uadk provider side sm2 key object
 *
 * @param keydata Key object related data.
 */
static void uadk_keymgmt_sm2_free(void *keydata)
{
	if (!get_default_sm2_keymgmt().free) {
		UADK_ERR("failed to get keymgmt free function\n");
		return;
	}

	get_default_sm2_keymgmt().free(keydata);
}

static int uadk_keymgmt_sm2_get_params(void *key, OSSL_PARAM params[])
{
	if (!get_default_sm2_keymgmt().get_params) {
		UADK_ERR("failed to get keymgmt get_params function\n");
		return UADK_P_FAIL;
	}

	return get_default_sm2_keymgmt().get_params(key, params);
}

static const OSSL_PARAM *uadk_keymgmt_sm2_gettable_params(void *provctx)
{
	if (!get_default_sm2_keymgmt().gettable_params) {
		UADK_ERR("failed to get keymgmt gettable_params function\n");
		return NULL;
	}

	return get_default_sm2_keymgmt().gettable_params(provctx);
}

static int uadk_keymgmt_sm2_set_params(void *key, const OSSL_PARAM params[])
{
	if (!get_default_sm2_keymgmt().set_params) {
		UADK_ERR("failed to get keymgmt set_params function\n");
		return UADK_P_FAIL;
	}

	return get_default_sm2_keymgmt().set_params(key, params);
}

static int uadk_keymgmt_sm2_gen_set_template(void *genctx, void *templates)
{
	if (!get_default_sm2_keymgmt().gen_set_template) {
		UADK_ERR("failed to get keymgmt gen_set_template function\n");
		return UADK_P_FAIL;
	}

	return get_default_sm2_keymgmt().gen_set_template(genctx, templates);
}

static void uadk_keymgmt_sm2_gen_cleanup(void *genctx)
{
	if (!get_default_sm2_keymgmt().gen_cleanup) {
		UADK_ERR("failed to get keymgmt gen_cleanup function\n");
		return;
	}

	get_default_sm2_keymgmt().gen_cleanup(genctx);
}

static void *uadk_keymgmt_sm2_load(const void *reference, size_t reference_sz)
{
	if (!get_default_sm2_keymgmt().load) {
		UADK_ERR("failed to get keymgmt load function\n");
		return NULL;
	}

	return get_default_sm2_keymgmt().load(reference, reference_sz);
}

static int uadk_keymgmt_sm2_validate(const void *keydata, int selection, int checktype)
{
	if (!get_default_sm2_keymgmt().validate) {
		UADK_ERR("failed to get keymgmt validate function\n");
		return UADK_P_FAIL;
	}

	return get_default_sm2_keymgmt().validate(keydata, selection, checktype);
}

static int uadk_keymgmt_sm2_match(const void *keydata1, const void *keydata2, int selection)
{
	if (!get_default_sm2_keymgmt().match) {
		UADK_ERR("failed to get keymgmt validate function\n");
		return UADK_P_FAIL;
	}

	return get_default_sm2_keymgmt().match(keydata1, keydata2, selection);
}

/**
 * Check if a sm2 key object has specific options, such as public key,
 * private key, domain params etc.
 *
 * @param keydata The key object to check.
 * @param selection Check options, like public key, private key, domain params etc.
 * @return Return 1 if success, return 0 if failed.
 */
static int uadk_keymgmt_sm2_has(const void *keydata, int selection)
{
	if (!get_default_sm2_keymgmt().has) {
		UADK_ERR("failed to get keymgmt has function\n");
		return UADK_P_FAIL;
	}

	return get_default_sm2_keymgmt().has(keydata, selection);
}

/**
 * Import a sm2 key object with key related params.
 *
 * @param keydata The key object to import.
 * @param selection The key params to import.
 * @param params OSSL params.
 * @return Return 1 if success, return 0 if failed.
 */
static int uadk_keymgmt_sm2_import(void *keydata, int selection, const OSSL_PARAM params[])
{
	if (!get_default_sm2_keymgmt().import) {
		UADK_ERR("failed to get keymgmt import function\n");
		return UADK_P_FAIL;
	}

	return get_default_sm2_keymgmt().import(keydata, selection, params);
}

/**
 * Returns an array of argument types based on the type selected.
 *
 * @param selection Type of the selected key.
 * @return Return param type array.
 */
static const OSSL_PARAM *uadk_keymgmt_sm2_import_types(int selection)
{
	if (!get_default_sm2_keymgmt().import_types) {
		UADK_ERR("failed to get keymgmt import_types function\n");
		return NULL;
	}

	return get_default_sm2_keymgmt().import_types(selection);
}

static int uadk_keymgmt_sm2_export(void *keydata, int selection,
				   OSSL_CALLBACK *param_callback, void *cbarg)
{
	if (!get_default_sm2_keymgmt().export_fun) {
		UADK_ERR("failed to get keymgmt export function\n");
		return UADK_P_FAIL;
	}

	return get_default_sm2_keymgmt().export_fun(keydata, selection, param_callback, cbarg);
}

static const OSSL_PARAM *uadk_keymgmt_sm2_export_types(int selection)
{
	if (!get_default_sm2_keymgmt().export_types) {
		UADK_ERR("failed to get keymgmt export_types function\n");
		return NULL;
	}

	return get_default_sm2_keymgmt().export_types(selection);
}

static void *uadk_keymgmt_sm2_dup(const void *keydata_from, int selection)
{
	if (!get_default_sm2_keymgmt().dup) {
		UADK_ERR("failed to get keymgmt dup function\n");
		return NULL;
	}

	return get_default_sm2_keymgmt().dup(keydata_from, selection);
}

/**
 * Init sm2 key generation context.
 *
 * @param provctx The provider context.
 * @param selection The selected params related to the key.
 * @param params OSSL params.
 * @return Return inited key generation context if success, return NULL if failed.
 */
static void *uadk_keymgmt_sm2_gen_init(void *provctx, int selection,
				       const OSSL_PARAM params[])
{
	if (!get_default_sm2_keymgmt().gen_init) {
		UADK_ERR("failed to get keymgmt gen_init function\n");
		return NULL;
	}

	return get_default_sm2_keymgmt().gen_init(provctx, selection, params);
}

/**
 * Set sm2 key params
 *
 * @param genctx The pkey generation context.
 * @param params OSSL params array.
 * @return Return 1 if success, return 0 if failed.
 */
static int uadk_keymgmt_sm2_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
	if (!get_default_sm2_keymgmt().gen_set_params) {
		UADK_ERR("failed to get keymgmt gen_set_params function\n");
		return UADK_P_FAIL;
	}

	return get_default_sm2_keymgmt().gen_set_params(genctx, params);
}

static const OSSL_PARAM *uadk_keymgmt_sm2_settable_params(ossl_unused void *provctx)
{
	if (!get_default_sm2_keymgmt().settable_params) {
		UADK_ERR("failed to get keymgmt settable_params function\n");
		return NULL;
	}

	return get_default_sm2_keymgmt().settable_params(provctx);
}

/**
 * Get the settable params list.
 *
 * @param genctx key generation context.
 * @param provctx provider context.
 * @return Return params list if success, return NULL if failed.
 */
static const OSSL_PARAM *uadk_keymgmt_sm2_gen_settable_params(ossl_unused void *genctx,
							      ossl_unused void *provctx)
{
	if (!get_default_sm2_keymgmt().gen_settable_params) {
		UADK_ERR("failed to get keymgmt gen_settable_params function\n");
		return NULL;
	}

	return get_default_sm2_keymgmt().gen_settable_params(genctx, provctx);
}

static int uadk_prov_sm2_set_key_to_ec_key(EC_KEY *ec, struct wd_ecc_req *req)
{
	unsigned char key_buff[ECC_POINT_SIZE(SM2_KEY_BYTES) + 1] = {0};
	struct wd_ecc_point *pubkey = NULL;
	struct wd_dtb *privkey = NULL;
	int x_offset, y_offset, ret;
	const EC_GROUP *group;
	EC_POINT *point, *ptr;
	BIGNUM *bn_key;

	wd_sm2_get_kg_out_params(req->dst, &privkey, &pubkey);
	if (privkey == NULL || pubkey == NULL) {
		UADK_ERR("failed to get privkey or pubkey\n");
		return UADK_P_FAIL;
	}

	if (pubkey->x.dsize > SM2_KEY_BYTES || pubkey->y.dsize > SM2_KEY_BYTES) {
		UADK_ERR("invalid pubkey size: %u, %u\n", pubkey->x.dsize, pubkey->y.dsize);
		return UADK_P_FAIL;
	}

	bn_key = BN_bin2bn((unsigned char *)privkey->data, privkey->dsize, NULL);
	ret = EC_KEY_set_private_key(ec, bn_key);
	BN_free(bn_key);
	if (ret == 0) {
		UADK_ERR("failed to EC KEY set private key\n");
		return UADK_P_FAIL;
	}

	group = EC_KEY_get0_group(ec);
	point = EC_POINT_new(group);
	if (point == NULL) {
		UADK_ERR("failed to EC POINT new\n");
		return UADK_P_FAIL;
	}

	key_buff[0] = UADK_OCTET_STRING;
	/* The component of sm2 pubkey need a SM2_KEY_BYTES align */
	x_offset = 1 + SM2_KEY_BYTES - pubkey->x.dsize;
	y_offset = 1 + ECC_POINT_SIZE(SM2_KEY_BYTES) - pubkey->y.dsize;
	memcpy(key_buff + x_offset, pubkey->x.data, pubkey->x.dsize);
	memcpy(key_buff + y_offset, pubkey->y.data, pubkey->y.dsize);
	bn_key = BN_bin2bn(key_buff, ECC_POINT_SIZE(SM2_KEY_BYTES) + 1, NULL);
	ptr = EC_POINT_bn2point(group, bn_key, point, NULL);
	BN_free(bn_key);
	if (ptr == NULL) {
		UADK_ERR("failed to EC_POINT_bn2point\n");
		EC_POINT_free(point);
		return UADK_P_FAIL;
	}

	ret = EC_KEY_set_public_key(ec, point);
	EC_POINT_free(point);
	if (ret == 0) {
		UADK_ERR("failed to EC_KEY_set_public_key\n");
		return UADK_P_FAIL;
	}

	return UADK_P_SUCCESS;
}

static int uadk_prov_sm2_keygen_init_iot(handle_t sess, struct wd_ecc_req *req)
{
	struct wd_ecc_out *ecc_out = wd_sm2_new_kg_out(sess);

	if (ecc_out == NULL) {
		UADK_ERR("failed to new sign out\n");
		return UADK_P_FAIL;
	}

	uadk_prov_ecc_fill_req(req, WD_SM2_KG, NULL, ecc_out);

	return UADK_P_SUCCESS;
}

static int uadk_prov_sm2_check_priv_key(EC_KEY *eckey)
{
	BIGNUM *priv_key;
	int ret;

	priv_key = (BIGNUM *)EC_KEY_get0_private_key(eckey);
	if (priv_key)
		return UADK_P_SUCCESS;

	priv_key = BN_new();
	if (!priv_key) {
		UADK_ERR("failed to BN_new priv_key\n");
		return UADK_P_FAIL;
	}

	ret = EC_KEY_set_private_key(eckey, priv_key);
	if (ret == 0)
		UADK_ERR("failed to set private key\n");

	BN_free(priv_key);

	return ret;
}

static int uadk_prov_sm2_keygen(EC_KEY *eckey)
{
	struct wd_ecc_req req = {0};
	handle_t sess;
	int ret;

	ret = uadk_prov_sm2_check_priv_key(eckey);
	if (ret == UADK_P_FAIL)
		goto error;

	sess = uadk_prov_ecc_alloc_sess(eckey, "sm2");
	if (sess == (handle_t)0)
		goto error;

	ret = uadk_prov_sm2_keygen_init_iot(sess, &req);
	if (ret == UADK_P_FAIL)
		goto free_sess;

	ret = uadk_prov_ecc_crypto(sess, &req, (void *)sess);
	if (ret == UADK_P_FAIL)
		goto uninit_iot;

	ret = uadk_prov_sm2_set_key_to_ec_key(eckey, &req);
	if (ret == UADK_P_FAIL)
		goto uninit_iot;

	wd_ecc_del_out(sess, req.dst);
	wd_ecc_free_sess(sess);

	return UADK_P_SUCCESS;

uninit_iot:
	wd_ecc_del_out(sess, req.dst);
free_sess:
	wd_ecc_free_sess(sess);
error:
	return UADK_P_FAIL;
}

static void *uadk_keymgmt_sm2_gen_sw(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
	if (!uadk_get_sw_offload_state())
		return NULL;

	if (!get_default_sm2_keymgmt().gen) {
		UADK_ERR("failed to get keymgmt gen function\n");
		return NULL;
	}

	UADK_INFO("switch to software sm2 keygen.\n");
	return get_default_sm2_keymgmt().gen(genctx, osslcb, cbarg);
}

/**
 * @brief Generate SM2 key pair.
 *
 * @param genctx Key generation context.
 * @param osslcb Callback function.
 * @param cbarg The param of callback function.
 *
 * @return Return generated key pair if success, return NULL if failed.
 */
static void *uadk_keymgmt_sm2_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
	struct ec_gen_ctx *gctx = genctx;
	EC_KEY *ec;
	int ret;

	if (gctx == NULL) {
		UADK_ERR("invalid: the generation context is NULL\n");
		return NULL;
	}

	ec = EC_KEY_new_ex(gctx->libctx, NULL);
	if (ec == NULL) {
		UADK_ERR("failed to EC_KEY_new_ex\n");
		return NULL;
	}

	ret = uadk_prov_ecc_genctx_check(genctx, ec);
	if (ret == UADK_P_FAIL) {
		UADK_ERR("failed to check genctx\n");
		goto free_ec_key;
	}

	ret = uadk_prov_keymgmt_get_support_state(KEYMGMT_SM2);
	if (ret == UADK_P_FAIL) {
		UADK_ERR("failed to get hardware sm2 keygen support\n");
		goto do_soft;
	}

	/* SM2 hardware init */
	ret = uadk_prov_ecc_init("sm2");
	if (ret == UADK_P_FAIL) {
		UADK_ERR("failed to init sm2\n");
		goto do_soft;
	}

	/* Do sm2 keygen with hardware */
	if ((gctx->selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0) {
		UADK_ERR("invalid keymgmt keypair selection\n");
		goto free_ec_key;
	}

	ret = uadk_prov_sm2_keygen(ec);
	if (ret == UADK_P_FAIL) {
		UADK_ERR("failed to generate sm2 key\n");
		goto do_soft;
	}

	return ec;

do_soft:
	EC_KEY_free(ec);
	return uadk_keymgmt_sm2_gen_sw(genctx, osslcb, cbarg);
free_ec_key:
	/* Something went wrong, throw the key away */
	EC_KEY_free(ec);
	return NULL;
}
