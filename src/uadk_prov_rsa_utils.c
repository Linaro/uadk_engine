// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2015-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include "uadk_prov_rsa_utils.h"

struct rsa_pss_params_30_st *ossl_rsa_get0_pss_params_30(RSA *r)
{
	return &r->pss_params;
}

struct rsa_pss_params_30_st  default_RSASSA_PSS_params = {
	NID_sha1, /* default hashAlgorithm */
	{
		NID_mgf1, /* default maskGenAlgorithm */
		NID_sha1 /* default MGF1 hash */
	},
	20, /* default saltLength */
	1 /* default trailerField (0xBC) */
};

int ossl_rsa_pss_params_30_is_unrestricted(const struct rsa_pss_params_30_st *rsa_pss_params)
{
	static struct rsa_pss_params_30_st pss_params_cmp = { 0, };

	return !rsa_pss_params ||
		memcmp(rsa_pss_params, &pss_params_cmp,
			sizeof(*rsa_pss_params)) == 0;
}

int ossl_rsa_pss_params_30_maskgenhashalg(const struct rsa_pss_params_30_st *rsa_pss_params)
{
	if (!rsa_pss_params)
		return default_RSASSA_PSS_params.hash_algorithm_nid;
	return rsa_pss_params->mask_gen.hash_algorithm_nid;
}

int ossl_rsa_pss_params_30_saltlen(const struct rsa_pss_params_30_st *rsa_pss_params)
{
	if (!rsa_pss_params)
		return default_RSASSA_PSS_params.salt_len;
	return rsa_pss_params->salt_len;
}

int ossl_rsa_pss_params_30_hashalg(const struct rsa_pss_params_30_st *rsa_pss_params)
{
	if (!rsa_pss_params)
		return default_RSASSA_PSS_params.hash_algorithm_nid;
	return rsa_pss_params->hash_algorithm_nid;
}
const char *nid2name(int meth, const OSSL_ITEM *items, size_t items_n)
{
	size_t i;

	for (i = 0; i < items_n; i++)
		if (meth == (int)items[i].id)
			return items[i].ptr;
	return NULL;
}

static const OSSL_ITEM oaeppss_name_nid_map[] = {
	{ NID_sha1,         OSSL_DIGEST_NAME_SHA1         },
	{ NID_sha224,       OSSL_DIGEST_NAME_SHA2_224     },
	{ NID_sha256,       OSSL_DIGEST_NAME_SHA2_256     },
	{ NID_sha384,       OSSL_DIGEST_NAME_SHA2_384     },
	{ NID_sha512,       OSSL_DIGEST_NAME_SHA2_512     },
	{ NID_sha512_224,   OSSL_DIGEST_NAME_SHA2_512_224 },
	{ NID_sha512_256,   OSSL_DIGEST_NAME_SHA2_512_256 },
};

const char *ossl_rsa_oaeppss_nid2name(int md)
{
	return nid2name(md, oaeppss_name_nid_map, OSSL_NELEM(oaeppss_name_nid_map));
}

/*
 * Internal library code deals with NIDs, so we need to translate from a name.
 * We do so using EVP_MD_is_a(), and therefore need a name to NID map.
 */
static int ossl_digest_md_to_nid(const EVP_MD *md, const OSSL_ITEM *it, size_t it_len)
{
	size_t i;

	if (!md)
		return NID_undef;

	for (i = 0; i < it_len; i++)
		if (EVP_MD_is_a(md, it[i].ptr))
			return (int)it[i].id;
	return NID_undef;
}

/*
 * Retrieve one of the FIPS approved hash algorithms by nid.
 * See FIPS 180-4 "Secure Hash Standard" and FIPS 202 - SHA-3.
 */
static int ossl_digest_get_approved_nid(const EVP_MD *md)
{
	static const OSSL_ITEM name_to_nid[] = {
		{ NID_sha1,      OSSL_DIGEST_NAME_SHA1      },
		{ NID_sha224,    OSSL_DIGEST_NAME_SHA2_224  },
		{ NID_sha256,    OSSL_DIGEST_NAME_SHA2_256  },
		{ NID_sha384,    OSSL_DIGEST_NAME_SHA2_384  },
		{ NID_sha512,    OSSL_DIGEST_NAME_SHA2_512  },
		{ NID_sha512_224, OSSL_DIGEST_NAME_SHA2_512_224 },
		{ NID_sha512_256, OSSL_DIGEST_NAME_SHA2_512_256 },
		{ NID_sha3_224,  OSSL_DIGEST_NAME_SHA3_224  },
		{ NID_sha3_256,  OSSL_DIGEST_NAME_SHA3_256  },
		{ NID_sha3_384,  OSSL_DIGEST_NAME_SHA3_384  },
		{ NID_sha3_512,  OSSL_DIGEST_NAME_SHA3_512  },
	};

	return ossl_digest_md_to_nid(md, name_to_nid, OSSL_NELEM(name_to_nid));
}

int ossl_digest_rsa_sign_get_md_nid(OSSL_LIB_CTX *ctx, const EVP_MD *md,
				    int sha1_allowed)
{
	return ossl_digest_get_approved_nid(md);
}
