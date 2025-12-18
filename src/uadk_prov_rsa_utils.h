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
#ifndef UADK_PROV_PROV_RSA_UTILS_H
#define UADK_PROV_PROV_RSA_UTILS_H
#include "uadk_prov_rsa.h"

/* True if PSS parameters are restricted */
#define rsa_pss_restricted(prsactx) (prsactx->min_saltlen != -1)

struct rsa_pss_params_30_st *ossl_rsa_get0_pss_params_30(RSA *r);
int ossl_rsa_pss_params_30_is_unrestricted(const struct rsa_pss_params_30_st *rsa_pss_params);
int ossl_rsa_pss_params_30_maskgenhashalg(const struct rsa_pss_params_30_st *rsa_pss_params);
int ossl_rsa_pss_params_30_saltlen(const struct rsa_pss_params_30_st *rsa_pss_params);
int ossl_rsa_pss_params_30_hashalg(const struct rsa_pss_params_30_st *rsa_pss_params);
const char *nid2name(int meth, const OSSL_ITEM *items, size_t items_n);
const char *ossl_rsa_oaeppss_nid2name(int md);
int ossl_digest_rsa_sign_get_md_nid(OSSL_LIB_CTX *ctx, const EVP_MD *md, int sha1_allowed);

#endif
