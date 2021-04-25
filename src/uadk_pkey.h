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
#ifndef UADK_PKEY_H
#define UADK_PKEY_H
#include <openssl/evp.h>

#define UADK_PKEY_DEBUG(fmt, args...)	printf(fmt, ##args)

struct uadk_pkey_meth {
	EVP_PKEY_METHOD *sm2;
	EVP_PKEY_METHOD *ec;
};

extern int uadk_sm2_create_pmeth(struct uadk_pkey_meth *pkey_meth);
extern void uadk_sm2_delete_pmeth(struct uadk_pkey_meth *pkey_meth);
extern int uadk_ec_create_pmeth(struct uadk_pkey_meth *pkey_meth);
extern void uadk_ec_delete_pmeth(struct uadk_pkey_meth *pkey_meth);


#endif
