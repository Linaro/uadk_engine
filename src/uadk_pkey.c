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
#include "uadk_pkey.h"

static int pkey_nids[] = {
	EVP_PKEY_EC,
	EVP_PKEY_SM2,
	0
};

static struct uadk_pkey_meth pkey_meth;

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

int uadk_bind_pkey(ENGINE *e)
{
	struct uacce_dev *dev;
	int is_setup_sm2 = 0;
	int is_setup_ec = 0;
	int ret;

	dev = wd_get_accel_dev("sm2");
	if (dev) {
		if (!uadk_sm2_create_pmeth(&pkey_meth)) {
			printf("Failed to register sm2 pmeth");
			return 0;
		}
		is_setup_sm2 = 1;
		free(dev);
	}

	dev = wd_get_accel_dev("ecdsa");
	if (dev) {
		if (!uadk_ec_create_pmeth(&pkey_meth)) {
			printf("Failed to register ec pmeth");
			goto del_sm2_meth;
		}
		is_setup_ec = 1;
		free(dev);
	}

	ret = ENGINE_set_pkey_meths(e, get_pkey_meths);
	if (!ret) {
		printf("Failed to engine set pkey meths, ret = %d\n", ret);
		goto del_ec_meth;
	}

	UADK_PKEY_DEBUG("uadk bind pkey algorithm successfully\n");
	return 1;

del_ec_meth:
	if (is_setup_ec)
		uadk_ec_delete_pmeth(&pkey_meth);
del_sm2_meth:
	if (is_setup_sm2)
		uadk_sm2_delete_pmeth(&pkey_meth);

	return ret;
}
