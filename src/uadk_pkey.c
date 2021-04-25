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
	struct uacce_dev_list *list;
	int is_setup_sm2 = 0;
	int is_setup_ec = 0;
	int ret;

	list = wd_get_accel_list("sm2");
	if (list) {
		wd_free_list_accels(list);
		if (!uadk_sm2_create_pmeth(&pkey_meth)) {
			printf("Failed to register sm2 pmeth");
			return 0;
		}
		is_setup_sm2 = 1;
	}

	list = wd_get_accel_list("ecdsa");
	if (list) {
		wd_free_list_accels(list);
		if (!uadk_ec_create_pmeth(&pkey_meth)) {
			printf("Failed to register ec pmeth");
			goto del_sm2_meth;
		}
		is_setup_ec = 1;
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
