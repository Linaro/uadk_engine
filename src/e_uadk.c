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

#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <openssl/engine.h>
#include <uadk/wd.h>
#include "uadk.h"
#include "uadk_async.h"
#ifdef KAE
#include "v1/uadk_v1.h"
#endif

/* Constants used when creating the ENGINE */
const char *engine_uadk_id = "uadk";
static const char *engine_uadk_name = "uadk hardware engine support";

static int uadk_cipher;
static int uadk_digest;
static int uadk_rsa;
static int uadk_dh;
static int uadk_ecc;

#ifdef KAE
static int uadk_cipher_nosva;
static int uadk_digest_nosva;
static int uadk_rsa_nosva;
static int uadk_pkey_nosva;
static int uadk_dh_nosva;
#endif

__attribute__((constructor))
static void uadk_constructor(void)
{
}

__attribute__((destructor))
static void uadk_destructor(void)
{
}

static int uadk_destroy(ENGINE *e)
{
#ifdef KAE
	if (uadk_cipher_nosva)
		sec_ciphers_free_ciphers();
	if (uadk_digest_nosva)
		sec_digests_free_methods();
	if (uadk_rsa_nosva)
		hpre_destroy();
	if (uadk_dh_nosva)
		hpre_dh_destroy();
#endif

	if (uadk_cipher)
		uadk_destroy_cipher();
	if (uadk_digest)
		uadk_destroy_digest();
	if (uadk_rsa)
		uadk_destroy_rsa();
	if (uadk_ecc)
		uadk_destroy_ecc();
	if (uadk_dh)
		uadk_destroy_dh();
	return 1;
}


static int uadk_init(ENGINE *e)
{
	return 1;
}

static int uadk_finish(ENGINE *e)
{
	return 1;
}

static void engine_init_child_at_fork_handler(void)
{
	async_module_init();
}

/*
 * This stuff is needed if this ENGINE is being
 * compiled into a self-contained shared-library.
 */
static int bind_fn(ENGINE *e, const char *id)
{
	struct uacce_dev *dev;

	if (!ENGINE_set_id(e, engine_uadk_id) ||
	    !ENGINE_set_destroy_function(e, uadk_destroy) ||
	    !ENGINE_set_init_function(e, uadk_init) ||
	    !ENGINE_set_finish_function(e, uadk_finish) ||
	    !ENGINE_set_name(e, engine_uadk_name)) {
		fprintf(stderr, "bind failed\n");
		return 0;
	}

#ifdef KAE
	dev = wd_get_accel_dev("cipher");
	if (dev) {
		if (!(dev->flags & UACCE_DEV_SVA)) {
			cipher_module_init();
			if (!ENGINE_set_ciphers(e, sec_engine_ciphers))
				fprintf(stderr, "uadk bind cipher failed\n");
			else
				uadk_cipher_nosva = 1;
		}
		free(dev);
	}

	dev = wd_get_accel_dev("digest");
	if (dev) {
		if (!(dev->flags & UACCE_DEV_SVA)) {
			digest_module_init();
			if (!ENGINE_set_digests(e, sec_engine_digests))
				fprintf(stderr, "uadk bind digest failed\n");
			else
				uadk_digest_nosva = 1;
		}
		free(dev);
	}

	dev = wd_get_accel_dev("rsa");
	if (dev) {
		if (!(dev->flags & UACCE_DEV_SVA)) {
			hpre_module_init();
			if (!ENGINE_set_RSA(e, hpre_get_rsa_methods()))
				fprintf(stderr, "uadk bind rsa failed\n");
			else
				uadk_rsa_nosva = 1;
		}
		free(dev);
	}

	dev = wd_get_accel_dev("dh");
	if (dev) {
		if (!(dev->flags & UACCE_DEV_SVA)) {
			hpre_module_dh_init();
			if (!ENGINE_set_DH(e, hpre_get_dh_methods()))
				fprintf(stderr, "uadk bind dh failed\n");
			else
				uadk_dh_nosva = 1;
		}
		free(dev);
	}

	dev = wd_get_accel_dev("sm2");
	if (dev) {
		if (!(dev->flags & UACCE_DEV_SVA)) {
			if (!ENGINE_set_pkey_meths(e, hpre_pkey_meths))
				fprintf(stderr, "uadk bind pkey failed\n");
			else
				uadk_pkey_nosva = 1;
		}
		free(dev);
	}

	if (uadk_cipher_nosva || uadk_digest_nosva || uadk_rsa_nosva ||
	   uadk_pkey_nosva || uadk_pkey_nosva) {
		async_module_init_v1();
		pthread_atfork(NULL, NULL, engine_init_child_at_fork_handler_v1);
		return 1;
	}
#endif

	async_module_init();
	pthread_atfork(NULL, NULL, engine_init_child_at_fork_handler);

	dev = wd_get_accel_dev("cipher");
	if (dev) {
		if (!uadk_bind_cipher(e))
			fprintf(stderr, "uadk bind cipher failed\n");
		else
			uadk_cipher = 1;
		free(dev);
	}

	if (!uadk_bind_digest(e))
		fprintf(stderr, "uadk bind digest failed\n");
	else
		uadk_digest = 1;

	dev = wd_get_accel_dev("rsa");
	if (dev) {
		if (!uadk_bind_rsa(e))
			fprintf(stderr, "uadk bind rsa failed\n");
		else
			uadk_rsa = 1;
		free(dev);
	}

	dev = wd_get_accel_dev("dh");
	if (dev) {
		if (!uadk_bind_dh(e))
			fprintf(stderr, "uadk bind dh failed\n");
		else
			uadk_dh = 1;
		free(dev);
	}

	if (!uadk_bind_ecc(e))
		fprintf(stderr, "uadk bind ecc failed\n");
	else
		uadk_ecc = 1;

	return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_fn)
