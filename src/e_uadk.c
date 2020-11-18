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

/* Constants used when creating the ENGINE */
const char *engine_uadk_id = "uadk";
static const char *engine_uadk_name = "uadk hardware engine support";

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
	uadk_destroy_cipher();
	uadk_destroy_digest();
	uadk_destroy_rsa();
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

/*
 * This stuff is needed if this ENGINE is being
 * compiled into a self-contained shared-library.
 */
static int bind_fn(ENGINE *e, const char *id)
{
	struct uacce_dev_list *list;

	if (id && (strcmp(id, engine_uadk_id) != 0)) {
		fprintf(stderr, "wrong engine id\n");
		return 0;
	}

	if (!ENGINE_set_id(e, engine_uadk_id) ||
	    !ENGINE_set_destroy_function(e, uadk_destroy) ||
	    !ENGINE_set_init_function(e, uadk_init) ||
	    !ENGINE_set_finish_function(e, uadk_finish) ||
	    !ENGINE_set_name(e, engine_uadk_name)) {
		fprintf(stderr, "bind failed\n");
		return 0;
	}

	async_module_init();

	list = wd_get_accel_list("cipher");
	if (list) {
		if (!uadk_bind_cipher(e, list))
			fprintf(stderr, "uadk bind cipher failed\n");

		wd_free_list_accels(list);
	}

	list = wd_get_accel_list("digest");
	if (list) {
		if (!uadk_bind_digest(e, list))
			fprintf(stderr, "uadk bind digest failed\n");

		wd_free_list_accels(list);
	}
	list = wd_get_accel_list("rsa");
	if (list) {
		if (!uadk_bind_rsa(e, list))
			fprintf(stderr, "uadk bind rsa failed\n");
		wd_free_list_accels(list);
	}

	return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_fn)
