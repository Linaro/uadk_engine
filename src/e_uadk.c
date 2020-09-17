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
#include <openssl/engine.h>


/* Constants used when creating the ENGINE */
static const char *engine_uadk_id = "uadk";
static const char *engine_uadk_name = "uadk hardware engine support";

__attribute__((constructor))
static void uadk_constructor(void)
{
}

__attribute__((destructor))
static void uadk_destructor(void)
{
}

/*
 * This stuff is needed if this ENGINE is being
 * compiled into a self-contained shared-library.
 */
static int bind_fn(ENGINE *e, const char *id)
{
    if (id && (strcmp(id, engine_uadk_id) != 0)) {
        fprintf(stderr, "wrong engine id\n");
        fprintf(stderr, "id = %s wrong engine id\n", id);
        return 0;
    }

    if (!ENGINE_set_id(e, engine_uadk_id) ||
        !ENGINE_set_name(e, engine_uadk_name)) {
        fprintf(stderr, "bind failed\n");
        return 0;
    }

    return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_fn)
