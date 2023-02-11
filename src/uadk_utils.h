/*
 * Copyright 2020-2022 Huawei Technologies Co.,Ltd. All rights reserved.
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
#ifndef UADK_UTILS
#define UADK_UTILS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void *uadk_memcpy(void *dstpp, const void *srcpp, size_t len);
int uadk_e_is_env_enabled(const char *alg_name);
void uadk_e_set_env_enabled(const char *alg_name, unsigned int value);
int uadk_e_set_env(const char *var_name, int numa_id);
#endif
