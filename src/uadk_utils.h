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
#include <string.h>
#include <syslog.h>
#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000
#define UADK_DEBUG(fmt, args...)  \
	do {\
		openlog("uadk-prov-debug", LOG_CONS | LOG_PID, LOG_LOCAL6);\
		syslog(LOG_DEBUG, fmt, ##args);\
	} while (0)

#define UADK_INFO(fmt, args...)  \
	do {\
		openlog("uadk-prov-info", LOG_CONS | LOG_PID, LOG_LOCAL6);\
		syslog(LOG_INFO, fmt, ##args);\
	} while (0)

#define UADK_ERR(fmt, args...)  \
	do {\
		openlog("uadk-prov-err", LOG_CONS | LOG_PID, LOG_LOCAL6);\
		syslog(LOG_ERR, fmt, ##args);\
	} while (0)
#else
#define UADK_DEBUG(fmt, args...)   fprintf(stderr, fmt, ##args)
#define UADK_INFO(fmt, args...)    fprintf(stderr, fmt, ##args)
#define UADK_ERR(fmt, args...)     fprintf(stderr, fmt, ##args)
#endif

void *uadk_memcpy(void *dstpp, const void *srcpp, size_t len);
struct uacce_dev *uadk_get_accel_dev(const char *alg_name);
#endif
