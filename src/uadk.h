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

extern int uadk_bind_cipher(ENGINE *e);
extern void uadk_destroy_cipher(void);
extern int uadk_bind_digest(ENGINE *e);
extern void uadk_destroy_digest(void);
extern void uadk_destroy_digest(void);

extern RSA_METHOD *uadk_get_rsa_methods(void);
extern int uadk_init_rsa(void);
extern void uadk_destroy_rsa(void);

#define uadk_eng_err(format, args...)			\
	fprintf(stderr, "ue: %s: "format, __func__, ##args)