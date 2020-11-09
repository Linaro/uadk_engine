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
#ifndef UADK_ASYNC_H
#define UADK_ASYNC_H

#include <openssl/async.h>
#include <semaphore.h>

struct async_op {
	ASYNC_JOB *job;
	int done;
	int ret;
};

typedef int (*async_recv_t)(void *ctx);

enum task_type {
	ASYNC_TASK_CIPHER,
	ASYNC_TASK_DIGEST,
	ASYNC_TASK_RSA,
	ASYNC_TASK_DH
};

struct async_poll_task {
	enum task_type type;
	void *ctx;
	struct async_op *op;
};

struct async_poll_queue {
	struct async_poll_task *head;
	int head_pos;
	int tail_pos;
	int cur_task;
	int left_task;
	sem_t empty_sem;
	sem_t full_sem;
	pthread_mutex_t async_task_mutex;
	pthread_t thread_id;
};

extern int async_setup_async_event_notification(struct async_op *op);
extern int async_clear_async_event_notification(void);
extern int async_pause_job(void *ctx, struct async_op *op, enum task_type type);
extern int async_register_poll_fn(int type, async_recv_t func);
extern void async_module_init(void);
#endif
