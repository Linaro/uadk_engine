/*
 * Copyright 2020-2021 Huawei Technologies Co.,Ltd. All rights reserved.
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

#include <stdio.h>
#include <string.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include "uadk.h"
#include "uadk_async.h"

#define ASYNC_POLL_TASK_NUM 1024
#define MAX_ALG_SIZE 6

static struct async_poll_queue poll_queue;

static async_recv_t async_recv_func[MAX_ALG_SIZE];

static void async_fd_cleanup(ASYNC_WAIT_CTX *ctx, const void *key,
			     OSSL_ASYNC_FD readfd, void *custom)
{
	close(readfd);
}

int async_setup_async_event_notification(struct async_op *op)
{
	ASYNC_WAIT_CTX *waitctx;
	OSSL_ASYNC_FD efd;
	void *custom;

	memset(op, 0, sizeof(struct async_op));
	op->job = ASYNC_get_current_job();
	if (op->job == NULL)
		return 0;

	waitctx = ASYNC_get_wait_ctx(op->job);
	if (waitctx == NULL)
		return 0;

	if (ASYNC_WAIT_CTX_get_fd(waitctx, engine_uadk_id,
				  &efd, &custom) == 0) {
		efd = eventfd(0, EFD_NONBLOCK);
		if (efd == -1)
			return 0;

		if (ASYNC_WAIT_CTX_set_wait_fd(waitctx, engine_uadk_id, efd,
					       custom, async_fd_cleanup) == 0) {
			async_fd_cleanup(waitctx, engine_uadk_id, efd, NULL);
			return 0;
		}
	}

	return 1;
}

int async_clear_async_event_notification(void)
{
	ASYNC_JOB *job;
	ASYNC_WAIT_CTX *waitctx;
	OSSL_ASYNC_FD efd;
	size_t num_add_fds;
	size_t num_del_fds;
	void *custom = NULL;

	job = ASYNC_get_current_job();
	if (job == NULL)
		return 0;

	waitctx = ASYNC_get_wait_ctx(job);
	if (waitctx == NULL)
		return 0;

	if (ASYNC_WAIT_CTX_get_changed_fds(waitctx, NULL, &num_add_fds,
					   NULL, &num_del_fds) == 0)
		return 0;

	if (num_add_fds > 0) {
		if (ASYNC_WAIT_CTX_get_fd(waitctx, engine_uadk_id,
					  &efd, &custom) == 0)
			return 0;

		async_fd_cleanup(waitctx, engine_uadk_id, efd, NULL);

		if (ASYNC_WAIT_CTX_clear_fd(waitctx, engine_uadk_id) == 0)
			return 0;
	}

	return 1;
}

static void async_poll_task_free(void)
{
	int error;
	struct async_poll_task *task;

	error = pthread_mutex_lock(&poll_queue.async_task_mutex);
	if (error != 0)
		return;

	task = poll_queue.head;
	if (task != NULL)
		OPENSSL_free(task);

	poll_queue.head = NULL;
	pthread_mutex_unlock(&poll_queue.async_task_mutex);
	sem_destroy(&poll_queue.empty_sem);
	sem_destroy(&poll_queue.full_sem);
	pthread_mutex_destroy(&poll_queue.async_task_mutex);
}

static struct async_poll_task *async_get_queue_task(void)
{
	struct async_poll_task *task_queue;
	struct async_poll_task *cur_task;
	int tail_pos;

	if (pthread_mutex_lock(&poll_queue.async_task_mutex) != 0)
		return NULL;

	tail_pos = poll_queue.tail_pos;
	task_queue = poll_queue.head;
	cur_task = &task_queue[tail_pos];

	poll_queue.tail_pos = (tail_pos + 1) % ASYNC_POLL_TASK_NUM;
	poll_queue.cur_task--;
	poll_queue.left_task++;

	if (pthread_mutex_unlock(&poll_queue.async_task_mutex) != 0)
		return NULL;

	if (sem_post(&poll_queue.empty_sem) != 0)
		return NULL;

	return cur_task;
}

static int async_add_poll_task(void *ctx, struct async_op *op, enum task_type type)
{
	struct async_poll_task *task_queue;
	struct async_poll_task *task;
	int head_pos;

	if (sem_wait(&poll_queue.empty_sem) != 0)
		return 0;

	if (pthread_mutex_lock(&poll_queue.async_task_mutex) != 0)
		return 0;

	head_pos = poll_queue.head_pos;
	task_queue = poll_queue.head;
	task = &task_queue[head_pos];
	task->ctx = ctx;
	task->op = op;
	task->type = type;

	head_pos = (head_pos + 1) % ASYNC_POLL_TASK_NUM;
	poll_queue.head_pos = head_pos;
	poll_queue.cur_task++;
	poll_queue.left_task--;

	if (pthread_mutex_unlock(&poll_queue.async_task_mutex) != 0)
		return 0;

	if (sem_post(&poll_queue.full_sem) != 0)
		return 0;

	return 1;
}

int async_pause_job(void *ctx, struct async_op *op, enum task_type type)
{
	ASYNC_WAIT_CTX *waitctx;
	OSSL_ASYNC_FD efd;
	void *custom;
	uint64_t buf;
	int ret;

	ret = async_add_poll_task(ctx, op, type);
	if (ret == 0)
		return ret;

	waitctx = ASYNC_get_wait_ctx((ASYNC_JOB *)op->job);
	if (waitctx == NULL)
		return 0;

	do {
		if (ASYNC_pause_job() == 0)
			return 0;

		ret = ASYNC_WAIT_CTX_get_fd(waitctx, engine_uadk_id, &efd, &custom);
		if (ret > 0) {
			if (read(efd, &buf, sizeof(uint64_t)) == -1) {
				if (errno != EAGAIN)
					printf("Failed to read from fd: %d - error: %d\n",
					       efd, errno);
				/* Not resumed by the expected async_wake_job() */
			}
		}
	} while (!op->done);

	return ret;
}

static int async_wake_job(ASYNC_JOB *job)
{
	ASYNC_WAIT_CTX *waitctx;
	OSSL_ASYNC_FD efd;
	void *custom;
	uint64_t buf = 1;
	int ret;

	waitctx = ASYNC_get_wait_ctx(job);
	if (waitctx == NULL)
		return 0;

	ret = ASYNC_WAIT_CTX_get_fd(waitctx, engine_uadk_id, &efd, &custom);
	if (ret > 0) {
		if (write(efd, &buf, sizeof(uint64_t)) == -1)
			printf("Failed to write to fd: %d - error: %d\n", efd, errno);
	}

	return ret;
}

int async_register_poll_fn(int type, async_recv_t func)
{
	if (type < 0 || type >= MAX_ALG_SIZE)
		return -1;

	async_recv_func[type] = func;
	return 0;
}

static void *async_poll_process_func(void *args)
{
	struct async_poll_task *task;
	struct async_op *op;

	while (1) {
		if (sem_wait(&poll_queue.full_sem) != 0) {
			if (errno == EINTR) {
				/* sem_wait is interrupted by interrupt, continue */
				continue;
			}
		}

		task = async_get_queue_task();
		if (task == NULL) {
			usleep(1);
			continue;
		}

		op = task->op;
		op->ret = async_recv_func[task->type](task->ctx);
		op->done = 1;
		if (op->job)
			async_wake_job(op->job);
	}

	return NULL;
}

void async_module_init(void)
{
	pthread_t thread_id;
	pthread_attr_t thread_attr;

	memset(&poll_queue, 0, sizeof(struct async_poll_queue));

	if (pthread_mutex_init(&(poll_queue.async_task_mutex), NULL) < 0)
		return;

	poll_queue.head = malloc(sizeof(struct async_poll_task) * ASYNC_POLL_TASK_NUM);
	if (poll_queue.head == NULL)
		return;

	memset(poll_queue.head, 0,
	       sizeof(struct async_poll_task) * ASYNC_POLL_TASK_NUM);
	poll_queue.left_task = ASYNC_POLL_TASK_NUM;

	if (sem_init(&poll_queue.empty_sem, 0,
		     (unsigned int)poll_queue.left_task) != 0)
		goto err;

	if (sem_init(&poll_queue.full_sem, 0, 0) != 0)
		goto err;

	pthread_attr_init(&thread_attr);
	pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);
	if (pthread_create(&thread_id, &thread_attr, async_poll_process_func, NULL))
		goto err;

	poll_queue.thread_id = thread_id;
	OPENSSL_atexit(async_poll_task_free);

	return;

err:
	async_poll_task_free();
}
