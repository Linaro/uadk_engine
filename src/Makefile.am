ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES=uadk_engine.la

uadk_engine_la_SOURCES=e_uadk.c uadk_cipher.c uadk_digest.c uadk_async.c uadk_rsa.c \
		uadk_sm2.c uadk_pkey.c uadk_dh.c uadk_ec.c uadk_ecx.c
uadk_engine_la_LIBADD=-ldl -lwd -lwd_crypto -lpthread
uadk_engine_la_LDFLAGS=-module

AUTOMAKE_OPTIONS = subdir-objects

if WD_KAE
uadk_engine_la_SOURCES+=v1/alg/ciphers/sec_ciphers.c \
		 v1/alg/ciphers/sec_ciphers_soft.c \
		 v1/alg/ciphers/sec_ciphers_utils.c \
		 v1/alg/ciphers/sec_ciphers_wd.c \
		 v1/alg/dh/hpre_dh.c \
		 v1/alg/dh/hpre_dh_soft.c \
		 v1/alg/dh/hpre_dh_wd.c \
		 v1/alg/digests/sec_digests.c \
		 v1/alg/digests/sec_digests_soft.c \
		 v1/alg/digests/sec_digests_wd.c \
		 v1/alg/pkey/hpre_rsa.c \
		 v1/alg/pkey/hpre_rsa_soft.c \
		 v1/alg/pkey/hpre_rsa_utils.c \
		 v1/alg/pkey/hpre_wd.c \
		 v1/wdmngr/wd_alg_queue.c \
		 v1/wdmngr/wd_queue_memory.c \
		 v1/utils/engine_check.c \
		 v1/utils/engine_config.c \
		 v1/utils/engine_fork.c \
		 v1/utils/engine_log.c \
		 v1/utils/engine_opensslerr.c \
		 v1/utils/engine_utils.c \
		 v1/async/async_callback.c \
		 v1/async/async_event.c \
		 v1/async/async_poll.c \
		 v1/async/async_task_queue.c
endif #WD_KAE
