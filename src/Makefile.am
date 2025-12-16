VERSION = 1:6
ACLOCAL_AMFLAGS = -I m4

if HAVE_CRYPTO
lib_LTLIBRARIES=uadk_engine.la
else

lib_LTLIBRARIES=uadk_provider.la

if WD_ENGINE
lib_LTLIBRARIES+=uadk_engine.la
endif #WD_ENGINE

endif #HAVE_CRYPTO

uadk_engine_la_SOURCES=uadk_utils.c uadk_engine_init.c uadk_cipher.c \
		       uadk_digest.c uadk_async.c uadk_rsa.c uadk_sm2.c \
		       uadk_pkey.c uadk_dh.c uadk_ec.c uadk_ecx.c \
		       uadk_aead.c uadk_cipher_adapter.c

uadk_engine_la_LIBADD=-ldl $(WD_LIBS) -lpthread
uadk_engine_la_LDFLAGS=-module -version-number $(VERSION)
uadk_engine_la_CFLAGS=$(WD_CFLAGS) $(libcrypto_CFLAGS)
uadk_engine_la_CFLAGS+=-DCRYPTO
uadk_engine_la_CFLAGS+=-fPIC -fPIE -pie -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
		       -O2 -ftrapv -Wl,-z,relro,-z,now -Wl,-s
if WD_ENGINE
uadk_engine_la_CFLAGS+=-DOPENSSL_SUPPRESS_DEPRECATED
endif #WD_ENGINE

AUTOMAKE_OPTIONS = subdir-objects

if WD_KAE
uadk_engine_la_CFLAGS += -DKAE
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

uadk_provider_la_SOURCES=uadk_prov_init.c uadk_async.c uadk_utils.c \
			 uadk_prov_digest.c uadk_prov_cipher.c \
			 uadk_prov_rsa.c uadk_prov_rsa_kmgmt.c \
			 uadk_prov_rsa_enc.c uadk_prov_rsa_sign.c \
			 uadk_prov_rsa_utils.c \
			 uadk_prov_dh.c uadk_prov_bio.c \
			 uadk_prov_der_writer.c uadk_prov_packet.c \
			 uadk_prov_pkey.c uadk_prov_sm2.c \
			 uadk_prov_ffc.c uadk_prov_aead.c \
			 uadk_prov_ec_kmgmt.c uadk_prov_ecdh_exch.c \
			 uadk_prov_ecx.c uadk_prov_ecdsa.c \
			 uadk_prov_hmac.c

uadk_provider_la_LDFLAGS=-module -version-number $(VERSION)
uadk_provider_la_LIBADD=$(WD_LIBS) -lpthread
uadk_provider_la_CFLAGS=$(WD_CFLAGS) $(libcrypto_CFLAGS)
uadk_provider_la_CFLAGS+=-DOPENSSL_SUPPRESS_DEPRECATED
uadk_provider_la_CFLAGS+=-fPIC -fPIE -pie -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
			-O2 -ftrapv -Wl,-z,relro,-z,now -Wl,-s
