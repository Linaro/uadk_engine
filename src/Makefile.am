ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES=uadk.la

uadk_la_SOURCES=e_uadk.c uadk_cipher.c uadk_digest.c uadk_async.c uadk_rsa.c
uadk_la_LIBADD=-ldl -lwd -lwd_crypto -lpthread
uadk_la_LDFLAGS=-module
