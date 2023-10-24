AC_PREREQ([2.71])
AC_INIT([uadk_engine],[1.2])
AM_INIT_AUTOMAKE([1.10 no-define])

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])

AC_PROG_CC
LT_INIT
LT_INIT

AC_ARG_ENABLE(kae,
	      AS_HELP_STRING([--enable-kae],[Enable kae support]))
AC_SUBST(enable_kae)
AM_CONDITIONAL([WD_KAE], [test "$enable_kae" = "yes"])

AC_ARG_ENABLE(rsa,
	      AS_HELP_STRING([--enable-rsa],[enable rsa support]))
AC_SUBST(enable_rsa)
AM_CONDITIONAL([DISABLE_RSA],[test "$enable_rsa" = "no"])

AC_ARG_ENABLE(dh,
	      AS_HELP_STRING([--enable-dh],[enable dh support]))
AC_SUBST(enable_dh)
AM_CONDITIONAL([DISABLE_DH],[test "$enable_dh"="no"])

AC_ARG_ENABLE(x448,
	      AS_HELP_STRING([--enable-x448],[enable x448 support]))
AC_SUBST(enable_x448)
AM_CONDITIONAL([DISABLE_X448],[test "$enable_x448" = "no"])

AC_ARG_ENABLE(x25519,
	      AS_HELP_STRING([--enable-x25519],[enable x25519 support]))
AC_SUBST(enable_x25519)
AM_CONDITIONAL([DISABLE_X25519],[test "$enable_x25519" = "no"])

PKG_CHECK_MODULES(WD, libwd libwd_crypto, [with_wd=yes], [with_wd=no])
AM_CONDITIONAL(HAVE_WD, [test "$with_wd" != "no"])

PKG_CHECK_MODULES(libcrypto, libcrypto < 3.0 libcrypto >= 1.1,
		  [with_crypto=yes], [with_crypto=no])
AM_CONDITIONAL(HAVE_CRYPTO, test "$with_crypto" != "no")

PKG_CHECK_MODULES(libcrypto, libcrypto >= 3.0,
		  [with_crypto3=yes], [with_crypto3=no])
AM_CONDITIONAL(HAVE_CRYPTO3, test "$with_crypto3" != "no")

AC_CONFIG_FILES([
	Makefile
	src/Makefile])
AC_OUTPUT
