AC_PREREQ([2.69])
AC_INIT([openssl-uadk], [1.0])
AC_CONFIG_SRCDIR([src/e_uadk.c])
AM_INIT_AUTOMAKE([1.10 no-define])

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])

AC_PROG_CC
AC_PROG_LIBTOOL
AM_PROG_LIBTOOL

AC_ARG_ENABLE(kae,
	      AS_HELP_STRING([--enable-kae],[Enable kae support]))
AC_SUBST(enable_kae)
AM_CONDITIONAL([WD_KAE], [test "$enable_kae" = "yes"])

AC_CHECK_HEADERS([openssl/engine.h])

AC_CONFIG_FILES([
	Makefile
	src/Makefile])
AC_OUTPUT
