AC_PREREQ([2.69])
AC_INIT([uadk_engine], [1.4])
AM_INIT_AUTOMAKE([1.10 no-define])

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])

AC_PROG_CC
LT_INIT
AC_SUBST([hardcode_into_libs], [no])

AC_ARG_ENABLE(kae,
	      AS_HELP_STRING([--enable-kae],[Enable kae support]))
AC_SUBST(enable_kae)
AM_CONDITIONAL([WD_KAE], [test "$enable_kae" = "yes"])

AC_ARG_ENABLE(engine,
	      AS_HELP_STRING([--enable-engine],[Enable engine in OpenSSL 3.0]))
AC_SUBST(enable_engine)
AM_CONDITIONAL([WD_ENGINE], [test "$enable_engine" = "yes"])

PKG_CHECK_MODULES(WD, libwd libwd_crypto, [with_wd=yes], [with_wd=no])
AM_CONDITIONAL(HAVE_WD, [test "$with_wd" != "no"])

PKG_CHECK_MODULES(libcrypto, libcrypto < 3.0 libcrypto >= 1.1,
		  [with_crypto=yes], [with_crypto=no])
AM_CONDITIONAL(HAVE_CRYPTO, test "$with_crypto" != "no")

PKG_CHECK_MODULES(libcrypto, libcrypto >= 3.0,
		  [with_crypto3=yes], [with_crypto3=no])
AM_CONDITIONAL(HAVE_CRYPTO3, test "$with_crypto3" != "no")

AC_DEFUN([AC_CHECK_BOARD_VERSION], [
  AC_MSG_CHECKING([for board version])
  board_version=""

  for dir in /sys/class/uacce/*; do
    if test -d "$dir" && test -f "$dir/api"; then
      if grep -q 'hisi_qm_v2' "$dir/api"; then
        board_version="hisi_qm_v2"
        AC_DEFINE(BOARD_VERSION_QM2, 1, [Board version is QM2])
        break
      elif grep -q 'hisi_qm_v3' "$dir/api"; then
        board_version="hisi_qm_v3"
        AC_DEFINE(BOARD_VERSION_QM3, 1, [Board version is QM3])
        break
      fi
    fi
  done
  AC_MSG_RESULT([$board_version])
])

AC_CHECK_BOARD_VERSION

AC_CONFIG_FILES([
	Makefile
	src/Makefile])
AC_OUTPUT
