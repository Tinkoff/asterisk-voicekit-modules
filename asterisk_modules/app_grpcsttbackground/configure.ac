AC_INIT([app_grpcsttbackground], [0.1])
AC_CONFIG_FILES([Makefile])

AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE
AC_ENABLE_SHARED
AC_DISABLE_STATIC
AC_PROG_CC
AC_PROG_CXX
AC_PROG_LIBTOOL
AC_LIBTOOL_SETUP


asteriskmoduledir="$libdir/asterisk/modules"
AC_SUBST(asteriskmoduledir)

asterisk_xmldoc_dir="$localstatedir/lib/asterisk/documentation"
AC_SUBST(asterisk_xmldoc_dir)

AC_OUTPUT
