AC_INIT([app_playbackground], [0.1])
AC_CONFIG_FILES([Makefile])

AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE
AC_ENABLE_SHARED
AC_DISABLE_STATIC
AC_PROG_CC
AC_PROG_CXX
AC_PROG_LIBTOOL
AC_LIBTOOL_SETUP

AC_PATH_PROG(XXD, xxd)
if test -z "$XXD"; then
    AC_MSG_ERROR([Please install 'xxd' tool])
fi

asteriskmoduledir="$libdir/asterisk/modules"
AC_SUBST(asteriskmoduledir)

AC_ARG_WITH([asterisk-xmldoc-dir],
    [AS_HELP_STRING([--with-asterisk-xmldoc-dir=DIR],
              [Asterisk XML documentation directory @<:@default=$localstatedir/lib/asterisk/documentation@:>@])],
    [asterisk_xmldoc_dir=$withval],
    [asterisk_xmldoc_dir=$localstatedir/lib/asterisk/documentation])
if test -z "$asterisk_xmldoc_dir"; then          
    AC_MSG_ERROR([Empty directory for '--with-asterisk-xmldoc-dir=' specified])
fi                                               
AC_SUBST(asterisk_xmldoc_dir)

PKG_CHECK_MODULES([OPUS],[opus >= 1.0.0])

AC_OUTPUT
