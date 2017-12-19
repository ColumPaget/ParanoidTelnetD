

AC_INIT([main.c])

VERSION="0.1" 
AC_SUBST(VERSION) 

AC_CONFIG_SUBDIRS([libUseful-3])

AC_PROG_CC 
AC_LANG_C 
AC_PROG_MAKE_SET 
AC_PROG_INSTALL 
AC_HEADER_STDC 

AC_ARG_ENABLE(pam, [  --enable-pam		enable Pluggable Authentication Modules (default=autodetect) ], cf_use_pam=$enableval )
AC_ARG_ENABLE(lua, [  --enable-lua		enable Lua scripting (default=no) ], cf_use_lua=$enableval )

if test "$cf_use_pam" != "no"
then
AC_CHECK_LIB(pam, pam_start,,)
cf_have_libpam=$ac_cv_lib_pam_pam_start
fi

AC_ARG_ENABLE(ip6, [  --enable-ip6		enable IPv6 (default=no) ], cf_use_ip6=$enableval )


AC_CHECK_LIB(crypt, crypt,,)
cf_have_libcrypt=$ac_cv_lib_crypt_crypt


if test "$cf_use_lua" = "yes"
AC_CHECK_LIB(lua, lua_newstate,,)
cf_have_liblua=$ac_cv_lib_lua_lua_newstate
if test "$cf_have_liblua" = "yes"
then
AC_DEFINE([USE_LUA],[1]);
fi
fi

AC_CHECK_LIB(m,pow,,)

AC_CHECK_HEADER(shadow.h,AC_DEFINE(HAVE_SHADOW_H, 1))

dnl read Makefile.in and write Makefile 
AC_OUTPUT(Makefile)

echo
echo "********** ParanoidTelnetD Compile Settings *********"

if test	"$cf_have_libpam" != "yes" 
then
echo "PAM authentication NOT enabled"
else
echo "PAM authentication enabled"
fi

if test	"$cf_have_libcrypt" != "yes" 
then
echo "LIBCRYPT authentication NOT enabled"
else
echo "LIBCRYPT authentication enabled"
fi

if test	"$ac_cv_header_shadow_h" != "yes" 
then
echo "/etc/shadow authentication NOT enabled"
else
echo "/etc/shadow authentication enabled"
fi

if test	"$cf_use_ip6" != "yes" 
then
echo "IPv6 NOT enabled"
else
echo "IPv6 enabled"
fi


