

AC_INIT([main.c])

VERSION="0.1" 
AC_SUBST(VERSION) 

AC_CONFIG_SUBDIRS([libUseful])

AC_PROG_CC 
AC_LANG_C 
AC_PROG_MAKE_SET 
AC_PROG_INSTALL 
AC_HEADER_STDC 

AC_ARG_ENABLE(crypt, [  --enable-crypt		enable linux 'crypt' password support (default=autodetect) ], cf_use_crypt=$enableval )
AC_ARG_ENABLE(pam, [  --enable-pam		enable Pluggable Authentication Modules (default=autodetect) ], cf_use_pam=$enableval )
AC_ARG_ENABLE(ip6, [  --enable-ip6		enable IPv6 (default=no) ], cf_use_ip6=$enableval )
AC_ARG_ENABLE(ssl, [  --enable-ssl		enable SSL/TLS (default=no) ], cf_use_ssl=$enableval )

if test "$cf_use_pam" != "no"
then
AC_CHECK_LIB(pam, pam_start,,)
cf_have_libpam=$ac_cv_lib_pam_pam_start
fi

AC_CHECK_HEADER(crypt.h,cf_have_crypt_h="yes")

if test "$cf_use_crypt" != "no" -a "$cf_have_crypt_h" = "yes"
then
AC_CHECK_LIB(crypt, crypt,,)
cf_have_libcrypt=$ac_cv_lib_crypt_crypt
fi

if test "$cf_use_ssl" = "yes"
then
AC_CHECK_LIB(ssl,SSL_library_init,,)
cf_have_libssl=$ac_cv_lib_ssl_SSL_library_init

AC_CHECK_LIB(crypto,EVP_CIPHER_CTX_init,,)
cf_have_libcrypto=$ac_cv_lib_crypto_EVP_CIPHER_CTX_init
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


