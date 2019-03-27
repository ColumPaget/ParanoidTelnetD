

AC_INIT([main.c])

AC_SUBST(VERSION) 


AC_PROG_CC 
AC_LANG_C 
AC_PROG_MAKE_SET 
AC_PROG_INSTALL 
AC_HEADER_STDC 

AC_ARG_ENABLE(crypt, [  --enable-crypt		enable linux 'crypt' password support (default=autodetect) ], cf_use_crypt=$enableval )
AC_ARG_ENABLE(pam, [  --enable-pam		enable Pluggable Authentication Modules (default=autodetect) ], cf_use_pam=$enableval )
AC_ARG_ENABLE(ip6, [  --enable-ip6		enable IPv6 (default=no) ], cf_use_ip6=$enableval )
AC_ARG_ENABLE(ssl, [  --enable-ssl		enable SSL/TLS (default=no) ], cf_use_ssl=$enableval )


AC_ARG_WITH(libuseful, [  --with-libuseful		use system-wide libUseful (default=auto) ], cf_system_libuseful=$withval )

if test "$cf_system_libuseful" != "no"
then
AC_CHECK_LIB(Useful,GetToken,[cf_have_libUseful=yes],[cf_have_libUseful=no])
fi

if test "$cf_have_libUseful" = "yes"
then
  echo "installed libUseful found, using that instead of bundled libUseful."
  echo "if you want to use bundled libUseful, force it with --with-libuseful=no"
  AC_SUBST(LIBUSEFUL_BUNDLED,"")
  dnl Default behavior of AC_CHECK_LIB is to add the library to the LIBS variable
  AC_CHECK_LIB(Useful,GetToken,,)
else
  AC_SUBST(LIBUSEFUL_BUNDLED,"libUseful/libUseful.a")
  AC_CONFIG_SUBDIRS([libUseful])
fi

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


if test "$cf_have_libUseful" = "yes"
then
echo "Using system-wide libUseful"
else
echo "Using bundled libUseful"
fi
