

AC_INIT
AC_CONFIG_SRCDIR([main.c])

AC_SUBST(VERSION) 


AC_PROG_CC 
AC_LANG([C]) 
AC_PROG_MAKE_SET 
AC_PROG_INSTALL 
AC_CHECK_INCLUDES_DEFAULT
AC_PROG_EGREP
 

dnl set these here, they can be changed by multiple 'enable' options below
cf_use_mdwe="no"
cf_use_nosu="no"
cf_use_fortify="no"
cf_use_stackprotect="no"



AC_ARG_ENABLE(crypt, [  --enable-crypt		enable linux 'crypt' password support (default=autodetect) ], cf_use_crypt=$enableval )
AC_ARG_ENABLE(pam, [  --enable-pam		enable Pluggable Authentication Modules (default=autodetect) ], cf_use_pam=$enableval )
AC_ARG_ENABLE(ip6, [  --enable-ip6		enable IPv6 (default=no) ], cf_use_ip6=$enableval )
AC_ARG_ENABLE(ssl, [  --enable-ssl		enable SSL/TLS (default=no) ], cf_use_ssl=$enableval )
AC_ARG_ENABLE(zlib, [  --enable-zlib               use ZLib Compression], cf_use_zlib=$enableval, cf_use_zlib=yes)
AC_ARG_ENABLE(harden, [  --enable-harden       enable both 'mdwe' and 'nosu' and other memory-harending features (default=no)], cf_use_harden=$enableval )
AC_ARG_ENABLE([wall], [AS_HELP_STRING([--enable-wall], [use -Wall to get maximum compile warnings])], [cf_use_wall=$enableval], [cf_use_wall=no])
AC_ARG_ENABLE([werror], [AS_HELP_STRING([--enable-werror], [treat compile warnings as errors])], [cf_use_werror=$enableval], [cf_use_werror=no])
AC_ARG_ENABLE([fortify], [AS_HELP_STRING([--enable-fortify], [use 'FORTIFY_SOURCE=3' to harden source code])], [cf_use_fortify=$enableval])
AC_ARG_ENABLE([stack-protect], [AS_HELP_STRING([--enable-stack-protect], [use '-fstack-protector-strong' to harden source code])], [cf_use_stackprotect=$enableval])
AC_ARG_ENABLE(nosu, [  --enable-nosu           enable prctl-based 'NO_NEW_PRIVS' to prevent su/sudo/suid (default=no)], cf_use_nosu=$enableval )
AC_ARG_ENABLE(sendfile, [  --enable-sendfile       enable sendfile support (default=yes)], cf_use_sendfile=$enableval, cf_use_sendfile=yes)


AC_ARG_WITH(libuseful, [  --with-libuseful		use system-wide libUseful (default=auto) ], cf_system_libuseful=$withval )



dnl define a function we can use to check if a compiler flag
dnl is supported by the compiler
AC_DEFUN([CHECK_COMPILER_OPT],
[
    COMP_OPT="$@"
    AC_MSG_CHECKING(["checking if compiler supports $COMP_OPT"])
    OLD_CFLAGS="$CFLAGS"
    CFLAGS="$CFLAGS $COMP_OPT"
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM(test(){return 1;})], [COMP_OPT_SUPPORT="yes"], [COMP_OPT_SUPPORT="no"])
    AC_MSG_RESULT([$COMP_OPT_SUPPORT])
    AS_IF([test "$COMP_OPT_SUPPORT" != "yes"], [CFLAGS="$OLD_CFLAGS"])
])




AS_IF([test "$cf_use_wall" = "yes"], [CFLAGS="$CFLAGS -Wall"])
AS_IF([test "$cf_use_werror" = "yes"], [CFLAGS="$CFLAGS -Werror"])


AS_IF([test "$cf_use_harden" = "yes"],
[
    cf_use_mdwe="yes"
    cf_use_nosu="yes"
    cf_use_fortify="yes"
    cf_use_stackprotect="yes"

    CHECK_COMPILER_OPT("-ftrivial-auto-var-init=zero")
    CHECK_COMPILER_OPT("-fstack-clash-protection")
    CHECK_COMPILER_OPT("-fno-strict-overflow")
    CHECK_COMPILER_OPT("-fno-strict-aliasing")
    CHECK_COMPILER_OPT("-fno-delete-null-pointer-checks")
    CHECK_COMPILER_OPT("-fcf-protection=full")
    CHECK_COMPILER_OPT("-mmitigate-rop")
])


dnl prctl gets used in conjunction with unshare
dnl and also for PR_SET_NO_NEW_PRIVS, so we check
dnl for it independantly of unshare now
AC_CHECK_LIB(c,prctl,,)

AS_IF([test "$ac_cv_lib_c_prctl" = "yes"],
[
AC_DEFINE([USE_PRCTL])
AC_CHECK_HEADERS([linux/prctl.h])

AC_CHECK_DECL([PR_SET_NO_NEW_PRIVS],,[cf_use_nosu=no],[
#ifdef HAVE_LINUX_PRCTL_H
#include <sys/prctl.h>
#endif
])

])

dnl these must come after check for '$cf_use_harden'
AS_IF([test "$cf_use_nosu" = "yes"], AC_DEFINE([USE_NOSU]))
AS_IF([test "$cf_use_sendfile" = "yes"], AC_DEFINE([USE_SENDFILE]))
AS_IF([test "$cf_use_fortify" = "yes"], [CFLAGS="$CFLAGS -O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3"])
AS_IF([test "$cf_use_stackprotect" = "yes"],
[
                CHECK_COMPILER_OPT("-fstack-protector-strong")
                AS_IF([test "$COMP_OPT_SUPPORT" != "yes"],[cf_use_stackprotect="no"])
])



dnl check if we should use system or bundled libUseful
AS_IF([test "$cf_system_libuseful" != "no"],[AC_CHECK_LIB([Useful], [GetToken],[cf_have_libUseful=yes],[cf_have_libUseful=no])])
AS_IF([test "$cf_have_libUseful" = "yes"],
[
  echo "installed libUseful found, using that instead of bundled libUseful."
  echo "if you want to use bundled libUseful, force it with --with-libuseful=no"
  AC_SUBST(LIBUSEFUL_BUNDLED,"")
  dnl Default behavior of AC_CHECK_LIB is to add the library to the LIBS variable
  AC_CHECK_LIB(Useful,GetToken,,)
],
[
  AC_DEFINE([USE_LIBUSEFUL_BUNDLED])
  AC_SUBST(LIBUSEFUL_BUNDLED,"libUseful-bundled/libUseful.a")
  AC_CONFIG_SUBDIRS([libUseful-bundled])
])

AS_IF([test "$cf_use_pam" != "no"],
[
AC_CHECK_LIB(pam, pam_start,,)
cf_have_libpam=$ac_cv_lib_pam_pam_start
])

AC_CHECK_HEADER(crypt.h,cf_have_crypt_h="yes")

AS_IF([test "$cf_use_crypt" != "no" -a "$cf_have_crypt_h" = "yes"],
[
AC_CHECK_LIB(crypt, crypt,,)
cf_have_libcrypt=$ac_cv_lib_crypt_crypt
])

AS_IF([test "$cf_use_ssl" = "yes"],
[
AC_CHECK_HEADER([openssl/crypto.h])
AC_CHECK_HEADER([openssl/ssl.h])

AC_CHECK_LIB(crypto,EVP_CIPHER_CTX_init,,)
cf_have_libcrypto=$ac_cv_lib_crypto_EVP_CIPHER_CTX_init

dnl New versions of openssl seem to lack EVP_CIPHER_CTX_init, so let's look for another function. I've no idea what's going on with openssl, this is why I use libressl instead.
AS_IF([test "$cf_have_libcrypto" != "yes"],
[
	AC_CHECK_LIB(crypto,EVP_CIPHER_CTX_new,,)
	cf_have_libcrypto=$ac_cv_lib_crypto_EVP_CIPHER_CTX_new
])


AC_CHECK_LIB(ssl,SSL_library_init,,)
cf_have_libssl=$ac_cv_lib_ssl_SSL_library_init

dnl New versions of openssl seem to lack SSL_library_init, so let's look for another function. I've no idea what's going on with openssl, this is why I use libressl instead.
AS_IF([test "$cf_have_libssl" != "yes"],
[
	AC_CHECK_LIB(ssl,OPENSSL_init_ssl,,)
	cf_have_libssl=$ac_cv_lib_ssl_OPENSSL_init_ssl
])



AS_IF([test "$cf_have_libssl" = "yes"],
[
cf_use_zlib=yes

AC_CHECK_FUNCS(OpenSSL_add_all_algorithms EVP_MD_CTX_create EVP_MD_CTX_new EVP_MD_CTX_destroy EVP_MD_CTX_free EVP_bf_cbc EVP_rc2_cbc EVP_rc4 EVP_rc5_32_12_16_cbc EVP_des_cbc EVP_desx_cbc EVP_cast5_cbc EVP_idea_cbc EVP_aes_128_cbc EVP_aes_256_cbc X509_check_host SSL_set_tlsext_host_name SSL_set_min_proto_version)


AC_CHECK_DECLS(OpenSSL_add_all_algorithms,AC_DEFINE([HAVE_OPENSSL_ADD_ALL_ALGORITHMS]),[],[[#include <openssl/ssl.h>]])
AC_CHECK_DECLS(SSL_set_tlsext_host_name,AC_DEFINE([HAVE_SSL_SET_TLSEXT_HOST_NAME]),[],[[#include <openssl/ssl.h>]])

 AC_MSG_CHECKING([that OpenSSL Library is at least version 0.9.7])   
 AC_EGREP_CPP(yes,      [
		#include <openssl/evp.h>
		#if SSLEAY_VERSION_NUMBER >= 0x00907000L
		yes        
		#endif
	],      
	[
		AC_MSG_RESULT([yes])
#    AC_DEFINE(USE_OPENSSL_ADD_ALL_ALGORITHMS, 1, [Use OpenSSL_add_all_algorithms]) 
	],[AC_MSG_RESULT([no])])
])


])




AS_IF([test "$cf_use_zlib" = "yes" -o "$cf_use_ssl" = "yes"], [
AC_CHECK_LIB(z,deflate,,)
cf_have_libz=$ac_cv_lib_z_deflate
])



AC_CHECK_LIB(m,pow,,)
AC_CHECK_LIB(c,prctl,,)

AC_CHECK_HEADER(shadow.h,AC_DEFINE(HAVE_SHADOW_H, 1))

dnl read Makefile.in and write Makefile 
AC_CONFIG_FILES([Makefile])
AC_OUTPUT

echo
echo "********** ParanoidTelnetD Compile Settings *********"

AS_IF([test "$cf_have_libpam" != "yes" ], [echo "PAM authentication NOT enabled"], [echo "PAM authentication enabled"])
AS_IF([test "$cf_have_libcrypt" != "yes" ], [echo "LIBCRYPT authentication NOT enabled"], [echo "LIBCRYPT authentication enabled"])
AS_IF([test "$ac_cv_header_shadow_h" != "yes" ], [echo "/etc/shadow authentication NOT enabled"], [echo "/etc/shadow authentication enabled"])
AS_IF([test "$cf_use_ip6" != "yes" ], [echo "IPv6 NOT enabled"], [echo "IPv6 enabled"])
AS_IF([test "$cf_have_libssl" != "yes" ], [echo "SSL/TLS encryption NOT enabled"], [echo "SSL/TLS encryption enabled"])
AS_IF([test "$cf_have_libUseful" = "yes"], [echo "Using system-wide libUseful"], [echo "Using bundled libUseful"])
AS_IF([test "$cf_use_nosu" = "yes"], [echo "Using 'no su'"], ["NOT using 'no su'"])
AS_IF([test "$cf_use_sendfile" = "yes"], [echo "Using sendfile"],["NOT using sendfile"])
AS_IF([test "$cf_use_fortify" = "yes"], [echo "Compiling with fortify"], ["NOT compiling with fortify"])
AS_IF([test "$cf_use_stackprotect" = "yes"], [echo "Compiling with stackprotect"], ["NOT compiling with stackprotect"])

