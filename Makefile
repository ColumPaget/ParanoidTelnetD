
CC = gcc
VERSION = 
CFLAGS = -g -O2 -fstack-clash-protection -fno-strict-overflow -fno-strict-aliasing -fno-delete-null-pointer-checks -fcf-protection=full -mmitigate-rop -O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 -fstack-protector-strong
LIBS = -lc -lm -lz -lssl -lcrypto -lcrypt -lUseful -lc 
STATIC_LIBS=
INSTALL=/usr/bin/install -c
prefix=/usr/local
sbindir=${exec_prefix}/sbin
mandir=${prefix}/share/man
FLAGS=$(CFLAGS) -DPACKAGE_NAME=\"\" -DPACKAGE_TARNAME=\"\" -DPACKAGE_VERSION=\"\" -DPACKAGE_STRING=\"\" -DPACKAGE_BUGREPORT=\"\" -DPACKAGE_URL=\"\" -DHAVE_STDIO_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1 -DHAVE_INTTYPES_H=1 -DHAVE_STDINT_H=1 -DHAVE_STRINGS_H=1 -DHAVE_SYS_STAT_H=1 -DHAVE_SYS_TYPES_H=1 -DHAVE_UNISTD_H=1 -DSTDC_HEADERS=1 -DHAVE_LIBC=1 -DUSE_PRCTL=1 -DHAVE_LINUX_PRCTL_H=1 -DUSE_NOSU=1 -DUSE_SENDFILE=1 -DHAVE_LIBUSEFUL=1 -DHAVE_LIBCRYPT=1 -DHAVE_LIBCRYPTO=1 -DHAVE_LIBSSL=1 -DHAVE_EVP_MD_CTX_NEW=1 -DHAVE_EVP_MD_CTX_FREE=1 -DHAVE_EVP_BF_CBC=1 -DHAVE_EVP_RC2_CBC=1 -DHAVE_EVP_RC4=1 -DHAVE_EVP_DES_CBC=1 -DHAVE_EVP_DESX_CBC=1 -DHAVE_EVP_CAST5_CBC=1 -DHAVE_EVP_AES_128_CBC=1 -DHAVE_EVP_AES_256_CBC=1 -DHAVE_X509_CHECK_HOST=1 -DHAVE_DECL_OPENSSL_ADD_ALL_ALGORITHMS=1 -DHAVE_OPENSSL_ADD_ALL_ALGORITHMS=1 -DHAVE_DECL_SSL_SET_TLSEXT_HOST_NAME=1 -DHAVE_SSL_SET_TLSEXT_HOST_NAME=1 -DHAVE_LIBZ=1 -DHAVE_LIBM=1 -DHAVE_LIBC=1 -DHAVE_SHADOW_H=1
OBJ=Authenticate.o common.o telnet-protocol.o settings.o 
EXE=ptelnetd

all: $(OBJ) $(STATIC_LIBS) main.c
	$(CC) -g -o$(EXE) $(FLAGS) $(OBJ) main.c $(STATIC_LIBS) $(LIBS)

libUseful-bundled/libUseful.a:
	$(MAKE) -C libUseful-bundled

Authenticate.o: Authenticate.c Authenticate.h
	$(CC) $(FLAGS) -c Authenticate.c

settings.o: settings.c settings.h
	$(CC) $(FLAGS) -c settings.c

telnet-protocol.o: telnet-protocol.c telnet-protocol.h
	$(CC) $(FLAGS) -c telnet-protocol.c

common.o: common.c common.h
	$(CC) $(FLAGS) -c common.c

clean:
	-rm -f *.orig *.o */*.o */*.a */*.so $(EXE)
	-rm -f config.log config.status */config.log */config.status
	-rm -fr autom4te.cache */autom4te.cache

distclean:
	-rm -f *.o */*.o */*.a */*.so $(EXE)
	-rm -f config.log config.status */config.log */config.status Makefile */Makefile
	-rm -fr autom4te.cache */autom4te.cache

install:
	@mkdir -p $(DESTDIR)/$(sbindir)
	@mkdir -p $(DESTDIR)/$(mandir)/man1
	cp -f ptelnetd $(DESTDIR)/$(sbindir)
	cp -f ptelnetd.1 $(DESTDIR)/$(mandir)/man1

test:
	echo "no tests"
