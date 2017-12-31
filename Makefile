
CC = gcc
VERSION = 0.1
CFLAGS = -g -O2
LIBS = -lm -lcrypt -lpam 
INSTALL=/bin/install -c
prefix=/usr/local
sbindir=${exec_prefix}/sbin
mandir=${prefix}/share/man
FLAGS=$(CFLAGS) -DPACKAGE_NAME=\"\" -DPACKAGE_TARNAME=\"\" -DPACKAGE_VERSION=\"\" -DPACKAGE_STRING=\"\" -DPACKAGE_BUGREPORT=\"\" -DPACKAGE_URL=\"\" -DSTDC_HEADERS=1 -DHAVE_LIBPAM=1 -DHAVE_LIBCRYPT=1 -DHAVE_LIBM=1 -DHAVE_SYS_TYPES_H=1 -DHAVE_SYS_STAT_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1 -DHAVE_MEMORY_H=1 -DHAVE_STRINGS_H=1 -DHAVE_INTTYPES_H=1 -DHAVE_STDINT_H=1 -DHAVE_UNISTD_H=1 -DHAVE_SHADOW_H=1
OBJ=Authenticate.o common.o telnet-protocol.o settings.o 
EXE=ptelnetd

all: $(OBJ) main.c
	@cd libUseful-3; $(MAKE)
	gcc -g -o$(EXE) $(OBJ) main.c libUseful-3/libUseful-3.a $(LIBS)


Authenticate.o: Authenticate.c Authenticate.h
	gcc $(FLAGS) -c Authenticate.c

settings.o: settings.c settings.h
	gcc $(FLAGS) -c settings.c

telnet-protocol.o: telnet-protocol.c telnet-protocol.h
	gcc $(FLAGS) -c telnet-protocol.c

common.o: common.c common.h
	gcc $(FLAGS) -c common.c

clean:
	-rm -f *.o */*.o */*.a */*.so $(EXE)
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

