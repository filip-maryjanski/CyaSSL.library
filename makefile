
SHELL = /bin/sh

##############################################################################

CODETYPE = PPC
VERSION  = 0

OUT = cyassl.library

##############################################################################

G_IPATH	   = -I./os-include -I./cyassl/
G_DEFINES  = -noixemul -DUSE_INLINE_STDARG
G_OPTFLAGS = -O2 \
	-Wall \
	-mresident32 \
	-fomit-frame-pointer \
	-fverbose-asm \
	-mno-prototype \
	-mcpu=604e \
	-mregnames \
	-Wformat \
	-Wunused \
	-Wuninitialized	\
	-Wconversion \
	-Wstrict-prototypes	\
	-Werror-implicit-function-declaration

##############################################################################

# subdirectories #
DIRS = cyassl
BUILDDIRS = $(DIRS:%=build-%)
CLEANDIRS = $(DIRS:%=clean-%)

##############################################################################

all: $(BUILDDIRS) os-include/ppcinline/cyassl.h \
     os-include/proto/cyassl.h \
     $(OUT).elf \
     libcyassl_shared.a \
     test

clean: $(CLEANDIRS)
	rm -f $(OUT).elf $(OUT).db $(OUT).dump test	*.o *.a os-include/ppcinline/cyassl.h os-include/proto/cyassl.h

##############################################################################

.c.o:
	ppc-morphos-gcc $(G_CFLAGS) $(G_OPTFLAGS) $(G_DEBUG) $(G_DEFINES) $(G_IPATH) -o $*.o -c $*.c

##############################################################################
##############################################################################
##############################################################################
##############################################################################
##############################################################################
##############################################################################
##############################################################################
#
# ABox Emulation
#


GLOBAL = libdata.h os-include/libraries/cyassl.h

lib.o:          lib.c          $(GLOBAL) cyassl.library.h
libdata.o:      libdata.c      $(GLOBAL)
libfunctions.o: libfunctions.c $(GLOBAL)
libfunctable.o: libfunctable.c $(GLOBAL)

OBJS = lib.o \
	libdata.o \
	libfunctions.o \
	libfunctable.o

os-include/ppcinline/cyassl.h: os-include/fd/cyassl_lib.fd os-include/clib/cyassl_protos.h
	@mkdir -p os-include/ppcinline
	cvinclude.pl --fd os-include/fd/cyassl_lib.fd --clib os-include/clib/cyassl_protos.h --inline $@

os-include/proto/cyassl.h: os-include/fd/cyassl_lib.fd
	@mkdir -p os-include/proto
	cvinclude.pl --fd os-include/fd/cyassl_lib.fd --proto $@

lib_glue.a: os-include/clib/cyassl_protos.h os-include/fd/cyassl_lib.fd os-include/ppcinline/cyassl.h os-include/proto/cyassl.h
	cvinclude.pl --fd os-include/fd/cyassl_lib.fd --clib os-include/clib/cyassl_protos.h --gluelib lib_glue.a

libcyassl_shared.a: lib_shared.o lib_glue.a
	@-rm -f libcyassl_shared.a
	cp lib_glue.a libcyassl_shared.a
	ppc-morphos-ar cru libcyassl_shared.a lib_shared.o
	ppc-morphos-ranlib libcyassl_shared.a

test.o: test.c os-include/ppcinline/cyassl.h os-include/proto/cyassl.h

#####################################################################
#
# Link Project
#

#####################################################################
#
# Project cyassl.library
#

$(OUT).elf: $(OBJS) cyassl/src/.libs/libcyassl.a
	ppc-morphos-gcc -noixemul -nostartfiles -mresident32 $(OBJS) -o $(OUT).db -lmath -lcyassl -Lcyassl/src/.libs/ -ldebug
	ppc-morphos-strip -o $(OUT).elf --remove-section=.comment $(OUT).db


bump:
	bumprev2 VERSION $(VERSION) FILE $(OUT) TAG cyassl.library ADD "© 2015 by Filip \"widelec\" Maryjanski, written by wolfSSL"


dump:
	ppc-morphos-objdump --section-headers --all-headers --reloc --disassemble-all $(OUT).db >$(OUT).dump


install: all
	@mkdir -p /sys/libs/
	cp $(OUT).elf /sys/libs/$(OUT)
	cp libcyassl_shared.a /gg/ppc-morphos/lib/libcyassl.a
	@-flushlib $(OUT)


#####################################################################
#
# Project test
#

test: test.c
	ppc-morphos-gcc test.c -o test $(G_IPATH) -O2 -noixemul -lc -ldebug

#####################################################################
#
# Project distribution package
#
dist: 
# delete old archive and directory
	@rm -rf RAM:$(OUT) RAM:$(OUT).lha
# make directory for new one
	@mkdir RAM:$(OUT)
	@mkdir RAM:$(OUT)/Libs
	@mkdir RAM:$(OUT)/demo
# copy library
	@copy >NIL: cyassl.library.elf RAM:$(OUT)/Libs/cyassl.library
# copy docs
	@copy >NIL: doc RAM:$(OUT)/ ALL
# copy includes
	@copy >NIL: os-include RAM:$(OUT)/include ALL
# copy demo
	@copy >NIL: test.c RAM:$(OUT)/demo
	@copy >NIL: test RAM:$(OUT)/demo
	@strip --strip-unneeded --remove-section=.comment RAM:$(OUT)/demo/test
# delete svn stuff
	@find RAM:$(OUT) -name .svn -printf "\"%p\"\n" | xargs rm -rf
#copy default drawer icon
	@copy SYS:Prefs/Presets/Deficons/def_drawer.info RAM:$(OUT).info
	@copy SYS:Prefs/Presets/Deficons/def_drawer.info RAM:$(OUT)/Libs.info
# create archive
	@MOSSYS:C/LHa a -r -a -e RAM:$(OUT).lha RAM:$(OUT) RAM:$(OUT).info >NIL:
# be happy ;-)
	@echo "Build dist package in <RAM:$(OUT).lha> is done."


#####################################################################

$(BUILDDIRS):
	@$(MAKE) -C $(@:build-%=%)

$(CLEANDIRS): 
	@$(MAKE) -C $(@:clean-%=%) clean

.PHONY: subdirs $(DIRS)
.PHONY: subdirs $(BUILDDIRS)
.PHONY: subdirs $(CLEANDIRS)

