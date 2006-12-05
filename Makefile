srcdir =	.

prefix =	/usr/local
exec_prefix =	${prefix}
bindir =	$(exec_prefix)/bin
libdir =	$(exec_prefix)/lib

INSTALL_DATA =	${INSTALL} -m 644
CC =		gcc
LIBS =		-L. -lclasses -ldw -lelf
INCLUDES =	-I. -I/usr/include/elfutils
CFLAGS =	-g -O2 -Wall
CPPFLAGS +=	$(INCLUDES)
LDFLAGS +=	$(LIBS)
LINKFLAGS =	-shared

INSTALL = cp

binprefix =

LIBCLASSES_SOURCES = classes.c
LIBCLASSES_OBJECTS = classes.o
LIBCLASSES_MAJOR = 1
LIBCLASSES_MINOR = 0
LIBCLASSES_PATCH = 0

ifdef STATIC
LIBCLASSES  = libclasses.a
else
LIBCLASSES  = libclasses.so
LDFLAGS += -Wl,-rpath,$(CURDIR)/$(srcdir)
endif

PAHOLE_SOURCES = pahole.c
PFUNCT_SOURCES = pfunct.c
PREFCNT_SOURCES = prefcnt.c
CODIFF_SOURCES = codiff.c

PAHOLE_OBJECTS = pahole.o
PFUNCT_OBJECTS = pfunct.o
PREFCNT_OBJECTS = prefcnt.o
CODIFF_OBJECTS = codiff.o

all: pahole pfunct prefcnt codiff

default: $(TARGETS)

$(LIBCLASSES_OBJECTS): $(LIBCLASSES_SOURCES) classes.h

libclasses.so: $(LIBCLASSES_OBJECTS)
	$(CC) $(LINKFLAGS) \
	  -o $@.$(LIBCLASSES_MAJOR).$(LIBCLASSES_MINOR).$(LIBCLASSES_PATCH) $<
	ln -f -s $@.$(LIBCLASSES_MAJOR).$(LIBCLASSES_MINOR).$(LIBCLASSES_PATCH) \
	  $@.$(LIBCLASSES_MAJOR).$(LIBCLASSES_MINOR)
	ln -f -s $@.$(LIBCLASSES_MAJOR).$(LIBCLASSES_MINOR) \
	  $@.$(LIBCLASSES_MAJOR)
	ln -f -s $@.$(LIBCLASSES_MAJOR) \
	  $@

libclasses.a: $(LIBCLASSES_OBJECTS)
	$(AR) $(ARFLAGS) $@ $^

pahole: $(PAHOLE_OBJECTS) $(LIBCLASSES)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $(PAHOLE_OBJECTS) $(LDFLAGS) 

pfunct: $(PFUNCT_OBJECTS) $(LIBCLASSES)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $(PFUNCT_OBJECTS) $(LDFLAGS) 

prefcnt: $(PREFCNT_OBJECTS) $(LIBCLASSES)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $(PREFCNT_OBJECTS) $(LDFLAGS) 

codiff: $(CODIFF_OBJECTS) $(LIBCLASSES)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $(CODIFF_OBJECTS) $(LDFLAGS) 

install: all
	$(INSTALL) pahole $(bindir)/pahole
	$(INSTALL) pfunct $(bindir)/pfunct
	$(INSTALL) prefcnt $(bindir)/prefcnt
	$(INSTALL) codiff $(bindir)/codiff

uninstall:
	-rm -f $(bindir)/{pahole,pfunct,prefcnt,codiff}

clean:
	rm -f *.o pahole pfunct prefcnt codiff *~ libclasses.*

distclean: clean
	rm -f tags
