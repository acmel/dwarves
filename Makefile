srcdir =	.

prefix =	/usr/local
exec_prefix =	${prefix}
bindir =	$(exec_prefix)/bin
libdir =	$(exec_prefix)/lib

INSTALL_DATA =	${INSTALL} -m 644
CC =		gcc
LIBS =		 -ldw -lelf
INCLUDES =	-I. -I/usr/include/elfutils
CFLAGS =	-g -O2 $(INCLUDES) -Wall
LDFLAGS =	  $(LIBS)

INSTALL = cp

binprefix =

PAHOLE_SOURCES = pahole.c classes.c classes.h
PFUNCT_SOURCES = pfunct.c classes.c classes.h
PREFCNT_SOURCES = prefcnt.c classes.c classes.h
CODIFF_SOURCES = codiff.c classes.c classes.h

PAHOLE_OBJECTS = pahole.o classes.c classes.h
PFUNCT_OBJECTS = pfunct.o classes.c classes.h
PREFCNT_OBJECTS = prefcnt.o classes.c classes.h
CODIFF_OBJECTS = codiff.o classes.c classes.h

all: pahole pfunct prefcnt codiff

default: $(TARGETS)

pahole: $(PAHOLE_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $(PAHOLE_OBJECTS) $(LDFLAGS) 

pfunct: $(PFUNCT_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $(PFUNCT_OBJECTS) $(LDFLAGS) 

prefcnt: $(PREFCNT_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $(PREFCNT_OBJECTS) $(LDFLAGS) 

codiff: $(CODIFF_OBJECTS)
	$(CC) $(CFLAGS) -o $@ $(CODIFF_OBJECTS) $(LDFLAGS) 

install: all
	$(INSTALL) pahole $(bindir)/pahole
	$(INSTALL) pfunct $(bindir)/pfunct
	$(INSTALL) prefcnt $(bindir)/prefcnt
	$(INSTALL) codiff $(bindir)/codiff

uninstall:
	-rm -f $(bindir)/{pahole,pfunct,prefcnt,codiff}

clean:
	rm -f *.o pahole pfunct prefcnt codiff *~

distclean: clean
	rm -f tags
