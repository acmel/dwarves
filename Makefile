srcdir =	.

prefix =	/usr/local
exec_prefix =	${prefix}
bindir =	$(exec_prefix)/bin
libdir =	$(exec_prefix)/lib

INSTALL_DATA =	${INSTALL} -m 644
SHELL =		/bin/sh
CC =		gcc
LIBS =		 -L../libdwarf -ldwarf -lelf
INCLUDES =	-I. -I$(srcdir) -I$(srcdir)/../libdwarf
CFLAGS =	-g -O2 $(INCLUDES)
LDFLAGS =	  $(LIBS)

DIRINC =  $(srcdir)/../libdwarf
INSTALL = cp

binprefix =

OBJECTS =  pahole.o

all: pahole

default: $(TARGETS)

pahole: $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $(OBJECTS) $(LDFLAGS) 

install: all
	$(INSTALL) pahole $(bindir)/pahole

uninstall:
	-rm -f $(bindir)/pahole

clean:
	rm -f *.o pahole *~

distclean: clean
	rm -f tags
