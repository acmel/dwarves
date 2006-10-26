srcdir =	.

prefix =	/usr/local
exec_prefix =	${prefix}
bindir =	$(exec_prefix)/bin
libdir =	$(exec_prefix)/lib

INSTALL_DATA =	${INSTALL} -m 644
CC =		gcc
LIBS =		 -ldw -lelf
INCLUDES =	-I. -I/usr/include/elfutils
CFLAGS =	-g -O2 $(INCLUDES)
LDFLAGS =	  $(LIBS)

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
