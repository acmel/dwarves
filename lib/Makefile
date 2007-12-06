obj-m := ctracer.o

ctracer-y := ctracer_collector.o ctracer_relay.o

# Files generated that shall be removed upon make clean
clean-files := ctracer_collector.c

CLASS=sock
#KDIR := /home/acme/git/OUTPUT/qemu/linux-2.6/
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	rm -rf .*.mod.c .*o.cmd *.mod.c *.ko *.o \
	ctracer_collector.c ctracer_methods.stp \
	ctracer_classes.h \
	Module.symvers .tmp_versions/ \
	$(CLASS).{fields,functions} ctracer2ostra*

$(src)/ctracer2ostra: ctracer_methods.stp
	$(CC) $@.c -o $@

cu_blacklist_file=/usr/share/dwarves/runtime/linux.blacklist.cu

LOG=/tmp/ctracer.log
callgraph:	ctracer2ostra
	./ctracer2ostra < $(LOG) > $(LOG).ostra ; \
	rm -rf $(CLASS).callgraph ; \
	PYTHONPATH=python/ ostra-cg $(CLASS) $(LOG).ostra

$(obj)/ctracer_collector.o: ctracer_collector.c

$(src)/ctracer_collector.c:
	ctracer --src_dir $(src) /usr/lib/debug/lib/modules/$(shell uname -r)/vmlinux \
		--cu_blacklist $(cu_blacklist_file) $(CLASS)
