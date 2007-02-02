obj-m := ctracer.o

ctracer-y := ctracer_methods.o ctracer_jprobe.o ctracer_relay.o

# Files generated that shall be removed upon make clean
clean-files := ctracer_methods.c

CLASS=sock
#KDIR := /home/acme/git/OUTPUT/qemu/linux-2.6/
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	rm -rf .*.mod.c .*o.cmd *.mod.c *.ko *.o \
	ctracer_methods.c Module.symvers .tmp_versions/ \
	$(CLASS).{fields,functions} ctracer2ostra*

$(src)/ctracer2ostra: ctracer_methods.c
	$(CC) $@.c -o $@

LOG=/tmp/ctracer.log
callgraph:	ctracer2ostra
	./ctracer2ostra < $(LOG) > $(LOG).ostra ; \
	rm -rf $(CLASS).callgraph ; \
	PYTHONPATH=python/ ostra-cg $(CLASS) $(LOG).ostra

$(obj)/ctracer_methods.o: ctracer_methods.c

# ctracer /home/acme/git/OUTPUT/qemu/linux-2.6/vmlinux --src_dir $(src) $(CLASS)
$(src)/ctracer_methods.c:
	ctracer /usr/lib/debug/lib/modules/$(shell uname -r)/vmlinux --src_dir $(src) $(CLASS)
