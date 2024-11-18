#!/bin/bash

echo -n "Default BTF on a system without BTF: "

ulimit -c 0

# To suppress the "Segmentation fault core dumped" message in bash we
# pipe it to some other command, if it segfaults it will not produce any
# lines and thus we can infer from the number of lines that the segfault
# took place, tricky, but couldn't find any other way to check this
# while suppressing the core dumped message. -acme

nr_lines=$(PAHOLE_VMLINUX_BTF_FILENAME=foobar pahole -F btf list_head 2>&1 | wc -l)

if [ $nr_lines -eq 0 ] ; then
	echo "FAILED"
	exit 1
fi

echo "Ok"
exit 0
