#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Test if BTF generated serially matches reproducible parallel DWARF loading + serial BTF encoding
# Arnaldo Carvalho de Melo <acme@redhat.com> (C) 2024-

vmlinux=${vmlinux:-$1}

if [ -z "$vmlinux" ] ; then
	vmlinux=$(pahole --running_kernel_vmlinux)
fi

if [ ! -f "$vmlinux" ] ; then
	echo "$vmlinux file not available, please specify another"
	exit 2
fi

outdir=$(mktemp -d /tmp/reproducible_build.sh.XXXXXX)

echo -n "Parallel reproducible DWARF Loading/Serial BTF encoding: "

test -n "$VERBOSE" && printf "\nserial encoding...\n"

pahole --btf_features=default --btf_encode_detached=$outdir/vmlinux.btf.serial $vmlinux
bpftool btf dump file $outdir/vmlinux.btf.serial > $outdir/bpftool.output.vmlinux.btf.serial

nr_proc=$(getconf _NPROCESSORS_ONLN)

for threads in $(seq $nr_proc) ; do
	test -n "$VERBOSE" && echo $threads threads encoding
	pahole -j$threads --btf_features=default,reproducible_build --btf_encode_detached=$outdir/vmlinux.btf.parallel.reproducible $vmlinux &
	pahole=$!
	# HACK: Wait a bit for pahole to start its threads
	sleep 0.3s
	# PID part to remove ps output headers
	nr_threads_started=$(ps -L -C pahole | grep -v PID | wc -l)

	if [ $threads -gt 1 ] ; then
		((nr_threads_started -= 1))
	fi

	if [ $threads != $nr_threads_started ] ; then
		echo "ERROR: pahole asked to start $threads encoding threads, started $nr_threads_started"
		exit 1;
	fi

	# ps -L -C pahole | grep -v PID | nl
	test -n "$VERBOSE" && echo $nr_threads_started threads started
	wait $pahole
	rm -f $outdir/bpftool.output.vmlinux.btf.parallel.reproducible
	bpftool btf dump file $outdir/vmlinux.btf.parallel.reproducible > $outdir/bpftool.output.vmlinux.btf.parallel.reproducible
	test -n "$VERBOSE" && echo "diff from serial encoding:"
	diff -u $outdir/bpftool.output.vmlinux.btf.serial $outdir/bpftool.output.vmlinux.btf.parallel.reproducible > $outdir/diff
	if [ -s $outdir/diff ] ; then
		echo "ERROR: BTF generated from DWARF in parallel is different from the one generated in serial!"
		exit 1
	fi
	test -n "$VERBOSE" && echo -----------------------------
done

rm $outdir/*
rmdir $outdir

echo "Ok"

exit 0
