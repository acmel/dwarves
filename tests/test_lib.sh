#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (c) 2026, Oracle and/or its affiliates.
#
# Common helper functions for the testsuite.
#

# if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
# 	echo "This script is meant to be sourced. Please use 'source test_lib.sh'."
# 	exit 1
# fi

check_color_support()
{
	if [ ! -z "$color_support" ] ; then
		return $color_support
	else
		if tput colors >/dev/null 2>&1; then
			num_colors=$(tput colors)
			if [ $num_colors -gt 0 ] && [ -n "$BASH_VERSION" ] ; then
				RED='\033[0;31m'
				GREEN='\033[0;32m'
				YELLOW='\033[0;33m'
				NC='\033[0m'
				color_support=1
			else
				RED=''
				GREEN=''
				YELLOW=''
				NC=''
				color_support=0
			fi
		else
			RED=''
			GREEN=''
			YELLOW=''
			NC=''
			color_support=0
		fi
	fi
	return $color_support
}

color_print()
{
	if [ $color_support -eq 1 ] ; then
		echo -e "$1$2${NC}"
	else
		echo $1
	fi
}

# Look for a vmlinux to use in the tests, given that most tests don't
# need the vmlinux to match the running kernel, just need a vmlinux
# with the kernel data structures, so search the standard places where
# the debug vmlinux is installed, trying the newest first.
find_vmlinux()
{
	local vmlinux

	# Prefer the /usr/lib/debug/lib/modules/<version>/vmlinux as that is
	# how Fedora installs the kernel vmlinux with debugging info,
	# /lib/modules/<version>/build/vmlinux is how the kernel build
	# directory installs it, and /boot/vmlinux-<version> on some other
	# distributions.
	ls -1 /usr/lib/debug/lib/modules/*/vmlinux \
		/lib/modules/*/build/vmlinux \
		/boot/vmlinux-* 2>/dev/null | sort -V | tail -1
}

get_vmlinux()
{
	
	vmlinux=${vmlinux:-$1}

	# The tests runner may pass the build directory as argument, so
	# if it isn't a real vmlinux file, consider it as not specified
	# and try to auto-detect a vmlinux.
	if [ -n "$vmlinux" ] && [ ! -f "$vmlinux" ] ; then
		vmlinux=""
	fi

	if [ -z "$vmlinux" ] ; then
		vmlinux=$(pahole --running_kernel_vmlinux 2>/dev/null)
		if [ -z "$vmlinux" ] ; then
			# No vmlinux matching the running kernel, so try to find
			# any vmlinux to run the tests, most tests don't need it
			# to match the running kernel.
			vmlinux=$(find_vmlinux)
			if [ -z "$vmlinux" ] ; then
				check_color_support
				color_print ${RED} "Please specify a vmlinux file to operate on"
				exit 2
			fi
		fi
	fi

	if [ ! -f "$vmlinux" ] ; then
		echo ${RED} "$vmlinux file not available, please specify another"
		exit 2
	fi

	echo $vmlinux
	return 0
}

make_tmpdir()
{
	outdir=$(mktemp -d /tmp/$(basename "$0").XXXXXX)
	echo $outdir
	return 0
}

make_tmpobj()
{
	outobj=$(mktemp $outdir/$0.obj.XXXXXX.o)
	echo $outobj
	return 0
}

make_tmpsrc()
{
	outsrc=$(mktemp $outdir/$0.src.XXXXXX.c)
	echo $outsrc
	return 0
}

make_tmpfile()
{
	outfile=$(mktemp $outdir/$0.data.XXXXXX)
	echo $outfile
	return 0
}

info_log()
{
	printf "   "
	echo $1
}

title_log()
{
	check_color_support
	color_print ${YELLOW} "$1"
}

verbose_log()
{
	if [[ -n "$VERBOSE" ]]; then
		printf "   "
		echo $1
	fi
}

error_log()
{
	printf "   "
	check_color_support
	color_print $RED "${1}"
}

test_softfail()
{
	if [ -z "$softfail_count" ] ; then
		softfail_count=1
	else
		softfail_count=$((softfail_count + 1))
	fi
}

test_fail()
{
	trap - EXIT
	check_color_support
	color_print ${RED} "Test $0 failed"
	if [ -d "$outdir" ]; then
		color_print ${RED} "Test data is in $outdir"
	fi
	exit 1
}

check_softfail()
{
	if [ ! -z "$softfail_count" ] ; then
		check_color_support
		color_print ${RED} "Soft failures: $softfail_count"
		return 1
	else
		return 0
	fi
}

test_pass()
{
	check_color_support
	color_print ${GREEN} "Test $0 passed"
	exit 0
}

test_skip()
{
	check_color_support
	color_print ${YELLOW} "Skipping test ..."
	exit 2
}

cleanup()
{
	rm ${outdir}/*
	rmdir $outdir
	return 0
}
