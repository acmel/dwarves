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
	
	# Priority: VMLINUX env var > passed argument > auto-detect
	vmlinux=${VMLINUX:-${vmlinux:-$1}}

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
				color_print ${RED} "Please specify a vmlinux file to operate on" >&2
				exit 2
			fi
		fi
	fi

	if [ ! -f "$vmlinux" ] ; then
		check_color_support
		if [ -n "$VMLINUX" ] ; then
			color_print ${RED} "VMLINUX env var points to non-existent file: $vmlinux" >&2
			color_print ${RED} "Either unset VMLINUX or set it to a valid path" >&2
			echo "   skip: no vmlinux available (VMLINUX points to non-existent file)" >&2
		else
			color_print ${RED} "$vmlinux file not available, please specify another" >&2
			echo "   skip: no vmlinux available" >&2
		fi
		exit 2
	fi

	echo $vmlinux
	return 0
}

make_tmpdir()
{
	# Ensure master test directory exists
	# All test artifacts go under /tmp/pahole-tests/ for easy cleanup
	test_master_dir="/tmp/pahole-tests"
	mkdir -p "$test_master_dir"

	outdir=$(mktemp -d "$test_master_dir/$(basename "$0").XXXXXX")
	echo $outdir
	return 0
}

make_tmpobj()
{
	outobj=$(mktemp "$outdir/$(basename "$0").obj.XXXXXX.o")
	echo $outobj
	return 0
}

make_tmpsrc()
{
	outsrc=$(mktemp "$outdir/$(basename "$0").src.XXXXXX.c")
	echo $outsrc
	return 0
}

make_tmpfile()
{
	outfile=$(mktemp "$outdir/$(basename "$0").data.XXXXXX")
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
	printf "   " >&2
	check_color_support
	color_print $RED "${1}" >&2
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
		if [ "${VERBOSE:-0}" = "1" ]; then
			# In verbose mode, dump test data inline for dm.log captures
			echo "=== Test artifacts in $outdir ==="
			echo "--- File list ---"
			ls -lah "$outdir" 2>&1 || echo "Failed to list directory"
			echo ""
			# Show content of each file (limit to reasonable size)
			for f in "$outdir"/*; do
				if [ -f "$f" ]; then
					file_size=$(wc -c < "$f" 2>/dev/null || echo "unknown")
					# Detect binary files by extension and file command
					# Skip: .o, .so, .a (object/library files), ELF executables
					# Show: empty files, .txt/.c/.h/.sh/.log, and anything 'file' says is text
					basename_f=$(basename "$f")
					case "$basename_f" in
						*.o|*.so|*.so.*|*.a)
							# Object files, libraries - always skip
							echo "--- Skipping binary file: $basename_f (${file_size} bytes) ---"
							;;
						*)
							# Empty files or text-like: always show
							# Non-empty: check with file command
							if [ "$file_size" -eq 0 ] || file "$f" 2>/dev/null | grep -qE "text|empty|ASCII"; then
								echo "--- Content of $basename_f (${file_size} bytes) ---"
								# Show first 500 lines max to avoid overwhelming output
								if [ "$file_size" -gt 0 ]; then
									head -500 "$f" 2>&1 || echo "Failed to read file"
								else
									echo "(empty file)"
								fi
								echo ""
							else
								echo "--- Skipping binary file: $basename_f (${file_size} bytes) ---"
							fi
							;;
					esac
				fi
			done
			echo "=== End of test artifacts ==="
		else
			color_print ${RED} "Test data is in $outdir"
		fi
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
	if [ -n "$outdir" ] && [ -d "$outdir" ]; then
		rm ${outdir}/*
		rmdir $outdir
	fi
	return 0
}
