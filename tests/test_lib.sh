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

# Auto-detect and use just-built binaries from build/ directory.
# When running tests after 'make -C build', automatically use those binaries
# instead of distro-installed or ~/bin versions, with no PATH setup required.
tests_root=$(cd "$(dirname "$0")" && pwd)
build_dir="$tests_root/../build"
if [ -d "$build_dir" ] && [ -x "$build_dir/pahole" ]; then
	export PATH="$build_dir:$PATH"
	export LD_LIBRARY_PATH="$build_dir:${LD_LIBRARY_PATH}"
fi

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

# Get perf binary with debug info, building from source if needed.
# Uses a shared cache directory for all tests in the run to avoid rebuilding.
# Returns: path to perf binary, or exits with skip if unavailable
get_perf_with_debug()
{
	# Check if user provided a pre-built perf binary via PERF_BIN
	# Useful when perf is already built (e.g., O=/tmp/build/perf)
	if [ -n "$PERF_BIN" ]; then
		if [ ! -f "$PERF_BIN" ]; then
			info_log "skip: PERF_BIN points to non-existent file: $PERF_BIN" >&2
			test_skip
		fi
		# Verify it has debug info
		if pahole --features=force_cu_merging -F dwarf -C perf_event_header "$PERF_BIN" 2>/dev/null | grep -q "^struct perf_event_header {"; then
			echo "$PERF_BIN"
			return 0
		else
			info_log "skip: PERF_BIN=$PERF_BIN lacks DWARF debug info" >&2
			test_skip
		fi
	fi

	# Check if system perf has usable DWARF debug info
	# Alpine Linux packages perf without debuginfo, so we can't rely on "not stripped"
	# check alone - verify actual DWARF type info is present using pahole.
	system_perf="$(command -v perf 2>/dev/null)"
	if [ -n "$system_perf" ]; then
		# First quick check: is it stripped? If yes, skip pahole verification
		if file "$system_perf" | grep -q "not stripped"; then
			# Binary has symbols, now verify DWARF debug info is actually present.
			# Check that pahole can extract type information from the binary.
			if pahole --features=force_cu_merging -F dwarf -C perf_event_header "$system_perf" 2>/dev/null | grep -q "^struct perf_event_header {"; then
				echo "$system_perf"
				return 0
			fi
			# Binary not stripped but lacks DWARF - Alpine case
		fi
		# Stripped or lacks DWARF, need to build from source
	fi

	# Build from source if needed - use shared cache across all tests
	perf_cache="${PERF_CACHE_DIR:-/tmp/pahole-test-perf-cache}"
	perf_bin="$perf_cache/tools/perf/perf"
	perf_complete="$perf_cache/.build-complete"

	# If build is complete and binary exists, use it
	if [ -f "$perf_complete" ] && [ -x "$perf_bin" ]; then
		echo "$perf_bin"
		return 0
	fi

	# Need to build perf - use atomic directory creation as lock to prevent parallel builds
	# (88 tests run concurrently, only one should build)
	# Download perf-specific tarball (much smaller than full kernel tree)
	# See https://www.kernel.org/pub/linux/kernel/tools/perf/HOWTO.build.perf
	lockdir="$perf_cache.lock"

	# Try to acquire lock by creating directory (atomic operation)
	max_wait=300  # seconds
	waited=0
	got_lock=0

	while [ $waited -lt $max_wait ]; do
		if mkdir "$lockdir" 2>/dev/null; then
			got_lock=1
			break
		fi

		# Another test is building, check if it's done
		if [ -f "$perf_complete" ] && [ -x "$perf_bin" ]; then
			echo "$perf_bin"
			return 0
		fi

		# Wait a bit and retry
		sleep 1
		waited=$((waited + 1))
	done

	if [ $got_lock -eq 0 ]; then
		info_log "skip: timeout waiting for perf build to complete" >&2
		test_skip
	fi

	# Got lock, check again (another test may have finished while we waited)
	if [ -f "$perf_complete" ] && [ -x "$perf_bin" ]; then
		rmdir "$lockdir"
		echo "$perf_bin"
		return 0
	fi

	# Clean up any incomplete build from previous failed attempt
	if [ -d "$perf_cache" ]; then
		rm -rf "$perf_cache"
	fi

	# Build perf from source
	if [ ! -d "$perf_cache" ]; then
		mkdir -p "$perf_cache"

		# Priority: PERF_SRC_DIR env var > /tmp/perf_src_dir > download from kernel.org
		# PERF_SRC_DIR allows using a pre-downloaded kernel source tree to avoid
		# hitting kernel.org mirrors (which fight against automatic downloaders)
		# /tmp/perf_src_dir is the standard location for containers (bind-mount source there)
		perf_src_dir=""

		if [ -n "$PERF_SRC_DIR" ]; then
			# Use user-provided source directory
			perf_src_dir="$PERF_SRC_DIR"
			info_log "Building perf from PERF_SRC_DIR=$perf_src_dir..." >&2
		elif [ -d "/tmp/perf_src_dir/tools/perf" ]; then
			# Fall back to /tmp/perf_src_dir if available (container-friendly)
			perf_src_dir="/tmp/perf_src_dir"
			info_log "Building perf from $perf_src_dir..." >&2
		fi

		if [ -n "$perf_src_dir" ]; then
			# Build from local source directory using O= for out-of-tree build
			# This avoids copying sources and puts build artifacts in cache directory

			# Verify it's a valid kernel/perf source tree
			if [ ! -d "$perf_src_dir/tools/perf" ]; then
				info_log "skip: $perf_src_dir does not contain tools/perf directory" >&2
				info_log "Source directory should point to kernel root (contains tools/perf/)" >&2
				rm -rf "$perf_cache"
				rmdir "$lockdir"
				test_skip
			fi

			# Build perf with debug info using O= for out-of-tree build
			# DEBUG=1 enables -g, EXTRA_CFLAGS adds explicit debug flags for paranoia
			if ! make -C "$perf_src_dir/tools/perf" O="$perf_cache/perf-build" \
				DEBUG=1 WERROR=0 EXTRA_CFLAGS="-g -ggdb3" \
				> "$perf_cache/build.log" 2>&1; then
				# Preserve build log for debugging before cleanup
				if [ -f "$perf_cache/build.log" ]; then
					mv "$perf_cache/build.log" "/tmp/pahole-perf-build-failed.log" 2>/dev/null || true
					info_log "skip: failed to build perf from $perf_src_dir" >&2
					info_log "See /tmp/pahole-perf-build-failed.log for details" >&2
				else
					info_log "skip: failed to build perf from $perf_src_dir" >&2
				fi
				rm -rf "$perf_cache"
				rmdir "$lockdir"
				test_skip
			fi

			perf_build_dir="$perf_cache/perf-build"
		else
			# No local source, download from kernel.org as last resort
			info_log "Downloading and building perf with debug info (one-time setup)..." >&2
			info_log "Tip: set PERF_SRC_DIR or place kernel at /tmp/perf_src_dir to avoid downloads" >&2

			perf_version="6.19.0"
			perf_tarball="perf-${perf_version}.tar.xz"
			perf_url="https://mirrors.edge.kernel.org/pub/linux/kernel/tools/perf/v${perf_version}/${perf_tarball}"

			# Download perf tarball (~3MB vs ~200MB+ for full kernel)
			# Try wget first, fall back to curl
			download_ok=0
			if command -v wget > /dev/null 2>&1; then
				if wget -q -O "$perf_cache/$perf_tarball" "$perf_url" 2>"$perf_cache/download.log"; then
					download_ok=1
				fi
			elif command -v curl > /dev/null 2>&1; then
				if curl -sL -o "$perf_cache/$perf_tarball" "$perf_url" 2>"$perf_cache/download.log"; then
					download_ok=1
				fi
			else
				info_log "skip: neither wget nor curl available to download perf" >&2
				info_log "Set PERF_SRC_DIR to build from local kernel source instead" >&2
				rm -rf "$perf_cache"
				rmdir "$lockdir"
				test_skip
			fi

			if [ $download_ok -eq 0 ]; then
				info_log "skip: failed to download perf tarball from $perf_url" >&2
				info_log "Set PERF_SRC_DIR to build from local kernel source instead" >&2
				rm -rf "$perf_cache"
				rmdir "$lockdir"
				test_skip
			fi

			# Extract tarball
			if ! tar -xf "$perf_cache/$perf_tarball" -C "$perf_cache" 2>"$perf_cache/extract.log"; then
				info_log "skip: failed to extract perf tarball" >&2
				rm -rf "$perf_cache"
				rmdir "$lockdir"
				test_skip
			fi

			# Move extracted directory to expected location
			if ! mv "$perf_cache/perf-${perf_version}" "$perf_cache/perf-src" 2>"$perf_cache/mv.log"; then
				info_log "skip: failed to move extracted perf directory" >&2
				rm -rf "$perf_cache"
				rmdir "$lockdir"
				test_skip
			fi

			# Build perf with debug info
			# DEBUG=1 enables -g, EXTRA_CFLAGS adds explicit debug flags for paranoia
			if ! make -C "$perf_cache/perf-src/tools/perf" \
				DEBUG=1 WERROR=0 EXTRA_CFLAGS="-g -ggdb3" \
				> "$perf_cache/build.log" 2>&1; then
				# Preserve build log for debugging before cleanup
				if [ -f "$perf_cache/build.log" ]; then
					mv "$perf_cache/build.log" "/tmp/pahole-perf-build-failed.log" 2>/dev/null || true
					info_log "skip: failed to build perf from source" >&2
					info_log "See /tmp/pahole-perf-build-failed.log for details" >&2
				else
					info_log "skip: failed to build perf from source" >&2
				fi
				rm -rf "$perf_cache"
				rmdir "$lockdir"
				test_skip
			fi

			perf_build_dir="$perf_cache/perf-src/tools/perf"
		fi  # end if [ -n "$perf_src_dir" ]

		# Find the actual ELF binary (perf creates a script wrapper, real binary elsewhere)
		# Look for 'perf' ELF file in the build output directory
		built_perf=$(find "$perf_build_dir" -type f -name 'perf' -executable \
			-exec file {} \; 2>/dev/null | grep 'ELF.*executable' | head -1 | cut -d: -f1)

		if [ -z "$built_perf" ] || [ ! -f "$built_perf" ]; then
			info_log "skip: could not find built perf ELF binary" >&2
			find "$perf_cache/perf-src/tools/perf" -name 'perf' > "$perf_cache/find.log" 2>&1
			rm -rf "$perf_cache"
			rmdir "$lockdir"
			test_skip
		fi

		# Verify binary has usable debug info before moving
		# Check that pahole can actually extract type information, not just that
		# the binary has some debug sections (file "not stripped" is insufficient)
		if ! pahole --features=force_cu_merging -F dwarf -C perf_event_header "$built_perf" 2>/dev/null | grep -q "^struct perf_event_header {"; then
			info_log "skip: built perf binary lacks DWARF type info (DEBUG=1 build failed)" >&2
			rm -rf "$perf_cache"
			rmdir "$lockdir"
			test_skip
		fi

		# Move built binary to expected location
		mkdir -p "$perf_cache/tools/perf"
		if ! mv "$built_perf" "$perf_bin" 2>"$perf_cache/mv-bin.log"; then
			info_log "skip: failed to move perf binary" >&2
			rm -rf "$perf_cache"
			rmdir "$lockdir"
			test_skip
		fi

		# Ensure filesystem has flushed the moved file before marking complete
		sync

		# Mark build as complete (atomic operation)
		touch "$perf_complete"

		info_log "Built perf from source at $perf_bin" >&2
	fi

	# Release lock
	rmdir "$lockdir" 2>/dev/null

	if [ -f "$perf_complete" ] && [ -x "$perf_bin" ]; then
		echo "$perf_bin"
		return 0
	else
		info_log "skip: perf not available"
		test_skip
	fi
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
	# Busybox mktemp doesn't support suffix in template, GNU mktemp does.
	# Try --suffix first, fall back to manual rename for portability.
	if outobj=$(mktemp --suffix=.o "$outdir/$(basename "$0").obj.XXXXXX" 2>/dev/null); then
		echo $outobj
		return 0
	else
		# Fallback: create without suffix, then rename
		tmp=$(mktemp "$outdir/$(basename "$0").obj.XXXXXX")
		outobj="${tmp}.o"
		mv "$tmp" "$outobj"
		echo $outobj
		return 0
	fi
}

make_tmpsrc()
{
	# Busybox mktemp doesn't support suffix in template, GNU mktemp does.
	# Try --suffix first, fall back to manual rename for portability.
	if outsrc=$(mktemp --suffix=.c "$outdir/$(basename "$0").src.XXXXXX" 2>/dev/null); then
		echo $outsrc
		return 0
	else
		# Fallback: create without suffix, then rename
		tmp=$(mktemp "$outdir/$(basename "$0").src.XXXXXX")
		outsrc="${tmp}.c"
		mv "$tmp" "$outsrc"
		echo $outsrc
		return 0
	fi
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

# Check if bpftool can dump a BTF file (i.e., supports the BTF format)
# Usage: check_bpftool_btf_support <btf_file> || test_skip_with_msg "reason"
# Returns 0 if bpftool can dump the file, 1 if not
check_bpftool_btf_support()
{
	local btf_file="$1"

	if ! command -v bpftool >/dev/null 2>&1; then
		return 1
	fi

	if [ ! -f "$btf_file" ]; then
		return 1
	fi

	# Try to dump the BTF file
	# Older bpftool versions return empty output when they encounter
	# BTF features they don't support (TYPE_TAG, DECL_TAG, etc.)
	local dump
	dump=$(bpftool btf dump file "$btf_file" 2>/dev/null)

	if [ -z "$dump" ]; then
		return 1
	fi

	return 0
}

cleanup()
{
	if [ -n "$outdir" ] && [ -d "$outdir" ]; then
		rm ${outdir}/*
		rmdir $outdir
	fi
	return 0
}
