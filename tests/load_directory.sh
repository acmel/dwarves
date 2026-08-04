#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Test loading DWARF from multiple object files (cus__load_files loop).
# pahole accepts multiple file arguments; each is loaded via
# cus__load_file and their CUs are merged into a single cus list.
#
# This exercises the multi-file loading path that iterates over argv
# in cus__load_files, verifying that structs from all files are
# visible and that filters work across file boundaries.

. "$(dirname "$0")/test_lib.sh"
outdir=$(make_tmpdir)

trap cleanup EXIT

title_log "Multi-file loading (cus__load_files)."

CC=${CC:-gcc}
if ! command -v "${CC%% *}" > /dev/null 2>&1; then
	info_log "skip: $CC not available"
	test_skip
fi

# Create two separate object files with distinct structs
src1="$outdir/file1.c"
src2="$outdir/file2.c"
obj1="$outdir/file1.o"
obj2="$outdir/file2.o"

cat > "$src1" << 'EOF'
struct alpha {
	int	x;
	int	y;
};
struct alpha g1;
EOF

cat > "$src2" << 'EOF'
struct beta {
	char	*name;
	long	count;
};
struct beta g2;
EOF

if ! $CC -g -c -o "$obj1" "$src1" 2>/dev/null; then
	error_log "FAIL: compilation of file1 failed"
	test_fail
fi
if ! $CC -g -c -o "$obj2" "$src2" 2>/dev/null; then
	error_log "FAIL: compilation of file2 failed"
	test_fail
fi

# --- Multiple files on command line ---
# pahole should process both files and show structs from each
output=$(pahole "$obj1" "$obj2" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: multi-file loading produced no output"
	test_fail
fi

if ! echo "$output" | grep -q "struct alpha"; then
	error_log "FAIL: alpha not found from multi-file load"
	test_fail
fi
if ! echo "$output" | grep -q "struct beta"; then
	error_log "FAIL: beta not found from multi-file load"
	test_fail
fi
info_log "multi-file loading: ok"

# --- -C filter works across files ---
# Requesting a struct from the second file should still work
output=$(pahole -C beta "$obj1" "$obj2" 2>/dev/null)
if ! echo "$output" | grep -q "struct beta"; then
	error_log "FAIL: -C beta not found across multi-file load"
	test_fail
fi
# Verify the filter actually filtered out alpha
if echo "$output" | grep -q "struct alpha"; then
	error_log "FAIL: -C beta should not show struct alpha"
	test_fail
fi
info_log "-C filter across files: ok"

# --- --sizes on multiple files ---
output=$(pahole --sizes "$obj1" "$obj2" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: --sizes on multi-file produced no output"
	test_fail
fi
if ! echo "$output" | grep -q "alpha"; then
	error_log "FAIL: alpha not in --sizes multi-file output"
	test_fail
fi
if ! echo "$output" | grep -q "beta"; then
	error_log "FAIL: beta not in --sizes multi-file output"
	test_fail
fi
info_log "--sizes across files: ok"

# --- BTF encoding from multiple files ---
# Each file gets its own BTF section independently
pahole -J "$obj1" 2>/dev/null
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: BTF encode on first file failed (rc=$rc)"
	test_fail
fi
pahole -J "$obj2" 2>/dev/null
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: BTF encode on second file failed (rc=$rc)"
	test_fail
fi

# Read back via BTF format from both
btf_out=$(pahole -F btf "$obj1" "$obj2" 2>/dev/null)
if [ -z "$btf_out" ]; then
	error_log "FAIL: BTF multi-file read produced no output"
	test_fail
fi
if ! echo "$btf_out" | grep -q "struct alpha"; then
	error_log "FAIL: alpha not in BTF multi-file output"
	test_fail
fi
if ! echo "$btf_out" | grep -q "struct beta"; then
	error_log "FAIL: beta not in BTF multi-file output"
	test_fail
fi
info_log "BTF round-trip across files: ok"

test_pass
