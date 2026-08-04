#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Test cacheline boundary display with large structs.
# Exercises cacheline annotation paths in dwarves_fprintf.c
# when structs span multiple cache lines.

. "$(dirname "$0")/test_lib.sh"
outdir=$(make_tmpdir)

trap cleanup EXIT

title_log "Cacheline boundary display with large structs."

CC=${CC:-gcc}
if ! command -v "${CC%% *}" > /dev/null 2>&1; then
	info_log "skip: $CC not available"
	test_skip
fi

src=$(make_tmpsrc)
obj=$(make_tmpobj)

# Struct spans 192 bytes (3 cache lines at 64 bytes, 6 at 32 bytes).
# Members are arranged so that cacheline boundaries fall between them,
# forcing dwarves_fprintf.c to emit boundary annotations.
cat > "$src" << 'EOF'
struct big_struct {
	/* header (first cache line at 64-byte boundary) */
	int id;
	long counter;
	char name[48];
	/* second cache line */
	double values[8];
	/* third cache line */
	int flags;
	char padding[60];
};

struct big_struct g_big;
EOF

if ! $CC -g -c -o "$obj" "$src" 2>/dev/null; then
	error_log "FAIL: compilation failed"
	test_fail
fi

# --- Test 1: -c 64 produces cacheline boundary markers ---
# With 192-byte struct and 64-byte cachelines, we expect boundary
# annotations at offsets 64 and 128 between struct members.
out64=$(pahole -c 64 -C big_struct "$obj" 2>/dev/null)
if [ -z "$out64" ]; then
	error_log "FAIL: -c 64 -C big_struct produced no output"
	test_fail
fi

boundary_count_64=$(echo "$out64" | grep -c "cacheline.*boundary")
if [ "$boundary_count_64" -lt 1 ]; then
	error_log "FAIL: -c 64 did not produce any cacheline boundary markers"
	test_fail
fi
info_log "-c 64: $boundary_count_64 boundary marker(s) found"

# The summary line should report cachelines: 3 for a 192-byte struct
# at 64-byte cacheline size (ceil(192/64) = 3).
if ! echo "$out64" | grep -q "cachelines: 3"; then
	error_log "FAIL: -c 64 summary does not show 'cachelines: 3'"
	test_fail
fi
info_log "-c 64: cachelines: 3 in summary"

# --- Test 2: -c 32 shows more cachelines than -c 64 ---
# Smaller cacheline size means the same struct spans more cachelines.
# At 32 bytes: ceil(192/32) = 6 cachelines.
out32=$(pahole -c 32 -C big_struct "$obj" 2>/dev/null)
if [ -z "$out32" ]; then
	error_log "FAIL: -c 32 -C big_struct produced no output"
	test_fail
fi

if ! echo "$out32" | grep -q "cacheline.*boundary"; then
	error_log "FAIL: -c 32 did not produce cacheline boundary markers"
	test_fail
fi

# Extract cacheline counts from the summary comments.
# With -c 32, the struct should report cachelines: 6.
cl_count_32=$(echo "$out32" | grep -o "cachelines: [0-9]*" | grep -o "[0-9]*")
cl_count_64=$(echo "$out64" | grep -o "cachelines: [0-9]*" | grep -o "[0-9]*")

if [ -z "$cl_count_32" ] || [ -z "$cl_count_64" ]; then
	error_log "FAIL: could not parse cacheline counts from output"
	test_fail
fi

# A smaller cacheline size must produce a larger cacheline count
# for the same struct.
if [ "$cl_count_32" -le "$cl_count_64" ]; then
	error_log "FAIL: -c 32 cachelines ($cl_count_32) should exceed -c 64 ($cl_count_64)"
	test_fail
fi
info_log "-c 32: cachelines: $cl_count_32 > -c 64 cachelines: $cl_count_64"

# --- Test 3: --sizes -c 64 runs without error ---
# Combines size listing with cacheline setting; should not crash
# or produce an error exit code.
sizes_out=$(pahole --sizes -c 64 "$obj" 2>/dev/null)
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: --sizes -c 64 exited with code $rc"
	test_fail
fi
if [ -z "$sizes_out" ]; then
	error_log "FAIL: --sizes -c 64 produced no output"
	test_fail
fi
# The sizes output should list big_struct with its size (192 bytes).
if ! echo "$sizes_out" | grep -q "big_struct"; then
	error_log "FAIL: --sizes -c 64 did not list big_struct"
	test_fail
fi
info_log "--sizes -c 64: ok"

test_pass
