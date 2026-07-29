#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Test BTF multi-dimensional array encoding and loading round-trip.
#
# BTF represents each dimension of a multi-dimensional array as a separate
# chained BTF_KIND_ARRAY node.  For int a[3][4]:
#   inner: ARRAY { type=int,   nelems=4 }
#   outer: ARRAY { type=inner, nelems=3 }
#
# The encoder (btf_encoder.c) must emit one BTF_KIND_ARRAY per dimension,
# from innermost to outermost.  The loader (btf_loader.c) must collapse
# the chain back into pahole's flat multi-dim array_type.
#
# Tests:
#  1. BTF dump has the right number of chained ARRAY nodes for each dim
#  2. pahole -F btf output matches DWARF output for all array members
#  3. Array sizes are preserved across the encode→load round-trip

. "$(dirname "$0")/test_lib.sh"

outdir=$(make_tmpdir)
trap cleanup EXIT

title_log "BTF multi-dimensional array encoding and round-trip."

CC=${CC:-gcc}
if ! command -v ${CC%% *} > /dev/null 2>&1; then
	info_log "skip: $CC not available"
	test_skip
fi

if ! command -v bpftool > /dev/null 2>&1; then
	info_log "skip: bpftool not available"
	test_skip
fi

src=$(make_tmpsrc)
obj=$(make_tmpobj)

cat > "$src" << 'EOF'
struct multidim {
	int a1d[5];
	int a2d[3][4];
	int a3d[2][3][4];
	char s[8];
};

struct multidim g;
EOF

$CC -g -c -o "$obj" "$src" 2>/dev/null
if [ $? -ne 0 ]; then
	error_log "FAIL: compilation failed"
	test_fail
fi

# --- BTF encoding ---

btf="$outdir/arrays.btf"
pahole --btf_encode_detached="$btf" "$obj" 2>/dev/null
if [ $? -ne 0 ] || [ ! -s "$btf" ]; then
	error_log "FAIL: pahole --btf_encode_detached failed"
	test_fail
fi

dump=$(bpftool btf dump file "$btf" 2>/dev/null)
if [ -z "$dump" ]; then
	error_log "FAIL: bpftool btf dump produced no output"
	test_fail
fi

# --- Check 1: chained ARRAY nodes for int[3][4] ---
# After btf__dedup the chain int[4] → int[3][4] must be present.

inner4_id=$(echo "$dump" | grep "ARRAY.*nr_elems=4" | head -1 | sed 's/\[\([0-9]*\)\].*/\1/')
if [ -z "$inner4_id" ]; then
	error_log "FAIL: no ARRAY with nr_elems=4 found for int[3][4] inner dim"
	test_fail
fi
info_log "inner ARRAY nr_elems=4 at type_id=$inner4_id: ok"

# There must be an ARRAY referencing inner4_id with nr_elems=3 (outer of int[3][4])
if ! echo "$dump" | grep -q "ARRAY.*type_id=${inner4_id}.*nr_elems=3"; then
	error_log "FAIL: no outer ARRAY(type=${inner4_id}, nr_elems=3) for int[3][4]"
	test_fail
fi
info_log "outer ARRAY nr_elems=3 referencing inner: ok"

# --- Check 2: struct member type_ids must differ between a2d and a3d ---
# If they were the same, a3d would not add the extra outer dimension.

a2d_type=$(echo "$dump" | grep "'a2d'" | sed "s/.*type_id=\([0-9]*\).*/\1/")
a3d_type=$(echo "$dump" | grep "'a3d'" | sed "s/.*type_id=\([0-9]*\).*/\1/")

if [ -z "$a2d_type" ] || [ -z "$a3d_type" ]; then
	error_log "FAIL: could not extract type_ids for a2d ($a2d_type) or a3d ($a3d_type)"
	test_fail
fi
if [ "$a2d_type" = "$a3d_type" ]; then
	error_log "FAIL: a2d and a3d share the same type_id ($a2d_type); a3d not encoded with extra dim"
	test_fail
fi
info_log "a2d type_id=$a2d_type, a3d type_id=$a3d_type (distinct): ok"

# --- Check 3: round-trip via pahole -F btf ---
# In-place encoding then reload via BTF frontend must match DWARF output.

pahole -J "$obj" 2>/dev/null
if [ $? -ne 0 ]; then
	error_log "FAIL: pahole -J in-place encoding failed"
	test_fail
fi

btf_out=$(pahole -F btf -C multidim "$obj" 2>/dev/null)

if [ -z "$btf_out" ]; then
	error_log "FAIL: pahole -F btf -C multidim produced no output"
	test_fail
fi

# 1D array preserved
if ! echo "$btf_out" | grep -q "a1d\[5\]"; then
	error_log "FAIL: round-trip: a1d[5] not found in BTF output"
	test_fail
fi
info_log "a1d[5] preserved: ok"

# 2D array — exact dimension order must match DWARF
if ! echo "$btf_out" | grep -q "a2d\[3\]\[4\]"; then
	error_log "FAIL: round-trip: a2d[3][4] not found in BTF output"
	test_fail
fi
info_log "a2d[3][4] preserved: ok"

# 3D array — exact dimension order must match DWARF
if ! echo "$btf_out" | grep -q "a3d\[2\]\[3\]\[4\]"; then
	error_log "FAIL: round-trip: a3d[2][3][4] not found in BTF output"
	test_fail
fi
info_log "a3d[2][3][4] preserved: ok"

# char array preserved
if ! echo "$btf_out" | grep -q "s\[8\]"; then
	error_log "FAIL: round-trip: s[8] not found in BTF output"
	test_fail
fi
info_log "s[8] preserved: ok"

# --- Check 4: struct size preserved ---
if ! echo "$btf_out" | grep -q "size: 172"; then
	error_log "FAIL: struct multidim size=172 not preserved after BTF round-trip"
	test_fail
fi
info_log "struct multidim size=172 preserved: ok"

test_pass
