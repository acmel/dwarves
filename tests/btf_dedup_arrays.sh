#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Test BTF deduplication of array types across multiple CUs.
# Exercises the BTF_KIND_ARRAY case in btf_encoder__type_is_equiv()
# which compares array element counts during type dedup.
#
# When multiple CUs define the same struct containing array members,
# the BTF dedup pass must compare array element types and counts
# (lines 1138-1147 of btf_encoder.c).  Identical arrays (same element
# type + same nelems) must merge; arrays differing only in nelems must
# remain separate.
#
# Tests:
#  1. Multi-CU object encodes to BTF successfully
#  2. Dedup merges duplicate struct shared (only one copy in BTF)
#  3. Array dimensions (int[8], char[32]) survive the dedup round-trip
#  4. Different nelems prevents merging (int[8] vs int[16])

. "$(dirname "$0")/test_lib.sh"
outdir=$(make_tmpdir)

trap cleanup EXIT

title_log "BTF deduplication of array types across CUs."

CC=${CC:-gcc}
if ! command -v "${CC%% *}" > /dev/null 2>&1; then
	info_log "skip: $CC not available"
	test_skip
fi

# We need a linker for partial linking (ld -r).  Respect $LD if set,
# fall back to using $CC -r -nostdlib if ld is missing.
LD=${LD:-ld}
use_cc_link=0
if command -v "${LD%% *}" > /dev/null 2>&1; then
	: # LD is available
else
	use_cc_link=1
fi

# --- Generate C sources ---
# Two CUs with identical struct shared (arrays must dedup-merge).

cat > "$outdir/cu1.c" << 'EOF'
struct shared {
	int values[8];
	char name[32];
};
struct shared g1;
EOF

cat > "$outdir/cu2.c" << 'EOF'
struct shared {
	int values[8];
	char name[32];
};
struct shared g2;
EOF

# Third CU with a different array size to exercise the a1->nelems != a2->nelems
# comparison path -- dedup must NOT merge int[16] with int[8].
cat > "$outdir/cu3.c" << 'EOF'
struct different_array {
	int values[16];
};
struct different_array g3;
EOF

# --- Compile each CU separately ---

if ! $CC -g -c -o "$outdir/cu1.o" "$outdir/cu1.c" 2>/dev/null; then
	error_log "FAIL: compilation of cu1.c failed"
	test_fail
fi

if ! $CC -g -c -o "$outdir/cu2.o" "$outdir/cu2.c" 2>/dev/null; then
	error_log "FAIL: compilation of cu2.c failed"
	test_fail
fi

if ! $CC -g -c -o "$outdir/cu3.o" "$outdir/cu3.c" 2>/dev/null; then
	error_log "FAIL: compilation of cu3.c failed"
	test_fail
fi

# --- Partial link into one multi-CU object ---

if [ "$use_cc_link" -eq 0 ]; then
	if ! $LD -r -o "$outdir/combined.o" "$outdir/cu1.o" "$outdir/cu2.o" "$outdir/cu3.o" 2>/dev/null; then
		error_log "FAIL: partial link (ld -r) failed"
		test_fail
	fi
else
	if ! $CC -r -nostdlib -o "$outdir/combined.o" "$outdir/cu1.o" "$outdir/cu2.o" "$outdir/cu3.o" 2>/dev/null; then
		error_log "FAIL: partial link (ld -r) failed"
		test_fail
	fi
fi
info_log "multi-CU object built via partial link: ok"

# --- Test 1: BTF encoding with dedup succeeds ---

btf="$outdir/dedup.btf"
if ! pahole --btf_encode_detached="$btf" "$outdir/combined.o" 2>/dev/null || [ ! -s "$btf" ]; then
	error_log "FAIL: pahole --btf_encode_detached failed on multi-CU object"
	test_fail
fi
info_log "BTF encoding succeeded: ok"

# --- Test 2: Dedup merged duplicate struct shared ---
# bpftool gives us exact counts; without it we use pahole -F btf.

if command -v bpftool > /dev/null 2>&1; then
	dump=$(bpftool btf dump file "$btf" 2>/dev/null)
	if [ -z "$dump" ]; then
		error_log "FAIL: bpftool btf dump produced no output"
		test_fail
	fi

	# Count how many STRUCT 'shared' entries exist -- dedup should leave exactly one.
	shared_count=$(echo "$dump" | grep -c "STRUCT 'shared'")
	if [ "$shared_count" -ne 1 ]; then
		error_log "FAIL: expected 1 'struct shared' after dedup, got $shared_count"
		test_fail
	fi
	info_log "dedup merged duplicate struct shared (count=$shared_count): ok"

	# Count struct different_array -- must also be exactly one.
	diff_count=$(echo "$dump" | grep -c "STRUCT 'different_array'")
	if [ "$diff_count" -ne 1 ]; then
		error_log "FAIL: expected 1 'struct different_array' after dedup, got $diff_count"
		test_fail
	fi
	info_log "struct different_array present (count=$diff_count): ok"
else
	info_log "bpftool not available, skipping raw BTF dump checks"
fi

# --- Test 3: Array dimensions preserved in pahole -F btf output ---
# Encode BTF in-place so pahole -F btf can reload it.

elf_obj="$outdir/combined_elf.o"
cp "$outdir/combined.o" "$elf_obj"
if ! pahole -J "$elf_obj" 2>/dev/null; then
	error_log "FAIL: pahole -J in-place encoding failed"
	test_fail
fi

# Bpftool-free dedup check: count 'struct shared' via pahole -F btf.
# This always runs so dedup is verified even when bpftool is absent.
shared_pahole=$(pahole -F btf "$elf_obj" 2>/dev/null | grep -c '^struct shared {')
if [ "$shared_pahole" -ne 1 ]; then
	error_log "FAIL: expected 1 'struct shared' after dedup, got $shared_pahole"
	test_fail
fi
info_log "dedup merged duplicate struct shared (pahole -F btf count=$shared_pahole): ok"

btf_shared=$(pahole -F btf -C shared "$elf_obj" 2>/dev/null)
if [ -z "$btf_shared" ]; then
	error_log "FAIL: pahole -F btf -C shared produced no output"
	test_fail
fi

# int values[8] must be present
if ! echo "$btf_shared" | grep -q "values\[8\]"; then
	error_log "FAIL: values[8] not found in BTF round-trip output"
	echo "$btf_shared"
	test_fail
fi
info_log "values[8] preserved after dedup: ok"

# char name[32] must be present
if ! echo "$btf_shared" | grep -q "name\[32\]"; then
	error_log "FAIL: name[32] not found in BTF round-trip output"
	echo "$btf_shared"
	test_fail
fi
info_log "name[32] preserved after dedup: ok"

# --- Test 4: Different nelems keeps structs separate ---
# struct different_array has int values[16], not int values[8].
# The dedup nelems comparison must prevent merging with struct shared's int[8].

btf_diff=$(pahole -F btf -C different_array "$elf_obj" 2>/dev/null)
if [ -z "$btf_diff" ]; then
	error_log "FAIL: pahole -F btf -C different_array produced no output"
	test_fail
fi

# int values[16] must appear (not values[8])
if ! echo "$btf_diff" | grep -q "values\[16\]"; then
	error_log "FAIL: values[16] not found in struct different_array"
	echo "$btf_diff"
	test_fail
fi
info_log "values[16] in different_array preserved (nelems comparison works): ok"

# Sanity: values[8] must NOT appear in different_array
if echo "$btf_diff" | grep -q "values\[8\]"; then
	error_log "FAIL: values[8] leaked into struct different_array -- nelems dedup is broken"
	test_fail
fi
info_log "values[8] absent from different_array (no incorrect merge): ok"

test_pass
