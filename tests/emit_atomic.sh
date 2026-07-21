#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Test --compile with C11 _Atomic types and the
# --skip_emitting_atomic_typedefs flag.

. "$(dirname "$0")/test_lib.sh"
outdir=$(make_tmpdir)

trap cleanup EXIT

title_log "Atomic typedef emission."

CC=${CC:-gcc}
if ! command -v "${CC%% *}" > /dev/null 2>&1; then
	info_log "skip: $CC not available"
	test_skip
fi

src=$(make_tmpsrc)
obj=$(make_tmpobj)

cat > "$src" << 'EOF'
typedef _Atomic int atomic_int;
typedef _Atomic unsigned int atomic_uint;
typedef _Atomic long atomic_long;
typedef _Atomic unsigned long atomic_ulong;

struct atomic_counters {
	atomic_int	count;
	atomic_uint	flags;
	atomic_long	total;
	atomic_ulong	mask;
};

struct atomic_counters g;
EOF

if ! $CC -g -std=c11 -c -o "$obj" "$src" 2>"$outdir/cc.log"; then
	info_log "$(cat "$outdir/cc.log")"
	# C11 _Atomic may not be supported
	info_log "skip: compiler does not support C11 _Atomic"
	test_skip
fi

# Check if the compiler properly encodes DW_TAG_atomic_type nodes in DWARF.
# Some older compilers (e.g., clang 21.1.8 on AlmaLinux 8) compile _Atomic
# but don't preserve the atomic qualifier in DWARF - they emit:
#   DW_TAG_typedef "atomic_int" → DW_TAG_base_type "int"
# instead of the correct:
#   DW_TAG_typedef "atomic_int" → DW_TAG_atomic_type → DW_TAG_base_type "int"
# When the atomic_type node is missing, pahole has no way to know the typedef
# was atomic, so it correctly emits "typedef int atomic_int;" without _Atomic.
if ! readelf -wi "$obj" 2>/dev/null | grep -q 'DW_TAG_atomic_type'; then
	info_log "skip: compiler does not encode DW_TAG_atomic_type in DWARF"
	test_skip
fi

# --compile should emit atomic typedefs for recompilation
output=$(pahole --compile "$obj" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: --compile produced no output"
	test_fail
fi

# Verify the atomic typedefs from user source are emitted.
# GCC represents these as DW_TAG_typedef -> DW_TAG_atomic_type ->
# DW_TAG_base_type, so they go through the normal typedef emit path.
if ! echo "$output" | grep -q "typedef.*_Atomic.*atomic_int"; then
	error_log "FAIL: --compile did not emit atomic_int typedef"
	test_fail
fi
info_log "   atomic_int emission: ok"

if ! echo "$output" | grep -q "typedef.*_Atomic.*atomic_uint"; then
	error_log "FAIL: --compile did not emit atomic_uint typedef"
	test_fail
fi
info_log "   atomic_uint emission: ok"

if ! echo "$output" | grep -q "typedef.*_Atomic.*atomic_long"; then
	error_log "FAIL: --compile did not emit atomic_long typedef"
	test_fail
fi
info_log "   atomic_long emission: ok"

if ! echo "$output" | grep -q "typedef.*_Atomic.*atomic_ulong"; then
	error_log "FAIL: --compile did not emit atomic_ulong typedef"
	test_fail
fi
info_log "   atomic_ulong emission: ok"

# Struct should use the typedef names in its members
if ! echo "$output" | grep -q "atomic_int.*count"; then
	error_log "FAIL: struct member not using atomic_int typedef"
	test_fail
fi
info_log "   struct uses atomic typedefs: ok"

# --skip_emitting_atomic_typedefs: this flag suppresses emission of
# base_type-originated atomic typedefs (kernel-style atomic_t).
# For user-defined DW_TAG_typedef chains, it has no effect since
# the typedef is a real DWARF entry, not synthesized from base types.
# Verify no crash and output is still valid.
skipped=$(pahole --compile --skip_emitting_atomic_typedefs "$obj" 2>/dev/null)
if [ -z "$skipped" ]; then
	error_log "FAIL: --skip_emitting_atomic_typedefs produced no output"
	test_fail
fi
if ! echo "$skipped" | grep -q "struct atomic_counters"; then
	error_log "FAIL: --skip_emitting_atomic_typedefs broke struct output"
	test_fail
fi
info_log "   --skip_emitting_atomic_typedefs: ok (no crash)"

test_pass
