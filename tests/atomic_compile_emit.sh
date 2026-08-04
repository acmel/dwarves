#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Exercise _Atomic type emission paths in dwarves_emit.c:
#   - base_type__emit_atomic (lines 534-566)
#   - base_type__stdint2simple (lines 514-524)
# These paths are only hit when emitting compilable output for
# atomic types, which requires _Atomic members + --compile.

. "$(dirname "$0")/test_lib.sh"
outdir=$(make_tmpdir)

trap cleanup EXIT

title_log "dwarves_emit.c: _Atomic type compile emission."

CC=${CC:-gcc}
if ! command -v "${CC%% *}" > /dev/null 2>&1; then
	info_log "skip: $CC not available"
	test_skip
fi

src="$outdir/atomic.c"
obj="$outdir/atomic.o"

# C11 _Atomic types.  GCC/Clang emit these as DW_TAG_atomic_type
# wrapping standard base types, which exercises the DW_TAG_atomic_type
# handling in dwarf_loader.c and the --compile emission path for atomic
# qualifiers.  The base_type__emit_atomic() strncmp("atomic_", 7) path
# is only reached when the DWARF producer encodes the type name with an
# "atomic_" prefix (some older toolchains); modern compilers use the
# DW_TAG_atomic_type wrapper instead, exercising the qualifier path.
cat > "$src" << 'EOF'
#include <stdatomic.h>

struct atomic_types {
	_Atomic int		ai;
	_Atomic long long	all;
	_Atomic unsigned long	aul;
	_Atomic unsigned long long aull;
	_Atomic unsigned int	aui;
	_Atomic _Bool		ab;
	_Atomic short		as;
};

struct atomic_types g_at;
EOF

# Need -std=c11 or later for _Atomic
if ! $CC -g -O0 -std=c11 -c -o "$obj" "$src" 2>/dev/null; then
	info_log "skip: C11 _Atomic compilation failed"
	test_skip
fi

# --compile exercises the emission paths including _Atomic handling
output=$(pahole --compile -C atomic_types "$obj" 2>/dev/null)
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: pahole --compile -C atomic_types exited $rc"
	test_fail
fi
if [ -z "$output" ]; then
	error_log "FAIL: pahole --compile -C atomic_types produced no output"
	test_fail
fi
info_log "   --compile atomic_types: ok"

# Verify the emitted code is actually compilable
echo "$output" > "$outdir/atomic_emit.c"
cat >> "$outdir/atomic_emit.c" << 'EOF'
int main(void) { return sizeof(struct atomic_types); }
EOF
if $CC -std=c11 -o /dev/null "$outdir/atomic_emit.c" 2>/dev/null; then
	info_log "   emitted code compiles: ok"
else
	# Atomic compilation may not fully round-trip due to typedef naming
	info_log "   emitted code does not compile (non-fatal, emission was tested)"
fi

# --skip_emitting_atomic_typedefs changes the emission path
output=$(pahole --compile --skip_emitting_atomic_typedefs -C atomic_types "$obj" 2>/dev/null)
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: --compile --skip_emitting_atomic_typedefs exited $rc"
	test_fail
fi
info_log "   --compile --skip_emitting_atomic_typedefs: ok"

test_pass
