#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Test _Atomic type display and --skip_emitting_atomic_typedefs.
# Exercises DW_TAG_atomic_type formatting in dwarves_fprintf.c
# and the atomic typedef suppression path in btf_encoder.

. "$(dirname "$0")/test_lib.sh"

outdir=$(make_tmpdir)
trap cleanup EXIT

title_log "_Atomic type display and --skip_emitting_atomic_typedefs."

CC=${CC:-gcc}
if ! command -v ${CC%% *} > /dev/null 2>&1; then
	info_log "skip: $CC not available"
	test_skip
fi

src=$(make_tmpsrc)
obj=$(make_tmpobj)

# C11 source using _Atomic qualifier and stdatomic.h typedefs.
# The struct exercises the DW_TAG_atomic_type DWARF tag, while the
# stdatomic.h typedefs (atomic_int, atomic_long) exercise the
# --skip_emitting_atomic_typedefs suppression path.
cat > "$src" << 'EOF'
#include <stdatomic.h>

struct atomic_test {
	_Atomic int	counter;
	_Atomic long	sequence;
	int		normal;
};

struct atomic_test g_at;
EOF

# Need C11 for _Atomic and DWARF 5 for DW_TAG_atomic_type.
# GCC defaults to DWARF 4 until version 12, and DWARF 4 has no atomic type tag,
# so the _Atomic qualifier is lost. Force DWARF 5 for consistent behavior.
$CC -std=c11 -gdwarf-5 -c -o "$obj" "$src" 2>/dev/null
if [ $? -ne 0 ]; then
	info_log "skip: $CC does not support -std=c11, -gdwarf-5, or <stdatomic.h>"
	test_skip
fi

# --- Test 1: _Atomic prefix appears in struct display ---
# The DW_TAG_atomic_type path in dwarves_fprintf.c (lines 361-362 and
# 912-913) should emit an "_Atomic " prefix for qualified members.
output=$(pahole -C atomic_test "$obj" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: pahole -C atomic_test produced no output"
	test_fail
fi

if ! echo "$output" | grep -q "_Atomic"; then
	error_log "FAIL: _Atomic prefix not found in struct display"
	test_fail
fi
info_log "_Atomic prefix in struct display: ok"

# --- Test 2: all three members are present ---
# Ensures the DW_TAG_atomic_type formatting path (line 641/657) does
# not swallow the member that follows it.
for member in counter sequence normal; do
	if ! echo "$output" | grep -q "$member"; then
		error_log "FAIL: member '$member' missing from struct display"
		test_fail
	fi
done
info_log "all 3 members present: ok"

# --- Test 3: --skip_emitting_atomic_typedefs completes without error ---
# This exercises the conf.skip_emitting_atomic_typedefs path in
# pahole.c (line 2115-2116). The flag suppresses emission of
# 'typedef _Atomic int atomic_int' and similar stdatomic.h typedefs
# but does not affect struct member display, so this is mainly a
# crash/error regression test.
if ! pahole --skip_emitting_atomic_typedefs "$obj" > /dev/null 2>&1; then
	error_log "FAIL: --skip_emitting_atomic_typedefs exited with error"
	test_fail
fi
info_log "--skip_emitting_atomic_typedefs: ok"

# --- Test 4: struct size is reasonable ---
# Extract the "/* size: NN */" comment from pahole output and verify
# it is a sane value (> 0 and <= 256). A corrupt DW_TAG_atomic_type
# chain could produce a zero or absurdly large size.
size=$(echo "$output" | sed -n 's|.*/\* *size: *\([0-9][0-9]*\)[, ].*|\1|p' | tail -1)
if [ -z "$size" ]; then
	error_log "FAIL: could not extract struct size from pahole output"
	test_fail
fi
if [ "$size" -eq 0 ]; then
	error_log "FAIL: struct size is 0"
	test_fail
fi
if [ "$size" -gt 256 ]; then
	error_log "FAIL: struct size $size looks unreasonably large"
	test_fail
fi
info_log "struct size ($size bytes): ok"

test_pass
