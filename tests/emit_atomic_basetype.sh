#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Exercise base_type__emit_definitions() and related functions in
# dwarves_emit.c (lines 637-720):
#   - base_type__emit_definitions: emits "typedef _Atomic ..." for base
#     types whose DW_AT_name starts with "atomic_"
#   - base_type__stdint2simple: converts stdint names to C keywords
#   - base_type_emissions__find_definition: dedup lookup
#   - base_type_emissions__add_definition: records emitted definitions
#
# Modern GCC/Clang encode _Atomic as DW_TAG_atomic_type wrapping a
# DW_TAG_base_type("int"), so these paths are never reached with
# compiler-generated DWARF.  Older toolchains (e.g. rhel8 OVS builds)
# produced DW_TAG_base_type entries named "atomic_int" directly.
#
# We use hand-crafted DWARF assembly to reproduce that legacy encoding,
# ensuring every branch in base_type__emit_definitions is covered.

. "$(dirname "$0")/test_lib.sh"
outdir=$(make_tmpdir)

trap cleanup EXIT

title_log "Legacy atomic_ base type emission via --compile (hand-crafted DWARF)."

CC=${CC:-gcc}
if ! command -v "${CC%% *}" > /dev/null 2>&1; then
	info_log "skip: $CC not available (need gas assembler)"
	test_skip
fi

asm_src="$outdir/atomic_basetype.S"
obj="$outdir/atomic_basetype.o"

# Hand-crafted DWARF with DW_TAG_base_type entries named "atomic_*".
# This encoding is what legacy toolchains produced; modern compilers
# use DW_TAG_atomic_type instead.  Each atomic_ variant targets a
# specific branch in base_type__emit_definitions():
#
#   atomic_int       → else (generic, stdint2simple pass-through)
#   atomic_uint      → 'u' branch, else sub (stdint2simple "int" → "int")
#   atomic_long      → else (generic)
#   atomic_ulong     → 'u' branch, 'l' sub (unsigned long)
#   atomic_llong     → 'l','l' branch (long long)
#   atomic_ullong    → 'u' branch, 'l','l' sub (unsigned long long)
#   atomic_short     → else (excluded: 's' with [1]=='h')
#   atomic_schar     → 's' branch (signed, [1] != 'i' && != 'h')
#   atomic_bool      → 'b' branch (_Bool)
#   atomic_size_t    → else (excluded: 's' with [1]=='i')
#   atomic_uint32_t  → 'u' branch, else sub → stdint2simple("int32_t")→"int"
cat > "$asm_src" << 'EOF'
	.section .debug_abbrev,"",@progbits
	.uleb128 1
	.uleb128 0x11	/* DW_TAG_compile_unit */
	.byte    1	/* has children */
	.uleb128 0x25	/* DW_AT_producer */
	.uleb128 0x08	/* DW_FORM_string */
	.byte    0, 0

	.uleb128 2	/* base_type */
	.uleb128 0x24	/* DW_TAG_base_type */
	.byte    0
	.uleb128 0x03	/* DW_AT_name */
	.uleb128 0x08	/* DW_FORM_string */
	.uleb128 0x0b	/* DW_AT_byte_size */
	.uleb128 0x0b	/* DW_FORM_data1 */
	.uleb128 0x3e	/* DW_AT_encoding */
	.uleb128 0x0b	/* DW_FORM_data1 */
	.byte    0, 0

	.uleb128 3	/* structure_type */
	.uleb128 0x13	/* DW_TAG_structure_type */
	.byte    1
	.uleb128 0x03	/* DW_AT_name */
	.uleb128 0x08	/* DW_FORM_string */
	.uleb128 0x0b	/* DW_AT_byte_size */
	.uleb128 0x0b	/* DW_FORM_data1 */
	.byte    0, 0

	.uleb128 4	/* member */
	.uleb128 0x0d	/* DW_TAG_member */
	.byte    0
	.uleb128 0x03	/* DW_AT_name */
	.uleb128 0x08	/* DW_FORM_string */
	.uleb128 0x49	/* DW_AT_type */
	.uleb128 0x13	/* DW_FORM_ref4 */
	.uleb128 0x38	/* DW_AT_data_member_location */
	.uleb128 0x0b	/* DW_FORM_data1 */
	.byte    0, 0

	.uleb128 5	/* variable */
	.uleb128 0x34	/* DW_TAG_variable */
	.byte    0
	.uleb128 0x03	/* DW_AT_name */
	.uleb128 0x08	/* DW_FORM_string */
	.uleb128 0x49	/* DW_AT_type */
	.uleb128 0x13	/* DW_FORM_ref4 */
	.uleb128 0x02	/* DW_AT_location */
	.uleb128 0x18	/* DW_FORM_exprloc */
	.byte    0, 0

	.byte    0	/* end abbreviation table */

	.section .debug_info,"",@progbits
.Lcu_hdr:
	.4byte   .Lcu_end - .Lcu_ver	/* CU length */
.Lcu_ver:
	.2byte   4		/* DWARF version 4 */
	.4byte   0		/* abbrev offset */
	.byte    8		/* address size */

	/* compile_unit */
	.uleb128 1
	.asciz   "hand-crafted-atomic"

	/* DW_TAG_base_type entries with "atomic_" prefix names */
.Latomic_int:
	.uleb128 2
	.asciz   "atomic_int"
	.byte    4
	.byte    5		/* DW_ATE_signed */

.Latomic_uint:
	.uleb128 2
	.asciz   "atomic_uint"
	.byte    4
	.byte    7		/* DW_ATE_unsigned */

.Latomic_long:
	.uleb128 2
	.asciz   "atomic_long"
	.byte    8
	.byte    5

.Latomic_ulong:
	.uleb128 2
	.asciz   "atomic_ulong"
	.byte    8
	.byte    7

.Latomic_llong:
	.uleb128 2
	.asciz   "atomic_llong"
	.byte    8
	.byte    5

.Latomic_ullong:
	.uleb128 2
	.asciz   "atomic_ullong"
	.byte    8
	.byte    7

.Latomic_short:
	.uleb128 2
	.asciz   "atomic_short"
	.byte    2
	.byte    5

.Latomic_schar:
	.uleb128 2
	.asciz   "atomic_schar"
	.byte    1
	.byte    6		/* DW_ATE_signed_char */

.Latomic_bool:
	.uleb128 2
	.asciz   "atomic_bool"
	.byte    1
	.byte    2		/* DW_ATE_boolean */

.Latomic_size_t:
	.uleb128 2
	.asciz   "atomic_size_t"
	.byte    8
	.byte    7

.Latomic_uint32_t:
	.uleb128 2
	.asciz   "atomic_uint32_t"
	.byte    4
	.byte    7

.Lint:
	.uleb128 2
	.asciz   "int"
	.byte    4
	.byte    5

	/* struct containing all atomic members */
.Lstruct:
	.uleb128 3
	.asciz   "legacy_atomics"
	.byte    56

	.uleb128 4
	.asciz   "a_int"
	.4byte   .Latomic_int - .Lcu_hdr
	.byte    0

	.uleb128 4
	.asciz   "a_uint"
	.4byte   .Latomic_uint - .Lcu_hdr
	.byte    4

	.uleb128 4
	.asciz   "a_long"
	.4byte   .Latomic_long - .Lcu_hdr
	.byte    8

	.uleb128 4
	.asciz   "a_ulong"
	.4byte   .Latomic_ulong - .Lcu_hdr
	.byte    16

	.uleb128 4
	.asciz   "a_llong"
	.4byte   .Latomic_llong - .Lcu_hdr
	.byte    24

	.uleb128 4
	.asciz   "a_ullong"
	.4byte   .Latomic_ullong - .Lcu_hdr
	.byte    32

	.uleb128 4
	.asciz   "a_short"
	.4byte   .Latomic_short - .Lcu_hdr
	.byte    40

	.uleb128 4
	.asciz   "a_schar"
	.4byte   .Latomic_schar - .Lcu_hdr
	.byte    42

	.uleb128 4
	.asciz   "a_bool"
	.4byte   .Latomic_bool - .Lcu_hdr
	.byte    43

	.uleb128 4
	.asciz   "a_size"
	.4byte   .Latomic_size_t - .Lcu_hdr
	.byte    44

	.uleb128 4
	.asciz   "a_u32"
	.4byte   .Latomic_uint32_t - .Lcu_hdr
	.byte    48

	.uleb128 4
	.asciz   "pad"
	.4byte   .Lint - .Lcu_hdr
	.byte    52

	.byte    0		/* end struct children */

	/* global variable so pahole can find the struct */
	.uleb128 5
	.asciz   "g_legacy"
	.4byte   .Lstruct - .Lcu_hdr
	.byte    9
	.byte    3		/* DW_OP_addr */
	.8byte   0

	.byte    0		/* end CU children */
.Lcu_end:

	.section .bss
	.globl g_legacy
g_legacy:
	.zero 56
EOF

if ! $CC -c -o "$obj" "$asm_src" 2>"$outdir/as.log"; then
	info_log "skip: assembler failed"
	info_log "$(cat "$outdir/as.log")"
	test_skip
fi

# Verify DWARF has the expected base type names
if command -v readelf > /dev/null 2>&1; then
	if ! readelf -wi "$obj" 2>/dev/null | grep -q 'atomic_int'; then
		error_log "FAIL: hand-crafted DWARF missing atomic_int base type"
		test_fail
	fi
	info_log "   hand-crafted DWARF verified: ok"
fi

# --- Test 1: --compile emits typedef _Atomic definitions ---
output=$(pahole --compile -C legacy_atomics "$obj" 2>"$outdir/pahole.log")
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: pahole --compile exited $rc"
	info_log "$(cat "$outdir/pahole.log")"
	test_fail
fi
if [ -z "$output" ]; then
	error_log "FAIL: pahole --compile produced no output"
	test_fail
fi

# Count typedef lines — must have at least 11 (one per atomic_ type)
td_count=$(echo "$output" | grep -c "^typedef _Atomic")
if [ "$td_count" -lt 11 ]; then
	error_log "FAIL: expected >= 11 typedef _Atomic lines, got $td_count"
	echo "$output" >&2
	test_fail
fi
info_log "   typedef _Atomic count ($td_count): ok"

# --- Test 2: verify specific branch outputs ---

# 's' branch: atomic_schar → "typedef _Atomic signed char atomic_schar;"
if ! echo "$output" | grep -q "typedef _Atomic signed char atomic_schar"; then
	error_log "FAIL: missing 'typedef _Atomic signed char atomic_schar'"
	test_fail
fi
info_log "   atomic_schar (signed branch): ok"

# 'l','l' branch: atomic_llong → "typedef _Atomic long long atomic_llong;"
if ! echo "$output" | grep -q "typedef _Atomic long long atomic_llong"; then
	error_log "FAIL: missing 'typedef _Atomic long long atomic_llong'"
	test_fail
fi
info_log "   atomic_llong (long long branch): ok"

# 'u' + 'l' branch: atomic_ulong → "typedef _Atomic unsigned long atomic_ulong;"
if ! echo "$output" | grep -q "typedef _Atomic unsigned long atomic_ulong"; then
	error_log "FAIL: missing 'typedef _Atomic unsigned long atomic_ulong'"
	test_fail
fi
info_log "   atomic_ulong (unsigned long branch): ok"

# 'u' + 'l','l' branch: atomic_ullong → "typedef _Atomic unsigned long long atomic_ullong;"
if ! echo "$output" | grep -q "typedef _Atomic unsigned long long atomic_ullong"; then
	error_log "FAIL: missing 'typedef _Atomic unsigned long long atomic_ullong'"
	test_fail
fi
info_log "   atomic_ullong (unsigned long long branch): ok"

# 'b' branch: atomic_bool → "typedef _Atomic _Bool atomic_bool;"
if ! echo "$output" | grep -q "typedef _Atomic _Bool atomic_bool"; then
	error_log "FAIL: missing 'typedef _Atomic _Bool atomic_bool'"
	test_fail
fi
info_log "   atomic_bool (_Bool branch): ok"

# 'u' + stdint2simple: atomic_uint32_t → "typedef _Atomic unsigned int atomic_uint32_t;"
# stdint2simple converts "int32_t" → "int", so the output has "unsigned int"
if ! echo "$output" | grep -q "typedef _Atomic unsigned int atomic_uint32_t"; then
	error_log "FAIL: missing 'typedef _Atomic unsigned int atomic_uint32_t'"
	error_log "stdint2simple should convert int32_t → int"
	test_fail
fi
info_log "   atomic_uint32_t (stdint2simple conversion): ok"

# generic: atomic_int → "typedef _Atomic int atomic_int;"
if ! echo "$output" | grep -q "typedef _Atomic int atomic_int"; then
	error_log "FAIL: missing 'typedef _Atomic int atomic_int'"
	test_fail
fi
info_log "   atomic_int (generic branch): ok"

# --- Test 3: --skip_emitting_atomic_typedefs suppresses all typedefs ---
skip_output=$(pahole --compile --skip_emitting_atomic_typedefs \
	-C legacy_atomics "$obj" 2>"$outdir/pahole_skip.log")
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: --skip_emitting_atomic_typedefs exited $rc"
	info_log "$(cat "$outdir/pahole_skip.log")"
	test_fail
fi
if echo "$skip_output" | grep -q "^typedef _Atomic"; then
	error_log "FAIL: --skip_emitting_atomic_typedefs did not suppress typedefs"
	test_fail
fi
info_log "   --skip_emitting_atomic_typedefs suppresses all: ok"

# --- Test 4: struct members still present in both modes ---
for member in a_int a_uint a_long a_ulong a_llong a_ullong a_short a_schar a_bool a_size a_u32 pad; do
	if ! echo "$output" | grep -q "$member"; then
		error_log "FAIL: member '$member' missing from --compile output"
		test_fail
	fi
done
info_log "   all 12 struct members present: ok"

test_pass
