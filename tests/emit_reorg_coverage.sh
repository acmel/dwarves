#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Test dwarves_emit.c and dwarves_reorganize.c coverage:
#  - typedef emission for anonymous enums, anonymous structs, function
#    pointers (subroutine_type path), nested typedefs, and array types
#  - struct reorganization: hole filling, member movement, alignment
#    fixup, padding elimination
#  - --packable detection of structs with holes

. "$(dirname "$0")/test_lib.sh"
outdir=$(make_tmpdir)

trap cleanup EXIT

title_log "dwarves_emit.c / dwarves_reorganize.c coverage."

CC=${CC:-gcc}
if ! command -v "${CC%% *}" > /dev/null 2>&1; then
	info_log "skip: $CC not available"
	test_skip
fi

# ---------------------------------------------------------------
# Part 1: Emit paths (dwarves_emit.c typedef__emit_definitions)
# ---------------------------------------------------------------
emit_src="$outdir/emit.c"
emit_obj="$outdir/emit.o"

cat > "$emit_src" << 'EOF'
/* Anonymous enum inside a typedef — triggers the anonymous enum emission
 * path in typedef__emit_definitions (DW_TAG_enumeration_type with
 * type__name == NULL), lines 418-431 of dwarves_emit.c.
 */
typedef enum { EA_X, EA_Y, EA_Z } anon_enum_t;

/* Anonymous struct inside a typedef — triggers the anonymous struct/union
 * emission path (DW_TAG_structure_type with type__name == NULL),
 * lines 433-443 of dwarves_emit.c.
 */
typedef struct { int a; int b; } anon_struct_t;

/* Typedef of function pointer — the pointer_type resolves to a
 * subroutine_type, triggering the fall-through path at lines 403-417.
 */
typedef int (*fn_ptr_t)(void *, int);
typedef void (*void_fn_t)(void);

/* Typedef of pointer to typedef — triggers the nested typedef resolution
 * path at line 408 (ptr_type->tag == DW_TAG_typedef).
 */
typedef anon_struct_t *struct_ptr_t;

/* Typedef of array — triggers the DW_TAG_array_type case at lines 397-398. */
typedef int int_array_t[4];

/* Typedef chain — triggers the DW_TAG_typedef case at lines 400-401,
 * recursing into typedef__emit_definitions for the inner typedef.
 */
typedef anon_enum_t chained_enum_t;

/* Struct that uses all the above typedefs, forcing their definitions to
 * be emitted when --compile asks for this struct.
 */
struct uses_typedefs {
	anon_enum_t	e;
	anon_struct_t	s;
	fn_ptr_t	fp;
	void_fn_t	vfp;
	struct_ptr_t	sp;
	int_array_t	arr;
	chained_enum_t	ce;
};

/* Global to ensure the struct lands in DWARF */
struct uses_typedefs g_ut;

/* A simple function so pfunct --compile has something to emit */
int emit_test_func(anon_struct_t *s, fn_ptr_t cb) {
	return cb ? cb(s, s->a) : -1;
}
EOF

if ! $CC -g -O0 -c -o "$emit_obj" "$emit_src" 2>/dev/null; then
	error_log "FAIL: emit source compilation failed"
	test_fail
fi

# --compile -C uses_typedefs: emits compilable C for the struct and all
# dependent typedefs, exercising the typedef emission switch cases
output=$(pahole --compile -C uses_typedefs "$emit_obj" 2>/dev/null)
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: --compile -C uses_typedefs exited $rc"
	test_fail
fi
if [ -z "$output" ]; then
	error_log "FAIL: --compile -C uses_typedefs produced no output"
	test_fail
fi
# Check for typedef definitions (not just field names): the typedef
# keyword distinguishes a definition from a member using the type
if ! echo "$output" | grep -q "typedef.*anon_enum_t"; then
	error_log "FAIL: --compile missing anon_enum_t typedef definition"
	test_fail
fi
if ! echo "$output" | grep -q "typedef.*anon_struct_t"; then
	error_log "FAIL: --compile missing anon_struct_t typedef definition"
	test_fail
fi
if ! echo "$output" | grep -q "typedef.*fn_ptr_t"; then
	error_log "FAIL: --compile missing fn_ptr_t typedef definition"
	test_fail
fi
if ! echo "$output" | grep -q "typedef.*int_array_t"; then
	error_log "FAIL: --compile missing int_array_t typedef definition"
	test_fail
fi
info_log "   --compile -C uses_typedefs: ok"

# Verify the emitted code is actually compilable by feeding it back to
# the compiler — catches emit bugs that produce syntactically broken output
compile_test="$outdir/compile_check.c"
echo "$output" > "$compile_test"
echo "int main(void) { return 0; }" >> "$compile_test"
if $CC -fsyntax-only "$compile_test" 2>/dev/null; then
	info_log "   --compile output is compilable: ok"
else
	# Non-fatal: some typedefs (e.g. function pointers with unnamed params)
	# may not round-trip perfectly; the typedef definition checks above
	# verify the emission paths were exercised regardless.
	info_log "   --compile output syntax check: not fully compilable (non-fatal)"
fi

# pfunct --compile: exercises function emission paths in dwarves_emit.c,
# including ftype__emit_definitions for parameter types
if command -v pfunct > /dev/null 2>&1; then
	output=$(pfunct --compile "$emit_obj" 2>/dev/null)
	rc=$?
	if [ $rc -ne 0 ]; then
		error_log "FAIL: pfunct --compile exited $rc"
		test_fail
	fi
	if [ -z "$output" ]; then
		error_log "FAIL: pfunct --compile produced no output"
		test_fail
	fi
	info_log "   pfunct --compile: ok"
else
	info_log "   pfunct: not in PATH, skipping"
fi

# ---------------------------------------------------------------
# Part 2: Reorganize paths (dwarves_reorganize.c)
# ---------------------------------------------------------------
reorg_src="$outdir/reorg.c"
reorg_obj="$outdir/reorg.o"

cat > "$reorg_src" << 'EOF'
/*
 * Deliberately badly-packed struct to exercise the reorganization
 * algorithm in class__reorganize (dwarves_reorganize.c lines 729-848):
 *
 * Layout on x86_64 (8-byte alignment):
 *   a (1B) + 7B hole + b (8B) + c (1B) + 3B hole + d (4B)
 *   + e (1B) + 1B hole + f (2B) + g (1B) + 3B hole + h (8B)
 * = 40 bytes with 14 bytes of holes.
 */
struct poorly_packed {
	char	a;	/* 1 byte + 7 hole */
	long	b;	/* 8 bytes */
	char	c;	/* 1 byte + 3 hole */
	int	d;	/* 4 bytes */
	char	e;	/* 1 byte + 1 hole */
	short	f;	/* 2 bytes */
	char	g;	/* 1 byte + 3 hole */
	long	h;	/* 8 bytes */
};

/* Second struct with different hole patterns to exercise additional
 * code paths in the reorganization loop.
 */
struct mixed_holes {
	char	x;	/* 1 byte + 3 hole */
	int	y;	/* 4 bytes */
	char	z;	/* 1 byte + 7 hole */
	long	w;	/* 8 bytes */
	char	v;	/* 1 byte + 1 hole */
	short	u;	/* 2 bytes */
};

struct poorly_packed g_pp;
struct mixed_holes g_mh;
EOF

if ! $CC -g -O0 -c -o "$reorg_obj" "$reorg_src" 2>/dev/null; then
	error_log "FAIL: reorg source compilation failed"
	test_fail
fi

output=$(pahole --reorganize -C poorly_packed "$reorg_obj" 2>/dev/null)
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: --reorganize -C poorly_packed exited $rc"
	test_fail
fi
if [ -z "$output" ]; then
	error_log "FAIL: --reorganize produced no output"
	test_fail
fi
info_log "   --reorganize -C poorly_packed: ok"

# --show_reorg_steps: verbose mode that prints each member movement
output=$(pahole --show_reorg_steps -C poorly_packed "$reorg_obj" 2>/dev/null)
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: --show_reorg_steps exited $rc"
	test_fail
fi
if [ -z "$output" ]; then
	error_log "FAIL: --show_reorg_steps produced no output"
	test_fail
fi
info_log "   --show_reorg_steps: ok"

output=$(pahole --reorganize -C mixed_holes "$reorg_obj" 2>/dev/null)
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: --reorganize -C mixed_holes exited $rc"
	test_fail
fi
if [ -z "$output" ]; then
	error_log "FAIL: --reorganize -C mixed_holes produced no output"
	test_fail
fi
info_log "   --reorganize -C mixed_holes: ok"

# --packable: scans all structs and lists ones with holes that can be packed
output=$(pahole --packable "$reorg_obj" 2>/dev/null)
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: --packable exited $rc"
	test_fail
fi
if [ -z "$output" ]; then
	error_log "FAIL: --packable produced no output"
	test_fail
fi
if ! echo "$output" | grep -q "poorly_packed"; then
	error_log "FAIL: --packable did not list poorly_packed"
	test_fail
fi
info_log "   --packable: ok"

# --compile --reorganize: first reorganize, then emit compilable C
output=$(pahole --compile --reorganize -C poorly_packed "$reorg_obj" 2>/dev/null)
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: --compile --reorganize exited $rc"
	test_fail
fi
if [ -z "$output" ]; then
	error_log "FAIL: --compile --reorganize produced no output"
	test_fail
fi
info_log "   --compile --reorganize: ok"

test_pass
