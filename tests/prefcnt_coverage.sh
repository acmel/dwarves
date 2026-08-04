#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Exercise prefcnt.c paths:
#   - refcnt_member (lines 26-35)
#   - refcnt_variable, refcnt_inline_expansion, refcnt_lexblock (lines 84-94)
# These are hit when prefcnt processes objects with variables,
# inlined subroutines, and lexical blocks.

. "$(dirname "$0")/test_lib.sh"
outdir=$(make_tmpdir)

trap cleanup EXIT

title_log "prefcnt.c: reference counting coverage."

CC=${CC:-gcc}
if ! command -v "${CC%% *}" > /dev/null 2>&1; then
	info_log "skip: $CC not available"
	test_skip
fi

if ! command -v prefcnt > /dev/null 2>&1; then
	info_log "skip: prefcnt not available"
	test_skip
fi

# Code with variables, inlined functions, lexical blocks to exercise
# all the reference counting switch cases in prefcnt.c
src="$outdir/refcnt.c"
obj="$outdir/refcnt.o"

cat > "$src" << 'EOF'
struct inner { int x; int y; };
struct outer { struct inner i; int z; };

/* Variables exercise refcnt_variable() */
struct outer g_outer;
struct inner g_inner;
int g_counter;

/* Inlined function exercises refcnt_inline_expansion() */
static inline int compute(struct inner *i) {
	return i->x + i->y;
}

/* Lexical blocks exercise refcnt_lexblock() */
int process(struct outer *o, int n) {
	int result = 0;
	int i;
	for (i = 0; i < n; i++) {
		{
			int tmp = compute(&o->i);
			result += tmp * i;
		}
	}
	return result + o->z;
}

/* More functions to increase reference chain depth */
int use_outer(struct outer *o) {
	struct inner local;
	local.x = o->i.x;
	local.y = o->z;
	return compute(&local);
}
EOF

# -O2 to ensure inlining and complex DWARF
if ! $CC -g -O2 -c -o "$obj" "$src" 2>/dev/null; then
	error_log "FAIL: compilation failed"
	test_fail
fi

# prefcnt counts type references — exercises all the refcnt_* functions
if ! prefcnt "$obj" > /dev/null 2>&1; then
	error_log "FAIL: prefcnt exited non-zero"
	test_fail
fi
# prefcnt may produce no stdout (it counts, may not print anything by default)
info_log "   prefcnt (optimized): ok (exit $rc)"

# Also test with an unoptimized build to get DW_TAG_variable and DW_TAG_lexical_block
obj2="$outdir/refcnt_O0.o"
if ! $CC -g -O0 -c -o "$obj2" "$src" 2>/dev/null; then
	error_log "FAIL: O0 compilation failed"
	test_fail
fi

if ! prefcnt "$obj2" > /dev/null 2>&1; then
	error_log "FAIL: prefcnt (O0) exited non-zero"
	test_fail
fi
info_log "   prefcnt (unoptimized): ok"

test_pass
