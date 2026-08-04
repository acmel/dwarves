#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Exercise uncovered dwarf_loader.c edge cases:
#   - bitfield layout display for cross-boundary bitfields (lines 1045-1160)
#     Note: actual recoding is gated by no_bitfield_type_recode (default on),
#     so these test the display/iteration paths, not the recode transform.
#   - abstract origin resolution with optimized inlined code (line ~3396)
#   - DW_TAG_call_site/DW_TAG_GNU_call_site tag iteration from optimized
#     builds — these tags are currently skipped with a FIXME comment
#     (lines 3479-3500), so this exercises the skip/continue path.

. "$(dirname "$0")/test_lib.sh"
outdir=$(make_tmpdir)

trap cleanup EXIT

title_log "dwarf_loader.c edge cases: bitfield recode, inlining, call sites."

CC=${CC:-gcc}
if ! command -v "${CC%% *}" > /dev/null 2>&1; then
	info_log "skip: $CC not available"
	test_skip
fi

# ---------------------------------------------------------------
# Part 1: Cross-boundary bitfields trigger bitfield recoding
# ---------------------------------------------------------------

src="$outdir/cross_bits.c"
obj="$outdir/cross_bits.o"

cat > "$src" << 'EOF'
/* Cross-boundary bitfields: these span more than one storage unit.
 * The bitfield recoding path (tag__recode_dwarf_bitfield) is gated
 * by no_bitfield_type_recode, which defaults to true.  This test
 * exercises the bitfield display and byte_offset/bitfield_offset
 * iteration paths that run regardless of the recode flag. */
struct cross_bits {
	unsigned long long a:40;
	unsigned long long b:24;
};

/* Bitfields mixed with regular members stress the recoding loop
 * that adjusts byte_offset and bitfield_offset. */
struct mixed_bits {
	int		normal;
	unsigned int	x:13;
	unsigned int	y:19;
	char		gap;
	unsigned int	z:7;
	unsigned int	w:9;
	long		tail;
};

struct cross_bits g_cb;
struct mixed_bits g_mb;
EOF

if ! $CC -g -O0 -c -o "$obj" "$src" 2>/dev/null; then
	error_log "FAIL: bitfield compilation failed"
	test_fail
fi

output=$(pahole -C cross_bits "$obj" 2>/dev/null)
rc=$?
if [ $rc -ne 0 ] || [ -z "$output" ]; then
	error_log "FAIL: pahole -C cross_bits produced no output"
	test_fail
fi
info_log "   cross-boundary bitfields: ok"

output=$(pahole -E -C cross_bits "$obj" 2>/dev/null)
rc=$?
if [ $rc -ne 0 ] || [ -z "$output" ]; then
	error_log "FAIL: pahole -E -C cross_bits produced no output"
	test_fail
fi
info_log "   -E cross_bits: ok"

output=$(pahole -C mixed_bits "$obj" 2>/dev/null)
rc=$?
if [ $rc -ne 0 ] || [ -z "$output" ]; then
	error_log "FAIL: pahole -C mixed_bits produced no output"
	test_fail
fi
info_log "   mixed bitfield recode: ok"

# ---------------------------------------------------------------
# Part 2: Optimized code — inlining, call sites, abstract origins
# ---------------------------------------------------------------

opt_src="$outdir/optimized.c"
opt_obj="$outdir/optimized.o"

cat > "$opt_src" << 'EOF'
/* Force inlining + -O2 to generate DW_TAG_inlined_subroutine with
 * abstract origins, and DW_TAG_call_site / DW_TAG_GNU_call_site
 * entries in the DWARF. */
static inline __attribute__((always_inline)) int inlined_helper(int x) {
	return x * 3 + 1;
}

int caller1(int x) { return inlined_helper(x) + 1; }
int caller2(int x) { return inlined_helper(x) * 2; }
int caller3(int x) { return inlined_helper(caller1(x)); }

/* Multiple levels of inlining to exercise deeper abstract origin chains */
static inline __attribute__((always_inline)) int inner(int a) {
	return a + 42;
}
static inline __attribute__((always_inline)) int middle(int a) {
	return inner(a) * 2;
}
int deep_caller(int x) { return middle(x) + inner(x); }

struct opt_data { int x; int y; };
struct opt_data g_opt;
EOF

# -O2 is needed to trigger call site DWARF tags and inlining
if ! $CC -g -O2 -c -o "$opt_obj" "$opt_src" 2>/dev/null; then
	error_log "FAIL: optimized compilation failed"
	test_fail
fi

# pfunct -V: verbose function listing processes all tags including
# DW_TAG_inlined_subroutine and DW_TAG_call_site
if command -v pfunct > /dev/null 2>&1; then
	output=$(pfunct -V "$opt_obj" 2>/dev/null)
	rc=$?
	if [ $rc -ne 0 ]; then
		error_log "FAIL: pfunct -V on optimized obj exited $rc"
		test_fail
	fi
	if [ -z "$output" ]; then
		error_log "FAIL: pfunct -V on optimized obj produced no output"
		test_fail
	fi
	info_log "   pfunct -V (optimized/inlined): ok"
else
	info_log "   skip: pfunct not available"
fi

# pahole --sizes: full CU traversal processes all tags including
# call sites and inlined subroutines
output=$(pahole --sizes "$opt_obj" 2>/dev/null)
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: pahole --sizes on optimized obj exited $rc"
	test_fail
fi
if [ -z "$output" ]; then
	error_log "FAIL: pahole --sizes on optimized obj produced no output"
	test_fail
fi
info_log "   pahole --sizes (optimized): ok"

# BTF encode of optimized code exercises more dwarf_loader paths
$CC -g -O2 -c -o "$outdir/opt_btf.o" "$opt_src" 2>/dev/null
pahole -J "$outdir/opt_btf.o" 2>/dev/null
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: BTF encode of optimized obj exited $rc"
	test_fail
fi
output=$(pahole -F btf "$outdir/opt_btf.o" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: BTF read-back of optimized obj empty"
	test_fail
fi
info_log "   BTF encode/decode (optimized): ok"

test_pass
