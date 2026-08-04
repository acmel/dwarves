#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Test bitfield typedef recoding (tag__recode_dwarf_bitfield coverage).
# When a bitfield uses a typedef'd type, pahole must "recode" it to
# find the underlying base type with the correct bit width.

. "$(dirname "$0")/test_lib.sh"

outdir=$(make_tmpdir)
trap cleanup EXIT

title_log "Bitfield typedef recoding (tag__recode_dwarf_bitfield)."

CC=${CC:-gcc}
if ! command -v "${CC%% *}" > /dev/null 2>&1; then
	info_log "skip: $CC not available"
	test_skip
fi

src=$(make_tmpsrc)
obj=$(make_tmpobj)

cat > "$src" << 'EOF'
/* Typedef'd bitfields: exercises tag__recode_dwarf_bitfield() in
 * dwarf_loader.c.  When the bitfield type is a typedef, pahole must
 * chase through the typedef chain to find the underlying base type
 * and create a recoded type with the correct bit width. */

typedef unsigned int uint_t;

/* Case 1: single-level typedef bitfield */
struct bf_typedef {
	uint_t flags:4;
	uint_t mode:3;
	uint_t valid:1;
};

/* Case 2: chained (two-level) typedef bitfield */
typedef uint_t custom_t;

struct bf_chained {
	custom_t a:5;
	custom_t b:3;
};

/* Case 3: plain (non-typedef) bitfield — baseline for size comparison */
struct bf_plain {
	unsigned int x:4;
	unsigned int y:4;
};

/* Instantiate all structs so they appear in DWARF */
struct bf_typedef g_td;
struct bf_chained g_ch;
struct bf_plain   g_pl;
EOF

if ! $CC -g -c -o "$obj" "$src" 2>/dev/null; then
	error_log "FAIL: compilation failed"
	test_fail
fi

# --- Case 1: typedef'd bitfield (bf_typedef) ---

dwarf_td=$(pahole -C bf_typedef "$obj" 2>/dev/null)
if [ -z "$dwarf_td" ]; then
	error_log "FAIL: pahole -C bf_typedef produced no output"
	test_fail
fi

# Verify each bitfield member and its width survive the typedef recode
if ! echo "$dwarf_td" | grep -q "flags:4"; then
	error_log "FAIL: bf_typedef — flags:4 not found"
	test_fail
fi
if ! echo "$dwarf_td" | grep -q "mode:3"; then
	error_log "FAIL: bf_typedef — mode:3 not found"
	test_fail
fi
if ! echo "$dwarf_td" | grep -q "valid:1"; then
	error_log "FAIL: bf_typedef — valid:1 not found"
	test_fail
fi
info_log "bf_typedef bitfield widths (flags:4 mode:3 valid:1): ok"

# --- Case 2: chained typedef bitfield (bf_chained) ---

dwarf_ch=$(pahole -C bf_chained "$obj" 2>/dev/null)
if [ -z "$dwarf_ch" ]; then
	error_log "FAIL: pahole -C bf_chained produced no output"
	test_fail
fi

if ! echo "$dwarf_ch" | grep -q "a:5"; then
	error_log "FAIL: bf_chained — a:5 not found"
	test_fail
fi
if ! echo "$dwarf_ch" | grep -q "b:3"; then
	error_log "FAIL: bf_chained — b:3 not found"
	test_fail
fi
info_log "bf_chained bitfield widths (a:5 b:3): ok"

# --- Case 3: size comparison — typedef vs plain ---
# Both bf_typedef (4+3+1 = 8 bits) and bf_plain (4+4 = 8 bits) pack
# into a single unsigned int, so both must report size: 4.

size_td=$(echo "$dwarf_td" | grep "/\* size:" | sed 's/.*size: \([0-9]*\).*/\1/')
size_pl=$(pahole -C bf_plain "$obj" 2>/dev/null | grep "/\* size:" | sed 's/.*size: \([0-9]*\).*/\1/')

if [ -z "$size_td" ] || [ -z "$size_pl" ]; then
	error_log "FAIL: could not extract struct sizes (td='$size_td' pl='$size_pl')"
	test_fail
fi
if [ "$size_td" != "$size_pl" ]; then
	error_log "FAIL: bf_typedef size ($size_td) != bf_plain size ($size_pl)"
	test_fail
fi
info_log "bf_typedef and bf_plain both report size $size_td: ok"

# --- Case 4: BTF round-trip ---
# Encode DWARF to BTF in-place, then reload via pahole -F btf and
# verify that the typedef'd bitfield widths survive the conversion.

if ! pahole -J "$obj" 2>/dev/null; then
	error_log "FAIL: pahole -J (in-place BTF encoding) failed"
	test_fail
fi

btf_td=$(pahole -F btf -C bf_typedef "$obj" 2>/dev/null)
if [ -z "$btf_td" ]; then
	error_log "FAIL: pahole -F btf -C bf_typedef produced no output"
	test_fail
fi

if ! echo "$btf_td" | grep -q "flags:4"; then
	error_log "FAIL: BTF round-trip — bf_typedef flags:4 not found"
	test_fail
fi
if ! echo "$btf_td" | grep -q "mode:3"; then
	error_log "FAIL: BTF round-trip — bf_typedef mode:3 not found"
	test_fail
fi
if ! echo "$btf_td" | grep -q "valid:1"; then
	error_log "FAIL: BTF round-trip — bf_typedef valid:1 not found"
	test_fail
fi

btf_ch=$(pahole -F btf -C bf_chained "$obj" 2>/dev/null)
if [ -z "$btf_ch" ]; then
	error_log "FAIL: pahole -F btf -C bf_chained produced no output"
	test_fail
fi

if ! echo "$btf_ch" | grep -q "a:5"; then
	error_log "FAIL: BTF round-trip — bf_chained a:5 not found"
	test_fail
fi
if ! echo "$btf_ch" | grep -q "b:3"; then
	error_log "FAIL: BTF round-trip — bf_chained b:3 not found"
	test_fail
fi
info_log "BTF round-trip preserves typedef'd bitfield widths: ok"

# Optional: cross-check with bpftool if available
if command -v bpftool > /dev/null 2>&1; then
	btf_file=$(make_tmpfile)
	if ! pahole --btf_encode_detached="$btf_file" "$obj" 2>/dev/null || [ ! -s "$btf_file" ]; then
		error_log "FAIL: pahole --btf_encode_detached failed"
		test_fail
	fi

	dump=$(bpftool btf dump file "$btf_file" 2>/dev/null)
	if [ -z "$dump" ]; then
		error_log "FAIL: bpftool btf dump produced no output"
		test_fail
	fi

	# The typedef name must appear in the BTF dump
	if ! echo "$dump" | grep -q "TYPEDEF.*uint_t"; then
		error_log "FAIL: bpftool dump missing TYPEDEF uint_t"
		test_fail
	fi
	info_log "bpftool btf dump shows TYPEDEF uint_t: ok"
else
	info_log "skip bpftool cross-check: bpftool not available"
fi

test_pass
