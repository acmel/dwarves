#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Exercise uncovered paths in smaller source files:
#   - elf_symtab.c: symtab iteration, stripped objects
#   - gobuffer.c: buffer operations via BTF encoding
#   - dutil.c: string operations, objcopy path
#   - pglobal.c: verbose variable listing

. "$(dirname "$0")/test_lib.sh"
outdir=$(make_tmpdir)

trap cleanup EXIT

title_log "Small files coverage: elf_symtab, gobuffer, dutil, pglobal."

CC=${CC:-gcc}
if ! command -v "${CC%% *}" > /dev/null 2>&1; then
	info_log "skip: $CC not available"
	test_skip
fi

src=$(make_tmpsrc)
obj=$(make_tmpobj)

cat > "$src" << 'EOF'
struct point { int x; int y; };
struct rect { struct point tl; struct point br; };

int compute(struct point *p) { return p->x + p->y; }
static int helper(int a) { return a * 2; }
int use_helper(int x) { return helper(x); }

struct point g_point;
struct rect g_rect;
int g_counter = 42;
static int s_internal = 99;
const char *g_str = "hello";
int g_arr[4] = { 1, 2, 3, 4 };
EOF

if ! $CC -g -O0 -c -o "$obj" "$src" 2>/dev/null; then
	error_log "FAIL: compilation failed"
	test_fail
fi

# ---------------------------------------------------------------
# elf_symtab.c: symtab iteration
# ---------------------------------------------------------------

if command -v pfunct > /dev/null 2>&1; then
	output=$(pfunct --symtab "$obj" 2>/dev/null)
	rc=$?
	if [ $rc -ne 0 ]; then
		error_log "FAIL: pfunct --symtab exited $rc"
		test_fail
	fi
	if [ -z "$output" ]; then
		error_log "FAIL: pfunct --symtab produced no output"
		test_fail
	fi
	info_log "   pfunct --symtab: ok"

	# Stripped object (no debug info) — exercises elf_symtab error/cleanup
	# paths when DWARF sections are missing
	stripped="$outdir/stripped.o"
	cp "$obj" "$stripped"
	if strip --strip-debug "$stripped" 2>/dev/null; then
		output=$(pfunct --symtab "$stripped" 2>/dev/null)
		rc=$?
		# pfunct --symtab on a stripped object may or may not produce
		# output depending on whether .symtab survives --strip-debug.
		# The key thing is it must not crash (exit > 128 = signal).
		if [ $rc -gt 128 ]; then
			error_log "FAIL: pfunct --symtab (stripped) crashed with signal $((rc - 128))"
			test_fail
		fi
		info_log "   pfunct --symtab (stripped): ok (exit $rc)"
	else
		info_log "   skip: strip not available"
	fi
else
	info_log "   skip: pfunct not available"
fi

# ---------------------------------------------------------------
# pglobal.c: verbose variable listing
# ---------------------------------------------------------------

if command -v pglobal > /dev/null 2>&1; then
	# -v -V: verbose variable display exercises deeper pglobal.c paths
	output=$(pglobal -v -V "$obj" 2>/dev/null)
	rc=$?
	if [ $rc -ne 0 ]; then
		error_log "FAIL: pglobal -v -V exited $rc"
		test_fail
	fi
	if [ -z "$output" ]; then
		error_log "FAIL: pglobal -v -V produced no output"
		test_fail
	fi
	if ! echo "$output" | grep -q "g_counter"; then
		error_log "FAIL: pglobal -v -V missing g_counter"
		test_fail
	fi
	info_log "   pglobal -v -V (verbose vars): ok"

	# -f -V: verbose function listing
	output=$(pglobal -f -V "$obj" 2>/dev/null)
	rc=$?
	if [ $rc -ne 0 ]; then
		error_log "FAIL: pglobal -f -V exited $rc"
		test_fail
	fi
	if [ -z "$output" ]; then
		error_log "FAIL: pglobal -f -V produced no output"
		test_fail
	fi
	info_log "   pglobal -f -V (verbose funcs): ok"
else
	info_log "   skip: pglobal not available"
fi

# ---------------------------------------------------------------
# gobuffer.c + dutil.c: BTF encoding exercises buffer operations
# ---------------------------------------------------------------

# BTF encoding with vars exercises gobuffer__add and gobuffer__allocate
# when building the DATASEC section
$CC -g -O0 -c -o "$outdir/btf_buf.o" "$src" 2>/dev/null
pahole -J --btf_features=default,var "$outdir/btf_buf.o" 2>/dev/null
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: BTF encode for buffer test exited $rc"
	test_fail
fi
output=$(pahole -F btf "$outdir/btf_buf.o" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: BTF buffer test read-back empty"
	test_fail
fi
info_log "   BTF encode (gobuffer paths): ok"

# ---------------------------------------------------------------
# BSS-only object: no functions, only STT_OBJECT symbols
# ---------------------------------------------------------------

bss_src="$outdir/bss_only.c"
bss_obj="$outdir/bss_only.o"
cat > "$bss_src" << 'EOF'
struct bss_data { int x; int y; };
struct bss_data g_bss;
int g_zero;
EOF

if ! $CC -g -O0 -c -o "$bss_obj" "$bss_src" 2>/dev/null; then
	error_log "FAIL: BSS source compilation failed"
	test_fail
fi

if command -v pfunct > /dev/null 2>&1; then
	# pfunct --symtab on a no-functions object exercises edge cases
	# in elf_symtab iteration when only data symbols exist.
	# Non-zero exit is fine (no functions to list), but a crash is not.
	output=$(pfunct --symtab "$bss_obj" 2>/dev/null)
	rc=$?
	if [ $rc -gt 128 ]; then
		error_log "FAIL: pfunct --symtab (bss-only) crashed with signal $((rc - 128))"
		test_fail
	fi
	info_log "   pfunct --symtab (bss-only): ok (exit $rc)"
fi

if command -v pglobal > /dev/null 2>&1; then
	output=$(pglobal -v "$bss_obj" 2>/dev/null)
	rc=$?
	if [ $rc -ne 0 ]; then
		error_log "FAIL: pglobal -v (bss-only) exited $rc"
		test_fail
	fi
	if [ -z "$output" ]; then
		error_log "FAIL: pglobal -v (bss-only) produced no output"
		test_fail
	fi
	info_log "   pglobal -v (bss-only): ok"
fi

test_pass
