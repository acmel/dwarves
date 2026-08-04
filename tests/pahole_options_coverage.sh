#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Exercise scattered uncovered option paths in pahole.c.
# Many uncovered lines are 1-4 line blocks inside option handlers.
# This test combines multiple option flags to hit as many as possible.

. "$(dirname "$0")/test_lib.sh"
outdir=$(make_tmpdir)

trap cleanup EXIT

title_log "pahole.c scattered option paths."

CC=${CC:-gcc}
if ! command -v "${CC%% *}" > /dev/null 2>&1; then
	info_log "skip: $CC not available"
	test_skip
fi

src=$(make_tmpsrc)
obj=$(make_tmpobj)

cat > "$src" << 'EOF'
struct padded {
	long a;
	char b;
	/* 7-byte hole */
	long c;
};

struct nested {
	struct padded p;
	int x;
};

struct small { char a; };
struct empty_like { };

union mix { int i; float f; long l; };

int func1(int a, int b) { return a + b; }
int func2(struct padded *p) { return p->a; }

struct padded g_padded;
struct nested g_nested;
struct small g_small;
union mix g_mix;
EOF

if ! $CC -g -O0 -c -o "$obj" "$src" 2>/dev/null; then
	error_log "FAIL: compilation failed"
	test_fail
fi

# --show_private_classes: exercises the private class iteration path
output=$(pahole --show_private_classes "$obj" 2>/dev/null)
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: --show_private_classes exited $rc"
	test_fail
fi
info_log "   --show_private_classes: ok"

# -n/--nr_members: show number of members per struct
output=$(pahole --nr_members "$obj" 2>/dev/null)
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: --nr_members exited $rc"
	test_fail
fi
info_log "   --nr_members: ok"

# --nr_definitions: show how many CUs define each type
output=$(pahole --nr_definitions "$obj" 2>/dev/null)
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: --nr_definitions exited $rc"
	test_fail
fi
info_log "   --nr_definitions: ok"

# --nr_methods: show method counts
output=$(pahole --nr_methods "$obj" 2>/dev/null)
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: --nr_methods exited $rc"
	test_fail
fi
info_log "   --nr_methods: ok"

# -t/--separator: custom separator in --sizes output
output=$(pahole --sizes --separator=";" "$obj" 2>/dev/null)
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: --sizes --separator exited $rc"
	test_fail
fi
info_log "   --sizes --separator: ok"

# --class_name_len: show size of classes
output=$(pahole --class_name_len "$obj" 2>/dev/null)
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: --class_name_len exited $rc"
	test_fail
fi
info_log "   --class_name_len: ok"

# -a/--anon_include and -A/--nested_anon_include
output=$(pahole -a "$obj" 2>/dev/null)
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: -a exited $rc"
	test_fail
fi
info_log "   -a (anon_include): ok"

output=$(pahole -A "$obj" 2>/dev/null)
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: -A exited $rc"
	test_fail
fi
info_log "   -A (nested_anon_include): ok"

# -r/--rel_offset: show relative offsets in nested structs
output=$(pahole -r -C nested "$obj" 2>/dev/null)
rc=$?
if [ $rc -ne 0 ] || [ -z "$output" ]; then
	error_log "FAIL: -r -C nested produced no output"
	test_fail
fi
info_log "   -r (rel_offset): ok"

# -R/--reorganize with -c for specific cacheline
output=$(pahole --reorganize -c 32 -C padded "$obj" 2>/dev/null)
rc=$?
if [ $rc -ne 0 ] || [ -z "$output" ]; then
	error_log "FAIL: --reorganize -c 32 -C padded produced no output"
	test_fail
fi
info_log "   --reorganize -c 32: ok"

# -p/--expand_pointers with -C
output=$(pahole -p -C nested "$obj" 2>/dev/null)
rc=$?
if [ $rc -ne 0 ] || [ -z "$output" ]; then
	error_log "FAIL: -p -C nested produced no output"
	test_fail
fi
info_log "   -p (expand_pointers): ok"

# --find_pointers_to: look for struct pointers
output=$(pahole --find_pointers_to=padded "$obj" 2>/dev/null)
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: --find_pointers_to exited $rc"
	test_fail
fi
info_log "   --find_pointers_to: ok"

# --unions: filter to only unions
output=$(pahole --unions "$obj" 2>/dev/null)
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: --unions exited $rc"
	test_fail
fi
if [ -z "$output" ]; then
	error_log "FAIL: --unions produced no output (union mix should appear)"
	test_fail
fi
if ! echo "$output" | grep -q "mix"; then
	error_log "FAIL: --unions missing mix"
	test_fail
fi
info_log "   --unions: ok"

# --classes_as_structs: print C++ classes as structs
output=$(pahole --classes_as_structs "$obj" 2>/dev/null)
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: --classes_as_structs exited $rc"
	test_fail
fi
info_log "   --classes_as_structs: ok"

# Combine: --holes with --hex for hex hole display
output=$(pahole --holes=1 --hex "$obj" 2>/dev/null)
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: --holes --hex exited $rc"
	test_fail
fi
info_log "   --holes --hex: ok"

# --bit_holes: show bit-level holes
output=$(pahole --bit_holes=1 "$obj" 2>/dev/null)
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: --bit_holes exited $rc"
	test_fail
fi
info_log "   --bit_holes: ok"

# --suppress_aligned_attribute and --suppress_packed together
output=$(pahole --suppress_aligned_attribute --suppress_packed -C padded "$obj" 2>/dev/null)
rc=$?
if [ $rc -ne 0 ] || [ -z "$output" ]; then
	error_log "FAIL: --suppress_aligned_attribute --suppress_packed produced no output"
	test_fail
fi
info_log "   --suppress_aligned/packed: ok"

# --flat_arrays: flatten array dimensions
output=$(pahole --flat_arrays "$obj" 2>/dev/null)
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: --flat_arrays exited $rc"
	test_fail
fi
info_log "   --flat_arrays: ok"

# -I/--show_decl_info: show file/line declaration info
output=$(pahole -I -C padded "$obj" 2>/dev/null)
rc=$?
if [ $rc -ne 0 ] || [ -z "$output" ]; then
	error_log "FAIL: -I -C padded produced no output"
	test_fail
fi
info_log "   -I (show_decl_info): ok"

# -u/--defined_in: show which CUs define a type
output=$(pahole -u -C padded "$obj" 2>/dev/null)
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: -u -C padded exited $rc"
	test_fail
fi
info_log "   -u (defined_in): ok"

test_pass
