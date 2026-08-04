#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Exercise uncovered paths in dwarves.c:
#   - cus__find_function_at_addr (pfunct --addr)
#   - cus__fprintf_load_files_err (nonexistent file error)
#   - cus__load_dir (directory loading)
#   - base_type__name_to_size (pfunct --compile)
#   - cu__find_first_typedef_of_type (pahole --compile)

. "$(dirname "$0")/test_lib.sh"
outdir=$(make_tmpdir)

trap cleanup EXIT

title_log "dwarves.c core API coverage."

CC=${CC:-gcc}
if ! command -v "${CC%% *}" > /dev/null 2>&1; then
	info_log "skip: $CC not available"
	test_skip
fi

src=$(make_tmpsrc)
obj=$(make_tmpobj)

cat > "$src" << 'EOF'
typedef int my_int_t;
typedef my_int_t nested_typedef_t;

enum color { RED, GREEN, BLUE };
typedef enum color color_t;

struct simple { int x; int y; };
typedef struct simple simple_t;

int global_func(int a, int b) { return a + b; }
static int static_func(int x) { return x * 2; }
int use_static(int x) { return static_func(x); }

struct simple g_simple;
my_int_t g_myint;
nested_typedef_t g_nested;
enum color g_color;
simple_t g_st;
color_t g_ct;
EOF

if ! $CC -g -O0 -c -o "$obj" "$src" 2>/dev/null; then
	error_log "FAIL: compilation failed"
	test_fail
fi

# pfunct --addr: look up a function by address using nm to get the address.
# Exercises cus__find_function_at_addr (dwarves.c line ~1079).
if command -v pfunct > /dev/null 2>&1; then
	# nm output format: "addr T symbol_name" — extract the address of global_func
	addr=$(nm "$obj" 2>/dev/null | grep ' T global_func$' | awk '{print "0x"$1}')
	if [ -n "$addr" ]; then
		output=$(pfunct --addr="$addr" "$obj" 2>/dev/null)
		rc=$?
		if [ $rc -ne 0 ]; then
			error_log "FAIL: pfunct --addr=$addr exited $rc"
			test_fail
		fi
		if [ -z "$output" ]; then
			error_log "FAIL: pfunct --addr=$addr produced no output"
			test_fail
		fi
		if ! echo "$output" | grep -q "global_func"; then
			error_log "FAIL: pfunct --addr did not find global_func"
			test_fail
		fi
		info_log "   pfunct --addr: ok"
	else
		info_log "   skip: could not extract global_func address from nm"
	fi

	# pfunct --compile: exercises base_type__name_to_size and typedef resolution
	output=$(pfunct --compile=global_func "$obj" 2>/dev/null)
	rc=$?
	if [ $rc -ne 0 ]; then
		error_log "FAIL: pfunct --compile=global_func exited $rc"
		test_fail
	fi
	if [ -z "$output" ]; then
		error_log "FAIL: pfunct --compile=global_func produced no output"
		test_fail
	fi
	info_log "   pfunct --compile=global_func: ok"
else
	info_log "   skip: pfunct not available"
fi

# pahole --compile: exercises cu__find_first_typedef_of_type
output=$(pahole --compile -C simple "$obj" 2>/dev/null)
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: pahole --compile -C simple exited $rc"
	test_fail
fi
if [ -z "$output" ]; then
	error_log "FAIL: pahole --compile -C simple produced no output"
	test_fail
fi
info_log "   pahole --compile -C simple: ok"

# pahole -E (expand): exercises type resolution chains
output=$(pahole -E -C simple "$obj" 2>/dev/null)
rc=$?
if [ $rc -ne 0 ] || [ -z "$output" ]; then
	error_log "FAIL: pahole -E -C simple produced no output"
	test_fail
fi
info_log "   pahole -E -C simple: ok"

# cus__load_dir: pass a directory containing .o files to pahole.
# This exercises the directory-walking code path (dwarves.c line ~2269).
dirtest="$outdir/dir_test"
mkdir -p "$dirtest"

cat > "$dirtest/a.c" << 'EOF'
struct dir_a { int x; };
struct dir_a g_da;
EOF
cat > "$dirtest/b.c" << 'EOF'
struct dir_b { long y; };
struct dir_b g_db;
EOF

$CC -g -c -o "$dirtest/a.o" "$dirtest/a.c" 2>/dev/null
$CC -g -c -o "$dirtest/b.o" "$dirtest/b.c" 2>/dev/null

if [ -f "$dirtest/a.o" ] && [ -f "$dirtest/b.o" ]; then
	output=$(pahole "$dirtest" 2>/dev/null)
	rc=$?
	if [ $rc -ne 0 ]; then
		info_log "   pahole <directory>: exited $rc (may not support directory loading)"
	elif [ -z "$output" ]; then
		info_log "   pahole <directory>: no output (may not support directory loading)"
	else
		info_log "   pahole <directory>: ok"
	fi
fi
# cleanup() in test_lib.sh can't remove subdirectories
rm -f "$dirtest"/* 2>/dev/null
rmdir "$dirtest" 2>/dev/null

# cus__fprintf_load_files_err: loading a nonexistent file exercises
# the error message path (dwarves.c line ~3054).
output=$(pahole /nonexistent/file.o 2>&1)
rc=$?
if [ $rc -ne 0 ]; then
	info_log "   pahole /nonexistent/file.o: exit code $rc (error path ok)"
else
	info_log "   pahole /nonexistent/file.o: exit code 0 (unexpected but non-fatal)"
fi

# -y / --prefix_filter: exercise the type name prefix search path
output=$(pahole -y simpl "$obj" 2>/dev/null)
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: pahole -y simpl exited $rc"
	test_fail
fi
info_log "   pahole -y (prefix_filter): ok"

# -z / --hole_size_ge: exercise the hole size threshold filter
output=$(pahole -z 1 "$obj" 2>/dev/null)
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: pahole -z 1 exited $rc"
	test_fail
fi
info_log "   pahole -z (hole_size_ge): ok"

test_pass
