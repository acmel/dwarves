#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Basic smoke tests for auxiliary tools: pglobal, prefcnt, dtagnames.
# These tools have near-zero test coverage; verify they run and
# produce reasonable output on a simple object file.

. "$(dirname "$0")/test_lib.sh"

outdir=$(make_tmpdir)

trap cleanup EXIT

title_log "Auxiliary tools: pglobal, prefcnt, dtagnames."

CC=${CC:-gcc}
if ! command -v "${CC%% *}" > /dev/null 2>&1; then
	info_log "skip: $CC not available"
	test_skip
fi

src=$(make_tmpsrc)
obj=$(make_tmpobj)

cat > "$src" << 'EOF'
int global_a = 1;
static int static_b = 2;

void func_one(void) { global_a++; }
static void func_two(void) { static_b++; }

struct tagged_s {
	int x;
	int y;
};

struct tagged_s gs;
EOF

if ! $CC -g -c -o "$obj" "$src" 2>/dev/null; then
	error_log "FAIL: compilation failed"
	test_fail
fi

# --- pglobal ---
if command -v pglobal > /dev/null 2>&1; then
	if ! out=$(pglobal "$obj" 2>/dev/null); then
		error_log "FAIL: pglobal exited with error"
		test_fail
	fi
	info_log "pglobal: ok"
else
	info_log "pglobal: not in PATH, skipping"
fi

# --- prefcnt ---
if command -v prefcnt > /dev/null 2>&1; then
	if ! out=$(prefcnt "$obj" 2>/dev/null); then
		error_log "FAIL: prefcnt exited with error"
		test_fail
	fi
	info_log "prefcnt: ok"
else
	info_log "prefcnt: not in PATH, skipping"
fi

# --- dtagnames ---
if command -v dtagnames > /dev/null 2>&1; then
	if ! out=$(dtagnames "$obj" 2>/dev/null); then
		error_log "FAIL: dtagnames exited with error"
		test_fail
	fi
	# dtagnames should list DWARF tag names from the object
	if [ -z "$out" ]; then
		error_log "FAIL: dtagnames produced no output"
		test_fail
	fi
	info_log "dtagnames: ok"
else
	info_log "dtagnames: not in PATH, skipping"
fi

test_pass
