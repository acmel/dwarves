#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Test pglobal -v (variables) and -f (functions) with global vs static symbols.

. "$(dirname "$0")/test_lib.sh"
outdir=$(make_tmpdir)

trap cleanup EXIT

title_log "pglobal basic: variables, functions, static exclusion."

CC=${CC:-gcc}
if ! command -v "${CC%% *}" > /dev/null 2>&1; then
	info_log "skip: $CC not available"
	test_skip
fi

if ! command -v pglobal > /dev/null 2>&1; then
	info_log "skip: pglobal not available"
	test_skip
fi

src=$(make_tmpsrc)
obj=$(make_tmpobj)

cat > "$src" << 'EOF'
struct point {
	int x;
	int y;
};

struct rect {
	struct point origin;
	int width;
	int height;
};

struct point global_point = { .x = 1, .y = 2 };
struct rect global_rect = { .origin = { 3, 4 }, .width = 10, .height = 20 };
int global_counter = 42;

static struct point static_point = { .x = 5, .y = 6 };
static int static_counter = 99;

int point_sum(struct point *p) {
	return p->x + p->y;
}

int rect_area(struct rect *r) {
	return r->width * r->height;
}

static int static_helper(int a, int b) {
	return a + b;
}

int use_statics(void) {
	return static_point.x + static_counter + static_helper(1, 2);
}
EOF

if ! $CC -g -O0 -c -o "$obj" "$src" 2>/dev/null; then
	error_log "FAIL: compilation failed"
	test_fail
fi

output=$(pglobal "$obj" 2>/dev/null)
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: pglobal with no flags returned $rc"
	test_fail
fi
info_log "   no flags (baseline): ok (rc=0)"

output=$(pglobal -v "$obj" 2>/dev/null)
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: pglobal -v returned $rc"
	test_fail
fi
if [ -z "$output" ]; then
	error_log "FAIL: pglobal -v produced no output"
	test_fail
fi
if ! echo "$output" | grep -q "global_point"; then
	error_log "FAIL: -v missing global_point"
	test_fail
fi
if ! echo "$output" | grep -q "global_rect"; then
	error_log "FAIL: -v missing global_rect"
	test_fail
fi
if ! echo "$output" | grep -q "global_counter"; then
	error_log "FAIL: -v missing global_counter"
	test_fail
fi
info_log "   -v (variables): ok"

if echo "$output" | grep -q "static_point"; then
	error_log "FAIL: -v should not list static_point"
	test_fail
fi
if echo "$output" | grep -q "static_counter"; then
	error_log "FAIL: -v should not list static_counter"
	test_fail
fi
info_log "   -v excludes static variables: ok"

output=$(pglobal --variables "$obj" 2>/dev/null)
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: pglobal --variables returned $rc"
	test_fail
fi
if [ -z "$output" ]; then
	error_log "FAIL: pglobal --variables produced no output"
	test_fail
fi
if ! echo "$output" | grep -q "global_point"; then
	error_log "FAIL: --variables missing global_point"
	test_fail
fi
info_log "   --variables (long form): ok"

output=$(pglobal -f "$obj" 2>/dev/null)
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: pglobal -f returned $rc"
	test_fail
fi
if [ -z "$output" ]; then
	error_log "FAIL: pglobal -f produced no output"
	test_fail
fi
if ! echo "$output" | grep -q "point_sum"; then
	error_log "FAIL: -f missing point_sum"
	test_fail
fi
if ! echo "$output" | grep -q "rect_area"; then
	error_log "FAIL: -f missing rect_area"
	test_fail
fi
if ! echo "$output" | grep -q "use_statics"; then
	error_log "FAIL: -f missing use_statics"
	test_fail
fi
info_log "   -f (functions): ok"

if echo "$output" | grep -q "static_helper"; then
	error_log "FAIL: -f should not list static_helper"
	test_fail
fi
info_log "   -f excludes static functions: ok"

output=$(pglobal --functions "$obj" 2>/dev/null)
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: pglobal --functions returned $rc"
	test_fail
fi
if [ -z "$output" ]; then
	error_log "FAIL: pglobal --functions produced no output"
	test_fail
fi
if ! echo "$output" | grep -q "point_sum"; then
	error_log "FAIL: --functions missing point_sum"
	test_fail
fi
info_log "   --functions (long form): ok"

test_pass
