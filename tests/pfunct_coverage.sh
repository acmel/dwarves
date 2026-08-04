#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Test pfunct --symtab, --class, --compile and -b (expand_types) paths.

. "$(dirname "$0")/test_lib.sh"
outdir=$(make_tmpdir)

trap cleanup EXIT

title_log "pfunct coverage: symtab, class, expand_types, compile."

CC=${CC:-gcc}
if ! command -v "${CC%% *}" > /dev/null 2>&1; then
	info_log "skip: $CC not available"
	test_skip
fi

if ! command -v pfunct > /dev/null 2>&1; then
	info_log "skip: pfunct not available"
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

typedef unsigned long size_type;

int point_sum(struct point *p) {
	return p->x + p->y;
}

struct point *rect_origin(struct rect *r) {
	return &r->origin;
}

int rect_area(struct rect *r) {
	return r->width * r->height;
}

size_type compute_size(size_type a, size_type b) {
	return a * b;
}

void no_params(void) { }

int global_var = 42;
EOF

if ! $CC -g -O0 -c -o "$obj" "$src" 2>/dev/null; then
	error_log "FAIL: compilation failed"
	test_fail
fi

output=$(pfunct --symtab "$obj" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: pfunct --symtab produced no output"
	test_fail
fi
if ! echo "$output" | grep -q "point_sum"; then
	error_log "FAIL: --symtab missing point_sum"
	test_fail
fi
info_log "   --symtab: ok"

output=$(pfunct --class=point "$obj" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: pfunct --class=point produced no output"
	test_fail
fi
if ! echo "$output" | grep -q "point_sum"; then
	error_log "FAIL: --class=point missing point_sum"
	test_fail
fi
info_log "   --class=point: ok"

output=$(pfunct --class=rect "$obj" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: pfunct --class=rect produced no output"
	test_fail
fi
if ! echo "$output" | grep -q "rect_area"; then
	error_log "FAIL: --class=rect missing rect_area"
	test_fail
fi
info_log "   --class=rect: ok"

output=$(pfunct -V --class=point "$obj" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: pfunct -V --class=point produced no output"
	test_fail
fi
if ! echo "$output" | grep -q "struct point"; then
	error_log "FAIL: -V --class=point missing prototype"
	test_fail
fi
info_log "   -V --class=point: ok"

output=$(pfunct -b "$obj" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: pfunct -b produced no output"
	test_fail
fi
if ! echo "$output" | grep -q "struct point"; then
	error_log "FAIL: -b missing struct point definition"
	test_fail
fi
info_log "   -b (expand_types): ok"

output=$(pfunct --compile "$obj" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: pfunct --compile produced no output"
	test_fail
fi
if ! echo "$output" | grep -q "return"; then
	error_log "FAIL: --compile missing return statement"
	test_fail
fi
info_log "   --compile (all functions): ok"

output=$(pfunct --compile=rect_origin "$obj" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: pfunct --compile=rect_origin produced no output"
	test_fail
fi
info_log "   --compile=rect_origin: ok"

output=$(pfunct --compile=rect_area "$obj" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: pfunct --compile=rect_area produced no output"
	test_fail
fi
info_log "   --compile=rect_area: ok"

output=$(pfunct --compile=no_params "$obj" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: pfunct --compile=no_params produced no output"
	test_fail
fi
info_log "   --compile=no_params: ok"

output=$(pfunct -b -f point_sum "$obj" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: pfunct -b -f point_sum produced no output"
	test_fail
fi
info_log "   -b -f point_sum: ok"

test_pass
