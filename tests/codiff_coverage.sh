#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Test codiff: --terse, --functions, --verbose, and multi-CU total diff paths.

. "$(dirname "$0")/test_lib.sh"
outdir=$(make_tmpdir)

trap cleanup EXIT

title_log "codiff coverage: terse, functions, verbose, multi-CU."

CC=${CC:-gcc}
if ! command -v "${CC%% *}" > /dev/null 2>&1; then
	info_log "skip: $CC not available"
	test_skip
fi

if ! command -v codiff > /dev/null 2>&1; then
	info_log "skip: codiff not available"
	test_skip
fi

# LD may contain flags (e.g. "ld -m elf_x86_64"), strip them for the
# availability check, same as the CC check above uses ${CC%% *}.
LD=${LD:-ld}
if ! command -v "${LD%% *}" > /dev/null 2>&1; then
	info_log "skip: $LD not available"
	test_skip
fi

cat > "$outdir/a_v1.c" << 'EOF'
struct widget {
	int	id;
	char	tag;
};

int widget_area(struct widget *w) { return w->id * 2; }
int widget_check(struct widget *w) { return w->id > 0; }
EOF

cat > "$outdir/b_v1.c" << 'EOF'
struct gadget {
	long	serial;
	short	flags;
};

int gadget_init(struct gadget *g) { return (int)g->serial; }
EOF

cat > "$outdir/a_v2.c" << 'EOF'
struct widget {
	int	id;
	char	tag;
	long	weight;
	short	priority;
};

int widget_area(struct widget *w) { return w->id * (int)w->weight; }
int widget_check(struct widget *w) { return w->id > 0 && w->priority > 0; }
EOF

cat > "$outdir/b_v2.c" << 'EOF'
struct gadget {
	long	serial;
	short	flags;
	int	revision;
};

int gadget_init(struct gadget *g) { return (int)g->serial + g->revision; }
EOF

if ! $CC -g -c -o "$outdir/a_v1.o" "$outdir/a_v1.c" 2>/dev/null; then
	error_log "FAIL: compilation of a_v1 failed"
	test_fail
fi
if ! $CC -g -c -o "$outdir/b_v1.o" "$outdir/b_v1.c" 2>/dev/null; then
	error_log "FAIL: compilation of b_v1 failed"
	test_fail
fi
if ! $CC -g -c -o "$outdir/a_v2.o" "$outdir/a_v2.c" 2>/dev/null; then
	error_log "FAIL: compilation of a_v2 failed"
	test_fail
fi
if ! $CC -g -c -o "$outdir/b_v2.o" "$outdir/b_v2.c" 2>/dev/null; then
	error_log "FAIL: compilation of b_v2 failed"
	test_fail
fi

if ! $LD -r -o "$outdir/old.o" "$outdir/a_v1.o" "$outdir/b_v1.o" 2>/dev/null; then
	error_log "FAIL: ld -r for old.o failed"
	test_fail
fi
if ! $LD -r -o "$outdir/new.o" "$outdir/a_v2.o" "$outdir/b_v2.o" 2>/dev/null; then
	error_log "FAIL: ld -r for new.o failed"
	test_fail
fi

old="$outdir/old.o"
new="$outdir/new.o"

output=$(codiff -t "$old" "$new" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: codiff -t produced no output"
	test_fail
fi
if ! echo "$output" | grep -q "widget"; then
	error_log "FAIL: codiff -t missing widget"
	test_fail
fi
info_log "   codiff -t (terse type changes): ok"

output=$(codiff -f "$old" "$new" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: codiff -f produced no output"
	test_fail
fi
info_log "   codiff -f (function diffs): ok"

output=$(codiff -f -V "$old" "$new" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: codiff -f -V produced no output"
	test_fail
fi
info_log "   codiff -f -V (verbose function diffs): ok"

output=$(codiff -s -V "$old" "$new" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: codiff -s -V produced no output"
	test_fail
fi
if ! echo "$output" | grep -q "widget"; then
	error_log "FAIL: codiff -s -V missing widget changes"
	test_fail
fi
info_log "   codiff -s -V (verbose struct diffs): ok"

output=$(codiff "$outdir/a_v1.o" "$outdir/a_v2.o" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: codiff single-CU produced no output"
	test_fail
fi
info_log "   codiff single-CU: ok"

test_pass
