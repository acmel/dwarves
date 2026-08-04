#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Test codiff member change detection: type changes, removed members,
# function prototype changes, and verbose diff output.
# Exercises uncovered codiff.c paths (lines 109-298).

. "$(dirname "$0")/test_lib.sh"
outdir=$(make_tmpdir)

trap cleanup EXIT

title_log "codiff member change coverage."

CC=${CC:-gcc}
if ! command -v "${CC%% *}" > /dev/null 2>&1; then
	info_log "skip: $CC not available"
	test_skip
fi

if ! command -v codiff > /dev/null 2>&1; then
	info_log "skip: codiff not available"
	test_skip
fi

# Version 1: original layout
cat > "$outdir/v1.c" << 'EOF'
struct record {
	int	id;
	char	name[16];
	short	flags;
	int	count;
};

int process_record(struct record *r) { return r->id + r->count; }

struct record g_rec;
EOF

# Version 2: member type change, member removal, member addition,
# function prototype change
cat > "$outdir/v2.c" << 'EOF'
struct record {
	int	id;
	char	name[32];	/* enlarged: 16 -> 32 */
	int	flags;		/* type change: short -> int */
	/* count removed */
	long	total;		/* new member */
};

/* Changed signature: return type and parameter list differ */
long process_record(struct record *r, int extra) {
	return r->id + r->total + extra;
}

struct record g_rec;
EOF

if ! $CC -g -c -o "$outdir/v1.o" "$outdir/v1.c" 2>/dev/null; then
	error_log "FAIL: v1 compilation failed"
	test_fail
fi
if ! $CC -g -c -o "$outdir/v2.o" "$outdir/v2.c" 2>/dev/null; then
	error_log "FAIL: v2 compilation failed"
	test_fail
fi

# Default codiff: should detect struct and function changes
output=$(codiff "$outdir/v1.o" "$outdir/v2.o" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: codiff default produced no output"
	test_fail
fi
if ! echo "$output" | grep -q "record"; then
	error_log "FAIL: codiff missing record changes"
	test_fail
fi
info_log "   codiff default: ok"

# -s: struct changes only
output=$(codiff -s "$outdir/v1.o" "$outdir/v2.o" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: codiff -s produced no output"
	test_fail
fi
info_log "   codiff -s: ok"

# -s -V: verbose struct changes — shows per-member diffs including
# type changes (line ~173) and removed members (line ~227)
output=$(codiff -s -V "$outdir/v1.o" "$outdir/v2.o" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: codiff -s -V produced no output"
	test_fail
fi
info_log "   codiff -s -V: ok"

# -f -V: verbose function changes — exercises prototype comparison
# (line ~109) where function signatures differ
output=$(codiff -f -V "$outdir/v1.o" "$outdir/v2.o" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: codiff -f -V produced no output"
	test_fail
fi
info_log "   codiff -f -V: ok"

# -t: terse type changes
output=$(codiff -t "$outdir/v1.o" "$outdir/v2.o" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: codiff -t produced no output"
	test_fail
fi
info_log "   codiff -t: ok"

test_pass
