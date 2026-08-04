#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Test codiff with multiple separate compilation units (nr_entries > 1).
# This exercises __cus__find_cu_by_name() in dwarves.c, which is only
# called when cus->nr_entries > 1 in cus__find_pair().
#
# Note: using `ld -r` to combine .o files merges CUs, so we must pass
# separate .o files with matching struct/function names across units.

. "$(dirname "$0")/test_lib.sh"
outdir=$(make_tmpdir)

trap cleanup EXIT

title_log "codiff multi-CU: __cus__find_cu_by_name coverage."

CC=${CC:-gcc}
if ! command -v "${CC%% *}" > /dev/null 2>&1; then
	info_log "skip: $CC not available"
	test_skip
fi

if ! command -v codiff > /dev/null 2>&1; then
	info_log "skip: codiff not available"
	test_skip
fi

# Create two compilation units with different source files but
# related types/functions. codiff will need to match CUs by name
# when comparing changes across multiple units.

cat > "$outdir/widget_v1.c" << 'EOF'
struct widget {
	int id;
	char tag;
};

int widget_init(struct widget *w) { return w->id; }
EOF

cat > "$outdir/gadget_v1.c" << 'EOF'
struct gadget {
	long serial;
	short flags;
};

int gadget_init(struct gadget *g) { return (int)g->serial; }
EOF

cat > "$outdir/widget_v2.c" << 'EOF'
struct widget {
	int id;
	char tag;
	long weight;  /* +8 bytes */
};

int widget_init(struct widget *w) { return w->id + (int)w->weight; }
EOF

cat > "$outdir/gadget_v2.c" << 'EOF'
struct gadget {
	long serial;
	short flags;
	int revision;  /* +4 bytes */
};

int gadget_init(struct gadget *g) { return (int)g->serial + g->revision; }
EOF

# Compile each source into its own .o file, preserving CU identity
if ! $CC -g -c -o "$outdir/widget_v1.o" "$outdir/widget_v1.c" 2>/dev/null; then
	error_log "FAIL: compilation of widget_v1 failed"
	test_fail
fi

if ! $CC -g -c -o "$outdir/gadget_v1.o" "$outdir/gadget_v1.c" 2>/dev/null; then
	error_log "FAIL: compilation of gadget_v1 failed"
	test_fail
fi

if ! $CC -g -c -o "$outdir/widget_v2.o" "$outdir/widget_v2.c" 2>/dev/null; then
	error_log "FAIL: compilation of widget_v2 failed"
	test_fail
fi

if ! $CC -g -c -o "$outdir/gadget_v2.o" "$outdir/gadget_v2.c" 2>/dev/null; then
	error_log "FAIL: compilation of gadget_v2 failed"
	test_fail
fi

# Create archive files containing multiple .o files. When codiff processes
# an archive, it loads all CUs from all members, creating a multi-CU cus
# with nr_entries > 1. cus__find_pair() must then use __cus__find_cu_by_name()
# to match old and new CUs by their source file name.

if ! ar rcs "$outdir/old.a" "$outdir/widget_v1.o" "$outdir/gadget_v1.o" 2>/dev/null; then
	error_log "FAIL: ar rcs old.a failed"
	test_fail
fi

if ! ar rcs "$outdir/new.a" "$outdir/widget_v2.o" "$outdir/gadget_v2.o" 2>/dev/null; then
	error_log "FAIL: ar rcs new.a failed"
	test_fail
fi

info_log "   created multi-CU archives: old.a (2 CUs), new.a (2 CUs)"

# Run codiff on the archives. This should trigger:
#   cus->nr_entries == 2 (widget + gadget)
#   → cus__find_pair calls __cus__find_cu_by_name() for each CU name
output=$(codiff "$outdir/old.a" "$outdir/new.a" 2>/dev/null)
rc=$?

if [ $rc -ne 0 ]; then
	error_log "FAIL: codiff on multi-CU archives exited with code $rc"
	echo "$output" >&2
	test_fail
fi

if [ -z "$output" ]; then
	error_log "FAIL: codiff on multi-CU archives produced no output"
	test_fail
fi

# Verify both widget and gadget changes are reported
if ! echo "$output" | grep -q "widget"; then
	error_log "FAIL: codiff output missing 'widget' changes"
	echo "$output" >&2
	test_fail
fi

if ! echo "$output" | grep -q "gadget"; then
	error_log "FAIL: codiff output missing 'gadget' changes"
	echo "$output" >&2
	test_fail
fi

info_log "   codiff multi-CU: both widget and gadget changes detected"

# Verify the size changes are positive (exact values depend on padding/alignment)
# widget: added 'long weight' → struct grows
# gadget: added 'int revision' → struct grows
if ! echo "$output" | grep -E "struct widget.*\+"; then
	error_log "FAIL: widget struct should grow"
	echo "$output" >&2
	test_fail
fi

if ! echo "$output" | grep -E "struct gadget.*\+"; then
	error_log "FAIL: gadget struct should grow"
	echo "$output" >&2
	test_fail
fi

info_log "   codiff multi-CU: struct size changes detected (both positive)"

test_pass
