#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Test that pahole correctly resolves types from dwz alternate debug
# files (.gnu_debugaltlink / DW_FORM_GNU_ref_alt).
#
# Creates two binaries sharing common types, runs dwz in multifile
# mode to deduplicate them into a .dwz alt file, then verifies pahole
# can resolve the shared types.

. "$(dirname "$0")/test_lib.sh"

outdir=$(make_tmpdir)
trap cleanup EXIT

title_log "DWZ alternate debug file type resolution."

CC=${CC:-gcc}
if ! command -v ${CC%% *} > /dev/null 2>&1; then
	info_log "skip: $CC not available"
	test_skip
fi

if ! command -v dwz > /dev/null 2>&1; then
	info_log "skip: dwz not available"
	test_skip
fi

READELF=${READELF:-$(command -v readelf || command -v eu-readelf || true)}
if [ -z "$READELF" ]; then
	info_log "skip: neither readelf nor eu-readelf available"
	test_skip
fi

cat > "$outdir/shared_types.h" << 'HEOF'
struct shared_base {
	int id;
	long flags;
	char *name;
	void *data;
};

struct shared_nested {
	struct shared_base base;
	int count;
	double value;
	char buffer[64];
};

struct shared_list {
	struct shared_nested item;
	struct shared_list *next;
	struct shared_list *prev;
};

enum shared_state {
	STATE_INIT = 0,
	STATE_RUNNING = 1,
	STATE_PAUSED = 2,
	STATE_STOPPED = 3,
	STATE_ERROR = 4,
};

typedef unsigned long shared_handle_t;
typedef int (*shared_callback_t)(struct shared_base *, enum shared_state);

struct shared_context {
	struct shared_base base;
	struct shared_list *items;
	shared_callback_t callback;
	shared_handle_t handle;
	enum shared_state state;
	int refcount;
	char description[128];
};
HEOF

cat > "$outdir/prog1.c" << 'EOF'
#include "shared_types.h"

int lib_init(struct shared_context *ctx) {
	ctx->state = STATE_INIT;
	ctx->refcount = 1;
	return 0;
}

int main(void) {
	struct shared_context ctx = { .base = { .id = 1, .name = "prog1" } };
	struct shared_nested item = { .count = 42, .value = 3.14 };
	lib_init(&ctx);
	return item.count;
}
EOF

cat > "$outdir/prog2.c" << 'EOF'
#include "shared_types.h"

shared_handle_t prog2_work(struct shared_context *ctx) {
	struct shared_list node = {
		.item = { .base = { .id = 2 }, .count = 10 },
	};
	ctx->items = &node;
	ctx->state = STATE_PAUSED;
	return ctx->handle;
}

int main(void) {
	struct shared_context ctx = { .base = { .id = 99, .name = "prog2" } };
	return (int)prog2_work(&ctx);
}
EOF

# Try DWARF 4 first (old dwz chokes on DWARF 5 input), then fall back
# to default -g so we do not silently lose coverage on distros where
# gcc defaults to DWARF 5 and dwz is too old for it.
dwz_ok=0
for dwarf_flag in -gdwarf-4 -g; do
	if ! $CC $dwarf_flag -I"$outdir" -o "$outdir/prog1" "$outdir/prog1.c" 2>"$outdir/cc.log"; then
		info_log "   compile prog1 ($dwarf_flag) failed:"
		info_log "   $(cat "$outdir/cc.log")"
		continue
	fi

	if ! $CC $dwarf_flag -I"$outdir" -o "$outdir/prog2" "$outdir/prog2.c" 2>"$outdir/cc.log"; then
		info_log "   compile prog2 ($dwarf_flag) failed:"
		info_log "   $(cat "$outdir/cc.log")"
		continue
	fi

	if ! dwz -m "$outdir/dwz_alt" "$outdir/prog1" "$outdir/prog2" 2>/dev/null; then
		info_log "   dwz multifile mode failed with $dwarf_flag (types too small?)"
		continue
	fi

	if ! $READELF -p .gnu_debugaltlink "$outdir/prog1" 2>/dev/null | grep -q dwz_alt; then
		info_log "   dwz ($dwarf_flag) did not produce .gnu_debugaltlink"
		continue
	fi

	info_log "   dwz multifile with $dwarf_flag: ok"
	dwz_ok=1
	break
done

if [ "$dwz_ok" -eq 0 ]; then
	info_log "skip: could not produce dwz alt file with any DWARF version"
	test_skip
fi

# Verify pahole can resolve the shared type from the alt file
if ! pahole -F dwarf -C shared_context "$outdir/prog1" 2>/dev/null | grep -q "struct shared_context {"; then
	error_log "FAIL: pahole could not resolve shared_context from prog1"
	test_fail
fi

if ! pahole -F dwarf -C shared_context "$outdir/prog2" 2>/dev/null | grep -q "struct shared_context {"; then
	error_log "FAIL: pahole could not resolve shared_context from prog2"
	test_fail
fi

# Verify member resolution (shared_base is in the alt file)
if ! pahole -F dwarf -C shared_context "$outdir/prog1" 2>/dev/null | grep -q "shared_base"; then
	error_log "FAIL: shared_base member not resolved in shared_context"
	test_fail
fi

# Verify no unexpected stderr output — catches warnings, errors, and
# any new class of dwz-related diagnostics regardless of format
pahole -F dwarf "$outdir/prog1" >/dev/null 2>"$outdir/pahole_stderr.log"
if test -s "$outdir/pahole_stderr.log"; then
	error_log "FAIL: pahole produced unexpected stderr processing dwz file:"
	error_log "$(cat "$outdir/pahole_stderr.log")"
	test_fail
fi

# Negative test: hide the alt file and verify pahole warns exactly once
# and does not crash.  This is the scenario users hit in the wild with
# partially installed debuginfo packages.
mv "$outdir/dwz_alt" "$outdir/dwz_alt.hidden"

pahole -F dwarf "$outdir/prog1" >/dev/null 2>"$outdir/pahole_noalt_stderr.log"
noalt_rc=$?

mv "$outdir/dwz_alt.hidden" "$outdir/dwz_alt"

if [ "$noalt_rc" -ne 0 ]; then
	error_log "FAIL: pahole crashed (rc=$noalt_rc) with missing alt file"
	test_fail
fi

if ! grep -q "could not resolve dwz alternate debug file" "$outdir/pahole_noalt_stderr.log"; then
	error_log "FAIL: missing-alt warning not emitted"
	error_log "$(cat "$outdir/pahole_noalt_stderr.log")"
	test_fail
fi

noalt_warn_count=$(grep -c "could not resolve dwz alternate debug file" "$outdir/pahole_noalt_stderr.log")
if [ "$noalt_warn_count" -ne 1 ]; then
	error_log "FAIL: missing-alt warning emitted $noalt_warn_count times, expected 1"
	test_fail
fi

test_pass
