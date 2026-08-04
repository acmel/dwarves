#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Test codiff: compare DWARF info between two object files.

. "$(dirname "$0")/test_lib.sh"
outdir=$(make_tmpdir)

trap cleanup EXIT

title_log "codiff struct comparison."

CC=${CC:-gcc}
if ! command -v "${CC%% *}" > /dev/null 2>&1; then
	info_log "skip: $CC not available"
	test_skip
fi

if ! command -v codiff > /dev/null 2>&1; then
	info_log "skip: codiff not available"
	test_skip
fi

src_v1="$outdir/v1.c"
src_v2="$outdir/v2.c"
obj_v1="$outdir/v1.o"
obj_v2="$outdir/v2.o"

# Version 1: original struct
cat > "$src_v1" << 'EOF'
struct data {
	int	id;
	char	name;
};

int process(struct data *d) { return d->id; }
EOF

# Version 2: struct with added field (size changed)
cat > "$src_v2" << 'EOF'
struct data {
	int	id;
	char	name;
	long	extra;
};

int process(struct data *d) { return d->id + (int)d->extra; }
EOF

if ! $CC -g -c -o "$obj_v1" "$src_v1" 2>/dev/null; then
	error_log "FAIL: v1 compilation failed"
	test_fail
fi

if ! $CC -g -c -o "$obj_v2" "$src_v2" 2>/dev/null; then
	error_log "FAIL: v2 compilation failed"
	test_fail
fi

# codiff should detect the struct change
output=$(codiff "$obj_v1" "$obj_v2" 2>/dev/null)
if ! echo "$output" | grep -q "data"; then
	error_log "FAIL: codiff did not detect struct data change"
	test_fail
fi
info_log "codiff struct change: ok"

# codiff -s: show struct diffs
output=$(codiff -s "$obj_v1" "$obj_v2" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: codiff -s produced no output"
	test_fail
fi
info_log "codiff -s: ok"

# codiff -V: verbose output
output=$(codiff -V "$obj_v1" "$obj_v2" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: codiff -V produced no output"
	test_fail
fi
info_log "codiff -V: ok"

test_pass
