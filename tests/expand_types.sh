#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Test --expand (-E) and --nested_anon_include (-a, -A) options.

. "$(dirname "$0")/test_lib.sh"
outdir=$(make_tmpdir)

trap cleanup EXIT

title_log "Type expansion and anonymous struct options."

CC=${CC:-gcc}
if ! command -v "${CC%% *}" > /dev/null 2>&1; then
	info_log "skip: $CC not available"
	test_skip
fi

src=$(make_tmpsrc)
obj=$(make_tmpobj)

cat > "$src" << 'EOF'
struct point {
	int	x;
	int	y;
};

struct rect {
	struct point	origin;
	struct point	size;
};

struct with_anon {
	int	id;
	struct {
		int	a;
		int	b;
	};
};

struct rect g1;
struct with_anon g2;
EOF

if ! $CC -g -c -o "$obj" "$src" 2>"$outdir/cc.err"; then
	error_log "FAIL: compilation failed"
	if [ -s "$outdir/cc.err" ]; then
		cat "$outdir/cc.err" | head -10 | while read line; do error_log "$line"; done
	fi
	test_fail
fi

# Detect if object was compiled with clang by checking DW_AT_producer
# See ~/git/todos/pahole-todos.md: "Clang anonymous struct handling"
# GCC creates anonymous structs as top-level types; clang embeds them inline
# as nested DIEs. Pahole only handles the GCC pattern currently.
is_clang=0
if readelf -wi "$obj" 2>/dev/null | grep -q "DW_AT_producer.*clang"; then
	is_clang=1
fi

# --expand (-E): should inline nested struct members
output=$(pahole -E -C rect "$obj" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: --expand produced no output"
	test_fail
fi
# expanded output should show the inner fields (x, y) directly
if ! echo "$output" | grep -q "int.*x;"; then
	error_log "FAIL: --expand did not inline inner field x"
	error_log "Output was:"
	error_log "$output"
	test_fail
fi
info_log "--expand: ok"

# -a (--anon_include): include anonymous structs in --sizes listing.
# Without -a, anonymous structs should not appear; with -a, they should
# appear with name "(null)".
# NOTE: Clang generates inline nested anonymous structs that pahole doesn't
# currently recognize. Skip this check for clang until fixed.
if [ $is_clang -eq 0 ]; then
	baseline=$(pahole --sizes "$obj" 2>/dev/null)
	anon=$(pahole -a --sizes "$obj" 2>/dev/null)

	# Check that baseline does NOT include (null)
	if echo "$baseline" | grep -q "(null)"; then
		error_log "FAIL: anonymous struct appeared in --sizes without -a flag"
		error_log "Baseline output:"
		echo "$baseline" | while read line; do error_log "  $line"; done
		test_fail
	fi

	# Check that -a output DOES include (null)
	if ! echo "$anon" | grep -q "(null)"; then
		error_log "FAIL: -a did not add anonymous struct to --sizes listing"
		error_log "Baseline output:"
		echo "$baseline" | while read line; do error_log "  $line"; done
		error_log "Anon (-a) output:"
		echo "$anon" | while read line; do error_log "  $line"; done
		test_fail
	fi
	info_log "-a (anon_include): ok"
else
	info_log "-a (anon_include): skipped (clang - known bug, see ~/git/todos/pahole-todos.md)"
fi

# -A (--nested_anon_include): with -a, emit anonymous structs as
# standalone type blocks.  Without -A, the anonymous struct is only
# shown inside its parent; with -a -A, it gets its own "size:" block.
# NOTE: Clang generates inline nested anonymous structs that pahole doesn't
# currently recognize. Skip this check for clang until fixed.
if [ $is_clang -eq 0 ]; then
	baseline_blocks=$(pahole "$obj" 2>/dev/null | grep -c '/\* size:')
	nested_blocks=$(pahole -a -A "$obj" 2>/dev/null | grep -c '/\* size:')
	if [ "$nested_blocks" -le "$baseline_blocks" ]; then
		error_log "FAIL: -A did not emit standalone anonymous struct block"
		error_log "baseline_blocks=$baseline_blocks, nested_blocks=$nested_blocks"
		error_log "Baseline output (size: blocks):"
		pahole "$obj" 2>&1 | grep '/\* size:' | while read line; do error_log "  $line"; done
		error_log "Nested (-a -A) output (size: blocks):"
		pahole -a -A "$obj" 2>&1 | grep '/\* size:' | while read line; do error_log "  $line"; done
		test_fail
	fi
	info_log "-A (nested_anon_include): ok"
else
	info_log "-A (nested_anon_include): skipped (clang - known bug, see ~/git/todos/pahole-todos.md)"
fi

test_pass
