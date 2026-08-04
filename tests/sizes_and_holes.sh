#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Test --sizes, --holes, and --bit_holes options.

. "$(dirname "$0")/test_lib.sh"
outdir=$(make_tmpdir)

trap cleanup EXIT

title_log "Sizes and holes display."

CC=${CC:-gcc}
if ! command -v "${CC%% *}" > /dev/null 2>&1; then
	info_log "skip: $CC not available"
	test_skip
fi

src=$(make_tmpsrc)
obj=$(make_tmpobj)

cat > "$src" << 'EOF'
struct small {
	char	a;
};

struct medium {
	int	x;
	int	y;
	int	z;
};

struct holey {
	int	a;
	char	b;
	int	c;
	char	d;
};

struct bitfields {
	unsigned int	x : 1;
	unsigned int	y : 2;
	unsigned int	  : 5;
	unsigned int	z : 1;
};

struct small g1;
struct medium g2;
struct holey g3;
struct bitfields g4;
EOF

if ! $CC -g -c -o "$obj" "$src" 2>/dev/null; then
	error_log "FAIL: compilation failed"
	test_fail
fi

# --sizes (-s): list structs with sizes
output=$(pahole -s "$obj" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: --sizes produced no output"
	test_fail
fi
if ! echo "$output" | grep -q "small"; then
	error_log "FAIL: --sizes did not list small"
	test_fail
fi
info_log "--sizes: ok"

# --holes (-H 1): list structs with at least 1 hole
output=$(pahole -H 1 "$obj" 2>/dev/null)
if ! echo "$output" | grep -q "holey"; then
	error_log "FAIL: --holes 1 did not list holey"
	test_fail
fi
# structs without holes must be excluded
if echo "$output" | grep -q "small"; then
	error_log "FAIL: --holes 1 should not list small (no holes)"
	test_fail
fi
info_log "--holes: ok"

# --bit_holes (-B 1): list structs with at least 1 bit hole
output=$(pahole -B 1 "$obj" 2>/dev/null)
if ! echo "$output" | grep -q "bitfields"; then
	error_log "FAIL: --bit_holes 1 did not list bitfields"
	test_fail
fi
# structs without bit holes must be excluded
if echo "$output" | grep -q "medium"; then
	error_log "FAIL: --bit_holes 1 should not list medium (no bit holes)"
	test_fail
fi
info_log "--bit_holes: ok"

test_pass
