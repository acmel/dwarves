#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Test class name filtering: --exclude (-x), --prefix_filter (-y), --nr_members (-n).

. "$(dirname "$0")/test_lib.sh"
outdir=$(make_tmpdir)

trap cleanup EXIT

title_log "Class name filtering."

CC=${CC:-gcc}
if ! command -v "${CC%% *}" > /dev/null 2>&1; then
	info_log "skip: $CC not available"
	test_skip
fi

src=$(make_tmpsrc)
obj=$(make_tmpobj)

cat > "$src" << 'EOF'
struct foo_one {
	int	x;
};

struct foo_two {
	int	y;
	int	z;
};

struct bar_one {
	char	c;
};

struct foo_one g1;
struct foo_two g2;
struct bar_one g3;
EOF

if ! $CC -g -c -o "$obj" "$src" 2>/dev/null; then
	error_log "FAIL: compilation failed"
	test_fail
fi

# --exclude (-x): exclude classes starting with "bar_"
output=$(pahole -x bar_ "$obj" 2>/dev/null)
if echo "$output" | grep -q "struct bar_one"; then
	error_log "FAIL: -x bar_ did not exclude bar_one"
	test_fail
fi
if ! echo "$output" | grep -q "struct foo_one"; then
	error_log "FAIL: -x bar_ excluded foo_one"
	test_fail
fi
info_log "--exclude: ok"

# --prefix_filter (-y): include only classes starting with "bar_"
output=$(pahole -y bar_ "$obj" 2>/dev/null)
if ! echo "$output" | grep -q "struct bar_one"; then
	error_log "FAIL: -y bar_ did not include bar_one"
	test_fail
fi
if echo "$output" | grep -q "struct foo_one"; then
	error_log "FAIL: -y bar_ included foo_one"
	test_fail
fi
info_log "--prefix_filter: ok"

# --nr_members (-n): show member count per struct
TAB=$(printf '\t')
output=$(pahole -n "$obj" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: --nr_members produced no output"
	test_fail
fi
# Verify actual member counts for each struct
if ! echo "$output" | grep -q "^foo_one${TAB}1$"; then
	error_log "FAIL: --nr_members expected 'foo_one	1', got: $(echo "$output" | grep foo_one)"
	test_fail
fi
if ! echo "$output" | grep -q "^foo_two${TAB}2$"; then
	error_log "FAIL: --nr_members expected 'foo_two	2', got: $(echo "$output" | grep foo_two)"
	test_fail
fi
if ! echo "$output" | grep -q "^bar_one${TAB}1$"; then
	error_log "FAIL: --nr_members expected 'bar_one	1', got: $(echo "$output" | grep bar_one)"
	test_fail
fi
info_log "--nr_members: ok"

test_pass
