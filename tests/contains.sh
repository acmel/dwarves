#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Test --contains and --find_pointers_to options.

. "$(dirname "$0")/test_lib.sh"
outdir=$(make_tmpdir)

trap cleanup EXIT

title_log "Type containment and pointer search."

CC=${CC:-gcc}
if ! command -v "${CC%% *}" > /dev/null 2>&1; then
	info_log "skip: $CC not available"
	test_skip
fi

src=$(make_tmpsrc)
obj=$(make_tmpobj)

cat > "$src" << 'EOF'
struct inner {
	int	id;
	char	*name;
};

struct outer {
	struct inner	item;
	int		count;
};

struct with_ptr {
	struct inner	*ref;
	int		flags;
};

struct outer g1;
struct with_ptr g2;
EOF

if ! $CC -g -c -o "$obj" "$src" 2>/dev/null; then
	error_log "FAIL: compilation failed"
	test_fail
fi

# --contains: outer contains inner, with_ptr does not
output=$(pahole -i inner "$obj" 2>/dev/null)
if ! echo "$output" | grep -q "outer"; then
	error_log "FAIL: --contains did not find outer"
	test_fail
fi
if echo "$output" | grep -q "with_ptr"; then
	error_log "FAIL: --contains should not list with_ptr"
	test_fail
fi
info_log "--contains: ok"

# --find_pointers_to: with_ptr has pointer to inner, outer does not
output=$(pahole -f inner "$obj" 2>/dev/null)
if ! echo "$output" | grep -q "with_ptr"; then
	error_log "FAIL: --find_pointers_to did not find with_ptr"
	test_fail
fi
if echo "$output" | grep -q "outer"; then
	error_log "FAIL: --find_pointers_to should not list outer"
	test_fail
fi
info_log "--find_pointers_to: ok"

test_pass
