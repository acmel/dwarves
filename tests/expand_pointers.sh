#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Test --expand_pointers (-p) option.

. "$(dirname "$0")/test_lib.sh"
outdir=$(make_tmpdir)

trap cleanup EXIT

title_log "Expand pointers option."

CC=${CC:-gcc}
if ! command -v "${CC%% *}" > /dev/null 2>&1; then
	info_log "skip: $CC not available"
	test_skip
fi

src=$(make_tmpsrc)
obj=$(make_tmpobj)

cat > "$src" << 'EOF'
struct leaf {
	int	value;
	char	tag;
};

struct middle {
	struct leaf	*leaf;
	int		count;
};

struct top {
	struct middle	*mid;
	int		flags;
};

struct self_ref {
	struct self_ref	*next;
	int		data;
};

struct top g1;
struct self_ref g2;
EOF

if ! $CC -g -c -o "$obj" "$src" 2>/dev/null; then
	error_log "FAIL: compilation failed"
	test_fail
fi

# Without --expand_pointers: pointer shown as opaque
output=$(pahole -C top "$obj" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: pahole -C top produced no output"
	test_fail
fi
if echo "$output" | grep -q "int.*value"; then
	error_log "FAIL: default should not expand pointer members"
	test_fail
fi
info_log "   default (no expansion): ok"

# --expand_pointers: should show pointed-to struct members
output=$(pahole --expand_pointers -C top "$obj" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: --expand_pointers produced no output"
	test_fail
fi
if ! echo "$output" | grep -q "count"; then
	error_log "FAIL: --expand_pointers did not expand middle members"
	test_fail
fi
info_log "   --expand_pointers: ok"

# -E -p combined: expand types and pointers together
output=$(pahole -E -p -C top "$obj" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: -E -p produced no output"
	test_fail
fi
info_log "   -E -p combined: ok"

# Self-referential struct should not infinite loop
output=$(pahole --expand_pointers -C self_ref "$obj" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: --expand_pointers on self-referential struct failed"
	test_fail
fi
info_log "   self-referential: ok"

test_pass
