#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Test typedef chain display with -E (expand types).

. "$(dirname "$0")/test_lib.sh"
outdir=$(make_tmpdir)

trap cleanup EXIT

title_log "Typedef chain display."

CC=${CC:-gcc}
if ! command -v "${CC%% *}" > /dev/null 2>&1; then
	info_log "skip: $CC not available"
	test_skip
fi

src=$(make_tmpsrc)
obj=$(make_tmpobj)

cat > "$src" << 'EOF'
typedef int base_int;
typedef base_int middle_int;
typedef middle_int top_int;

typedef void (*callback_t)(int);
typedef callback_t handler_t;

struct chain_user {
	top_int		value;
	handler_t	on_event;
	base_int	simple;
};

struct chain_user g1;
EOF

if ! $CC -g -c -o "$obj" "$src" 2>/dev/null; then
	error_log "FAIL: compilation failed"
	test_fail
fi

# -E should expand typedefs recursively, showing the chain as a comment
# like "/* typedef top_int -> middle_int -> base_int */ int ..."
expanded=$(pahole -E -C chain_user "$obj" 2>/dev/null)
if [ -z "$expanded" ]; then
	error_log "FAIL: -E -C chain_user produced no output"
	test_fail
fi
# The expanded output should show the typedef chain and the resolved type
if ! echo "$expanded" | grep -q "typedef top_int"; then
	error_log "FAIL: -E did not show typedef expansion chain for top_int"
	test_fail
fi
info_log "   -E typedef expansion: ok"

# Without -E, should show typedef names
unexpanded=$(pahole -C chain_user "$obj" 2>/dev/null)
if [ -z "$unexpanded" ]; then
	error_log "FAIL: -C chain_user produced no output"
	test_fail
fi
if ! echo "$unexpanded" | grep -q "top_int"; then
	error_log "FAIL: default should show typedef name top_int"
	test_fail
fi
info_log "   default typedef names: ok"

# Function pointer typedef chain — verify in unexpanded output
if ! echo "$unexpanded" | grep -q "handler_t"; then
	error_log "FAIL: default should show typedef name handler_t"
	test_fail
fi
info_log "   function pointer typedef: ok"

test_pass
