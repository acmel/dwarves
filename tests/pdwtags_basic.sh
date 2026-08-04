#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Test pdwtags: DWARF information pretty printer.

. "$(dirname "$0")/test_lib.sh"
outdir=$(make_tmpdir)

trap cleanup EXIT

title_log "pdwtags DWARF tag display."

CC=${CC:-gcc}
if ! command -v "${CC%% *}" > /dev/null 2>&1; then
	info_log "skip: $CC not available"
	test_skip
fi

if ! command -v pdwtags > /dev/null 2>&1; then
	info_log "skip: pdwtags not available"
	test_skip
fi

src=$(make_tmpsrc)
obj=$(make_tmpobj)

cat > "$src" << 'EOF'
typedef unsigned long size_t_alias;

struct node {
	int		key;
	char		*value;
	struct node	*next;
};

enum state { INIT = 0, RUNNING = 1, DONE = 2 };

int lookup(struct node *head, int key) {
	while (head) {
		if (head->key == key)
			return 1;
		head = head->next;
	}
	return 0;
}

struct node g1;
enum state g2;
size_t_alias g3;
EOF

if ! $CC -g -c -o "$obj" "$src" 2>/dev/null; then
	error_log "FAIL: compilation failed"
	test_fail
fi

# pdwtags should list DWARF tags
output=$(pdwtags "$obj" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: pdwtags produced no output"
	test_fail
fi

# Should show struct, enum, and function tags
if ! echo "$output" | grep -q "node"; then
	error_log "FAIL: pdwtags did not show struct node"
	test_fail
fi
info_log "pdwtags struct: ok"

if ! echo "$output" | grep -q "state"; then
	error_log "FAIL: pdwtags did not show enum state"
	test_fail
fi
info_log "pdwtags enum: ok"

if ! echo "$output" | grep -q "lookup"; then
	error_log "FAIL: pdwtags did not show function lookup"
	test_fail
fi
info_log "pdwtags function: ok"

test_pass
