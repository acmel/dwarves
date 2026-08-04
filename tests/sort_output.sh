#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Test --sort and --separator options.

. "$(dirname "$0")/test_lib.sh"
outdir=$(make_tmpdir)

trap cleanup EXIT

title_log "Sort output and separator."

CC=${CC:-gcc}
if ! command -v "${CC%% *}" > /dev/null 2>&1; then
	info_log "skip: $CC not available"
	test_skip
fi

src=$(make_tmpsrc)
obj=$(make_tmpobj)

cat > "$src" << 'EOF'
/* Names chosen so DWARF order (zebra, apple, mango) differs
   from alphabetical order (apple, mango, zebra). */
struct zebra {
	long	a;
	long	b;
	long	c;
	long	d;
};

struct apple {
	char	x;
};

struct mango {
	int	m;
	int	n;
};

struct zebra g1;
struct apple g2;
struct mango g3;
EOF

if ! $CC -g -c -o "$obj" "$src" 2>/dev/null; then
	error_log "FAIL: compilation failed"
	test_fail
fi

# --sort: output should be alphabetically sorted (apple before zebra)
# Without --sort, DWARF order is zebra, apple, mango (source order).
# With --sort, it should be apple, mango, zebra (alphabetical).
unsorted=$(pahole "$obj" 2>/dev/null | grep "^struct " | head -1)
if ! echo "$unsorted" | grep -q "zebra"; then
	error_log "FAIL: default DWARF order not zebra-first (got: $unsorted)"
	test_fail
fi
sorted=$(pahole --sort "$obj" 2>/dev/null | grep "^struct " | head -1)
if ! echo "$sorted" | grep -q "apple"; then
	error_log "FAIL: --sort did not sort alphabetically (first: $sorted)"
	test_fail
fi
info_log "--sort: ok"

# --separator (-t): use custom column separator
output=$(pahole -s -t '|' "$obj" 2>/dev/null)
if ! echo "$output" | grep -q '|'; then
	error_log "FAIL: --separator did not use | delimiter"
	test_fail
fi
info_log "--separator: ok"

# --defined_in (-u): show where types are defined
output=$(pahole -u -C zebra "$obj" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: --defined_in produced no output"
	test_fail
fi
if ! echo "$output" | grep -q "\.c"; then
	error_log "FAIL: --defined_in did not show source file"
	test_fail
fi
info_log "--defined_in: ok"

test_pass
