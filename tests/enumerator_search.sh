#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Test --contains_enumerator option.

. "$(dirname "$0")/test_lib.sh"

outdir=$(make_tmpdir)
trap cleanup EXIT

title_log "Enumerator search."

CC=${CC:-gcc}
if ! command -v ${CC%% *} > /dev/null 2>&1; then
	info_log "skip: $CC not available"
	test_skip
fi

src=$(make_tmpsrc)
obj=$(make_tmpobj)

cat > "$src" << 'EOF'
enum color { RED = 0, GREEN = 1, BLUE = 2 };
enum flavor { SWEET = 10, SOUR = 20, BITTER = 30 };

enum color g1;
enum flavor g2;
EOF

$CC -g -c -o "$obj" "$src" 2>/dev/null
if [ $? -ne 0 ]; then
	error_log "FAIL: compilation failed"
	test_fail
fi

# --contains_enumerator should find the enum containing GREEN
output=$(pahole --contains_enumerator GREEN "$obj" 2>/dev/null)
if ! echo "$output" | grep -q "color"; then
	error_log "FAIL: --contains_enumerator GREEN did not find enum color"
	test_fail
fi
info_log "--contains_enumerator GREEN -> color: ok"

# Should find BITTER in flavor
output=$(pahole --contains_enumerator BITTER "$obj" 2>/dev/null)
if ! echo "$output" | grep -q "flavor"; then
	error_log "FAIL: --contains_enumerator BITTER did not find enum flavor"
	test_fail
fi
info_log "--contains_enumerator BITTER -> flavor: ok"

# Should produce no output for nonexistent enumerator
output=$(pahole --contains_enumerator NONEXISTENT "$obj" 2>/dev/null)
if [ -n "$output" ]; then
	error_log "FAIL: --contains_enumerator NONEXISTENT produced unexpected output"
	test_fail
fi
info_log "--contains_enumerator NONEXISTENT -> empty: ok"

test_pass
