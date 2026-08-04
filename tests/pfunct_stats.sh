#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Test pfunct function stats and verbose output.

. "$(dirname "$0")/test_lib.sh"
outdir=$(make_tmpdir)

trap cleanup EXIT

title_log "pfunct function statistics."

CC=${CC:-gcc}
if ! command -v "${CC%% *}" > /dev/null 2>&1; then
	info_log "skip: $CC not available"
	test_skip
fi

src=$(make_tmpsrc)
obj=$(make_tmpobj)

cat > "$src" << 'EOF'
static inline int helper(int x) { return x * 2; }

int compute(int a, int b) {
	int tmp = helper(a);
	return tmp + b;
}

void process(int *data, int len) {
	int i;
	for (i = 0; i < len; i++)
		data[i] = compute(data[i], i);
}

int noparms(void) { return 42; }
EOF

if ! $CC -g -O2 -c -o "$obj" "$src" 2>/dev/null; then
	error_log "FAIL: compilation failed"
	test_fail
fi

# -V -f: verbose with function body stats
output=$(pfunct -V -f process "$obj" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: pfunct -V -f process produced no output"
	test_fail
fi
info_log "   -V -f: ok"

# -T -V -f: show variables
output=$(pfunct -T -V -f process "$obj" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: pfunct -T -V -f produced no output"
	test_fail
fi
info_log "   -T -V -f: ok"

# -s: function sizes
output=$(pfunct -s "$obj" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: pfunct -s produced no output"
	test_fail
fi
if ! echo "$output" | grep -q "process"; then
	error_log "FAIL: -s missing process"
	test_fail
fi
info_log "   -s: ok"

# -S: number of variables
output=$(pfunct -S "$obj" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: pfunct -S produced no output"
	test_fail
fi
info_log "   -S: ok"

# -p: number of parameters
output=$(pfunct -p "$obj" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: pfunct -p produced no output"
	test_fail
fi
info_log "   -p: ok"

# -N: function name lengths
output=$(pfunct -N "$obj" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: pfunct -N produced no output"
	test_fail
fi
info_log "   -N: ok"

# -P: prototypes
output=$(pfunct -P "$obj" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: pfunct -P produced no output"
	test_fail
fi
info_log "   -P: ok"

# -I: inline expansion stats
if ! pfunct -I "$obj" > /dev/null 2>&1; then
	error_log "FAIL: pfunct -I failed"
	test_fail
fi
info_log "   -I: ok"

# -g: goto labels
if ! pfunct -g "$obj" > /dev/null 2>&1; then
	error_log "FAIL: pfunct -g failed"
	test_fail
fi
info_log "   -g: ok"

# -t: total inline expansion stats
output=$(pfunct -t "$obj" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: pfunct -t produced no output"
	test_fail
fi
info_log "   -t: ok"

test_pass
