#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Test -C file:// class name loading from file.

. "$(dirname "$0")/test_lib.sh"
outdir=$(make_tmpdir)

trap cleanup EXIT

title_log "Class name list from file."

CC=${CC:-gcc}
if ! command -v "${CC%% *}" > /dev/null 2>&1; then
	info_log "skip: $CC not available"
	test_skip
fi

src=$(make_tmpsrc)
obj=$(make_tmpobj)

cat > "$src" << 'EOF'
struct alpha {
	int	x;
	int	y;
};

struct beta {
	char	*name;
	int	id;
};

struct gamma {
	long	offset;
	void	*ptr;
};

struct alpha g1;
struct beta g2;
struct gamma g3;
EOF

if ! $CC -g -c -o "$obj" "$src" 2>/dev/null; then
	error_log "FAIL: compilation failed"
	test_fail
fi

# Create a file listing two of the three structs
listfile="$outdir/classes.txt"
cat > "$listfile" << 'EOF'
alpha
gamma
EOF

output=$(pahole -C "file://$listfile" "$obj" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: -C file:// produced no output"
	test_fail
fi

# alpha and gamma should appear, beta should not
if ! echo "$output" | grep -q "struct alpha"; then
	error_log "FAIL: alpha not in output"
	test_fail
fi
if ! echo "$output" | grep -q "struct gamma"; then
	error_log "FAIL: gamma not in output"
	test_fail
fi
if echo "$output" | grep -q "struct beta"; then
	error_log "FAIL: beta should not be in output"
	test_fail
fi
info_log "   multi-class file: ok"

# Single name in file
echo "beta" > "$listfile"
output=$(pahole -C "file://$listfile" "$obj" 2>/dev/null)
if ! echo "$output" | grep -q "struct beta"; then
	error_log "FAIL: single-class file did not show beta"
	test_fail
fi
if echo "$output" | grep -q "struct alpha"; then
	error_log "FAIL: single-class file should not show alpha"
	test_fail
fi
info_log "   single-class file: ok"

test_pass
