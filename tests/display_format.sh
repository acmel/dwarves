#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Test --hex, --flat_arrays, and --suppress options.

. "$(dirname "$0")/test_lib.sh"
outdir=$(make_tmpdir)

trap cleanup EXIT

title_log "Display format options."

CC=${CC:-gcc}
if ! command -v "${CC%% *}" > /dev/null 2>&1; then
	info_log "skip: $CC not available"
	test_skip
fi

src=$(make_tmpsrc)
obj=$(make_tmpobj)

cat > "$src" << 'EOF'
struct padded {
	int	a;
	char	b;
	int	c;
} __attribute__((packed));

struct needs_padding {
	char	a;
	long	b;
};

struct with_array {
	int	matrix[3][4];
	char	name[16];
};

struct aligned_member {
	int	x __attribute__((aligned(16)));
	int	y;
};

struct padded g1;
struct with_array g2;
struct aligned_member g3;
struct needs_padding g4;
EOF

if ! $CC -g -c -o "$obj" "$src" 2>/dev/null; then
	error_log "FAIL: compilation failed"
	test_fail
fi

# --hex: show offsets in hex
output=$(pahole --hex -C with_array "$obj" 2>/dev/null)
if ! echo "$output" | grep -q "0x"; then
	error_log "FAIL: --hex did not produce hex offsets"
	test_fail
fi
info_log "--hex: ok"

# --flat_arrays: multi-dim array should be flattened
output=$(pahole --flat_arrays -C with_array "$obj" 2>/dev/null)
if ! echo "$output" | grep -q "\[12\]"; then
	error_log "FAIL: --flat_arrays did not flatten matrix[3][4] to [12]"
	test_fail
fi
info_log "--flat_arrays: ok"

# --suppress_aligned_attribute: verify baseline has it, then suppression removes it.
# Older toolchains may not emit DW_AT_alignment, so skip gracefully.
with_aligned=$(pahole -C aligned_member "$obj" 2>/dev/null)
if [ -z "$with_aligned" ]; then
	error_log "FAIL: pahole -C aligned_member produced no output (crash?)"
	test_fail
fi
if ! echo "$with_aligned" | grep -q "__aligned__"; then
	info_log "--suppress_aligned_attribute: skip (compiler lacks DW_AT_alignment)"
else
	without_aligned=$(pahole --suppress_aligned_attribute -C aligned_member "$obj" 2>/dev/null)
	if [ -z "$without_aligned" ]; then
		error_log "FAIL: --suppress_aligned_attribute produced no output (crash?)"
		test_fail
	fi
	if echo "$without_aligned" | grep -q "__aligned__"; then
		error_log "FAIL: --suppress_aligned_attribute did not remove aligned"
		test_fail
	fi
	info_log "--suppress_aligned_attribute: ok"
fi

# --suppress_packed: verify baseline has it, then suppression removes it
with_packed=$(pahole -C padded "$obj" 2>/dev/null)
if ! echo "$with_packed" | grep -q "__packed__"; then
	error_log "FAIL: baseline output for padded missing __packed__"
	test_fail
fi
without_packed=$(pahole --suppress_packed -C padded "$obj" 2>/dev/null)
if [ -z "$without_packed" ]; then
	error_log "FAIL: --suppress_packed produced no output (crash?)"
	test_fail
fi
if echo "$without_packed" | grep -q "__packed__"; then
	error_log "FAIL: --suppress_packed did not remove packed"
	test_fail
fi
info_log "--suppress_packed: ok"

# --suppress_force_paddings: option-parsing level only — "Force padding:"
# synthetic members require padding > addr_size with power-of-2 member
# sizes, which is hard to construct portably.  Verify no crash.
output=$(pahole --suppress_force_paddings -C needs_padding "$obj" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: --suppress_force_paddings produced no output"
	test_fail
fi
if ! echo "$output" | grep -q "needs_padding"; then
	error_log "FAIL: --suppress_force_paddings output missing struct name"
	test_fail
fi
info_log "--suppress_force_paddings: ok (option-parsing level)"

test_pass
