#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Test CLI display and filtering options that lack coverage:
#   -c (cacheline_size), -I (show_decl_info), -q (quiet),
#   --packed, --with_flexible_array, --first_obj_only,
#   --ptr_table_stats, -D (decl_exclude_prefix), -X (cu_exclude_prefix)

. "$(dirname "$0")/test_lib.sh"
outdir=$(make_tmpdir)

trap cleanup EXIT

title_log "CLI display and filtering options."

CC=${CC:-gcc}
if ! command -v "${CC%% *}" > /dev/null 2>&1; then
	info_log "skip: $CC not available"
	test_skip
fi

src=$(make_tmpsrc)
obj=$(make_tmpobj)

cat > "$src" << 'EOF'
struct holey {
	int	a;
	char	b;
	/* 3-byte hole here */
	int	c;
};

struct __attribute__((packed)) packed_s {
	int	x;
	char	y;
	int	z;
};

struct flex {
	int	count;
	char	data[];
};

struct small {
	char	a;
};

struct holey g1;
struct packed_s g2;
struct flex g3;
struct small g4;
EOF

if ! $CC -g -c -o "$obj" "$src" 2>/dev/null; then
	error_log "FAIL: compilation failed"
	test_fail
fi

# --- -c (cacheline_size) ---
out=$(pahole -c 64 -C holey "$obj" 2>/dev/null)
if [ -z "$out" ]; then
	error_log "FAIL: -c 64 -C holey produced no output"
	test_fail
fi
info_log "-c 64: ok"

# --- -I (show_decl_info) ---
out=$(pahole -I -C holey "$obj" 2>/dev/null)
if [ -z "$out" ]; then
	error_log "FAIL: -I -C holey produced no output"
	test_fail
fi
# -I should add file/line declaration info
if ! echo "$out" | grep -q "/\*.*:[0-9]"; then
	error_log "FAIL: -I did not show declaration info"
	test_fail
fi
info_log "-I (show_decl_info): ok"

# --- -q (quiet) ---
# Quiet mode suppresses stats/comments; output should be shorter than normal
normal=$(pahole -C holey "$obj" 2>/dev/null)
quiet=$(pahole -q -C holey "$obj" 2>/dev/null)
if [ -z "$quiet" ]; then
	error_log "FAIL: -q -C holey produced no output"
	test_fail
fi
normal_lines=$(echo "$normal" | wc -l)
quiet_lines=$(echo "$quiet" | wc -l)
if [ "$quiet_lines" -ge "$normal_lines" ]; then
	error_log "FAIL: -q did not reduce output ($quiet_lines lines vs $normal_lines normal)"
	test_fail
fi
info_log "-q (quiet): ok"

# --- --packed ---
out=$(pahole --packed "$obj" 2>/dev/null)
if [ -z "$out" ]; then
	error_log "FAIL: --packed produced no output"
	test_fail
fi
if ! echo "$out" | grep -q "packed_s"; then
	error_log "FAIL: --packed did not list packed_s"
	test_fail
fi
# Non-packed structs should not appear
if echo "$out" | grep -q "struct holey"; then
	error_log "FAIL: --packed listed non-packed struct holey"
	test_fail
fi
info_log "--packed: ok"

# --- --with_flexible_array ---
out=$(pahole --with_flexible_array "$obj" 2>/dev/null)
if [ -z "$out" ]; then
	error_log "FAIL: --with_flexible_array produced no output"
	test_fail
fi
if ! echo "$out" | grep -q "flex"; then
	error_log "FAIL: --with_flexible_array did not list flex"
	test_fail
fi
info_log "--with_flexible_array: ok"

# --- --first_obj_only ---
out=$(pahole --first_obj_only -C holey "$obj" 2>/dev/null)
if [ -z "$out" ]; then
	error_log "FAIL: --first_obj_only produced no output"
	test_fail
fi
info_log "--first_obj_only: ok"

# --- --ptr_table_stats ---
# Should produce internal data structure statistics on stderr
out=$(pahole --ptr_table_stats "$obj" 2>&1)
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: --ptr_table_stats exited with $rc"
	test_fail
fi
if [ -z "$out" ]; then
	error_log "FAIL: --ptr_table_stats produced no output"
	test_fail
fi
info_log "--ptr_table_stats: ok"

# --- -D (decl_exclude_prefix) ---
# Excluding with a prefix matching our source file should filter everything
src_dir=$(dirname "$src")
out=$(pahole -D "$src_dir" "$obj" 2>/dev/null)
# With a matching prefix, struct output should be filtered out
out_nofilter=$(pahole "$obj" 2>/dev/null)
if [ -n "$out_nofilter" ] && [ ${#out} -ge ${#out_nofilter} ]; then
	error_log "FAIL: -D did not filter output"
	test_fail
fi
info_log "-D (decl_exclude_prefix): ok"

# --- -X (cu_exclude_prefix) ---
out=$(pahole -X "/nonexistent" -C holey "$obj" 2>/dev/null)
if [ -z "$out" ]; then
	error_log "FAIL: -X /nonexistent should not filter anything"
	test_fail
fi
info_log "-X (cu_exclude_prefix): ok"

test_pass
