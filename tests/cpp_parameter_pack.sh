#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Test C++ variadic template parameter pack handling.
# Exercises DW_TAG_template_parameter_pack and
# DW_TAG_formal_parameter_pack processing in dwarf_loader.c.

. "$(dirname "$0")/test_lib.sh"
outdir=$(make_tmpdir)

trap cleanup EXIT

title_log "C++ variadic template parameter pack handling."

CXX=${CXX:-g++}
if ! command -v "${CXX%% *}" > /dev/null 2>&1; then
	info_log "skip: $CXX not available"
	test_skip
fi

cxx_src="$outdir/parameter_pack.cpp"
cxx_obj="$outdir/parameter_pack.o"

# Create C++ source with variadic templates that produce
# DW_TAG_template_parameter_pack and DW_TAG_formal_parameter_pack
# entries in DWARF.
cat > "$cxx_src" << 'EOF'
/* Variadic class template — triggers DW_TAG_template_parameter_pack */
template<typename... Ts>
struct Tuple {
	int size;
};

/* Variadic function template — triggers DW_TAG_formal_parameter_pack */
template<typename... Args>
int sum(Args... args) {
	return sizeof...(args);
}

/* Explicit instantiations to ensure DWARF is emitted */
template struct Tuple<int, double, char>;
Tuple<int, float> g_tuple;
template int sum<int, double>(int, double);
EOF

# Step 1: Compile — skip if the compiler doesn't handle variadic templates
if ! $CXX -g -c -o "$cxx_obj" "$cxx_src" 2>/dev/null; then
	info_log "skip: $CXX failed to compile variadic template source"
	test_skip
fi

# Step 2: Run pahole on the full object.  This exercises both the
# template_parameter_pack (on the struct) and formal_parameter_pack
# (on the function) code paths in dwarf_loader.c without crashing.
pahole_out="$outdir/pahole_full.txt"
pahole_err="$outdir/pahole_full_err.txt"
if ! pahole "$cxx_obj" > "$pahole_out" 2>"$pahole_err"; then
	error_log "FAIL: pahole returned an error"
	cat "$pahole_err" >&2
	test_fail
fi
info_log "pahole (full object): OK"

# Step 3: Verify the Tuple struct appears in the output with its member.
# pahole -C splits on commas so we grep the full dump instead.
if ! grep -q 'struct Tuple' "$pahole_out"; then
	error_log "FAIL: Tuple struct not found in pahole output"
	cat "$pahole_out" >&2
	test_fail
fi

if ! grep -q 'size' "$pahole_out"; then
	error_log "FAIL: 'size' member not found in Tuple output"
	cat "$pahole_out" >&2
	test_fail
fi
info_log "Tuple struct with 'size' member: OK"

# Step 4: If pfunct is available, verify it can process the formal
# parameter pack in sum<>() without crashing.  The DWARF name includes
# template arguments so we list all functions and grep.
if command -v pfunct > /dev/null 2>&1; then
	pfunct_out="$outdir/pfunct_sum.txt"
	if ! pfunct "$cxx_obj" > "$pfunct_out" 2>&1; then
		error_log "FAIL: pfunct returned an error"
		cat "$pfunct_out" >&2
		test_fail
	fi
	if ! grep -q 'sum' "$pfunct_out"; then
		error_log "FAIL: pfunct did not list sum<> function"
		cat "$pfunct_out" >&2
		test_fail
	fi
	info_log "pfunct lists sum<> function: OK"
else
	info_log "skip pfunct check: pfunct not in PATH"
fi

test_pass
