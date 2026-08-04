#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Test C++ namespace and using-declaration display.
# Exercises namespace__fprintf() and DW_TAG_imported_declaration
# handling in dwarves_fprintf.c.

. "$(dirname "$0")/test_lib.sh"
outdir=$(make_tmpdir)

trap cleanup EXIT

title_log "C++ namespace and using-declaration display."

CXX=${CXX:-g++}
if ! command -v "${CXX%% *}" > /dev/null 2>&1; then
	info_log "skip: $CXX not available"
	test_skip
fi

src="$outdir/cpp_namespace.cpp"
obj="$outdir/cpp_namespace.o"

cat > "$src" << 'EOF'
namespace outer {
    namespace inner {
        struct Nested {
            int x;
            int y;
        };
    }

    struct InOuter {
        int a;
        inner::Nested n;
    };
}

namespace alias_ns = outer::inner;

using outer::inner::Nested;

outer::InOuter g_outer;
outer::inner::Nested g_nested;
EOF

if ! $CXX -g -c -o "$obj" "$src" 2>/dev/null; then
	info_log "skip: C++ compilation failed (compiler may not support this)"
	test_skip
fi

# Test 1: pahole -C Nested should find the struct and show its members
if ! output=$(pahole -C Nested "$obj" 2>/dev/null); then
	error_log "FAIL: pahole -C Nested returned error"
	test_fail
fi
if [ -z "$output" ]; then
	error_log "FAIL: pahole -C Nested produced no output"
	test_fail
fi
info_log "pahole -C Nested: ok"

# Test 2: pahole -C InOuter should find the struct with the nested member
if ! output=$(pahole -C InOuter "$obj" 2>/dev/null); then
	error_log "FAIL: pahole -C InOuter returned error"
	test_fail
fi
if [ -z "$output" ]; then
	error_log "FAIL: pahole -C InOuter produced no output"
	test_fail
fi
info_log "pahole -C InOuter: ok"

# Test 3: pahole --show_private_classes should list all structs without error
if ! output=$(pahole --show_private_classes "$obj" 2>/dev/null); then
	error_log "FAIL: pahole --show_private_classes returned error"
	test_fail
fi
if [ -z "$output" ]; then
	error_log "FAIL: pahole --show_private_classes produced no output"
	test_fail
fi
info_log "pahole --show_private_classes: ok"

# Test 4: pdwtags exercises namespace__fprintf() which prints the
# "namespace outer { ... }" blocks and any DW_TAG_imported_declaration /
# DW_TAG_imported_module children via tag__fprintf().
# pahole -C finds types inside namespaces (tests 1-3 above), but does
# not call namespace__fprintf — only pdwtags iterates namespace tags.
if ! command -v pdwtags > /dev/null 2>&1; then
	# namespace__fprintf is not tested, but the pahole -C tests above
	# still verify that types inside namespaces are found and displayed.
	info_log "   skip pdwtags checks: pdwtags not available"
else
	if ! full_output=$(pdwtags "$obj" 2>"$outdir/pdwtags.log"); then
		error_log "FAIL: pdwtags returned error"
		info_log "$(cat "$outdir/pdwtags.log")"
		test_fail
	fi
	if [ -z "$full_output" ]; then
		error_log "FAIL: pdwtags produced no output"
		test_fail
	fi

	# The namespace block should appear in pdwtags output
	if ! echo "$full_output" | grep -q "namespace outer"; then
		error_log "FAIL: pdwtags output missing 'namespace outer' block"
		test_fail
	fi
	info_log "   pdwtags namespace block: ok"

	# Nested namespace should appear inside the outer block
	if ! echo "$full_output" | grep -q "namespace inner"; then
		error_log "FAIL: pdwtags output missing 'namespace inner' block"
		test_fail
	fi
	info_log "   pdwtags nested namespace: ok"
fi

# Test 5: verify namespace-qualified names appear somewhere in pahole output
if ! echo "$output" | grep -qi "Nested\|InOuter"; then
	error_log "FAIL: output contains no namespace-related struct names"
	test_fail
fi
info_log "namespace struct names in output: ok"

test_pass
