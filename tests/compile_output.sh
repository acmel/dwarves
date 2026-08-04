#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Test --compile, --classes_as_structs, and --structs/--unions.

. "$(dirname "$0")/test_lib.sh"
outdir=$(make_tmpdir)

trap cleanup EXIT

title_log "Compilable output and type filtering."

CC=${CC:-gcc}
if ! command -v "${CC%% *}" > /dev/null 2>&1; then
	info_log "skip: $CC not available"
	test_skip
fi

src=$(make_tmpsrc)
obj=$(make_tmpobj)

cat > "$src" << 'EOF'
struct point {
	int	x;
	int	y;
};

union variant {
	int	i;
	float	f;
	char	c;
};

struct point g1;
union variant g2;
EOF

if ! $CC -g -c -o "$obj" "$src" 2>/dev/null; then
	error_log "FAIL: compilation failed"
	test_fail
fi

# --compile: output should be compilable C
compile_out=$(pahole --compile -C point "$obj" 2>/dev/null)
if ! echo "$compile_out" | grep -q "struct point"; then
	error_log "FAIL: --compile did not produce struct definition"
	test_fail
fi
# verify the output actually compiles
compile_check="$outdir/compile_check.c"
echo "$compile_out" > "$compile_check"
if ! $CC -c -o /dev/null "$compile_check" 2>/dev/null; then
	error_log "FAIL: --compile output does not compile"
	test_fail
fi
info_log "--compile: ok"

# --structs: only show structs
output=$(pahole --structs "$obj" 2>/dev/null)
if ! echo "$output" | grep -q "struct point"; then
	error_log "FAIL: --structs did not show point"
	test_fail
fi
if echo "$output" | grep -q "union variant"; then
	error_log "FAIL: --structs showed union"
	test_fail
fi
info_log "--structs: ok"

# --unions: only show unions
output=$(pahole --unions "$obj" 2>/dev/null)
if ! echo "$output" | grep -q "union variant"; then
	error_log "FAIL: --unions did not show variant"
	test_fail
fi
if echo "$output" | grep -q "struct point"; then
	error_log "FAIL: --unions showed struct"
	test_fail
fi
info_log "--unions: ok"

# --classes_as_structs: requires C++ class input
CXX=${CXX:-g++}
if ! command -v "${CXX%% *}" > /dev/null 2>&1; then
	info_log "skip --classes_as_structs: $CXX not available"
	test_skip
fi

cxx_src="$outdir/widget.cpp"
cxx_obj="$outdir/widget.o"

cat > "$cxx_src" << 'EOF'
class Widget {
public:
	int	width;
	int	height;
	void resize(int w, int h) { width = w; height = h; }
};
Widget g;
EOF

if ! $CXX -g -c -o "$cxx_obj" "$cxx_src" 2>/dev/null; then
	error_log "FAIL: C++ compilation failed"
	test_fail
fi

# Without --classes_as_structs: should show "class Widget"
output=$(pahole -C Widget "$cxx_obj" 2>/dev/null)
if ! echo "$output" | grep -q "class Widget"; then
	error_log "FAIL: C++ class not shown as class"
	test_fail
fi

# With --classes_as_structs: should show "struct Widget" instead
output=$(pahole --classes_as_structs -C Widget "$cxx_obj" 2>/dev/null)
if ! echo "$output" | grep -q "struct Widget"; then
	error_log "FAIL: --classes_as_structs did not convert class to struct"
	test_fail
fi
if echo "$output" | grep -q "class Widget"; then
	error_log "FAIL: --classes_as_structs still shows class keyword"
	test_fail
fi
info_log "--classes_as_structs: ok"

test_pass
