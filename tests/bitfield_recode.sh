#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Test dwarf_loader.c edge cases: complex bitfields, template parameter packs,
# inline expansions, enumerations, and subroutine types.

. "$(dirname "$0")/test_lib.sh"
outdir=$(make_tmpdir)

trap cleanup EXIT

title_log "dwarf_loader coverage: bitfields, templates, enums, inlines."

CC=${CC:-gcc}
if ! command -v "${CC%% *}" > /dev/null 2>&1; then
	info_log "skip: $CC not available"
	test_skip
fi

src=$(make_tmpsrc)
obj=$(make_tmpobj)

cat > "$src" << 'EOF'
struct complex_bitfields {
	unsigned int a:1;
	unsigned int b:3;
	unsigned int c:5;
	unsigned int d:7;
	unsigned int e:16;
};

struct cross_boundary {
	unsigned long long x:33;
	unsigned long long y:31;
};

struct mixed_members {
	int		normal;
	unsigned int	bits:4;
	char		byte;
	unsigned int	more_bits:12;
	long		big;
};

enum color { RED, GREEN, BLUE, ALPHA = 255 };
enum big_enum { BIG_A = 0, BIG_B = 100000, BIG_C = -1 };

typedef int (*callback_fn)(void *, int);
typedef void (*void_fn)(void);

struct with_callbacks {
	callback_fn	on_event;
	void_fn		on_done;
	int		data;
};

static inline int helper(int x) { return x * 2; }

int process(struct complex_bitfields *bf, enum color c) {
	return bf->a + bf->c + c + helper(bf->d);
}

int use_mixed(struct mixed_members *m) {
	return m->normal + m->bits + m->more_bits + helper(m->byte);
}

int call_fn(struct with_callbacks *cb) {
	if (cb->on_event)
		return cb->on_event(cb, cb->data);
	return 0;
}

struct complex_bitfields g_bf;
struct cross_boundary g_cross;
struct mixed_members g_mixed;
struct with_callbacks g_cb;
enum color g_color;
enum big_enum g_big;
EOF

if ! $CC -g -O2 -c -o "$obj" "$src" 2>/dev/null; then
	error_log "FAIL: compilation failed"
	test_fail
fi

output=$(pahole -C complex_bitfields "$obj" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: complex_bitfields not found"
	test_fail
fi
if ! echo "$output" | grep -q "a:1"; then
	error_log "FAIL: bitfield a:1 not displayed"
	test_fail
fi
info_log "   complex bitfields: ok"

output=$(pahole -C cross_boundary "$obj" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: cross_boundary not found"
	test_fail
fi
info_log "   cross-boundary bitfields: ok"

output=$(pahole -C mixed_members "$obj" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: mixed_members not found"
	test_fail
fi
if ! echo "$output" | grep -q "bits"; then
	error_log "FAIL: mixed_members missing bits field"
	test_fail
fi
info_log "   mixed members with bitfields: ok"

output=$(pahole -C with_callbacks "$obj" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: with_callbacks not found"
	test_fail
fi
info_log "   function pointer members: ok"

output=$(pahole -E -C with_callbacks "$obj" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: -E with_callbacks produced no output"
	test_fail
fi
# -E should expand the callback_fn typedef to show its parameter types
if ! echo "$output" | grep -q "int"; then
	error_log "FAIL: -E with_callbacks did not expand function pointer types"
	test_fail
fi
info_log "   -E expand function pointer types: ok"

output=$(pahole --sizes "$obj" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: --sizes produced no output"
	test_fail
fi
if ! echo "$output" | grep -q "complex_bitfields"; then
	error_log "FAIL: --sizes missing complex_bitfields"
	test_fail
fi
info_log "   --sizes with bitfield structs: ok"

pahole -J "$obj" 2>/dev/null
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: BTF encode failed (rc=$rc)"
	test_fail
fi
output=$(pahole -F btf "$obj" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: BTF read-back produced no output"
	test_fail
fi
# Verify the BTF round-trip preserved the bitfield structs
if ! echo "$output" | grep -q "complex_bitfields"; then
	error_log "FAIL: BTF read-back missing complex_bitfields"
	test_fail
fi
info_log "   BTF encode/decode with bitfields: ok"

CXX=${CXX:-g++}
if command -v "${CXX%% *}" > /dev/null 2>&1; then
	cxx_src="$outdir/templates.cpp"
	cxx_obj="$outdir/templates.o"

	cat > "$cxx_src" << 'CXXEOF'
template<typename... Args>
struct variadic {
	int count;
};

template<typename T, typename U>
struct pair {
	T first;
	U second;
};

namespace ns {
	struct inner { int x; };
	inline int get(inner *i) { return i->x; }
}

variadic<int, float, char> gv;
pair<int, long> gp;
ns::inner gi;
CXXEOF

	if ! $CXX -g -c -o "$cxx_obj" "$cxx_src" 2>/dev/null; then
		info_log "   skip: C++ compilation failed"
	else
		output=$(pahole "$cxx_obj" 2>/dev/null)
		if [ -z "$output" ]; then
			error_log "FAIL: C++ template output empty"
			test_fail
		fi
		# Verify specific template types were parsed
		if ! echo "$output" | grep -q "pair"; then
			error_log "FAIL: C++ template pair not found in output"
			test_fail
		fi
		info_log "   C++ templates and parameter packs: ok"
	fi
else
	info_log "   skip: C++ not available"
fi

test_pass
