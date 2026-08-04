#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Test btf_encoder.c coverage: variables, verbose encoding, detached output,
# enum edge cases, complex function signatures, and various feature flags.

. "$(dirname "$0")/test_lib.sh"
outdir=$(make_tmpdir)

trap cleanup EXIT

title_log "BTF encoder coverage."

CC=${CC:-gcc}
if ! command -v "${CC%% *}" > /dev/null 2>&1; then
	info_log "skip: $CC not available"
	test_skip
fi

src="$outdir/types.c"
obj="$outdir/types.o"

cat > "$src" << 'EOF'
struct simple { int x; int y; };
struct nested { struct simple s; int z; };
struct with_ptr { void *ptr; int len; };
struct with_array { int arr[8]; int count; };

union mixed {
	int		ival;
	float		fval;
	char		bytes[4];
};

typedef unsigned long size_type;
typedef int (*callback_fn)(void *, int);
typedef struct simple simple_t;

enum color { RED, GREEN, BLUE, ALPHA = 255 };
enum signed_vals { NEG = -100, ZERO = 0, POS = 100 };

struct with_enum {
	enum color	c;
	enum signed_vals sv;
	int		data;
};

struct has_bitfields {
	unsigned int	a:3;
	unsigned int	b:5;
	unsigned int	c:8;
	unsigned int	d:16;
};

struct complex {
	struct nested		n;
	union mixed		u;
	struct with_ptr		*wp;
	callback_fn		cb;
	size_type		sz;
	struct with_array	wa;
};

int func_simple(int a, int b) { return a + b; }
void *func_ptr_ret(struct with_ptr *p) { return p->ptr; }
int func_struct_param(struct nested n) { return n.z; }
int func_variadic(const char *fmt, ...) { (void)fmt; return 0; }
int func_many_params(int a, int b, int c, int d, int e, int f) {
	return a + b + c + d + e + f;
}
int func_enum_param(enum color c) { return (int)c; }
int func_callback(callback_fn fn, void *data) {
	return fn ? fn(data, 0) : -1;
}
void func_void(void) { }
static int func_static(int x) { return x * 2; }
int func_uses_static(int x) { return func_static(x); }

struct simple g_simple = { 1, 2 };
struct nested g_nested;
struct with_ptr g_wp;
union mixed g_mixed;
struct with_enum g_we;
struct has_bitfields g_bf;
struct complex g_complex;
int g_int = 42;
size_type g_sz = 100;
simple_t g_st;
const char *g_str = "hello";
int g_arr[4] = { 1, 2, 3, 4 };
EOF

if ! $CC -g -O0 -c -o "$obj" "$src" 2>/dev/null; then
	error_log "FAIL: compilation failed"
	test_fail
fi

pahole -J --btf_features=default,var "$obj" 2>/dev/null
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: BTF encode with vars failed (rc=$rc)"
	test_fail
fi
output=$(pahole -F btf "$obj" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: BTF read-back empty"
	test_fail
fi
if ! echo "$output" | grep -q "struct complex"; then
	error_log "FAIL: struct complex not in BTF"
	test_fail
fi
info_log "   BTF encode with vars: ok"

# Use a pristine copy without BTF for verbose encode test
$CC -g -O0 -c -o "$outdir/verbose.o" "$src" 2>/dev/null
output=$(pahole -J -V --btf_features=default,var "$outdir/verbose.o" 2>&1)
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: verbose BTF encode failed (rc=$rc)"
	test_fail
fi
if [ -z "$output" ]; then
	error_log "FAIL: verbose BTF encode empty"
	test_fail
fi
info_log "   BTF verbose encode: ok"

# Pristine copy for detached BTF test
$CC -g -O0 -c -o "$outdir/detached.o" "$src" 2>/dev/null
detached_file="$outdir/detached.btf"
pahole -J --btf_encode_detached="$detached_file" "$outdir/detached.o" 2>/dev/null
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: detached BTF encode failed (rc=$rc)"
	test_fail
fi
if [ ! -f "$detached_file" ]; then
	error_log "FAIL: detached BTF file not created"
	test_fail
fi
if [ ! -s "$detached_file" ]; then
	error_log "FAIL: detached BTF file is empty"
	test_fail
fi
info_log "   BTF detached file: ok"

# Pristine copy for floats test
$CC -g -O0 -c -o "$outdir/floats.o" "$src" 2>/dev/null
pahole -J --btf_gen_floats "$outdir/floats.o" 2>/dev/null
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: BTF encode with floats failed (rc=$rc)"
	test_fail
fi
output=$(pahole -F btf "$outdir/floats.o" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: BTF floats read-back empty"
	test_fail
fi
if ! echo "$output" | grep -q "float"; then
	error_log "FAIL: BTF floats output missing float type"
	test_fail
fi
info_log "   BTF gen floats: ok"

# Pristine copy for skip vars test
$CC -g -O0 -c -o "$outdir/skipvars.o" "$src" 2>/dev/null
pahole -J --skip_encoding_btf_vars "$outdir/skipvars.o" 2>/dev/null
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: skip_encoding_btf_vars failed (rc=$rc)"
	test_fail
fi
info_log "   BTF skip vars: ok"

enum_src="$outdir/enums.c"
enum_obj="$outdir/enums.o"
cat > "$enum_src" << 'EOF'
enum tiny { T_A, T_B };
enum signed_extremes { SE_MIN = -2147483647 - 1, SE_MAX = 2147483647 };
enum unsigned_full { UF_MIN = 0, UF_MAX = 0xFFFFFFFFU };
enum singleton { SINGLE = 42 };
/*
 * Values exceed 32 bits, so the compiler uses a 64-bit underlying type.
 * This gives --skip_encoding_btf_enum64 something to actually skip.
 */
enum wide { W_BIG = 0x100000000LL, W_SMALL = 1 };

struct has_enums {
	enum tiny		t;
	enum signed_extremes	se;
	enum unsigned_full	uf;
	enum singleton		s;
	enum wide		w;
};

struct has_enums g_he;
EOF

if ! $CC -g -c -o "$enum_obj" "$enum_src" 2>/dev/null; then
	error_log "FAIL: enum compilation failed"
	test_fail
fi
cp "$enum_obj" "$outdir/enum_btf.o"
pahole -J -V "$outdir/enum_btf.o" >/dev/null 2>&1
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: enum BTF encode failed (rc=$rc)"
	test_fail
fi
output=$(pahole -F btf "$outdir/enum_btf.o" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: enum BTF read-back empty"
	test_fail
fi
info_log "   BTF enum edge cases: ok"

cp "$enum_obj" "$outdir/enum_skip64.o"
pahole -J --skip_encoding_btf_enum64 "$outdir/enum_skip64.o" 2>/dev/null
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: skip_encoding_btf_enum64 failed (rc=$rc)"
	test_fail
fi
# --skip_encoding_btf_enum64 doesn't remove the enum; it encodes 64-bit
# values as 32-bit, truncating values that don't fit.  Verify the original
# 64-bit value (4294967296 = 0x100000000) was truncated to 0.
output=$(pahole -F btf -E "$outdir/enum_skip64.o" 2>/dev/null)
if echo "$output" | grep -q "4294967296"; then
	error_log "FAIL: skip_encoding_btf_enum64 did not truncate W_BIG"
	test_fail
fi
info_log "   BTF skip enum64: ok"

funcs_src="$outdir/funcs.c"
funcs_obj="$outdir/funcs.o"
cat > "$funcs_src" << 'EOF'
struct param_s { int a; int b; };
union param_u { int x; float y; };
enum param_e { PE_A, PE_B };

int fn_struct(struct param_s *s) { return s->a; }
int fn_union(union param_u *u) { return u->x; }
int fn_enum(enum param_e e) { return (int)e; }
int fn_callback(int (*cb)(int)) { return cb ? cb(0) : -1; }
void *fn_ptr_ptr(void **pp) { return *pp; }
int fn_eight(int a, int b, int c, int d, int e, int f, int g, int h) {
	return a+b+c+d+e+f+g+h;
}
int fn_variadic_struct(struct param_s s, ...) { return s.a; }
void fn_void_ret(int x) { (void)x; }

int (*g_fnptr)(int) = 0;
struct param_s g_ps;
union param_u g_pu;
EOF

if ! $CC -g -O0 -c -o "$funcs_obj" "$funcs_src" 2>/dev/null; then
	error_log "FAIL: funcs compilation failed"
	test_fail
fi
cp "$funcs_obj" "$outdir/funcs_btf.o"
pahole -J -V --btf_features=default,var "$outdir/funcs_btf.o" >/dev/null 2>&1
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: funcs BTF encode failed (rc=$rc)"
	test_fail
fi
output=$(pahole -F btf "$outdir/funcs_btf.o" 2>/dev/null)
if [ -z "$output" ]; then
	error_log "FAIL: funcs BTF read-back empty"
	test_fail
fi
info_log "   BTF complex function signatures: ok"

multi_a="$outdir/multi_a.c"
multi_b="$outdir/multi_b.c"
cat > "$multi_a" << 'EOF'
struct cu_a { int x; };
int fn_a(struct cu_a *a) { return a->x; }
struct cu_a g_a;
EOF

cat > "$multi_b" << 'EOF'
struct cu_b { long y; };
int fn_b(struct cu_b *b) { return (int)b->y; }
struct cu_b g_b;
EOF

if ! $CC -g -c -o "$outdir/multi_a.o" "$multi_a" 2>/dev/null; then
	error_log "FAIL: multi_a compilation failed"
	test_fail
fi
if ! $CC -g -c -o "$outdir/multi_b.o" "$multi_b" 2>/dev/null; then
	error_log "FAIL: multi_b compilation failed"
	test_fail
fi
if command -v ld > /dev/null 2>&1; then
	if ld -r -o "$outdir/multi.o" "$outdir/multi_a.o" "$outdir/multi_b.o" 2>/dev/null; then
		pahole -J -V --btf_features=default,var "$outdir/multi.o" >/dev/null 2>&1
		rc=$?
		if [ $rc -ne 0 ]; then
			error_log "FAIL: multi-CU BTF encode failed (rc=$rc)"
			test_fail
		fi
		output=$(pahole -F btf "$outdir/multi.o" 2>/dev/null)
		if ! echo "$output" | grep -q "struct cu_a"; then
			error_log "FAIL: cu_a not in multi-CU BTF"
			test_fail
		fi
		if ! echo "$output" | grep -q "struct cu_b"; then
			error_log "FAIL: cu_b not in multi-CU BTF"
			test_fail
		fi
		info_log "   BTF multi-CU encode: ok"
	else
		info_log "   skip: ld -r failed"
	fi
else
	info_log "   skip: ld not available"
fi

# Pristine copy — first -J creates .BTF, second -J overwrites it
$CC -g -O0 -c -o "$outdir/overwrite.o" "$src" 2>/dev/null
pahole -J "$outdir/overwrite.o" 2>/dev/null
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: first BTF encode for overwrite failed (rc=$rc)"
	test_fail
fi
pahole -J "$outdir/overwrite.o" 2>/dev/null
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: BTF ELF overwrite failed (rc=$rc)"
	test_fail
fi
info_log "   BTF ELF overwrite: ok"

test_pass
