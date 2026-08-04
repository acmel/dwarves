#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Test BTF_KIND_FLOAT and BTF_KIND_ENUM64 encoding.
#
# BTF_KIND_FLOAT: btf_encoder__add_float() in btf_encoder.c.
#   float/double/long double must each produce a distinct FLOAT type
#   when --btf_features includes 'float' (part of 'default').
#
# BTF_KIND_ENUM64: btf__add_enum64 path in btf_encoder__add_enum().
#   A C enum whose values exceed 32 bits must encode as ENUM64 when
#   libbpf >= 1.0 supports it; a 32-bit enum always encodes as ENUM.
#   When the enum64 feature is absent, even a 64-bit enum falls back
#   to BTF_KIND_ENUM.

. "$(dirname "$0")/test_lib.sh"
outdir=$(make_tmpdir)

trap cleanup EXIT

title_log "BTF FLOAT and ENUM64 type encoding."

CC=${CC:-gcc}
if ! command -v "${CC%% *}" > /dev/null 2>&1; then
	info_log "skip: $CC not available"
	test_skip
fi

if ! command -v bpftool > /dev/null 2>&1; then
	info_log "skip: bpftool not available"
	test_skip
fi

src=$(make_tmpsrc)
obj=$(make_tmpobj)

# A struct with all three IEEE float widths ensures the float base-type
# DWARF entries are present in the CU and will be encoded.
# Two enums: big_e has a value requiring 64 bits; small_e stays in 32 bits.
cat > "$src" << 'EOF'
struct floats_test {
	float       f32;
	double      f64;
	long double f128;
};

enum big_e  { VAL_HIGH = 0x100000000ULL } big_e_var;
enum small_e{ SMALL_A  = 1             } small_e_var;

struct floats_test ft;
EOF

if ! $CC -g -c -o "$obj" "$src" 2>/dev/null; then
	error_log "FAIL: compilation failed"
	test_fail
fi

btf_default="$outdir/default.btf"
if ! pahole --btf_features=default --btf_encode_detached="$btf_default" "$obj" 2>/dev/null; then
	error_log "FAIL: pahole BTF encoding (default features) failed"
	test_fail
fi

dump=$(bpftool btf dump file "$btf_default" 2>/dev/null)
if [ -z "$dump" ]; then
	# bpftool returned no output - likely doesn't support FLOAT/ENUM64 BTF kinds
	info_log "skip: bpftool doesn't support FLOAT/ENUM64 BTF kinds"
	test_skip
fi

# --- float encoding ---

# Each IEEE float width must appear as a distinct BTF_KIND_FLOAT
if ! echo "$dump" | grep -q "FLOAT 'float' size=4"; then
	error_log "FAIL: FLOAT 'float' size=4 not found"
	test_fail
fi
info_log "FLOAT 'float' size=4: ok"

if ! echo "$dump" | grep -q "FLOAT 'double' size=8"; then
	error_log "FAIL: FLOAT 'double' size=8 not found"
	test_fail
fi
info_log "FLOAT 'double' size=8: ok"

# Compute the expected size of long double from the compiler; it varies by
# architecture (16 on x86-64, 12 on 32-bit x86, 8 on 32-bit ARM, etc.).
# Use -E so this works for cross-compilers too (no need to run the binary).
ld_size=$(echo | $CC -x c -E -dM - 2>/dev/null | awk '/__SIZEOF_LONG_DOUBLE__/{print $3}')
[ -z "$ld_size" ] && ld_size=16

if ! echo "$dump" | grep -q "FLOAT 'long double' size=${ld_size}"; then
	error_log "FAIL: FLOAT 'long double' size=${ld_size} not found"
	test_fail
fi
info_log "FLOAT 'long double' size=${ld_size}: ok"

# --- 32-bit enum: always ENUM regardless of libbpf version ---

if ! echo "$dump" | grep -q "ENUM 'small_e'"; then
	error_log "FAIL: ENUM 'small_e' not found"
	test_fail
fi
info_log "ENUM 'small_e': ok"

# --- 64-bit enum: ENUM64 when libbpf >= 1.0, ENUM fallback otherwise ---

has_enum64=0
if pahole --supported_btf_features 2>/dev/null | tr ',' '\n' | grep -qx 'enum64'; then
	has_enum64=1
fi

if [ "$has_enum64" -eq 1 ]; then
	if ! echo "$dump" | grep -q "ENUM64 'big_e'"; then
		error_log "FAIL: ENUM64 'big_e' not found (libbpf supports enum64)"
		test_fail
	fi
	info_log "ENUM64 'big_e': ok"

	# With enum64 explicitly excluded, the 64-bit enum must fall back to
	# BTF_KIND_ENUM (same as pre-1.0 libbpf behavior).
	btf_no64="$outdir/no_enum64.btf"
	# Construct a feature string with all default features except enum64.
	# Also filter distilled_base which requires --btf_base.
	features_no64=$(pahole --supported_btf_features 2>/dev/null | tr ',' '\n' | grep -vE '^(enum64|distilled_base)$' | tr '\n' ',' | sed 's/,$//')
	if ! pahole --btf_features="$features_no64" --btf_encode_detached="$btf_no64" "$obj" 2>/dev/null; then
		error_log "FAIL: pahole BTF encoding (no enum64) failed"
		test_fail
	fi
	dump_no64=$(bpftool btf dump file "$btf_no64" 2>/dev/null)
	if ! echo "$dump_no64" | grep -q "ENUM 'big_e'"; then
		error_log "FAIL: expected fallback ENUM 'big_e' when enum64 excluded"
		test_fail
	fi
	# Must NOT have ENUM64 in the fallback BTF
	if echo "$dump_no64" | grep -q "ENUM64 'big_e'"; then
		error_log "FAIL: ENUM64 'big_e' present even though enum64 feature was excluded"
		test_fail
	fi
	info_log "ENUM 'big_e' fallback (enum64 excluded): ok"
else
	# libbpf < 1.0: big_e must be emitted as ENUM (not ENUM64)
	if ! echo "$dump" | grep -q "ENUM 'big_e'"; then
		error_log "FAIL: expected fallback ENUM 'big_e' (libbpf lacks enum64 support)"
		test_fail
	fi
	info_log "ENUM 'big_e' fallback (libbpf lacks enum64): ok"
fi

test_pass
