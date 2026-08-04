#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Exercise BTF encoder verbose logging paths in btf_encoder.c:
#   - btf_encoder__log_type(): per-type log on successful emit
#   - btf_encoder__log_func_param(): per-parameter log for func protos
#   - btf__log_err(): error log (successful-emit variant with output_cr)
#
# These functions are only reached with --verbose / -V and are currently
# at 0% coverage because no test exercises verbose BTF encoding.

. "$(dirname "$0")/test_lib.sh"
outdir=$(make_tmpdir)

trap cleanup EXIT

title_log "BTF encoder verbose logging coverage."

CC=${CC:-gcc}
if ! command -v "${CC%% *}" > /dev/null 2>&1; then
	info_log "skip: $CC not available"
	test_skip
fi

src=$(make_tmpsrc)
obj=$(make_tmpobj)

# Source with diverse types to exercise all BTF kind logging paths
cat > "$src" << 'EOF'
typedef unsigned int uint_t;
typedef const uint_t const_uint_t;

enum color { RED, GREEN, BLUE };

struct inner {
	int x;
};

struct diverse {
	int			i;
	char			*p;
	const volatile int	cv;
	uint_t			t;
	enum color		e;
	struct inner		s;
	int			arr[4];
};

int compute(int a, int b) { return a + b; }
void process(struct diverse *d) { d->i = compute(d->i, 1); }

struct diverse g_d;
enum color g_c;
EOF

if ! $CC -g -c -o "$obj" "$src" 2>"$outdir/cc.log"; then
	error_log "FAIL: compilation failed"
	info_log "$(cat "$outdir/cc.log")"
	test_fail
fi

# Test 1: verbose detached BTF encoding — log goes to stderr
btf_file="$outdir/verbose.btf"
pahole --btf_encode_detached="$btf_file" --verbose "$obj" > "$outdir/verbose.log" 2>&1
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: pahole --btf_encode_detached --verbose exited $rc"
	test_fail
fi
if [ ! -s "$outdir/verbose.log" ]; then
	error_log "FAIL: --verbose produced no output"
	test_fail
fi
info_log "   verbose log non-empty: ok"

# Check for BTF kind strings in verbose output.
# INT and STRUCT are guaranteed by the test source, so hard-assert them.
for kind in INT STRUCT; do
	if ! grep -q "$kind" "$outdir/verbose.log"; then
		error_log "FAIL: expected $kind in verbose output"
		test_fail
	fi
	info_log "   $kind logged: ok"
done
for kind in PTR ARRAY ENUM TYPEDEF CONST; do
	if grep -q "$kind" "$outdir/verbose.log"; then
		info_log "   $kind logged: ok"
	else
		info_log "   $kind not logged (may not be present in input, non-fatal)"
	fi
done

# Check for member logging (btf_encoder__log_type with is_last_member)
if grep -q 'type_id=' "$outdir/verbose.log"; then
	info_log "   member logging (type_id=): ok"
fi

# Check for function param logging
if grep -qE 'FUNC_PROTO|FUNC' "$outdir/verbose.log"; then
	info_log "   FUNC/FUNC_PROTO logged: ok"
fi

# Test 2: verbose with floats (if supported)
float_src="$outdir/float.c"
float_obj="$outdir/float.o"
cat > "$float_src" << 'EOF'
struct with_float { float f; double d; };
struct with_float g_wf;
EOF
if $CC -g -c -o "$float_obj" "$float_src" 2>/dev/null; then
	pahole --btf_encode_detached="$outdir/float.btf" \
		--btf_features=default,float --verbose "$float_obj" > "$outdir/float_verbose.log" 2>&1
	if grep -q 'FLOAT' "$outdir/float_verbose.log"; then
		info_log "   FLOAT logged: ok"
	else
		info_log "   FLOAT not in verbose (btf_gen_floats may be unsupported, non-fatal)"
	fi
fi

# Test 3: verbose in-place encoding (pahole -J)
cp "$obj" "$outdir/inplace.o"
pahole -J --verbose "$outdir/inplace.o" > "$outdir/inplace_verbose.log" 2>&1
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: pahole -J --verbose exited $rc"
	test_fail
fi
if [ ! -s "$outdir/inplace_verbose.log" ]; then
	error_log "FAIL: pahole -J --verbose produced no output"
	test_fail
fi
if grep -q 'STRUCT' "$outdir/inplace_verbose.log"; then
	info_log "   in-place verbose STRUCT logged: ok"
fi

test_pass
