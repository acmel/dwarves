#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Test BTF encoding on vmlinux: exercises multi-CU dedup, kfunc collection,
# optimized function encoding, verbose output, and btf_gen_all — code paths
# that small .o test objects cannot reach.

. "$(dirname "$0")/test_lib.sh"
outdir=$(make_tmpdir)

trap cleanup EXIT

title_log "BTF encoding on vmlinux."

if ! command -v bpftool > /dev/null 2>&1; then
	info_log "skip: bpftool not available"
	test_skip
fi

vmlinux=$(get_vmlinux)
if [ -z "$vmlinux" ] || [ ! -f "$vmlinux" ]; then
	info_log "skip: no vmlinux with DWARF available"
	test_skip
fi

# --- Basic vmlinux BTF encode ---
btf_basic="$outdir/basic.btf"
pahole -J --btf_encode_detached="$btf_basic" "$vmlinux" 2>/dev/null
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: basic BTF encode failed (rc=$rc)"
	test_fail
fi
if [ ! -s "$btf_basic" ]; then
	error_log "FAIL: basic BTF file is empty"
	test_fail
fi
dump=$(bpftool btf dump file "$btf_basic" 2>/dev/null)
if [ -z "$dump" ]; then
	info_log "skip: bpftool cannot parse BTF (too old or missing features)"
	test_skip
fi
if ! echo "$dump" | grep -q "'task_struct'"; then
	error_log "FAIL: BTF missing task_struct"
	test_fail
fi
if ! echo "$dump" | grep -q "'sk_buff'"; then
	error_log "FAIL: BTF missing sk_buff"
	test_fail
fi
info_log "   basic vmlinux BTF encode: ok"

# --- Optimized function encoding ---
btf_opt="$outdir/optimized.btf"
pahole -J --btf_gen_optimized --btf_encode_detached="$btf_opt" "$vmlinux" 2>/dev/null
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: --btf_gen_optimized failed (rc=$rc)"
	test_fail
fi
if [ ! -s "$btf_opt" ]; then
	error_log "FAIL: optimized BTF file is empty"
	test_fail
fi
info_log "   --btf_gen_optimized: ok"

# --- kfunc collection via decl_tag_kfuncs feature ---
# Only if vmlinux has a .BTF_ids section (kernels with BPF kfuncs)
if readelf -S "$vmlinux" 2>/dev/null | grep -q '\.BTF_ids'; then
	btf_kfunc="$outdir/kfunc.btf"
	pahole -J --btf_features=default,decl_tag_kfuncs \
		--btf_encode_detached="$btf_kfunc" "$vmlinux" 2>/dev/null
	rc=$?
	if [ $rc -ne 0 ]; then
		error_log "FAIL: decl_tag_kfuncs failed (rc=$rc)"
		test_fail
	fi
	kfunc_count=$(bpftool btf dump file "$btf_kfunc" 2>/dev/null | grep -c "DECL_TAG 'bpf_kfunc'")
	if [ "$kfunc_count" -lt 1 ]; then
		error_log "FAIL: no bpf_kfunc DECL_TAGs in output"
		test_fail
	fi
	info_log "   decl_tag_kfuncs: ok ($kfunc_count kfuncs tagged)"
else
	info_log "   skip: vmlinux has no .BTF_ids section"
fi

# --- Verbose mode exercises variable encoding output ---
btf_verbose="$outdir/verbose.btf"
pahole -J -V --btf_encode_detached="$btf_verbose" "$vmlinux" \
	>"$outdir/verbose.out" 2>&1
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: verbose BTF encode failed (rc=$rc)"
	test_fail
fi
if [ ! -s "$btf_verbose" ]; then
	error_log "FAIL: verbose BTF file is empty"
	test_fail
fi
info_log "   verbose BTF encode: ok"

# --- btf_gen_all enables all features ---
btf_all="$outdir/all.btf"
pahole -J --btf_gen_all --btf_encode_detached="$btf_all" "$vmlinux" 2>/dev/null
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: --btf_gen_all failed (rc=$rc)"
	test_fail
fi
if [ ! -s "$btf_all" ]; then
	error_log "FAIL: btf_gen_all BTF file is empty"
	test_fail
fi
# btf_gen_all should produce at least as many types as the basic encode
basic_types=$(bpftool btf dump file "$btf_basic" 2>/dev/null | wc -l)
all_types=$(bpftool btf dump file "$btf_all" 2>/dev/null | wc -l)
if [ "$all_types" -lt "$basic_types" ]; then
	error_log "FAIL: btf_gen_all produced fewer types ($all_types) than basic ($basic_types)"
	test_fail
fi
info_log "   --btf_gen_all: ok ($all_types lines vs $basic_types basic)"

# --- Reproducible build on vmlinux ---
btf_repro1="$outdir/repro1.btf"
btf_repro2="$outdir/repro2.btf"
pahole -J --reproducible_build --btf_encode_detached="$btf_repro1" "$vmlinux" 2>/dev/null
pahole -J --reproducible_build --btf_encode_detached="$btf_repro2" "$vmlinux" 2>/dev/null
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: reproducible_build on vmlinux failed (rc=$rc)"
	test_fail
fi
if ! cmp -s "$btf_repro1" "$btf_repro2"; then
	error_log "FAIL: reproducible_build produced different output"
	test_fail
fi
info_log "   --reproducible_build on vmlinux: ok"

test_pass
