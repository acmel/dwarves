#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Compare default CU loading with explicit force_cu_merging for binaries
# with inter-CU type references (e.g. Rust CUs in perf).
#
# When cus__merging_cu() correctly detects DW_FORM_ref_addr usage, it
# automatically falls back to the merged CU path.  This test verifies
# that the automatic detection produces the same output as explicitly
# forcing CU merging.

. "$(dirname "$0")/test_lib.sh"

outdir=$(make_tmpdir)
trap cleanup EXIT

title_log "Compare parallel vs merged CU loading for inter-CU type references."

perf=$(which perf 2>/dev/null)
if [ -z "$perf" ] ; then
	info_log "skip: No 'perf' binary available"
	test_skip
fi

if ! pahole --features=force_cu_merging -F dwarf -C perf_event_header "$perf" 2>/dev/null | grep -q "^struct perf_event_header {" ; then
	info_log "skip: $perf doesn't have 'struct perf_event_header' type info"
	test_skip
fi

parallel_out=$outdir/parallel.txt
merged_out=$outdir/merged.txt

if ! pahole -F dwarf "$perf" > "$parallel_out" 2>/dev/null ; then
	error_log "FAIL: pahole failed processing $perf (parallel mode)"
	test_fail
fi

if ! pahole --features=force_cu_merging -F dwarf "$perf" > "$merged_out" 2>/dev/null ; then
	error_log "FAIL: pahole failed processing $perf (merged mode)"
	test_fail
fi

if diff -u "$parallel_out" "$merged_out" > /dev/null 2>&1 ; then
	test_pass
else
	nr_diff=$(diff "$parallel_out" "$merged_out" | grep '^[<>]' | wc -l)
	error_log "FAIL: $nr_diff lines differ between parallel and merged CU loading"
	test_fail
fi
