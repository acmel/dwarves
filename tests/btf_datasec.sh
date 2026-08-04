#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Test BTF VAR and DATASEC encoding for global variables via
# btf_encoder__add_var() and btf_encoder__add_datasec() in btf_encoder.c,
# exercised through --btf_features=global_var on a small linked binary.
#
# External globals and statics must each produce a BTF_KIND_VAR entry with
# the correct linkage, and their ELF section must appear as a
# BTF_KIND_DATASEC entry that back-references the VAR type.

. "$(dirname "$0")/test_lib.sh"
outdir=$(make_tmpdir)

trap cleanup EXIT

title_log "BTF VAR and DATASEC encoding for global variables."

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
bin="$outdir/btf_datasec_bin"
btf="$outdir/btf_datasec.btf"

# g_counter: external (global) linkage, zero-initialized → .bss
#   must appear as BTF_KIND_VAR with linkage=global
# s_threshold: internal (static) linkage, non-zero → .data
#   must appear as BTF_KIND_VAR with linkage=static
# Each section hosting a VAR must appear as a BTF_KIND_DATASEC.
cat > "$src" << 'EOF'
int g_counter = 0;
static int s_threshold = 100;
int main(void) { return g_counter - s_threshold; }
EOF

# -O0 prevents the compiler from inlining the static constant
# and removing the variable from the ELF section.
if ! $CC -g -O0 -o "$bin" "$src" 2>/dev/null; then
	error_log "FAIL: compilation failed"
	test_fail
fi

if ! pahole --btf_features=default,global_var --btf_encode_detached="$btf" "$bin" 2>/dev/null; then
	error_log "FAIL: pahole BTF encoding failed"
	test_fail
fi

dump=$(bpftool btf dump file "$btf" 2>/dev/null)
if [ -z "$dump" ]; then
	error_log "FAIL: bpftool btf dump produced no output"
	test_fail
fi

# Both variables must appear as BTF_KIND_VAR entries
if ! echo "$dump" | grep -q "VAR 'g_counter'"; then
	error_log "FAIL: BTF_KIND_VAR 'g_counter' not found"
	test_fail
fi
info_log "VAR 'g_counter': ok"

if ! echo "$dump" | grep -q "VAR 's_threshold'"; then
	error_log "FAIL: BTF_KIND_VAR 's_threshold' not found"
	test_fail
fi
info_log "VAR 's_threshold': ok"

# External variable must have global linkage (BTF_VAR_GLOBAL_ALLOCATED).
# Newer bpftool dumps print "linkage=global", older ones the numeric
# value (1), so accept both.
if ! echo "$dump" | grep "VAR 'g_counter'" | grep -qE "linkage=(global|1)"; then
	error_log "FAIL: VAR 'g_counter' does not have global linkage"
	test_fail
fi
info_log "g_counter linkage=global: ok"

# Static variable must have static linkage (BTF_VAR_STATIC).
if ! echo "$dump" | grep "VAR 's_threshold'" | grep -qE "linkage=(static|0)"; then
	error_log "FAIL: VAR 's_threshold' does not have static linkage"
	test_fail
fi
info_log "s_threshold linkage=static: ok"

# Each ELF section that hosts a VAR must produce a BTF_KIND_DATASEC entry
nr_datasec=$(echo "$dump" | grep -c "^.*DATASEC")
if [ "$nr_datasec" -lt 1 ]; then
	error_log "FAIL: no BTF_KIND_DATASEC found (expected at least one for .data or .bss)"
	test_fail
fi
info_log "DATASEC entries ($nr_datasec): ok"

# bpftool annotates each DATASEC member with the VAR name it references;
# verify both variables are covered by a DATASEC
# Older bpftool versions (e.g., v5.10) don't show the (VAR 'name') annotation
if echo "$dump" | grep -q "(VAR '"; then
	# New bpftool format with VAR annotations
	if ! echo "$dump" | grep -q "(VAR 'g_counter')"; then
		error_log "FAIL: no DATASEC references VAR 'g_counter'"
		test_fail
	fi
	info_log "DATASEC references g_counter: ok"

	if ! echo "$dump" | grep -q "(VAR 's_threshold')"; then
		error_log "FAIL: no DATASEC references VAR 's_threshold'"
		test_fail
	fi
	info_log "DATASEC references s_threshold: ok"
else
	# Old bpftool doesn't show VAR references in DATASEC - just verify VARs exist
	info_log "DATASEC VAR references: skipped (old bpftool format)"
fi

test_pass
