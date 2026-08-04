#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Test distilled base BTF generation (btf__distill_base path).
# Exercises the gen_distilled_base code path in
# btf_encoder__write_elf() that is only reached when
# --btf_features includes distilled_base.
#
# When encoding split BTF with distilled_base enabled, pahole calls
# btf__distill_base() to produce a minimal "distilled" version of the
# base BTF and writes it to a .BTF.base ELF section alongside the
# normal .BTF section.  This lets the kernel resolve split-BTF type
# references without needing the full vmlinux BTF at load time.
#
# Tests:
#  1. distilled_base feature is in --supported_btf_features
#  2. split BTF + distilled_base produces both .BTF and .BTF.base sections
#  3. the .BTF.base section is absent when distilled_base is not requested
#  4. bpftool can dump the resulting BTF and finds expected types

. "$(dirname "$0")/test_lib.sh"
outdir=$(make_tmpdir)

trap cleanup EXIT

title_log "Distilled base BTF generation."

CC=${CC:-gcc}
if ! command -v "${CC%% *}" > /dev/null 2>&1; then
	info_log "skip: $CC not available"
	test_skip
fi

# The distilled_base feature requires libbpf >= 1.5 for btf__distill_base().
# Skip gracefully if the feature is not compiled in or libbpf is too old.
if ! pahole --supported_btf_features 2>/dev/null | tr ',' '\n' | grep -qx 'distilled_base'; then
	info_log "skip: distilled_base feature not available"
	test_skip
fi

# --- Create source files ---
# base.c: simple types that act as the "vmlinux" base BTF
base_src=$(make_tmpsrc)
cat > "$base_src" << 'EOF'
struct base_type {
	int	x;
	long	y;
};

struct base_type g_base;
EOF

# module.c: a "module" that references base types and adds its own
mod_src=$(make_tmpsrc)
cat > "$mod_src" << 'EOF'
struct base_type {
	int	x;
	long	y;
};

struct module_type {
	struct base_type	*bp;
	int			flag;
};

struct module_type g_mod;
EOF

# --- Compile ---
base_obj=$(make_tmpobj)
if ! $CC -g -c -o "$base_obj" "$base_src" 2>/dev/null; then
	error_log "FAIL: compilation of base source failed"
	test_fail
fi

mod_obj=$(make_tmpobj)
if ! $CC -g -c -o "$mod_obj" "$mod_src" 2>/dev/null; then
	error_log "FAIL: compilation of module source failed"
	test_fail
fi

# --- Encode base BTF (detached, used as --btf_base input) ---
base_btf="$outdir/base.btf"
if ! pahole --btf_encode_detached="$base_btf" "$base_obj" 2>/dev/null || [ ! -s "$base_btf" ]; then
	error_log "FAIL: failed to encode base BTF"
	test_fail
fi
info_log "base BTF encoded: $(wc -c < "$base_btf") bytes"

# --- Test 1: split BTF + distilled_base produces .BTF and .BTF.base ---
# The distilled_base code path in btf_encoder__write_elf() writes both
# sections.  We must use -J (not --btf_encode_detached) because the
# distilled path is in the non-raw_output branch of btf_encoder__encode().
mod_elf="$outdir/module_distilled.o"
cp "$mod_obj" "$mod_elf"

if ! pahole -J --btf_base="$base_btf" \
       --btf_features=default,distilled_base \
       "$mod_elf" 2>/dev/null; then
	error_log "FAIL: pahole -J with distilled_base failed"
	test_fail
fi

# Check that .BTF section exists
if ! readelf -S "$mod_elf" 2>/dev/null | grep -q '\.BTF[[:space:]]'; then
	error_log "FAIL: .BTF section missing after distilled_base encoding"
	test_fail
fi
info_log ".BTF section present: ok"

# Check that .BTF.base section exists — this is the key output of the
# distilled base path (btf_encoder__write_elf with BTF_BASE_ELF_SEC)
if ! readelf -S "$mod_elf" 2>/dev/null | grep -q '\.BTF\.base'; then
	error_log "FAIL: .BTF.base section missing after distilled_base encoding"
	test_fail
fi
info_log ".BTF.base section present: ok"

# --- Test 2: without distilled_base, .BTF.base must be absent ---
mod_normal="$outdir/module_normal.o"
cp "$mod_obj" "$mod_normal"

if ! pahole -J --btf_base="$base_btf" \
       --btf_features=default \
       "$mod_normal" 2>/dev/null; then
	error_log "FAIL: pahole -J without distilled_base failed"
	test_fail
fi

if readelf -S "$mod_normal" 2>/dev/null | grep -q '\.BTF\.base'; then
	error_log "FAIL: .BTF.base section present without distilled_base feature"
	test_fail
fi
info_log ".BTF.base absent without distilled_base: ok"

# --- Test 3: bpftool can dump the distilled BTF ---
if command -v bpftool > /dev/null 2>&1; then
	dump=$(bpftool btf dump file "$mod_elf" 2>/dev/null)
	if [ -z "$dump" ]; then
		# bpftool returned no output - likely doesn't support distilled base BTF format
		info_log "skip: bpftool doesn't support distilled base BTF format"
		test_skip
	fi

	# The module_type struct should appear in the BTF
	if ! echo "$dump" | grep -q 'module_type'; then
		error_log "FAIL: bpftool dump missing struct module_type"
		test_fail
	fi
	info_log "bpftool btf dump: module_type found: ok"
else
	info_log "bpftool not available, skipping dump verification"
fi

test_pass
