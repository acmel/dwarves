#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Test BTF encoding with invalid symbol names.
# Exercises dump_invalid_symbol() and --btf_encode_force paths
# in btf_encoder.c.
#
# btf_name_valid() rejects names whose first character is not a letter,
# underscore, or dot.  We create a valid object, then binary-patch a
# variable name so its first character becomes '0', which makes the
# name invalid for BTF.  This lets us exercise:
#
#   1. The error path (no --btf_encode_force): pahole must print an
#      Error message and refuse to emit BTF.
#   2. The force path (--btf_encode_force): pahole must succeed.
#   3. The force+verbose path (--btf_encode_force --verbose): pahole
#      must print a Warning and succeed.

. "$(dirname "$0")/test_lib.sh"

outdir=$(make_tmpdir)
trap cleanup EXIT

title_log "BTF encoding with invalid symbol names."

CC=${CC:-gcc}
if ! command -v ${CC%% *} > /dev/null 2>&1; then
	info_log "skip: $CC not available"
	test_skip
fi

src=$(make_tmpsrc)
obj=$(make_tmpobj)

# The variable "xbadvar" will be binary-patched to "0badvar" in DWARF
# and ELF strings.  A name starting with '0' fails btf_name_valid()
# because the first character is not a letter, underscore, or dot.
cat > "$src" << 'EOF'
int normal_var = 42;
struct simple { int x; };
struct simple g;
int xbadvar = 99;
EOF

$CC -g -c -o "$obj" "$src" 2>/dev/null
if [ $? -ne 0 ]; then
	error_log "FAIL: compilation failed"
	test_fail
fi

# --- Baseline: normal object encodes cleanly ---
elf_obj="$outdir/baseline.o"
cp "$obj" "$elf_obj"
# Use --btf_features=global_var to enable variable encoding without
# the "default" feature set (which implicitly enables encode_force).
pahole -J --btf_features=global_var "$elf_obj" 2>"$outdir/baseline_stderr.txt"
if [ $? -ne 0 ]; then
	error_log "FAIL: baseline pahole -J failed on valid object"
	test_fail
fi
# No error messages expected on a clean object
if grep -qiE 'error|invalid' "$outdir/baseline_stderr.txt"; then
	error_log "FAIL: unexpected error on clean object"
	test_fail
fi
info_log "Baseline (valid object): ok"

# --- Patch the object to create an invalid DWARF variable name ---
# Binary-replace "xbadvar" with "0badvar" in both .debug_str and .strtab.
# LC_ALL=C ensures sed treats the file as raw bytes.
patched="$outdir/patched.o"
cp "$obj" "$patched"
LC_ALL=C sed -i 's/xbadvar/0badvar/g' "$patched"

# Verify the patch landed in DWARF
if ! readelf --debug-dump=info "$patched" 2>/dev/null | grep -q '0badvar'; then
	info_log "skip: binary patch did not produce '0badvar' in DWARF"
	test_skip
fi

# --- Test 1: Error path (no force) ---
# Without --btf_encode_force, an invalid variable name must produce
# an error and must NOT emit BTF.
elf_err="$outdir/error_test.o"
cp "$patched" "$elf_err"
pahole -J --btf_features=global_var "$elf_err" 2>"$outdir/error_stderr.txt"
# The Error message from dump_invalid_symbol() must appear on stderr
if ! grep -q 'PAHOLE: Error:.*invalid variable name' "$outdir/error_stderr.txt"; then
	error_log "FAIL: expected 'Error:.*invalid variable name' on stderr"
	test_fail
fi
# The hint about --btf_encode_force must also appear
if ! grep -q 'btf_encode_force' "$outdir/error_stderr.txt"; then
	error_log "FAIL: expected '--btf_encode_force' hint on stderr"
	test_fail
fi
# BTF section must NOT have been written (the error prevents it)
if readelf -S "$elf_err" 2>/dev/null | grep -q '\.BTF[[:space:]]'; then
	error_log "FAIL: BTF section written despite invalid symbol error"
	test_fail
fi
info_log "Error path (no force): ok"

# --- Test 2: Force path (silent success) ---
# With --btf_encode_force, invalid names are skipped and BTF is emitted.
elf_force="$outdir/force_test.o"
cp "$patched" "$elf_force"
pahole -J --btf_features=global_var --btf_encode_force "$elf_force" \
	2>"$outdir/force_stderr.txt"
# Must succeed: BTF section should be present
if ! readelf -S "$elf_force" 2>/dev/null | grep -q '\.BTF[[:space:]]'; then
	error_log "FAIL: --btf_encode_force did not produce BTF section"
	test_fail
fi
# Without --verbose, the Warning must NOT appear (force path is silent)
if grep -q 'Warning' "$outdir/force_stderr.txt"; then
	error_log "FAIL: Warning printed without --verbose"
	test_fail
fi
info_log "Force path (--btf_encode_force): ok"

# --- Test 3: Force+verbose path (warning emitted) ---
# With both --btf_encode_force and --verbose, the Warning must appear.
elf_verbose="$outdir/verbose_test.o"
cp "$patched" "$elf_verbose"
pahole -J --btf_features=global_var --btf_encode_force --verbose \
	"$elf_verbose" >"$outdir/verbose_stdout.txt" 2>"$outdir/verbose_stderr.txt"
# BTF must still be produced
if ! readelf -S "$elf_verbose" 2>/dev/null | grep -q '\.BTF[[:space:]]'; then
	error_log "FAIL: --btf_encode_force --verbose did not produce BTF"
	test_fail
fi
# The Warning line from dump_invalid_symbol() must appear
if ! grep -q 'PAHOLE: Warning:.*invalid variable name' "$outdir/verbose_stderr.txt"; then
	error_log "FAIL: expected Warning about invalid variable name"
	test_fail
fi
# The warning must mention the symbol name '0badvar'
if ! grep -q "'0badvar'" "$outdir/verbose_stderr.txt"; then
	error_log "FAIL: Warning did not mention the invalid symbol '0badvar'"
	test_fail
fi
info_log "Force+verbose path (Warning printed): ok"

# --- Test 4: Valid variables must still be encoded despite invalid ones ---
# When force is on, the invalid variable is skipped but valid ones
# (normal_var, g) must still appear in the BTF.
if command -v bpftool > /dev/null 2>&1; then
	dump=$(bpftool btf dump file "$elf_verbose" 2>/dev/null)
	if [ -z "$dump" ]; then
		info_log "skip: bpftool cannot parse BTF (too old or missing features)"
		test_skip
	fi
	# Check if bpftool supports VAR entries in output
	# Old bpftool versions (e.g., v4.18.0 on RHEL8) may not dump VAR entries
	if ! echo "$dump" | grep -q '\[.*\] VAR'; then
		info_log "skip: bpftool doesn't support VAR in dump output"
		test_skip
	fi
	# Old bpftool (v4.18.0 on RHEL8) may not display .bss DATASEC sections,
	# so only check .data variables. Variable 'g' is in .bss so skip that check
	# on old bpftool versions.
	if ! echo "$dump" | grep -q "VAR 'normal_var'"; then
		error_log "FAIL: valid 'normal_var' missing from BTF after force"
		test_fail
	fi
	# Check if bpftool displays .bss DATASEC (newer versions only)
	if echo "$dump" | grep -q "DATASEC '\\.bss'"; then
		# New bpftool: check that 'g' (.bss variable) is present
		if ! echo "$dump" | grep -q "VAR 'g'"; then
			error_log "FAIL: valid 'g' missing from BTF after force"
			test_fail
		fi
	else
		info_log "skip: bpftool doesn't display .bss DATASEC, can't verify 'g'"
	fi
	# The invalid variable must NOT be in BTF (it was skipped)
	if echo "$dump" | grep -q "VAR '0badvar'"; then
		error_log "FAIL: invalid '0badvar' should not appear in BTF"
		test_fail
	fi
	info_log "Valid vars encoded, invalid skipped: ok"
else
	info_log "skip: bpftool not available, skipping BTF content check"
fi

test_pass
