#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Test BTF encoding into ELF via pahole -J (btf_encoder__write_elf).
# Covers both first-time .BTF section creation and overwrite of an
# existing .BTF section.
#
# Path 1 (lines ~2049-2098 in btf_encoder.c): No .BTF section exists yet,
#   so pahole writes raw BTF to a temp file and uses objcopy
#   --add-section to inject it into the ELF.
#
# Path 2 (lines ~2038-2048 in btf_encoder.c): A .BTF section already
#   exists from the first encode.  pahole opens the ELF with ELF_C_RDWR,
#   overwrites the Elf_Data buffer in place, and calls elf_update() --
#   no objcopy needed.  This is the "Existing .BTF section found" path.

. "$(dirname "$0")/test_lib.sh"
outdir=$(make_tmpdir)

trap cleanup EXIT

title_log "BTF encoding into ELF via pahole -J (btf_encoder__write_elf)."

CC=${CC:-gcc}
if ! command -v "${CC%% *}" > /dev/null 2>&1; then
	info_log "skip: $CC not available"
	test_skip
fi

src=$(make_tmpsrc)
obj=$(make_tmpobj)

# Simple struct with a global so the CU has type info to encode.
cat > "$src" << 'EOF'
struct elf_test {
	int	a;
	long	b;
};

struct elf_test g;
EOF

if ! $CC -g -c -o "$obj" "$src" 2>/dev/null; then
	error_log "FAIL: compilation failed"
	test_fail
fi

# We need a writable copy -- pahole -J modifies the file in place.
elf_obj="$outdir/write_elf_test.o"
cp "$obj" "$elf_obj"

# --- Path 1: first -J encode, creates .BTF section via objcopy ---

if ! pahole -J "$elf_obj" 2>/dev/null; then
	error_log "FAIL: first pahole -J failed (exit code != 0)"
	test_fail
fi
info_log "first pahole -J: ok (exit code 0)"

# Verify the .BTF section was actually added to the ELF.
if ! readelf -S "$elf_obj" 2>/dev/null | grep -q '\.BTF[[:space:]]'; then
	error_log "FAIL: .BTF section not found after first pahole -J"
	test_fail
fi
info_log ".BTF section present after first encode: ok"

# If bpftool is available, verify the BTF content is valid and contains
# our struct.  Otherwise just rely on the readelf check above.
has_bpftool=0
if command -v bpftool > /dev/null 2>&1; then
	has_bpftool=1
fi

if [ "$has_bpftool" -eq 1 ]; then
	dump1=$(bpftool btf dump file "$elf_obj" 2>/dev/null)
	if [ -z "$dump1" ]; then
		error_log "FAIL: bpftool btf dump produced no output after first -J"
		test_fail
	fi
	if ! echo "$dump1" | grep -q "elf_test"; then
		error_log "FAIL: struct elf_test not found in BTF after first -J"
		test_fail
	fi
	info_log "BTF content valid after first encode (elf_test found): ok"
fi

# --- Path 2: second -J encode, overwrites existing .BTF section ---
# This exercises the "Existing .BTF section found" branch that uses
# elf_update() instead of objcopy.

if ! pahole -J "$elf_obj" 2>/dev/null; then
	error_log "FAIL: second pahole -J failed (exit code != 0)"
	test_fail
fi
info_log "second pahole -J (overwrite existing .BTF): ok (exit code 0)"

# The .BTF section must still be present after the overwrite.
if ! readelf -S "$elf_obj" 2>/dev/null | grep -q '\.BTF[[:space:]]'; then
	error_log "FAIL: .BTF section missing after second pahole -J"
	test_fail
fi
info_log ".BTF section still present after overwrite: ok"

if [ "$has_bpftool" -eq 1 ]; then
	dump2=$(bpftool btf dump file "$elf_obj" 2>/dev/null)
	if [ -z "$dump2" ]; then
		error_log "FAIL: bpftool btf dump produced no output after second -J"
		test_fail
	fi
	if ! echo "$dump2" | grep -q "elf_test"; then
		error_log "FAIL: struct elf_test not found in BTF after second -J"
		test_fail
	fi
	info_log "BTF content valid after overwrite (elf_test found): ok"
fi

test_pass
