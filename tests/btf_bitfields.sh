#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Test BTF bitfield encoding and loading round-trip.
#
# class__fixup_btf_bitfields() in btf_loader.c reconstructs per-member
# byte/bit offsets from BTF data (which stores only the bit offset and
# bitfield size).  This path was previously untested: bitfield_layout.sh
# covers only DWARF display.
#
# Each case encodes DWARF → BTF in-place (-J), then reloads via
# pahole -F btf -C and verifies the displayed offsets and holes match
# what pahole computed from DWARF.

. "$(dirname "$0")/test_lib.sh"

outdir=$(make_tmpdir)

trap cleanup EXIT

title_log "BTF bitfield encoding and loading round-trip."

CC=${CC:-gcc}
if ! command -v "${CC%% *}" > /dev/null 2>&1; then
	info_log "skip: $CC not available"
	test_skip
fi

src=$(make_tmpsrc)
obj=$(make_tmpobj)

cat > "$src" << 'EOF'
/* Case 1: four bitfields packed into one 32-bit word.
 * class__fixup_btf_bitfields must recover byte_offset=0 and
 * bitfield_offset 0,1,2,3 from the raw BTF bit_offset values. */
struct flags {
	unsigned int readable  : 1;
	unsigned int writable  : 1;
	unsigned int executable: 1;
	unsigned int reserved  : 29;
};

/* Case 2: regular fields flanking bitfields, with a bit hole.
 * pahole must detect the 28-bit hole between the bitfields and
 * the next int, even after reconstructing offsets from BTF. */
struct mixed {
	int          id;
	unsigned int active : 1;
	unsigned int mode   : 3;
	int          value;
};

/* Case 3: bitfield struct with size matching a single byte.
 * Ensures byte_size=1 base types are handled (not just int-sized). */
struct byte_bits {
	unsigned char hi : 4;
	unsigned char lo : 4;
};

struct flags     g1;
struct mixed     g2;
struct byte_bits g3;
EOF

if ! $CC -g -c -o "$obj" "$src" 2>/dev/null; then
	error_log "FAIL: compilation failed"
	test_fail
fi

# Encode BTF in-place; pahole -F btf will then load it back
if ! pahole -J "$obj" 2>/dev/null; then
	error_log "FAIL: pahole -J (in-place BTF encoding) failed"
	test_fail
fi

# --- Case 1: struct flags ---

btf_flags=$(pahole -F btf -C flags "$obj" 2>/dev/null)
if [ -z "$btf_flags" ]; then
	error_log "FAIL: pahole -F btf -C flags produced no output"
	test_fail
fi

# All four bitfields must survive with correct bit positions
# Format: <offset>: <bit_offset>  <type_size>
for member_pat in "readable:1.*0: 0" "writable:1.*0: 1" "executable:1.*0: 2" "reserved:29.*0: 3"; do
	if ! echo "$btf_flags" | grep -qE "$member_pat"; then
		error_log "FAIL: struct flags — member pattern '$member_pat' not found in BTF output"
		test_fail
	fi
done
# Struct size must be preserved
if ! echo "$btf_flags" | grep -q "size: 4"; then
	error_log "FAIL: struct flags size=4 not found after BTF round-trip"
	test_fail
fi
info_log "struct flags bitfields (4 members in one word): ok"

# --- Case 2: struct mixed (bitfields + hole) ---

btf_mixed=$(pahole -F btf -C mixed "$obj" 2>/dev/null)
if [ -z "$btf_mixed" ]; then
	error_log "FAIL: pahole -F btf -C mixed produced no output"
	test_fail
fi

# int id at offset 0, bitfields starting at offset 4
if ! echo "$btf_mixed" | grep -qE "id.*0 +4"; then
	error_log "FAIL: struct mixed — int id at offset 0 not found"
	test_fail
fi
if ! echo "$btf_mixed" | grep -qE "active:1.*4: 0"; then
	error_log "FAIL: struct mixed — active:1 at 4:0 not found"
	test_fail
fi
if ! echo "$btf_mixed" | grep -qE "mode:3.*4: 1"; then
	error_log "FAIL: struct mixed — mode:3 at 4:1 not found"
	test_fail
fi

# The 28-bit hole between the bitfields and int value must be detected
if ! echo "$btf_mixed" | grep -q "28 bits hole"; then
	error_log "FAIL: struct mixed — 28-bit hole not detected after BTF round-trip"
	test_fail
fi
if ! echo "$btf_mixed" | grep -q "size: 12"; then
	error_log "FAIL: struct mixed size=12 not found after BTF round-trip"
	test_fail
fi
info_log "struct mixed bitfields + hole detection: ok"

# --- Case 3: struct byte_bits (char-sized bitfields) ---

btf_byte=$(pahole -F btf -C byte_bits "$obj" 2>/dev/null)
if [ -z "$btf_byte" ]; then
	error_log "FAIL: pahole -F btf -C byte_bits produced no output"
	test_fail
fi
if ! echo "$btf_byte" | grep -qE "hi:4.*0: 0"; then
	error_log "FAIL: struct byte_bits — hi:4 at 0:0 not found"
	test_fail
fi
if ! echo "$btf_byte" | grep -qE "lo:4.*0: 4"; then
	error_log "FAIL: struct byte_bits — lo:4 at 0:4 not found"
	test_fail
fi
if ! echo "$btf_byte" | grep -q "size: 1"; then
	error_log "FAIL: struct byte_bits size=1 not found after BTF round-trip"
	test_fail
fi
info_log "struct byte_bits (char-sized bitfields): ok"

test_pass
