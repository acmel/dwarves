#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Test BTF_KIND_FWD encoding and loading round-trip.
#
# When a struct or union is only forward-declared (DW_AT_declaration in DWARF),
# the encoder calls btf_encoder__add_ref_type(BTF_KIND_FWD) with kind_flag=false
# for structs and kind_flag=true for unions.  The loader's
# create_new_forward_decl() reconstructs a class with declaration=1 so that
# pahole knows the type is incomplete.
#
# Tests:
#  1. struct FWD — fwd_kind=struct in BTF dump
#  2. union FWD — fwd_kind=union in BTF dump
#  3. pointer-to-FWD — the canonical opaque-pointer idiom
#  4. round-trip — pahole -F btf output matches DWARF output for the
#     containing struct (member types rendered as "struct foo *" / "union bar *")
#  5. forward declarations are not emitted as full types by pahole -C

. "$(dirname "$0")/test_lib.sh"
outdir=$(make_tmpdir)

trap cleanup EXIT

title_log "BTF_KIND_FWD encoding and loading round-trip."

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

# struct opaque / union variant are forward-declared only.
# struct user contains pointers to both — the most common opaque-pointer idiom.
cat > "$src" << 'EOF'
struct opaque;
union variant;

struct user {
	struct opaque *ptr_s;
	union variant *ptr_u;
};

struct user u;
EOF

if ! $CC -g -c -o "$obj" "$src" 2>/dev/null; then
	error_log "FAIL: compilation failed"
	test_fail
fi

# Encode BTF in-place; the detached dump is used for precise BTF inspection
btf="$outdir/fwd.btf"
if ! pahole -J "$obj" 2>/dev/null; then
	error_log "FAIL: pahole -J (in-place BTF encoding) failed"
	test_fail
fi
pahole --btf_encode_detached="$btf" "$obj" 2>/dev/null

dump=$(bpftool btf dump file "$btf" 2>/dev/null)
if [ -z "$dump" ]; then
	error_log "FAIL: bpftool btf dump produced no output"
	test_fail
fi

# --- struct forward declaration ---

if ! echo "$dump" | grep -q "FWD 'opaque' fwd_kind=struct"; then
	error_log "FAIL: FWD 'opaque' fwd_kind=struct not found in BTF"
	test_fail
fi
info_log "FWD 'opaque' fwd_kind=struct: ok"

# --- union forward declaration ---

if ! echo "$dump" | grep -q "FWD 'variant' fwd_kind=union"; then
	error_log "FAIL: FWD 'variant' fwd_kind=union not found in BTF"
	test_fail
fi
info_log "FWD 'variant' fwd_kind=union: ok"

# --- pointers to FWD types must be present ---

# The PTR entry for struct opaque must reference the FWD entry by type_id
opaque_id=$(echo "$dump" | grep "FWD 'opaque'" | sed 's/\[\([0-9]*\)\].*/\1/')
if [ -z "$opaque_id" ]; then
	error_log "FAIL: could not extract BTF id for FWD 'opaque'"
	test_fail
fi
if ! echo "$dump" | grep -qE "PTR.*type_id=$opaque_id"; then
	error_log "FAIL: no PTR referencing FWD 'opaque' (type_id=$opaque_id)"
	test_fail
fi
info_log "PTR → FWD 'opaque': ok"

variant_id=$(echo "$dump" | grep "FWD 'variant'" | sed 's/\[\([0-9]*\)\].*/\1/')
if [ -z "$variant_id" ]; then
	error_log "FAIL: could not extract BTF id for FWD 'variant'"
	test_fail
fi
if ! echo "$dump" | grep -qE "PTR.*type_id=$variant_id"; then
	error_log "FAIL: no PTR referencing FWD 'variant' (type_id=$variant_id)"
	test_fail
fi
info_log "PTR → FWD 'variant': ok"

# --- round-trip: BTF output must preserve struct user member types ---

btf_out=$(pahole -F btf -C user "$obj" 2>/dev/null)

if [ -z "$btf_out" ]; then
	error_log "FAIL: pahole -F btf -C user produced no output"
	test_fail
fi

if ! echo "$btf_out" | grep -q "struct opaque \*.*ptr_s"; then
	error_log "FAIL: round-trip: 'struct opaque * ptr_s' not found in BTF output"
	test_fail
fi
if ! echo "$btf_out" | grep -q "union variant \*.*ptr_u"; then
	error_log "FAIL: round-trip: 'union variant * ptr_u' not found in BTF output"
	test_fail
fi
info_log "round-trip struct user (opaque pointer members): ok"

# Size must be preserved across encode→load.
# struct user has two pointers; size depends on pointer width.
# Use -E so this works for cross-compilers too (no need to run the binary).
ptr_bytes=$(echo | $CC -x c -E -dM - 2>/dev/null | awk '/__SIZEOF_POINTER__/{print $3}')
ptr_bytes=$(( ${ptr_bytes:-8} ))
expected_size=$(( 2 * ptr_bytes ))
if ! echo "$btf_out" | grep -q "size: ${expected_size}"; then
	error_log "FAIL: struct user size=${expected_size} not preserved after BTF round-trip"
	test_fail
fi
info_log "struct user size=${expected_size} preserved: ok"

# --- forward declarations must not appear as full type definitions ---
# pahole -C on a forward-declared name should produce no output

fwd_lookup=$(pahole -F btf -C opaque "$obj" 2>/dev/null)
if [ -n "$fwd_lookup" ]; then
	error_log "FAIL: pahole -F btf -C opaque should be empty for a FWD type, got: $fwd_lookup"
	test_fail
fi
info_log "FWD type not emitted as full definition: ok"

test_pass
