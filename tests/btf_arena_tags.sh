#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Test BTF arena type tag encoding for kfuncs.
# Exercises btf__add_bpf_arena_type_tags, btf__tag_bpf_arena_arg,
# and btf__tag_bpf_arena_ptr in btf_encoder.c.

. "$(dirname "$0")/test_lib.sh"
outdir=$(make_tmpdir)

trap cleanup EXIT

title_log "BTF arena type tag encoding for kfuncs."

CC=${CC:-gcc}
if ! command -v "${CC%% *}" > /dev/null 2>&1; then
	info_log "skip: $CC not available"
	test_skip
fi

if ! command -v bpftool > /dev/null 2>&1; then
	info_log "skip: bpftool not available"
	test_skip
fi

if ! command -v readelf > /dev/null 2>&1; then
	info_log "skip: readelf not available"
	test_skip
fi

# Arena encoding requires libbpf >= 1.6 (btf__add_type_attr);
# skip gracefully on systems where pahole was built without it.
if ! pahole --supported_btf_features 2>/dev/null | tr ',' '\n' | grep -qx 'attributes'; then
	info_log "skip: pahole lacks 'attributes' BTF feature (needs libbpf >= 1.6)"
	test_skip
fi

# Arena TYPE_TAG generation also requires compiler btf_type_tag support
$CC -x c -E -P - <<'EOF' 2>/dev/null | grep -qx 1 || {
#ifndef __has_attribute
#define __has_attribute(x) 0
#endif
#if __has_attribute(btf_type_tag)
1
#else
0
#endif
EOF
	info_log "skip: compiler doesn't support btf_type_tag attribute"
	test_skip
}

src=$(make_tmpsrc)
obj=$(make_tmpobj)

# Two functions mimicking kernel arena kfuncs, plus a .BTF_ids section
# that replicates the kernel's BTF_KFUNCS_START/BTF_ID_FLAGS layout.
#
# bpf_arena_alloc: KF_ARENA_RET  (0x2000) — return ptr gets TYPE_TAG
# bpf_arena_free:  KF_ARENA_ARG1 (0x4000) | KF_ARENA_ARG2 (0x8000)
#                  — first two pointer args get TYPE_TAG
cat > "$src" << 'EOF'
void *bpf_arena_alloc(void *arena, int size) { return (void *)0; }
void bpf_arena_free(void *arena, void *ptr, int size) { }

asm(
".pushsection \".BTF_ids\",\"a\";                        \n"
".local __BTF_ID__set8__arena_kfuncs;                     \n"
"__BTF_ID__set8__arena_kfuncs:                            \n"
".long 0;                                                 \n"
".long 1;                                                 \n"

".local __BTF_ID__func__bpf_arena_alloc__1;               \n"
"__BTF_ID__func__bpf_arena_alloc__1:                      \n"
".long 0;                                                 \n"
".long 0x2000;                                            \n"

".local __BTF_ID__func__bpf_arena_free__2;                \n"
"__BTF_ID__func__bpf_arena_free__2:                       \n"
".long 0;                                                 \n"
".long 0xc000;                                            \n"

".size __BTF_ID__set8__arena_kfuncs, . - __BTF_ID__set8__arena_kfuncs \n"
".popsection;                                             \n"
);

void *(*alloc_ptr)(void *, int) = bpf_arena_alloc;
void (*free_ptr)(void *, void *, int) = bpf_arena_free;
EOF

if ! $CC -g -c -o "$obj" "$src" 2>/dev/null; then
	error_log "FAIL: compilation failed"
	test_fail
fi

# Verify .BTF_ids section was created
if ! readelf -S "$obj" 2>/dev/null | grep -q '\.BTF_ids'; then
	error_log "FAIL: .BTF_ids section not found in object"
	test_fail
fi
info_log ".BTF_ids section: ok"

btf="$outdir/arena.btf"

# Encode with kfunc tagging and arena attributes enabled
if ! pahole --btf_features=default,attributes --btf_encode_detached="$btf" "$obj" 2>/dev/null; then
	error_log "FAIL: pahole BTF encoding failed"
	test_fail
fi

dump=$(bpftool btf dump file "$btf" 2>/dev/null)
if [ -z "$dump" ]; then
	# bpftool returned no output - likely doesn't support newer BTF features
	# (TYPE_TAG, DECL_TAG, or arena-specific attributes)
	info_log "skip: bpftool doesn't support BTF arena features (TYPE_TAG/DECL_TAG)"
	test_skip
fi

# TYPE_TAG 'address_space(1)' must be present — this is the arena attribute
if ! echo "$dump" | grep -q "TYPE_TAG 'address_space(1)'"; then
	error_log "FAIL: TYPE_TAG 'address_space(1)' not found in BTF"
	test_fail
fi
info_log "TYPE_TAG 'address_space(1)': ok"

# Both functions must be tagged as bpf_kfunc via DECL_TAG
if ! echo "$dump" | grep -q "FUNC 'bpf_arena_alloc'"; then
	error_log "FAIL: FUNC 'bpf_arena_alloc' not found in BTF"
	test_fail
fi

if ! echo "$dump" | grep -q "FUNC 'bpf_arena_free'"; then
	error_log "FAIL: FUNC 'bpf_arena_free' not found in BTF"
	test_fail
fi

# Each kfunc should have a DECL_TAG 'bpf_kfunc'
nr_kfunc_tags=$(echo "$dump" | grep -c "DECL_TAG 'bpf_kfunc'")
if [ "$nr_kfunc_tags" -lt 2 ]; then
	error_log "FAIL: expected at least 2 DECL_TAG 'bpf_kfunc', got $nr_kfunc_tags"
	test_fail
fi
info_log "DECL_TAG 'bpf_kfunc' ($nr_kfunc_tags tags): ok"

# The return type of bpf_arena_alloc should chain through the TYPE_TAG.
# Its FUNC_PROTO should have a ret_type_id pointing to a PTR that
# references the TYPE_TAG, not a plain PTR to void.
alloc_func_line=$(echo "$dump" | grep "FUNC 'bpf_arena_alloc'")
alloc_type_id=$(echo "$alloc_func_line" | sed 's/.*type_id=\([0-9]*\).*/\1/')
alloc_proto=$(echo "$dump" | grep "^\[$alloc_type_id\]")
alloc_ret_id=$(echo "$alloc_proto" | sed 's/.*ret_type_id=\([0-9]*\).*/\1/')
alloc_ret_type=$(echo "$dump" | grep "^\[$alloc_ret_id\]")
# The return should be a PTR pointing to the TYPE_TAG, not plain void
if ! echo "$alloc_ret_type" | grep -q "PTR"; then
	error_log "FAIL: bpf_arena_alloc return type is not a PTR (got: $alloc_ret_type)"
	test_fail
fi
# Follow one more level — the PTR should point to TYPE_TAG
ret_target_id=$(echo "$alloc_ret_type" | sed 's/.*type_id=\([0-9]*\).*/\1/')
ret_target=$(echo "$dump" | grep "^\[$ret_target_id\]")
if ! echo "$ret_target" | grep -q "TYPE_TAG 'address_space(1)'"; then
	error_log "FAIL: bpf_arena_alloc return PTR does not point to TYPE_TAG (got: $ret_target)"
	test_fail
fi
info_log "bpf_arena_alloc arena return type: ok"

# Verify bpf_arena_free arguments got TYPE_TAG annotations.
# KF_ARENA_ARG1 | KF_ARENA_ARG2 means the first two pointer params
# (arena and ptr) should each point through TYPE_TAG 'address_space(1)'.
free_func_line=$(echo "$dump" | grep "FUNC 'bpf_arena_free'")
free_type_id=$(echo "$free_func_line" | sed 's/.*type_id=\([0-9]*\).*/\1/')

# bpftool prints FUNC_PROTO params on indented lines following the header;
# extract 'arena' and 'ptr' param type_ids from those continuation lines.
free_proto_line=$(echo "$dump" | grep -n "^\[$free_type_id\]" | head -1 | cut -d: -f1)
arena_param_id=$(echo "$dump" | sed -n "$((free_proto_line + 1))p" | sed "s/.*type_id=\([0-9]*\).*/\1/")
ptr_param_id=$(echo "$dump" | sed -n "$((free_proto_line + 2))p" | sed "s/.*type_id=\([0-9]*\).*/\1/")

# Each param should be a PTR pointing to TYPE_TAG 'address_space(1)'
arena_tagged=0
for pid in $arena_param_id $ptr_param_id; do
	param_type=$(echo "$dump" | grep "^\[$pid\]")
	if echo "$param_type" | grep -q "PTR"; then
		ptr_target_id=$(echo "$param_type" | sed 's/.*type_id=\([0-9]*\).*/\1/')
		ptr_target=$(echo "$dump" | grep "^\[$ptr_target_id\]")
		if echo "$ptr_target" | grep -q "TYPE_TAG 'address_space(1)'"; then
			arena_tagged=$((arena_tagged + 1))
		fi
	fi
done

if [ "$arena_tagged" -lt 2 ]; then
	error_log "FAIL: bpf_arena_free expected 2 arena-tagged params, got $arena_tagged"
	test_fail
fi
info_log "bpf_arena_free arena arg tagging ($arena_tagged params): ok"

test_pass
