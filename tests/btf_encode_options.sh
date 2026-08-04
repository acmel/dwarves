#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Test BTF encoding options that lack coverage:
#   -J (btf_encode into ELF), --btf_encode_force,
#   --skip_encoding_btf_vars, --skip_encoding_btf_enum64,
#   --skip_encoding_btf_decl_tag, --skip_encoding_btf_type_tag,
#   --skip_emitting_atomic_typedefs,
#   --btf_gen_all, --btf_gen_floats,
#   --reproducible_build, --btf_features_strict

. "$(dirname "$0")/test_lib.sh"
outdir=$(make_tmpdir)

trap cleanup EXIT

title_log "BTF encoding options."

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

cat > "$src" << 'EOF'
int global_var = 42;

struct simple {
	int	a;
	float	b;
	double	c;
};

enum small_enum { SE_A = 1, SE_B = 2 };

struct simple g1;
enum small_enum g2;
EOF

if ! $CC -g -c -o "$obj" "$src" 2>/dev/null; then
	error_log "FAIL: compilation failed"
	test_fail
fi

# We need a writable copy of the object for -J (writes BTF into ELF)
elf_obj="$outdir/encode_test.o"
cp "$obj" "$elf_obj"

# --- -J (btf_encode into ELF) ---
if ! pahole -J "$elf_obj" 2>/dev/null; then
	error_log "FAIL: pahole -J failed"
	test_fail
fi
# Verify BTF section was added
dump=$(bpftool btf dump file "$elf_obj" 2>/dev/null)
if [ -z "$dump" ]; then
	error_log "FAIL: -J did not produce BTF in ELF"
	test_fail
fi
if ! echo "$dump" | grep -q "simple"; then
	error_log "FAIL: -J BTF missing struct simple"
	test_fail
fi
info_log "-J (btf_encode into ELF): ok"

# --- --btf_encode_force ---
# Should succeed even on objects that might have odd symbols
cp "$obj" "$elf_obj"
if ! pahole -J --btf_encode_force "$elf_obj" 2>/dev/null; then
	error_log "FAIL: --btf_encode_force failed"
	test_fail
fi
info_log "--btf_encode_force: ok"

# --- --skip_encoding_btf_vars ---
btf_novars="$outdir/novars.btf"
if ! pahole --btf_encode_detached="$btf_novars" --skip_encoding_btf_vars "$obj" 2>/dev/null; then
	error_log "FAIL: --skip_encoding_btf_vars failed"
	test_fail
fi
dump_novars=$(bpftool btf dump file "$btf_novars" 2>/dev/null)
# global_var should NOT appear as a VAR
if echo "$dump_novars" | grep -q "VAR 'global_var'"; then
	error_log "FAIL: --skip_encoding_btf_vars did not skip global_var"
	test_fail
fi
info_log "--skip_encoding_btf_vars: ok"

# --- --skip_encoding_btf_enum64 ---
btf_noenum64="$outdir/noenum64.btf"
if ! pahole --btf_encode_detached="$btf_noenum64" --skip_encoding_btf_enum64 "$obj" 2>/dev/null; then
	error_log "FAIL: --skip_encoding_btf_enum64 failed"
	test_fail
fi
info_log "--skip_encoding_btf_enum64: ok"

# --- --reproducible_build ---
btf_repro1="$outdir/repro1.btf"
btf_repro2="$outdir/repro2.btf"
pahole --btf_encode_detached="$btf_repro1" --reproducible_build "$obj" 2>/dev/null
if ! pahole --btf_encode_detached="$btf_repro2" --reproducible_build "$obj" 2>/dev/null; then
	error_log "FAIL: --reproducible_build failed"
	test_fail
fi
# Two runs on the same input must produce identical output
if ! cmp -s "$btf_repro1" "$btf_repro2"; then
	error_log "FAIL: --reproducible_build produced different output on same input"
	test_fail
fi
info_log "--reproducible_build: ok"

# --- --btf_gen_all ---
btf_all="$outdir/genall.btf"
if ! pahole --btf_encode_detached="$btf_all" --btf_gen_all "$obj" 2>/dev/null; then
	error_log "FAIL: --btf_gen_all failed"
	test_fail
fi
info_log "--btf_gen_all: ok"

# --- --btf_gen_floats ---
btf_floats="$outdir/floats.btf"
if ! pahole --btf_encode_detached="$btf_floats" --btf_gen_floats "$obj" 2>/dev/null; then
	error_log "FAIL: --btf_gen_floats failed"
	test_fail
fi
dump_floats=$(bpftool btf dump file "$btf_floats" 2>/dev/null)
if [ -z "$dump_floats" ]; then
	# Old bpftool (< v5.13) doesn't support BTF_KIND_FLOAT
	info_log "--btf_gen_floats: skipped (bpftool doesn't support FLOAT kind)"
elif ! echo "$dump_floats" | grep -q "FLOAT"; then
	error_log "FAIL: --btf_gen_floats did not produce FLOAT types"
	test_fail
else
	info_log "--btf_gen_floats: ok"
fi

# --- --skip_encoding_btf_decl_tag ---
# The source lacks decl_tag attributes so this exercises the option
# parsing and flag-setting path; the actual filtering is tested in
# btf_arena_tags.sh which has __attribute__((btf_decl_tag)).
btf_nodecl="$outdir/nodecltag.btf"
if ! pahole --btf_encode_detached="$btf_nodecl" --skip_encoding_btf_decl_tag "$obj" 2>/dev/null; then
	error_log "FAIL: --skip_encoding_btf_decl_tag failed"
	test_fail
fi
info_log "--skip_encoding_btf_decl_tag: ok"

# --- --skip_encoding_btf_type_tag ---
# Same as above: exercises option parsing; actual type_tag filtering is
# tested in btf_type_tag_order.sh which uses __attribute__((btf_type_tag)).
btf_notype="$outdir/notypetag.btf"
if ! pahole --btf_encode_detached="$btf_notype" --skip_encoding_btf_type_tag "$obj" 2>/dev/null; then
	error_log "FAIL: --skip_encoding_btf_type_tag failed"
	test_fail
fi
info_log "--skip_encoding_btf_type_tag: ok"

# --- --skip_emitting_atomic_typedefs ---
# Exercises option parsing; actual atomic typedef filtering is tested
# in atomic_types.sh which uses _Atomic types.
btf_noatomic="$outdir/noatomic.btf"
if ! pahole --btf_encode_detached="$btf_noatomic" --skip_emitting_atomic_typedefs "$obj" 2>/dev/null; then
	error_log "FAIL: --skip_emitting_atomic_typedefs failed"
	test_fail
fi
info_log "--skip_emitting_atomic_typedefs: ok"

# --- --btf_features_strict ---
# Using a known-good feature set should succeed
btf_strict="$outdir/strict.btf"
if ! pahole --btf_features_strict=default --btf_encode_detached="$btf_strict" "$obj" 2>/dev/null; then
	error_log "FAIL: --btf_features_strict=default failed"
	test_fail
fi
info_log "--btf_features_strict=default: ok"

# Using an unknown feature should fail (strict mode rejects unknowns)
if pahole --btf_features_strict=nonexistent_feature --btf_encode_detached=/dev/null "$obj" 2>/dev/null; then
	error_log "FAIL: --btf_features_strict=nonexistent_feature should have failed"
	test_fail
fi
info_log "--btf_features_strict rejects unknown: ok"

test_pass
