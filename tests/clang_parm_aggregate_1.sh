#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only

source test_lib.sh

outdir=$(make_tmpdir)

# Comment this out to save test data.
trap cleanup EXIT

title_log "Validation of BTF encoding of true_signatures."

clang_true="${outdir}/clang_true"
CC=$(which clang 2>/dev/null)

if [[ -z "$CC" ]]; then
	info_log "skip: clang not available"
	test_skip
fi

cat > ${clang_true}.c << EOF
struct t { long f1; long f2; };
__attribute__((noinline)) static long foo(struct t a, struct t b, int i)
{
        return a.f1 + b.f1 + b.f2 + i;
}

struct t p1, p2;
int i;
int main()
{
        return (int)foo(p1, p2, i);
}
EOF

CFLAGS="$CFLAGS -g -O2"
${CC} ${CFLAGS} -o $clang_true ${clang_true}.c
if [[ $? -ne 0 ]]; then
	error_log "Could not compile ${clang_true}.c"
	test_fail
fi
LLVM_OBJCOPY=objcopy pahole -J --btf_features=+true_signature $clang_true
if [[ $? -ne 0 ]]; then
	error_log "Could not encode BTF for $clang_true"
	test_fail
fi

btf_optimized=$(pfunct --all --format_path=btf $clang_true |grep "foo")
if [[ -z "$btf_optimized" ]]; then
	info_log "skip: no optimizations applied."
	test_skip
fi

btf_cmp=$btf_optimized
dwarf=$(pfunct --all $clang_true |grep "foo")

verbose_log "BTF: $btf_optimized  DWARF: $dwarf"

arch=$(uname -m)

if [[ "$arch" == "x86_64" ]]; then
	# On x86_64, clang emits DW_CC_nocall for optimized functions,
	# so pahole should detect the optimization and produce a
	# different BTF signature.
	if [[ "$btf_cmp" == "$dwarf" ]]; then
		error_log "BTF and DWARF signatures should be different and they are not: BTF: $btf_optimized ; DWARF $dwarf"
		test_fail
	fi
elif [[ "$arch" == "aarch64" ]]; then
	# On arm64, clang does not emit DW_CC_nocall, so pahole cannot
	# detect the optimization. BTF and DWARF signatures are expected
	# to be the same.
	if [[ "$btf_cmp" != "$dwarf" ]]; then
		error_log "On arm64, BTF and DWARF signatures should be the same but they are not: BTF: $btf_optimized ; DWARF $dwarf"
		test_fail
	fi
else
	# On other architectures, skip if we cannot determine the
	# expected behavior.
	if [[ "$btf_cmp" == "$dwarf" ]]; then
		info_log "skip: no optimization detected on $arch"
		test_skip
	fi
fi
test_pass
