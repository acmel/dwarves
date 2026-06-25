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

# the expected true signature: long foo(union big u, int x).
cat > ${clang_true}.c << EOF
union big { long a; char buf[24]; };
__attribute__((noinline)) static long foo(union big u, int dead, int x)
{
        return u.a + x;
}

union big g;
int dead, x;
int main()
{
        return (int)foo(g, dead, x);
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
dwarf=$(pfunct --all $clang_true |grep "foo")

verbose_log "BTF: $btf_optimized  DWARF: $dwarf"

arch=$(uname -m)

if [[ "$arch" == "x86_64" ]]; then
	# On x86_64, clang emits DW_CC_nocall for optimized functions.  The
	# stack-passed aggregate must remain present and 'dead' must be
	# dropped, so a true signature must be produced and it must differ
	# from the DWARF signature.
	if [[ -z "$btf_optimized" ]]; then
		error_log "BTF for foo missing; the stack-passed aggregate was likely rejected"
		test_fail
	fi
	if [[ "$btf_optimized" == "$dwarf" ]]; then
		error_log "BTF and DWARF signatures should be different and they are not: BTF: $btf_optimized ; DWARF $dwarf"
		test_fail
	fi
else
	# On other architectures clang may not emit DW_CC_nocall, so we
	# cannot assert the optimization was detected.
	if [[ -z "$btf_optimized" ]]; then
		info_log "skip: no optimization detected on $arch"
		test_skip
	fi
fi
test_pass
