#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only

source test_lib.sh

outdir=$(make_tmpdir)

# Comment this out to save test data.
trap cleanup EXIT

title_log "Validation of GCC optimized parameters in default BTF."

CC=${CC:-gcc}
if ! command -v "$CC" >/dev/null 2>&1; then
	info_log "skip: gcc not available"
	test_skip
fi

src=${outdir}/gcc_optimized_default.c
obj=${outdir}/gcc_optimized_default
btf=${outdir}/gcc_optimized_default.btf
log=${outdir}/gcc_optimized_default.log

cat > "$src" << EOF
__attribute__((noinline)) int bar(int a, int b)
{
	return a + 1;
}

__attribute__((noinline)) static int foo(int a, int b, int c)
{
	return a * b - a - b;
}

int a, b, c;
int main(void)
{
	return bar(a, c) + foo(a, b, c);
}
EOF

"$CC" -g -O2 -o "$obj" "$src"
if [[ $? -ne 0 ]]; then
	error_log "Could not compile $src"
	test_fail
fi

LLVM_OBJCOPY=objcopy pahole -J --btf_features=default --btf_encode_detached="$btf" --verbose "$obj" > "$log"
if [[ $? -ne 0 ]]; then
	error_log "Could not encode BTF for $obj"
	test_fail
fi

if ! grep -q "foo : skipping BTF encoding of function due to optimized parameters" "$log"; then
	error_log "foo() should be skipped for default BTF due to optimized parameters"
	test_fail
fi

if pfunct --all --format_path=btf "$btf" | grep -Fq "int foo("; then
	error_log "foo() should be absent from default BTF"
	test_fail
fi

if ! pfunct --all --format_path=btf "$btf" | grep -Fq "int bar(int a, int b);"; then
	error_log "bar() is missing from default BTF"
	test_fail
fi

test_pass
