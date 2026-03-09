#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only

source test_lib.sh

outdir=$(make_tmpdir)

# Comment this out to save test data.
trap cleanup EXIT

title_log "Validation of BTF encoding of true_signatures."

gcc_true="${outdir}/gcc_true"
CC=$(which gcc 2>/dev/null)

if [[ -z "$CC" ]]; then
	info_log "skip: gcc not available"
	test_skip
fi

cat > ${gcc_true}.c << EOF
struct t { int a; };
__attribute__((noinline)) char *tar(struct t *a, struct t *d)
{
	if (a->a == d->a)
		return (char *)10;
	else
		return (char *)0;
}

__attribute__((noinline)) static char * foo(struct t *a, int b, struct t *d)
{
	return tar(a, d);
}

__attribute__((noinline)) char *bar(struct t *a, struct t *d)
{
	return foo(a, 1, d);
}

struct t p1, p2;
int main()
{
	return !!bar(&p1, &p2);
}
EOF

CFLAGS="$CFLAGS -g -O2"
${CC} ${CFLAGS} -o $gcc_true ${gcc_true}.c
if [[ $? -ne 0 ]]; then
	error_log "Could not compile ${gcc_true}.c"
	test_fail
fi
LLVM_OBJCOPY=objcopy pahole -J --btf_features=+true_signature $gcc_true
if [[ $? -ne 0 ]]; then
	error_log "Could not encode BTF for $gcc_true"
	test_fail
fi

btf_optimized=$(pfunct --all --format_path=btf $gcc_true |grep "foo\.")
if [[ -z "$btf_optimized" ]]; then
	info_log "skip: no optimizations applied."
	test_skip
fi
# Convert foo.[constprop|isra].0 to foo to allow comparison.
btf_cmp="$(echo $btf_optimized \
	awk '/foo/ {sub(/\.constprop.0/,""); sub(/\.isra.0/,""); print $0 }')"
dwarf=$(pfunct --all $gcc_true |grep "foo")

verbose_log "BTF: $btf_optimized  DWARF: $dwarf"

if [[ "$btf_cmp" == "$dwarf" ]]; then
	error_log "BTF and DWARF signatures should be different and they are not: BTF: $btf_optimized ; DWARF $dwarf"
	test_fail
fi
test_pass
