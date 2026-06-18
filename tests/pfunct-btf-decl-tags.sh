#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only

# Check that pfunct can print btf_decl_tags read from BTF

source test_lib.sh

outdir=$(make_tmpdir)

# Comment this out to save test data.
trap cleanup EXIT

title_log "Check that pfunct can print btf_decl_tags read from BTF."

# gcc 16+ supports decl tags via DW_TAG_GNU_annotation (gcc commit ac7027f180b).

GCC=${GCC:-gcc}
CLANG=${CLANG:-clang}

use_gcc=0
if command -v $GCC > /dev/null; then
	gcc_ver=$($GCC -dumpversion 2>/dev/null | cut -d. -f1)
	if [ "$gcc_ver" -ge 16 ] 2>/dev/null; then
		use_gcc=1
	fi
fi

use_clang=0
if command -v $CLANG > /dev/null; then
	use_clang=1
fi

if [ "$use_gcc" -eq 0 ] && [ "$use_clang" -eq 0 ]; then
	error_log "Need gcc >= 16 or clang for test $0"
	test_fail
fi

src=$(cat <<EOF
#define __tag(x) __attribute__((btf_decl_tag(#x)))

__tag(a) __tag(b) __tag(c) void foo(void) {}
__tag(a) __tag(b)          void bar(void) {}
__tag(a)                   void buz(void) {}
void qux(int __tag(param_a) arg) {}

EOF
)

# tags order is not guaranteed
sort_tags=$(cat <<EOF
{
delete tags_arr;
if (match(\$0,/^(.*) (void .*)/,tags_and_proto)) {
	tags  = tags_and_proto[1];
	proto = tags_and_proto[2];
	split(tags, tags_arr ,/ /);
	asort(tags_arr);
	for (t in tags_arr) printf "%s ", tags_arr[t];
	print proto;
} else {
	print \$0;
}
}
EOF
)

expected=$(cat <<EOF
a b c void foo(void);
a b void bar(void);
a void buz(void);
void qux(param_a int arg);
EOF
)

run_test() {
	local compiler=$1
	local tmpobj=$2

	info_log "Testing with $compiler"
	out=$(pfunct -P -F btf $tmpobj | awk "$sort_tags" | sort)
	d=$(diff -u <(echo "$expected") <(echo "$out"))

	if [[ "$d" == "" ]]; then
		info_log "  passed"
		return 0
	else
		error_log "pfunct output does not match expected ($compiler):"
		info_log "$d"
		info_log
		info_log "Complete output:"
		info_log "$out"
		return 1
	fi
}

failed=0

if [ "$use_gcc" -eq 1 ]; then
	tmpobj=$(make_tmpobj)
	echo "$src" | $GCC -c -g -x c -o $tmpobj - 2>/dev/null
	pahole -J $tmpobj 2>/dev/null
	run_test "$GCC (version $gcc_ver)" "$tmpobj" || failed=1
fi

if [ "$use_clang" -eq 1 ]; then
	tmpobj=$(make_tmpobj)
	echo "$src" | $CLANG -c -g -x c -o $tmpobj -
	pahole -J $tmpobj 2>/dev/null
	run_test "$CLANG" "$tmpobj" || failed=1
fi

if [ "$failed" -eq 0 ]; then
	test_pass
else
	test_fail
fi
