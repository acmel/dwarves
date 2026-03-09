#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only

# Check that pfunct can print btf_decl_tags read from BTF

source test_lib.sh

outdir=$(make_tmpdir)
tmpobj=$(make_tmpobj)

# Comment this out to save test data.
trap cleanup EXIT

title_log "Check that pfunct can print btf_decl_tags read from BTF."

# gcc now also supports decl tags as of gcc commit 43dcea48b8c,
# in upstream version 16.
# UPTODO: add a check here for that.

CLANG=${CLANG:-clang}
if ! command -v $CLANG > /dev/null; then
	error_log "Need clang for test $0"
	test_fail
fi

(cat <<EOF
#define __tag(x) __attribute__((btf_decl_tag(#x)))

__tag(a) __tag(b) __tag(c) void foo(void) {}
__tag(a) __tag(b)          void bar(void) {}
__tag(a)                   void buz(void) {}

EOF
) | $CLANG --target=bpf -c -g -x c -o $tmpobj -

# tags order is not guaranteed
sort_tags=$(cat <<EOF
{
match(\$0,/^(.*) (void .*)/,tags_and_proto);
tags  = tags_and_proto[1];
proto = tags_and_proto[2];
split(tags, tags_arr ,/ /);
asort(tags_arr);
for (t in tags_arr) printf "%s ", tags_arr[t];
print proto;
}
EOF
)

expected=$(cat <<EOF
a b c void foo(void);
a b void bar(void);
a void buz(void);
EOF
)

out=$(pfunct -P -F btf $tmpobj | awk "$sort_tags" | sort)
d=$(diff -u <(echo "$expected") <(echo "$out"))

if [[ "$d" == "" ]]; then
	test_pass
else
	error_log "pfunct output does not match expected:"
	info_log "$d"
	info_log
	info_log "Complete output:"
	info_log "$out"
	test_fail
fi
