#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only

# Check that pahole preserves btf_type_tag order when emitting BTF from DWARF.

source test_lib.sh

outdir=$(make_tmpdir)

# Comment this out to save test data.
trap cleanup EXIT

title_log "Check BTF type tag order."

GCC=${GCC:-gcc}
CLANG=${CLANG:-clang}
PAHOLE=${PAHOLE:-pahole}
BPFTOOL=${BPFTOOL:-bpftool}

if ! command -v "$BPFTOOL" > /dev/null; then
	info_log "skip: bpftool not available"
	test_skip
fi

compiler_has_btf_type_tag()
{
	local compiler=$1

	if ! command -v "$compiler" > /dev/null; then
		return 1
	fi

	"$compiler" -x c -E -P - <<'EOF' 2>/dev/null | grep -qx 1
#ifndef __has_attribute
#define __has_attribute(x) 0
#endif
#if __has_attribute(btf_type_tag)
1
#else
0
#endif
EOF
}

use_gcc=0
if compiler_has_btf_type_tag "$GCC"; then
	use_gcc=1
fi

use_clang=0
if compiler_has_btf_type_tag "$CLANG"; then
	use_clang=1
fi

if [ "$use_gcc" -eq 0 ] && [ "$use_clang" -eq 0 ]; then
	error_log "Need gcc or clang with btf_type_tag support for test $0"
	test_fail
fi

src=$(cat <<EOF
#define __tag(x) __attribute__((btf_type_tag(#x)))

struct sample {
	int value;
};

struct sample __tag(outer) __tag(inner) *global_ptr;

EOF
)

check_type_tag_order()
{
	local btf=$1
	local dump

	if ! dump=$("$BPFTOOL" btf dump file "$btf"); then
		return 1
	fi

	printf '%s\n' "$dump" | awk '
	function parse_id(line, m) {
		if (match(line, /^\[([0-9]+)\]/, m))
			return m[1]
		return 0
	}
	function parse_name(line, m) {
		if (match(line, /\047([^\047]*)\047/, m))
			return m[1]
		return ""
	}
	function parse_type(line, m) {
		if (match(line, /type_id=([0-9]+)/, m))
			return m[1]
		return 0
	}
	function check_ptr(ptr, id, tags, seen) {
		id = type[ptr]
		while (id != 0 && !seen[id]) {
			seen[id] = 1
			if (kind[id] == "TYPE_TAG") {
				tags = tags (tags == "" ? "" : " -> ") name[id]
				id = type[id]
				continue
			}
			if (kind[id] == "STRUCT" && name[id] == "sample") {
				if (tags == "inner -> outer")
					exit 0
				candidates = candidates (candidates == "" ? "" : ", ") tags
			}
			return
		}
	}
	/^\[[0-9]+\]/ {
		id = parse_id($0)
		kind[id] = $2
		name[id] = parse_name($0)
		type[id] = parse_type($0)
		if (kind[id] == "PTR")
			ptrs[++nr_ptrs] = id
	}
	END {
		for (i = 1; i <= nr_ptrs; i++)
			check_ptr(ptrs[i])
		if (candidates != "") {
			print "type tag order mismatch; expected inner -> outer, found " candidates > "/dev/stderr"
			exit 1
		}
		print "could not find tagged pointer to struct sample" > "/dev/stderr"
		exit 1
	}'
}

run_test()
{
	local compiler=$1
	local tmpobj=$2
	local btf=$3

	info_log "Testing with $compiler"

	if ! echo "$src" | "$compiler" -g -c -x c -o "$tmpobj" - 2>/dev/null; then
		error_log "Could not compile type tag order test with $compiler"
		return 1
	fi

	if ! "$PAHOLE" --btf_features=+type_tag --btf_encode_detached="$btf" "$tmpobj" 2>/dev/null; then
		error_log "Could not encode BTF for $tmpobj"
		return 1
	fi

	if check_type_tag_order "$btf"; then
		info_log "  passed"
		return 0
	fi

	error_log "BTF type tag order does not match expected order ($compiler)"
	return 1
}

failed=0

if [ "$use_gcc" -eq 1 ]; then
	tmpobj=$(make_tmpobj)
	btf=${tmpobj%.o}.btf
	run_test "$GCC" "$tmpobj" "$btf" || failed=1
fi

if [ "$use_clang" -eq 1 ]; then
	tmpobj=$(make_tmpobj)
	btf=${tmpobj%.o}.btf
	run_test "$CLANG" "$tmpobj" "$btf" || failed=1
fi

if [ "$failed" -eq 0 ]; then
	test_pass
else
	test_fail
fi
