#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (c) 2024, Oracle and/or its affiliates.
#
# Examine functions - especially those for which we skipped BTF encoding -
# to validate that they were indeed skipped for BTF encoding, and that they
# also should have been.
#

source test_lib.sh

vmlinux=$(get_vmlinux $1)
if [ $? -ne 0 ] ; then
	info_log "$vmlinux"
	test_fail
fi

outdir=$(make_tmpdir)

# Comment this out to save test data.
trap cleanup EXIT

title_log "Validation of BTF encoding of functions."
info_log "This may take some time."
verbose_log "Encoding..."

# Here we use both methods so that we test pahole --lang_exclude, that is
# used in the Linux kernel BTF encoding phase, and as well to make sure all
# other pahole and pfunct use in this script will exclude the Rust CUs, testing
# the fallback to PAHOLE_LANG_EXCLUDE.
export PAHOLE_LANG_EXCLUDE=rust

pahole --btf_features=default --lang_exclude=rust --btf_encode_detached=$outdir/vmlinux.btf --verbose $vmlinux |\
	grep "skipping BTF encoding of function" > ${outdir}/skipped_fns

verbose_log "done."

funcs=$(pfunct --format_path=btf $outdir/vmlinux.btf 2>/dev/null|sort)

# all functions from DWARF; some inline functions are not inlined so include them too
pfunct --all --no_parm_names --format_path=dwarf $vmlinux | \
	sort|uniq > $outdir/dwarf.funcs
# all functions from BTF (removing bpf_kfunc prefix where found)
pfunct --all --no_parm_names --format_path=btf $outdir/vmlinux.btf 2>/dev/null|\
	awk '{ gsub("^(bpf_kfunc |bpf_fastcall )+",""); print $0}'|sort|uniq > $outdir/btf.funcs

exact=0
inline=0
const_insensitive=0

while IFS= read -r btf ; do
	# look for non-inline match first
	dwarf=$(grep -F "$btf" $outdir/dwarf.funcs)
	if [[ "$btf" != "$dwarf" ]]; then
		# function might be declared inline in DWARF.
		if [[ "inline $btf" != "$dwarf" ]]; then
			# some functions have multiple instances in DWARF where one has
			# const param(s) and another does not (see errpos()).  We do not
			# mark these functions inconsistent as though they technically
			# have different prototypes, the data itself is not different.
			btf_noconst=$(echo $btf | awk '{gsub("const ",""); print $0 }')
			dwarf_noconst=$(echo $dwarf | awk '{gsub("const ",""); print $0 }')
			if [[ "$dwarf_noconst" =~ "$btf_noconst" ]]; then
				const_insensitive=$((const_insensitive+1))
			else
				error_log "ERROR: mismatch : BTF '$btf' not found; DWARF '$dwarf'"
				test_fail
			fi
		else
			inline=$((inline+1))
		fi
	else
		exact=$((exact+1))
	fi
done < $outdir/btf.funcs

verbose_log "Matched $exact functions exactly."
verbose_log "Matched $inline functions with inlines."
verbose_log "Matched $const_insensitive functions with multiple const/non-const instances."
verbose_log "Ok"
verbose_log "Validation of skipped function logic..."

skipped_cnt=$(wc -l ${outdir}/skipped_fns | awk '{ print $1}')

skipped_fns=$(awk '{print $1}' $outdir/skipped_fns)
for s in $skipped_fns ; do
	# Ensure the skipped function are not in BTF
	inbtf=$(grep " $s(" $outdir/btf.funcs)
	if [[ -n "$inbtf" ]]; then
		error_log "ERROR: '${s}()' was added incorrectly to BTF: '$inbtf'"
		test_fail
	fi
done

verbose_log "Skipped encoding $skipped_cnt functions in BTF."
verbose_log "Ok"
verbose_log "Validating skipped functions have incompatible return values..."

return_mismatches=$(awk '/return type mismatch/ { print $1 }' $outdir/skipped_fns)
return_count=0

for r in $return_mismatches ; do
	# Ensure there are multiple instances with incompatible return values
	grep " $r(" $outdir/dwarf.funcs | \
	awk -v FN=$r '{i = index($0, FN); if (i>0) print substr($0, 0, i-1) }' \
	| uniq > ${outdir}/retvals.$r
	cnt=$(wc -l ${outdir}/retvals.$r | awk '{ print $1 }')
	if [[ $cnt -lt 2 ]]; then
		error_log "ERROR: '${r}()' has only one return value; it should not be reported as having incompatible return values"
		test_fail
	fi
	return_count=$((return_count+1))
done

verbose_log "Found $return_count functions with multiple incompatible return values."
verbose_log "Ok"
verbose_log "Validating skipped functions have incompatible params/counts..."

param_mismatches=$(awk '/due to param / { print $1 }' $outdir/skipped_fns)

multiple=0
multiple_inline=0
optimized=0
warnings=0

for p in $param_mismatches ; do
	skipmsg=$(awk -v FN=$p '{ if ($1 == FN) print $0 }' $outdir/skipped_fns)
	altname=$(echo $skipmsg | awk '{ i=index($2,")"); print substr($2,2,i-2); }')
	if [[ "$altname" != "$p" ]]; then
		optimized=$((optimized+1))
		continue
	fi
	# Ensure there are multiple instances with incompatible params
	grep " $p(" $outdir/dwarf.funcs | uniq > ${outdir}/protos.$p
	cnt=$(wc -l ${outdir}/protos.$p | awk '{ print $1 }')
	if [[ $cnt -lt 2 ]]; then
		# function may be inlined in multiple sites with different protos
		inlined=$(grep inline ${outdir}/protos.$p)
		if [[ -n "$inlined" ]]; then
			multiple_inline=$((multiple_inline+1))
		else
			verbose_log "WARN: '${p}()' has only one prototype; if it was subject to late optimization, pfunct may not reflect inconsistencies pahole found."
			verbose_log "Full skip message from pahole: $skipmsg"
			warnings=$((warnings+1))
		fi
	else
		multiple=$((multiple+1))
	fi
done

verbose_log "Found $multiple instances with multiple instances with incompatible parameters."
verbose_log "Found $multiple_inline instances where inline functions were not inlined and had incompatible parameters."
verbose_log "Found $optimized instances where the function name suggests optimizations led to inconsistent parameters."
verbose_log "Found $warnings instances where pfunct did not notice inconsistencies."

# Some specific cases can not  be tested directly with a standard kernel.
# We can use the small binary in bin/ to test those cases, like packed
# structs passed on the stack.

verbose_log "Validation of BTF encoding corner cases with test_bin functions; this may take some time: "

verbose_log "Building test_bin..."
tests_dir=$(realpath $(dirname $0))
make -C ${tests_dir}/bin >/dev/null

verbose_log "Encoding..."
pahole --btf_features=default --lang_exclude=rust --btf_encode_detached=$outdir/test_bin.btf \
	--verbose ${tests_dir}/bin/test_bin | grep "skipping BTF encoding of function" \
	> ${outdir}/test_bin_skipped_fns

funcs=$(pfunct --format_path=btf $outdir/test_bin.btd 2>/dev/null|sort)
pfunct --all --no_parm_names --format_path=dwarf bin/test_bin | \
	sort|uniq > $outdir/test_bin_dwarf.funcs
pfunct --all --no_parm_names --format_path=btf $outdir/test_bin.btf 2>/dev/null|\
	awk '{ gsub("^(bpf_kfunc |bpf_fastcall )+",""); print $0}'|sort|uniq > $outdir/test_bin_btf.funcs

exact=0
while IFS= read -r btf ; do
	# Matching process can be kept simpler as the tested binary is
	# specifically tailored for tests
	dwarf=$(grep -F "$btf" $outdir/test_bin_dwarf.funcs)
	if [[ "$btf" != "$dwarf" ]]; then
		error_log "ERROR: mismatch : BTF '$btf' not found; DWARF '$dwarf'"
		test_fail
	else
		exact=$((exact+1))
	fi
done < $outdir/test_bin_btf.funcs

verbose_log "Matched $exact functions exactly."
verbose_log "Ok"
verbose_log "Validation of skipped function logic..."

skipped_cnt=$(wc -l ${outdir}/test_bin_skipped_fns | awk '{ print $1}')

skipped_fns=$(awk '{print $1}' $outdir/test_bin_skipped_fns)
for s in $skipped_fns ; do
	# Ensure the skipped function are not in BTF
	inbtf=$(grep " $s(" $outdir/test_bin_btf.funcs)
	if [[ -n "$inbtf" ]]; then
		error_log "ERROR: '${s}()' was added incorrectly to BTF: '$inbtf'"
		test_fail
	fi
done

verbose_log "Skipped encoding $skipped_cnt functions in BTF."
verbose_log "Ok"
verbose_log "Validating skipped functions have uncertain parameter location..."

uncertain_loc=$(awk '/due to uncertain parameter location/ { print $1 }' $outdir/test_bin_skipped_fns)
legitimate_skip=0

for f in $uncertain_loc ; do
	# Extract parameters types
	raw_params=$(grep ${f} $outdir/test_bin_dwarf.funcs|sed -n 's/^[^(]*(\([^)]*\)).*/\1/p')
	IFS=',' read -ra params <<< "${raw_params}"
	for param in "${params[@]}"
	do
		# Search any param that could be a struct
		struct_type=$(echo ${param}|grep -E '^struct [^*]' | sed -E 's/^struct //')
		if [ -n "${struct_type}" ]; then
			# Check with pahole if the struct is detected as
			# packed
			if pahole -F dwarf -C "${struct_type}" ${tests_dir}/bin/test_bin|tail -n 2|grep -q __packed__
			then
				legitimate_skip=$((legitimate_skip+1))
				continue 2
			fi
		fi
	done
	error_log "ERROR: '${f}()' should not have been skipped; it has no parameter with uncertain location"
	test_fail
done

verbose_log "Found ${legitimate_skip} legitimately skipped function due to uncertain loc"

test_pass
