#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (c) 2024, Oracle and/or its affiliates.
#
# Examine functions - especially those for which we skipped BTF encoding -
# to validate that they were indeed skipped for BTF encoding, and that they
# also should have been.
#

outdir=

fail()
{
	# Do not remove test dir; might be useful for analysis
	trap - EXIT
	if [[ -d "$outdir" ]]; then
		echo "Test data is in $outdir"
	fi
	exit 1
}

cleanup()
{
	rm ${outdir}/*
	rmdir $outdir
}

vmlinux=${vmlinux:-$1}

if [ -z "$vmlinux" ] ; then
	vmlinux=$(pahole --running_kernel_vmlinux)
	if [ -z "$vmlinux" ] ; then
		echo "Please specify a vmlinux file to operate on"
		exit 2
	fi
fi

if [ ! -f "$vmlinux" ] ; then
	echo "$vmlinux file not available, please specify another"
	exit 2
fi

outdir=$(mktemp -d /tmp/btf_functions.sh.XXXXXX)

trap cleanup EXIT

echo -n "Validation of BTF encoding of functions; this may take some time: "
test -n "$VERBOSE" && printf "\nEncoding..."

pahole --btf_features=default --btf_encode_detached=$outdir/vmlinux.btf --verbose $vmlinux |\
	grep "skipping BTF encoding of function" > ${outdir}/skipped_fns

test -n "$VERBOSE" && printf "done.\n"

funcs=$(pfunct --format_path=btf $outdir/vmlinux.btf |sort)

# all functions from DWARF; some inline functions are not inlined so include them too
pfunct --all --no_parm_names --format_path=dwarf $vmlinux | \
	sort|uniq > $outdir/dwarf.funcs
# all functions from BTF (removing bpf_kfunc prefix where found)
pfunct --all --no_parm_names --format_path=btf $outdir/vmlinux.btf |\
	awk '{ gsub("^bpf_kfunc ",""); print $0}'|sort|uniq > $outdir/btf.funcs

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
				echo "ERROR: mismatch : BTF '$btf' not found; DWARF '$dwarf'"
				fail
			fi
		else
			inline=$((inline+1))
		fi
	else
		exact=$((exact+1))
	fi
done < $outdir/btf.funcs

if [[ -n "$VERBOSE" ]]; then
	echo "Matched $exact functions exactly."
	echo "Matched $inline functions with inlines."
	echo "Matched $const_insensitive functions with multiple const/non-const instances."
	echo "Ok"
	echo "Validation of skipped function logic..."
fi

skipped_cnt=$(wc -l ${outdir}/skipped_fns | awk '{ print $1}')

if [[ "$skipped_cnt" == "0" ]]; then
	echo "No skipped functions.  Done."
	exit 0
fi

skipped_fns=$(awk '{print $1}' $outdir/skipped_fns)
for s in $skipped_fns ; do
	# Ensure the skipped function are not in BTF
	inbtf=$(grep " $s(" $outdir/btf.funcs)
	if [[ -n "$inbtf" ]]; then
		echo "ERROR: '${s}()' was added incorrectly to BTF: '$inbtf'"
		fail
	fi
done

if [[ -n "$VERBOSE" ]]; then
	echo "Skipped encoding $skipped_cnt functions in BTF."
	echo "Ok"
	echo "Validating skipped functions have incompatible return values..."
fi

return_mismatches=$(awk '/return type mismatch/ { print $1 }' $outdir/skipped_fns)
return_count=0

for r in $return_mismatches ; do
	# Ensure there are multiple instances with incompatible return values
	grep " $r(" $outdir/dwarf.funcs | \
	awk -v FN=$r '{i = index($0, FN); if (i>0) print substr($0, 0, i-1) }' \
	| uniq > ${outdir}/retvals.$r
	cnt=$(wc -l ${outdir}/retvals.$r | awk '{ print $1 }')
	if [[ $cnt -lt 2 ]]; then
		echo "ERROR: '${r}()' has only one return value; it should not be reported as having incompatible return values"
		fail
	fi
	return_count=$((return_count+1))
done

if [[ -n "$VERBOSE" ]]; then
	echo "Found $return_count functions with multiple incompatible return values."
	echo "Ok"
	echo "Validating skipped functions have incompatible params/counts..."
fi

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
			if [[ -n "$VERBOSE" ]]; then
				echo "WARN: '${p}()' has only one prototype; if it was subject to late optimization, pfunct may not reflect inconsistencies pahole found."
				echo "Full skip message from pahole: $skipmsg"
			fi
			warnings=$((warnings+1))
		fi
	else
		multiple=$((multiple+1))
	fi
done

if [[ -n "$VERBOSE" ]]; then
	echo "Found $multiple instances with multiple instances with incompatible parameters."
	echo "Found $multiple_inline instances where inline functions were not inlined and had incompatible parameters."
	echo "Found $optimized instances where the function name suggests optimizations led to inconsistent parameters."
	echo "Found $warnings instances where pfunct did not notice inconsistencies."
fi
echo "Ok"

exit 0
