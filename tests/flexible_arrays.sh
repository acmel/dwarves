#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Match flexible array member info with the per struct final stats.
#
# Arnaldo Carvalho de Melo <acme@redhat.com> (C) 2024-

vmlinux=${vmlinux:-$1}

if [ -z "$vmlinux" ] ; then
	vmlinux=$(pahole --running_kernel_vmlinux)
fi

if [ ! -f "$vmlinux" ] ; then
	echo "$vmlinux file not available, please specify another"
	exit 2
fi

pretty=$(mktemp /tmp/flexible_arrays.data.sh.XXXXXX.c)

echo -n "Flexible arrays accounting: "

for struct in $(pahole -F btf --sizes --with_embedded_flexible_array $vmlinux | cut -f1) ; do
	pahole $struct $vmlinux > $pretty

	# We need to check for just one tab before the comment as when expanding unnamed
	# structs with members with flexible arrays inside another struct we would mess
	# up the accounting, see 'pahole fanotify_fid_event' for instance, circa October 2024:
	# $ pahole fanotify_fid_event
	# struct fanotify_fid_event {
	#	struct fanotify_event      fae;                  /*     0    48 */
	#	__kernel_fsid_t            fsid;                 /*    48     8 */
	#	struct {
	#		struct fanotify_fh object_fh;            /*    56     4 */
	#		/* XXX last struct has a flexible array */
	#		unsigned char      _inline_fh_buf[12];   /*    60    12 */
	#	};                                               /*    56    16 */

	#	/* XXX last struct has embedded flexible array(s) */
	#	/* size: 72, cachelines: 2, members: 3 */
	#	/* flexible array members: middle: 1 */
	#	/* last cacheline: 8 bytes */
	# }

	nr_flexible_arrays=$(grep $'^\t/\* XXX last struct has a flexible array' $pretty | wc -l)
	nr_embedded_flexible_arrays=$(grep $'^\t/\* XXX last struct.*embedded flexible array' $pretty | wc -l)
	stat_nr_flexible_arrays=$(grep "flexible array members:.*end:" $pretty | sed -r 's/.*end: *([[:digit:]]+).*/\1/g')
	[ -z "$stat_nr_flexible_arrays" ] && stat_nr_flexible_arrays=0
	stat_nr_embedded_flexible_arrays=$(grep "flexible array members:.*middle:" $pretty | sed -r 's/.*middle: *([[:digit:]]+).*/\1/g')
	[ -z "$stat_nr_embedded_flexible_arrays" ] && stat_nr_embedded_flexible_arrays=0
	test -n "$VERBOSE" && echo "end: $struct: $nr_flexible_arrays $stat_nr_flexible_arrays"
	test -n "$VERBOSE" && echo "middle: $struct: $nr_embedded_flexible_arrays $stat_nr_embedded_flexible_arrays"

	if [ "$nr_embedded_flexible_arrays" != "$stat_nr_embedded_flexible_arrays" ] ; then
		test -n "$VERBOSE" && printf "struct %s: The number of embedded flexible arrays (%s) doesn't match the number of members marked as such (%s)\n" \
			"$struct" "$stat_nr_embedded_flexible_arrays" "$nr_embedded_flexible_arrays"
		test -n "$VERBOSE" && pahole $struct $vmlinux
		FAILED=1
	fi

	if [ "$nr_flexible_arrays" != "$stat_nr_flexible_arrays" ] ; then
		test -n "$VERBOSE" && printf "struct %s: The number of flexible arrays (%s) doesn't match the number of members marked as such (%s)\n" \
			"$struct" "$stat_nr_flexible_arrays" "$nr_flexible_arrays"
		test -n "$VERBOSE" && pahole $struct $vmlinux
		FAILED=1
	fi

	rm -f $pretty
done

if [ -n "$FAILED" ] ; then
	echo "FAILED"
	exit 1
fi

echo "Ok"
exit 0
