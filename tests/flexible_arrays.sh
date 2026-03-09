#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Match flexible array member info with the per struct final stats.
#
# Arnaldo Carvalho de Melo <acme@redhat.com> (C) 2024-

source test_lib.sh

vmlinux=$(get_vmlinux $1)
if [ $? -ne 0 ] ; then
	info_log "$vmlinux"
	test_fail
fi

outdir=$(make_tmpdir)

# Comment this out to save test data.
trap cleanup EXIT

title_log "Flexible arrays accounting."

for struct in $(pahole -F btf --sizes --with_embedded_flexible_array $vmlinux | cut -f1) ; do
	pretty=$(make_tmpsrc)
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
	verbose_log "end: $struct: $nr_flexible_arrays $stat_nr_flexible_arrays"
	verbose_log "middle: $struct: $nr_embedded_flexible_arrays $stat_nr_embedded_flexible_arrays"

	if [ "$nr_embedded_flexible_arrays" != "$stat_nr_embedded_flexible_arrays" ] ; then
		verbose_log "struct %s: The number of embedded flexible arrays (%s) doesn't match the number of members marked as such (%s)\n" \
			"$struct" "$stat_nr_embedded_flexible_arrays" "$nr_embedded_flexible_arrays"
		verbose_log pahole $struct $vmlinux
		test_softfail
	fi

	if [ "$nr_flexible_arrays" != "$stat_nr_flexible_arrays" ] ; then
		verbose_log printf "struct %s: The number of flexible arrays (%s) doesn't match the number of members marked as such (%s)\n" \
			"$struct" "$stat_nr_flexible_arrays" "$nr_flexible_arrays"
		verbose_log pahole $struct $vmlinux
		test_softfail
	fi
done

check_softfail
if [ $? -ne 0 ] ; then
	test_fail
else
	test_pass
fi
