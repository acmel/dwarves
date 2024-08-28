#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2024 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
# 
# Use pahole to pretty print a perf.data file

# Check if the perf binary is available, if it is from a distro, normally it
# will get the needed DWARF info using libddebuginfod, we'll check if the
# needed types are available, skipping the test and informing the reason.

echo -n "Pretty printing of files using DWARF type information: "

perf=$(which perf 2> /dev/null)
if [ -z "$perf" ] ; then
	echo "skip: No 'perf' binary available"
	exit 2
fi

perf_lacks_type_info() {
	local type_keyword=$1
	local type_name=$2
	if ! pahole -C $type_name $perf | grep -q "^$type_keyword $type_name {"; then
		echo "skip: $perf doesn't have '$type_keyword $type_name' type info"
		return 1
	fi
	return 0
}

perf_data=$(mktemp /tmp/prettify_perf.data.sh.XXXXXX.perf.data)

perf_lacks_type_info struct perf_event_header || exit 2
perf_lacks_type_info enum perf_event_type || exit 2
perf_lacks_type_info enum perf_user_event_type || exit 2

$perf record --quiet -o $perf_data sleep 0.00001

number_of_filtered_perf_record_metadata() {
	local metadata_record=$1
	local count=$(pahole -F dwarf -V $perf --header=perf_file_header --seek_bytes '$header.data.offset' --size_bytes='$header.data.size' -C "perf_event_header(sizeof,type,type_enum=perf_event_type+perf_user_event_type,filter=type==PERF_RECORD_$metadata_record)" --prettify $perf_data | grep ".type = PERF_RECORD_$metadata_record," | wc -l)
	echo "$count"
}

check_expected_number_of_filtered_perf_record_metadata() {
	local metadata_record=$1
	local expected_records=$2
	local nr_records=$(number_of_filtered_perf_record_metadata $metadata_record)

	if [ "$nr_records" != "$expected_records" ] ; then
		echo "FAIL: expected $expected_records PERF_RECORD_$metadata_record metadata records, got $nr_records"
		return 1;
	fi
	return 0
}

check_expected_number_of_filtered_perf_record_metadata COMM 2 || exit 1
check_expected_number_of_filtered_perf_record_metadata EXIT 1 || exit 1
check_expected_number_of_filtered_perf_record_metadata TIME_CONV 1 || exit 1
check_expected_number_of_filtered_perf_record_metadata THREAD_MAP 1 || exit 1
check_expected_number_of_filtered_perf_record_metadata CPU_MAP 1 || exit 1
check_expected_number_of_filtered_perf_record_metadata FINISHED_INIT 1 || exit 1

# XXX write more tests that look at the events contents, not just for the presence of a known number of them

echo "Ok"

rm -f $perf_data
