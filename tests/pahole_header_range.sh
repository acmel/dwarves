#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Test --header, --range, --seek_bytes, --size_bytes prettify paths.
# Exercises the binary record parsing paths in pahole.c (lines 2692-2982):
#   - header struct reading and field extraction
#   - $header.field references in --seek_bytes and --size_bytes
#   - --range with nested struct offset/size members
#   - numeric --seek_bytes without header

. "$(dirname "$0")/test_lib.sh"
outdir=$(make_tmpdir)

trap cleanup EXIT

title_log "Header, range and seek_bytes prettify paths."

CC=${CC:-gcc}
if ! command -v "${CC%% *}" > /dev/null 2>&1; then
	info_log "skip: $CC not available"
	test_skip
fi

src=$(make_tmpsrc)
obj=$(make_tmpobj)

# The header struct has a nested 'data' sub-struct with 'offset' and 'size'
# fields, which is what --range=data expects (it looks up data.offset and
# data.size in the header).
cat > "$src" << 'EOF'
struct data_range {
	unsigned int offset;
	unsigned int size;
};

struct file_header {
	unsigned int magic;
	unsigned int version;
	struct data_range data;
};

struct data_record {
	int id;
	int value;
	char name[8];
};

struct file_header g_hdr;
struct data_record g_rec;
EOF

if ! $CC -g -c -o "$obj" "$src" 2>/dev/null; then
	error_log "FAIL: compilation failed"
	test_fail
fi

# Build a binary file: 16-byte header followed by a 16-byte data record.
# All values are little-endian, using POSIX-safe octal escapes.
#
# NOTE: This binary data is LE-encoded.  On big-endian hosts the DWARF
# struct layout will also be BE, so pahole will misinterpret these
# fields.  Skip the test on BE architectures rather than producing
# false failures.
#
# Header (16 bytes):
#   magic       = 0x12345678 -> LE: \170\126\064\022
#   version     = 1          -> LE: \001\000\000\000
#   data.offset = 16         -> LE: \020\000\000\000
#   data.size   = 16         -> LE: \020\000\000\000
#
# Record (16 bytes):
#   id    = 42      -> LE: \052\000\000\000
#   value = 100     -> LE: \144\000\000\000
#   name  = "testREC\0" -> 8 ASCII bytes
# Detect host endianness — binary data below is LE-only.
# Write a 32-bit int value 1 via a tiny C program and check byte order.
endian_src="$outdir/endian.c"
endian_bin="$outdir/endian"
cat > "$endian_src" << 'EEOF'
#include <stdio.h>
int main(void) {
	unsigned int x = 1;
	unsigned char *c = (unsigned char *)&x;
	printf("%s\n", c[0] ? "little" : "big");
	return 0;
}
EEOF
if $CC -o "$endian_bin" "$endian_src" 2>/dev/null; then
	host_endian=$("$endian_bin")
	if [ "$host_endian" = "big" ]; then
		info_log "skip: big-endian host, binary test data is little-endian"
		test_skip
	fi
fi

binfile="$outdir/test.bin"
printf '\170\126\064\022' > "$binfile"
printf '\001\000\000\000' >> "$binfile"
printf '\020\000\000\000' >> "$binfile"
printf '\020\000\000\000' >> "$binfile"
printf '\052\000\000\000' >> "$binfile"
printf '\144\000\000\000' >> "$binfile"
printf 'testREC\000' >> "$binfile"

# Verify the binary file is exactly 32 bytes (header + one record)
binsize=$(wc -c < "$binfile")
if [ "$binsize" -ne 32 ]; then
	error_log "FAIL: binary file size is $binsize, expected 32"
	test_fail
fi

# --header_type with --prettify: reads header, then prints record after it
output=$(pahole -C data_record --header_type=file_header \
	--prettify "$binfile" "$obj" 2>/dev/null)
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: --header_type prettify exited $rc"
	test_fail
fi
if [ -z "$output" ]; then
	error_log "FAIL: --header_type prettify produced no output"
	test_fail
fi
if ! echo "$output" | grep -q "\.id"; then
	error_log "FAIL: --header_type prettify missing .id field"
	test_fail
fi
info_log "   --header_type with --prettify: ok"

# --seek_bytes with $header reference: exercises the
# strstarts(conf.seek_bytes, "$header.") path in pahole.c
output=$(pahole -C data_record --header_type=file_header \
	--seek_bytes='$header.data.offset' \
	--prettify "$binfile" "$obj" 2>/dev/null)
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: --seek_bytes \$header ref exited $rc"
	test_fail
fi
if [ -z "$output" ]; then
	error_log "FAIL: --seek_bytes \$header ref produced no output"
	test_fail
fi
info_log "   --seek_bytes with \$header.data.offset: ok"

# --size_bytes with $header reference
output=$(pahole -C data_record --header_type=file_header \
	--seek_bytes='$header.data.offset' \
	--size_bytes='$header.data.size' \
	--prettify "$binfile" "$obj" 2>/dev/null)
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: --size_bytes \$header ref exited $rc"
	test_fail
fi
if [ -z "$output" ]; then
	error_log "FAIL: --size_bytes \$header ref produced no output"
	test_fail
fi
info_log "   --size_bytes with \$header.data.size: ok"

# --range=data: looks up data.offset and data.size in the header struct
# via type_instance__int_value to determine where and how much to read
output=$(pahole -C data_record --header_type=file_header \
	--range=data \
	--prettify "$binfile" "$obj" 2>/dev/null)
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: --range=data exited $rc"
	test_fail
fi
if [ -z "$output" ]; then
	error_log "FAIL: --range=data produced no output"
	test_fail
fi
info_log "   --range=data: ok"

# Numeric --seek_bytes without header: exercises the else branch
# seek_bytes = strtol(conf.seek_bytes, NULL, 0)
output=$(pahole -C data_record \
	--seek_bytes=16 \
	--prettify "$binfile" "$obj" 2>/dev/null)
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: numeric --seek_bytes exited $rc"
	test_fail
fi
if [ -z "$output" ]; then
	error_log "FAIL: numeric --seek_bytes produced no output"
	test_fail
fi
info_log "   numeric --seek_bytes=16: ok"

# Numeric --size_bytes without header
output=$(pahole -C data_record \
	--seek_bytes=16 --size_bytes=16 \
	--prettify "$binfile" "$obj" 2>/dev/null)
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: numeric --size_bytes exited $rc"
	test_fail
fi
if [ -z "$output" ]; then
	error_log "FAIL: numeric --size_bytes produced no output"
	test_fail
fi
info_log "   numeric --size_bytes=16: ok"

# --header_type alone: prints just the header struct itself
output=$(pahole --header_type=file_header \
	--prettify "$binfile" "$obj" 2>/dev/null)
rc=$?
if [ $rc -ne 0 ]; then
	error_log "FAIL: --header_type alone exited $rc"
	test_fail
fi
if [ -z "$output" ]; then
	error_log "FAIL: --header_type alone produced no output"
	test_fail
fi
if ! echo "$output" | grep -q "\.magic"; then
	error_log "FAIL: --header_type alone missing .magic field"
	test_fail
fi
info_log "   --header_type alone: ok"

test_pass
