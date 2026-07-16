#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Test --numeric_version, --version, and --devel_version options.

. "$(dirname "$0")/test_lib.sh"

title_log "Version output."

# --numeric_version: should output a number
output=$(pahole --numeric_version 2>/dev/null)
rc=$?
if [ $rc -gt 128 ]; then
	error_log "FAIL: --numeric_version crashed (signal $((rc - 128)))"
	test_fail
fi
if [ -z "$output" ]; then
	error_log "FAIL: --numeric_version produced no output"
	test_fail
fi
# should be a single number on its own line (e.g. 128)
numeric_line=$(echo "$output" | grep -cE '^[0-9]+$')
if [ "$numeric_line" -eq 0 ]; then
	error_log "FAIL: --numeric_version output not numeric: $output"
	test_fail
fi
info_log "--numeric_version: $output ok"

# --version: should show version string
output=$(pahole --version 2>/dev/null)
rc=$?
if [ $rc -gt 128 ]; then
	error_log "FAIL: --version crashed (signal $((rc - 128)))"
	test_fail
fi
if [ -z "$output" ]; then
	error_log "FAIL: --version produced no output"
	test_fail
fi
if ! echo "$output" | grep -qE '^v[0-9]+\.[0-9]+$'; then
	error_log "FAIL: --version output doesn't match v<major>.<minor> format (kernel build expects this): $output"
	test_fail
fi
info_log "--version: $output ok"

# --devel_version: should show development version (git describe or fallback)
output=$(pahole --devel_version 2>/dev/null)
rc=$?
if [ $rc -gt 128 ]; then
	error_log "FAIL: --devel_version crashed (signal $((rc - 128)))"
	test_fail
fi
if [ -z "$output" ]; then
	error_log "FAIL: --devel_version produced no output"
	test_fail
fi
# Should be one of:
#   v<major>.<minor>                              (tarball without HEAD file)
#   v<major>.<minor>-<commits>-g<sha>[-dirty]     (git describe)
#   v<major>.<minor>-tarball-g<sha>               (tarball with HEAD file)
if ! echo "$output" | grep -qE '^v[0-9]+\.[0-9]+((-[0-9]+-g[0-9a-f]+(-dirty)?)|(-tarball-g[0-9a-f]+))?$'; then
	error_log "FAIL: --devel_version output doesn't match expected format: $output"
	test_fail
fi
info_log "--devel_version: $output ok"

test_pass
