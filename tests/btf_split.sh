#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Test split BTF encoding — vmlinux as base BTF, kernel module as split BTF.
#
# Split BTF (introduced in kernel 5.11) lets module BTF omit types already
# present in vmlinux BTF, drastically reducing per-module BTF size.
# pahole implements this via --btf_base=<vmlinux.btf> when encoding a module.
#
# Tests:
#  1. vmlinux encodes to a non-empty base BTF file
#  2. a kernel module encodes to a split BTF file that is smaller than the base
#  3. bpftool -B can resolve and dump the split BTF using the base BTF
#  4. split BTF type IDs start strictly above the vmlinux type count
#     (i.e. the module references base types by the correct offset)
#
# Requirements:
#  - bpftool with --base-btf (-B) support
#  - python3 (for ELF note parsing)
#  - debuginfod-find (to download module debuginfo)
#  - a running kernel whose vmlinux is fetchable via debuginfod
#  - at least one loaded module whose debuginfo is also in debuginfod

. "$(dirname "$0")/test_lib.sh"
outdir=$(make_tmpdir)

trap cleanup EXIT

title_log "Split BTF encoding (vmlinux base + kernel module)."

for cmd in bpftool python3 debuginfod-find; do
	if ! command -v "$cmd" > /dev/null 2>&1; then
		info_log "skip: $cmd not available"
		test_skip
	fi
done

# Obtain vmlinux via get_vmlinux() which respects VMLINUX env var,
# or auto-detects via pahole --running_kernel_vmlinux (debuginfod).
vmlinux=$(get_vmlinux 2>/dev/null)
if [ -z "$vmlinux" ] || [ ! -f "$vmlinux" ]; then
	info_log "skip: no vmlinux available"
	test_skip
fi
info_log "vmlinux: $vmlinux"

# Find a loaded kernel module whose debuginfo is available via debuginfod.
# We read the ELF GNU build-id note (type=3, name="GNU") from each module's
# /sys/module/<name>/notes/.note.gnu.build-id sysfs file and ask debuginfod
# to resolve it.  The first successful hit wins.
cat > "$outdir/find_mod.py" << 'PYEOF'
import sys, struct, glob, subprocess

for note_path in sorted(glob.glob('/sys/module/*/notes/.note.gnu.build-id'))[:20]:
    try:
        data = open(note_path, 'rb').read()
        if len(data) < 28:
            continue
        namesz, descsz, typ = struct.unpack_from('=III', data, 0)
        if namesz != 4 or typ != 3 or descsz < 20 or data[12:16] != b'GNU\x00':
            continue
        build_id = data[16:16 + descsz].hex()
        r = subprocess.run(['debuginfod-find', 'debuginfo', build_id],
                           capture_output=True, text=True, timeout=10)
        if r.returncode == 0 and r.stdout.strip():
            mod = note_path.split('/')[3]
            print(mod, r.stdout.strip())
            sys.exit(0)
    except Exception:
        pass

sys.exit(1)
PYEOF

mod_info=$(python3 "$outdir/find_mod.py" 2>/dev/null)
if [ -z "$mod_info" ]; then
	info_log "skip: no loaded module with debuginfod-available debuginfo found"
	test_skip
fi

mod_name=$(echo "$mod_info" | awk '{print $1}')
mod_path=$(echo "$mod_info" | awk '{print $2}')
info_log "module: $mod_name ($mod_path)"

# --- Encode vmlinux → base BTF ---

base_btf="$outdir/vmlinux.btf"
if ! pahole --btf_features=default --btf_encode_detached="$base_btf" "$vmlinux" 2>/dev/null || [ ! -s "$base_btf" ]; then
	error_log "FAIL: pahole failed to encode vmlinux BTF"
	test_fail
fi
base_size=$(wc -c < "$base_btf")
info_log "base BTF encoded: $base_size bytes"

# --- Encode module → split BTF (references base by type ID) ---

split_btf="$outdir/${mod_name}.btf"
pahole --btf_features=default \
       --btf_base="$base_btf" \
       --btf_encode_detached="$split_btf" \
       "$mod_path" 2>/dev/null
if ! [ -s "$split_btf" ]; then
	error_log "FAIL: pahole failed to encode split BTF for $mod_name"
	test_fail
fi
split_size=$(wc -c < "$split_btf")
info_log "split BTF encoded: $split_size bytes"

# --- Check 1: split BTF must be smaller than base BTF ---
# The whole point of split BTF is deduplication against the base.

if [ "$split_size" -ge "$base_size" ]; then
	error_log "FAIL: split BTF ($split_size bytes) not smaller than base BTF ($base_size bytes)"
	test_fail
fi
info_log "split BTF smaller than base BTF: ok"

# --- Check 2: bpftool -B can resolve and dump the split BTF ---

mod_dump=$(bpftool -B "$base_btf" btf dump file "$split_btf" 2>/dev/null)
if [ -z "$mod_dump" ]; then
	error_log "FAIL: bpftool -B dump of split BTF produced no output"
	test_fail
fi
info_log "bpftool -B dump: ok"

# --- Check 3: module type IDs start above vmlinux type count ---
# bpftool prints one "[N] KIND ..." line per type (plus indented member lines).
# Extract the last type ID from the base dump; module IDs must exceed it.

last_base_id=$(bpftool btf dump file "$base_btf" 2>/dev/null | grep '^\[' | tail -1 | sed 's/\[\([0-9]*\)\].*/\1/')
if [ -z "$last_base_id" ] || [ "$last_base_id" -eq 0 ]; then
	error_log "FAIL: could not determine last type ID from base BTF dump"
	test_fail
fi

# Filter to type lines (starting with '[') to skip any bpftool header
first_split_id=$(echo "$mod_dump" | grep '^\[' | head -1 | sed 's/\[\([0-9]*\)\].*/\1/')
if [ -z "$first_split_id" ]; then
	error_log "FAIL: could not parse first type ID from split BTF dump"
	test_fail
fi
if [ "$first_split_id" -le "$last_base_id" ]; then
	error_log "FAIL: first split BTF type ID ($first_split_id) not above last base type ID ($last_base_id)"
	test_fail
fi
info_log "split type IDs ($first_split_id+) above last base type ID ($last_base_id): ok"

test_pass
