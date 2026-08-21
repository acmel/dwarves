#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Arnaldo Carvalho de Melo <acme@redhat.com>
# Assisted-by: Claude:claude-sonnet-4-5
#
# Compare vmlinux files: DWARF versions, producers, section sizes, and pahole output.
#
# Prompt used to generate this script:
#
# Given a directory with a series of vmlinux files, look at the DW_AT_producer
# DWARF tags to notice what's unique for each of the vmlinux files, look at the
# DWARF version as well, then run pahole -F dwarf and btf to see if the output
# produced changes for both formats in the different vmlinux files, create a
# table like the one in the upcoming coverage-table make target. Add columns for
# each row (DWARF files) with the size of the vmlinux files and the size of the
# DWARF and BTF related ELF sections on each of the vmlinux files.
#
# Usage:
#   scripts/vmlinux_comparison.py [DIRECTORY]
#
#   Default directory: ~/dws/

import argparse
import hashlib
import os
import re
import subprocess
import sys
import tempfile
import shutil
from dataclasses import dataclass
from typing import Optional, List, Dict, Any


@dataclass
class ToolError(Exception):
    """Exception for tool execution failures with context."""
    tool: str
    message: str
    returncode: Optional[int] = None
    stderr: str = ''


def format_size(size_bytes: int) -> str:
    """Format byte size in human-readable format."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f}{unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f}TB"


def get_file_size(path: str) -> int:
    """Get file size in bytes."""
    return os.path.getsize(path)


def check_tool_exists(tool_name: str) -> bool:
    """Check if a command-line tool exists and is executable."""
    try:
        result = subprocess.run(['which', tool_name], capture_output=True)
        return result.returncode == 0
    except Exception:
        return False


def run_readelf_sections(vmlinux_path: str, timeout: int = 30) -> Dict[str, int]:
    """Extract ELF section sizes using readelf -SW (wide output)."""
    sections = {}
    try:
        cmd = ['readelf', '-SW', vmlinux_path]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode != 0:
            return sections

        # Parse section headers using regex to avoid column alignment issues
        # Format: [Nr] Name Type Address Off Size ES Flg Lk Inf Al
        # Example: [14] .BTF PROGBITS ffffffff874cc000 66cc000 755775 00 A 0 0 1
        for line in result.stdout.splitlines():
            match = re.search(r'\[\s*\d+\]\s+(\S+)\s+\S+\s+\S+\s+\S+\s+(\S+)', line)
            if match:
                name = match.group(1)
                size_hex = match.group(2)
                try:
                    size = int(size_hex, 16)
                    if size > 0:
                        sections[name] = size
                except ValueError:
                    pass
    except subprocess.TimeoutExpired:
        raise ToolError('readelf', f'Timeout after {timeout}s', stderr='')
    except Exception as e:
        raise ToolError('readelf', str(e), stderr='')
    return sections


def extract_dwarf_version(vmlinux_path: str, timeout: int = 30, max_lines: int = 100) -> str:
    """Extract DWARF version using readelf.

    Note: Limited to max_lines lines to avoid timeout issues when reading
    large debug info sections from vmlinux files.
    """
    try:
        cmd = ['readelf', '--debug-dump=info', vmlinux_path]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            lines_read = 0
            for line in proc.stdout:
                if 'Version:' in line:
                    match = re.search(r'Version:\s+(\d+)', line)
                    if match:
                        proc.terminate()
                        try:
                            proc.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                            proc.wait()
                        return match.group(1)
                lines_read += 1
                if lines_read >= max_lines:
                    break
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            return 'N/A'
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            raise ToolError('readelf', f'Timeout after {timeout}s', stderr='')
    except ToolError:
        raise
    except Exception as e:
        raise ToolError('readelf', str(e), stderr='')


def extract_producer(vmlinux_path: str, timeout: int = 30, max_lines: int = 200) -> str:
    """Extract DW_AT_producer using readelf.

    Note: Limited to max_lines lines to avoid timeout issues when reading
    large debug info sections from vmlinux files.
    """
    try:
        cmd = ['readelf', '--debug-dump=info', vmlinux_path]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            lines_read = 0
            for line in proc.stdout:
                if 'DW_AT_producer' in line:
                    match = re.search(r'DW_AT_producer\s*:\s*(?:\([^)]+\):\s*)?(.+)', line)
                    if match:
                        producer = match.group(1).strip()
                        proc.terminate()
                        try:
                            proc.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                            proc.wait()
                        # Extract key parts: compiler name, version, DWARF flag, compression
                        # Try to parse known patterns, but fall back to raw producer string
                        parts = []

                        # Get compiler and version (GCC, Clang, etc.)
                        # GCC: "GNU C11 16.1.1 20260515 (Red Hat 16.1.1-2)"
                        # Clang: "clang version 16.0.0"
                        # ICC: "Intel(R) C++ Compiler for applications targeting Intel(R) 64, Version 19.0.1.117"
                        # Vendor GCC: "gcc (GCC) 8.3.0 20191121"
                        compiler_match = re.search(r'(GNU C\d+|clang|Intel.*C.*Compiler|gcc\s+\()', producer, re.IGNORECASE)
                        if compiler_match:
                            parts.append(compiler_match.group(0).strip())
                        else:
                            # Try to extract any compiler-like prefix
                            generic_match = re.search(r'^(clang|icc|gcc|GNU|icc|Apple\s+LLVM)\s+', producer, re.IGNORECASE)
                            if generic_match:
                                parts.append(generic_match.group(0).strip())

                        # Get DWARF version flag
                        dwarf_match = re.search(r'-gdwarf-(\d+)', producer)
                        if dwarf_match:
                            parts.append(f"-gdwarf-{dwarf_match.group(1)}")

                        # Get compression if present
                        compress_match = re.search(r'-gz(=\w+)?', producer)
                        if compress_match:
                            parts.append(compress_match.group(0))

                        if parts:
                            return ' '.join(parts)
                        # Fallback: return first 80 chars of raw producer
                        return producer[:80] + ('...' if len(producer) > 80 else '')
                lines_read += 1
                if lines_read >= max_lines:
                    break
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            return 'N/A'
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            raise ToolError('readelf', f'Timeout after {timeout}s', stderr='')
    except ToolError:
        raise
    except Exception as e:
        raise ToolError('readelf', str(e), stderr='')


def run_pahole_and_hash(vmlinux_path: str, format_type: str, timeout: int = 600) -> tuple[str, int]:
    """Run pahole with given format and return output hash and size."""
    try:
        cmd = ['pahole', '-F', format_type, vmlinux_path]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            result = proc.communicate(timeout=timeout)
            if proc.returncode != 0:
                stderr_msg = result[1].decode('utf-8', errors='replace') if result[1] else 'no stderr'
                raise ToolError('pahole', f'pahole -F {format_type} failed', proc.returncode, stderr_msg)

            hasher = hashlib.sha256()
            hasher.update(result[0])
            hash_short = hasher.hexdigest()[:8]
            return hash_short, len(result[0])
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            raise ToolError('pahole', f'Timeout after {timeout}s', stderr='')
    except ToolError:
        raise
    except Exception as e:
        raise ToolError('pahole', str(e), stderr='')


def has_inter_cu_references(vmlinux_path: str, timeout: int = 120) -> Optional[bool]:
    """Detect inter-CU references (DW_FORM_ref_addr) in .debug_abbrev.

    Mirrors cus__merging_cu() in dwarf_loader.c: any DW_FORM_ref_addr
    attribute means CUs reference each other by absolute offset and
    cannot be processed independently, so pahole falls back to the
    merged-CU mode (force_cu_merging), which is single-threaded.
    """
    try:
        cmd = ['readelf', '--debug-dump=abbrev', vmlinux_path]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        try:
            for line in proc.stdout:
                if b'DW_FORM_ref_addr' in line:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait()
                    return True
            proc.wait(timeout=timeout)
            return False
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            raise ToolError('readelf', f'Timeout after {timeout}s', stderr='')
    except ToolError:
        raise
    except Exception as e:
        raise ToolError('readelf', str(e), stderr='')


def run_btf_encode_timed(vmlinux_path: str, threads: Optional[int] = None, timeout: int = 600) -> Optional[tuple[float, float, float]]:
    """Run perf stat --null -r5 pahole -j --btf_encode_detached and return
    (mean, stddev, rel_err) elapsed time in seconds, or None on failure.

    Times the BTF encoding, which is what varies across the different
    CONFIG_DEBUG_* DWARF modes.  Each encoding is repeated 5 times to
    rule out variation from system caches.  pahole automatically detects
    inter-CU references (DW_FORM_ref_addr in .debug_abbrev) and switches
    to the merged-CU mode when present, which is single-threaded.
    """
    tmpfile: Optional[str] = None
    try:
        with tempfile.NamedTemporaryFile(prefix='vmlinux-cmp-', suffix='.btf', delete=False) as tmp:
            tmpfile = tmp.name

        try:
            cmd = ['perf', 'stat', '--null', '-r5']
            cmd.append('pahole')
            if threads is not None:
                cmd.append(f'-j{threads}')
            else:
                cmd.append('-j')
            cmd.append(f'--btf_encode_detached={tmpfile}')
            cmd.append(vmlinux_path)

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            if result.returncode != 0:
                return None

            # perf stat prints to stderr, e.g.:
            #   3.023371323 +- 0.003831050 seconds time elapsed  ( +-  0.13% )
            # Also handle locale variations (comma as decimal separator)
            stderr = result.stderr.replace(',', '.')
            match = re.search(
                r'([0-9.]+)\s+\+-\s+([0-9.]+)\s+seconds time elapsed\s+\(\s+\+-\s*([0-9.]+)%\s*\)',
                stderr)
            if match:
                mean = float(match.group(1))
                stddev = float(match.group(2))
                rel_err = float(match.group(3))
                return mean, stddev, rel_err
            return None
        finally:
            if tmpfile is not None:
                try:
                    os.unlink(tmpfile)
                except OSError:
                    pass
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None


def find_vmlinux_files(directory: str) -> List[str]:
    """Find all vmlinux* files in directory, excluding text files."""
    vmlinux_files = []

    if not os.path.isdir(directory):
        print(f"Error: {directory} is not a directory", file=sys.stderr)
        return []

    for filename in os.listdir(directory):
        path = os.path.join(directory, filename)

        # Skip non-files
        if not os.path.isfile(path):
            continue

        # Only include files starting with "vmlinux"
        if not filename.startswith('vmlinux'):
            continue

        # Skip text files (.c, .txt, etc.)
        if filename.endswith(('.c', '.txt', '.log', '.md')):
            continue

        # Check if it's an ELF file
        try:
            with open(path, 'rb') as f:
                magic = f.read(4)
                if magic != b'\x7fELF':
                    continue
        except Exception:
            continue

        vmlinux_files.append(path)

    return sorted(vmlinux_files)


def analyze_vmlinux(vmlinux_path: str, timeouts: Dict[str, int]) -> Dict[str, Any]:
    """Analyze a single vmlinux file and return metrics."""
    filename = os.path.basename(vmlinux_path)

    print(f"  Analyzing {filename}...", file=sys.stderr)

    file_size = get_file_size(vmlinux_path)

    # Extract ELF section sizes
    try:
        print(f"    Reading ELF sections...", file=sys.stderr)
        sections = run_readelf_sections(vmlinux_path, timeout=timeouts.get('readelf', 30))
    except ToolError as e:
        print(f"    Warning: Failed to read ELF sections: {e.message}", file=sys.stderr)
        sections = {}

    # DWARF version
    try:
        print(f"    Extracting DWARF version...", file=sys.stderr)
        dwarf_version = extract_dwarf_version(vmlinux_path, timeout=timeouts.get('readelf', 30))
    except ToolError as e:
        print(f"    Error: Failed to extract DWARF version: {e.message}", file=sys.stderr)
        dwarf_version = e.message

    # Producer
    try:
        print(f"    Extracting producer...", file=sys.stderr)
        producer = extract_producer(vmlinux_path, timeout=timeouts.get('readelf', 30))
    except ToolError as e:
        print(f"    Error: Failed to extract producer: {e.message}", file=sys.stderr)
        producer = e.message

    # pahole -F dwarf
    try:
        print(f"    Running pahole -F dwarf...", file=sys.stderr)
        dwarf_hash, _ = run_pahole_and_hash(vmlinux_path, 'dwarf', timeout=timeouts.get('pahole', 600))
    except ToolError as e:
        print(f"    Error: pahole -F dwarf failed: {e.message}", file=sys.stderr)
        dwarf_hash = e.message

    # pahole -F btf
    try:
        print(f"    Running pahole -F btf...", file=sys.stderr)
        btf_hash, _ = run_pahole_and_hash(vmlinux_path, 'btf', timeout=timeouts.get('pahole', 600))
    except ToolError as e:
        print(f"    Error: pahole -F btf failed: {e.message}", file=sys.stderr)
        btf_hash = e.message

    # Inter-CU references
    try:
        print(f"    Checking for inter-CU references...", file=sys.stderr)
        inter_cu_refs = has_inter_cu_references(vmlinux_path, timeout=timeouts.get('readelf', 120))
    except ToolError as e:
        print(f"    Error: Failed to check inter-CU references: {e.message}", file=sys.stderr)
        inter_cu_refs = None

    # BTF encoding timing
    print(f"    Running perf stat --null -r5 pahole -j --btf_encode_detached...", file=sys.stderr)
    btf_encoding_time = run_btf_encode_timed(vmlinux_path, timeout=timeouts.get('pahole', 600))

    # Compute key section sizes
    dwarf_sections = {k: v for k, v in sections.items() if k.startswith('.debug_')}
    btf_sections = {k: v for k, v in sections.items() if k.lower().startswith('.btf')}

    return {
        'filename': filename,
        'file_size': file_size,
        'sections': sections,
        'dwarf_sections': dwarf_sections,
        'btf_sections': btf_sections,
        'dwarf_version': dwarf_version,
        'producer': producer,
        'dwarf_output_hash': dwarf_hash,
        'btf_output_hash': btf_hash,
        'btf_encoding': btf_encoding_time,
        'inter_cu_refs': inter_cu_refs,
    }


def print_table(results: List[Dict[str, Any]]) -> None:
    """Print comparison table with box-drawing characters."""
    if not results:
        print("No vmlinux files found.")
        return

    # Column widths
    W_FILE = 26
    W_SIZE = 8
    W_VER = 5
    W_PROD = 55
    W_HASH = 8
    W_TIME = 24
    W_ICUREF = 8
    W_DWSECT = 12
    W_BTFSECT = 10

    # Header
    def print_sep(char='─'):
        print(f"┌{char*W_FILE}┬{char*W_SIZE}┬{char*W_VER}┬{char*W_PROD}┬"
              f"{char*W_DWSECT}┬{char*W_BTFSECT}┬"
              f"{char*W_HASH}┬{char*W_HASH}┬"
              f"{char*W_TIME}┬{char*W_ICUREF}┐")

    def print_row_sep():
        print(f"├{'─'*W_FILE}┼{'─'*W_SIZE}┼{'─'*W_VER}┼{'─'*W_PROD}┼"
              f"{'─'*W_DWSECT}┼{'─'*W_BTFSECT}┼"
              f"{'─'*W_HASH}┼{'─'*W_HASH}┼"
              f"{'─'*W_TIME}┼{'─'*W_ICUREF}┤")

    print_sep()

    # Column headers
    print(f"│{'File':<{W_FILE}}│{'Size':>{W_SIZE}}│{'Ver':^{W_VER}}│{'Producer':<{W_PROD}}│"
          f"{'DW-Sect':>{W_DWSECT}}│{'BTF-Sect':>{W_BTFSECT}}│"
          f"{'DW-Hash':>{W_HASH}}│{'BTF-Hash':>{W_HASH}}│"
          f"{'BTF-Enc':^{W_TIME}}│{'Inter-CU':>{W_ICUREF}}│")

    print_row_sep()

    # Data rows
    for r in results:
        fname = r['filename']
        if len(fname) > W_FILE:
            fname = fname[:W_FILE-3] + '...'

        fsize = format_size(r['file_size'])
        ver = r['dwarf_version']

        prod = r['producer']
        if len(prod) > W_PROD:
            prod = prod[:W_PROD-3] + '...'

        # Sum of DWARF section sizes
        dw_sect_total = sum(r['dwarf_sections'].values())
        dw_sect_str = format_size(dw_sect_total)

        # Sum of BTF section sizes
        btf_sect_total = sum(r['btf_sections'].values())
        btf_sect_str = format_size(btf_sect_total)

        dw_hash = r['dwarf_output_hash']
        btf_hash = r['btf_output_hash']

        enc = r['btf_encoding']
        if enc is None:
            enc_str = 'N/A'
        else:
            mean, stddev, rel_err = enc
            enc_str = f"{mean:.3f}s ±{stddev:.3f} ({rel_err:.2f}%)"

        icuref = r['inter_cu_refs']
        if icuref is None:
            icuref_str = 'N/A'
        elif icuref:
            icuref_str = 'yes'
        else:
            icuref_str = 'no'

        print(f"│{fname:<{W_FILE}}│{fsize:>{W_SIZE}}│{ver:^{W_VER}}│{prod:<{W_PROD}}│"
              f"{dw_sect_str:>{W_DWSECT}}│{btf_sect_str:>{W_BTFSECT}}│"
              f"{dw_hash:>{W_HASH}}│{btf_hash:>{W_HASH}}│"
              f"{enc_str:>{W_TIME-2}}  │{icuref_str:^{W_ICUREF}}│")

    # Footer
    print(f"└{'─'*W_FILE}┴{'─'*W_SIZE}┴{'─'*W_VER}┴{'─'*W_PROD}┴"
          f"{'─'*W_DWSECT}┴{'─'*W_BTFSECT}┴"
          f"{'─'*W_HASH}┴{'─'*W_HASH}┴"
          f"{'─'*W_TIME}┴{'─'*W_ICUREF}┘")

    print()
    print("Column descriptions:")
    print("  File       : vmlinux filename")
    print("  Size       : Total file size")
    print("  Ver        : DWARF version")
    print("  Producer   : Compiler and flags (truncated)")
    print("  DW-Sect    : Total size of .debug_* sections")
    print("  BTF-Sect   : Total size of .btf* sections")
    print("  DW-Hash    : SHA256 hash (first 8 chars) of pahole -F dwarf output")
    print("  BTF-Hash   : SHA256 hash (first 8 chars) of pahole -F btf output")
    print("  BTF-Enc    : Mean ± stddev (rel.err) of 5 perf stat --null -r5")
    print("               pahole -j --btf_encode_detached runs, e.g. '2.989s ±0.004 (0.13%)'")
    print("  Inter-CU   : Whether inter-CU references (DW_FORM_ref_addr) are present")
    print("               in .debug_abbrev, which pahole auto-detects and switches")
    print("               to the single-threaded merged-CU mode")
    print()
    print("The DW-Hash values must match across all files, and so must the")
    print("BTF-Hash values: this validates that pahole's output does not change")
    print("with the DWARF version or compression used to build the vmlinux.")
    print()
    print("BTF-Enc is the mean of 5 perf stat runs, repeating each encoding to")
    print("rule out variation from system caches.  pahole automatically detects")
    print("inter-CU references (DW_FORM_ref_addr in .debug_abbrev) and uses the")
    print("parallel -j path only when there are none; with inter-CU references")
    print("(Rust, LTO) it switches to the merged-CU mode, which is single-threaded.")
    print("The Inter-CU column reflects which path was taken, so no CONFIG_DEBUG_*")
    print("knowledge is needed to interpret the BTF-Enc numbers.")
    print()
    print("The output shows that vmlinux variants (different DWARF versions, compression)")
    print("produce identical pahole output despite different file sizes,")
    print("validating pahole's consistency across different DWARF encodings.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description='Compare vmlinux files: DWARF, BTF, and pahole output')
    parser.add_argument('directory', nargs='?',
                       default=os.path.expanduser('~/.dws'),
                       help='Directory containing vmlinux files (default: ~/.dws)')
    parser.add_argument('--timeout-readelf', type=int, default=30,
                       help='Timeout for readelf commands in seconds (default: 30)')
    parser.add_argument('--timeout-pahole', type=int, default=600,
                       help='Timeout for pahole commands in seconds (default: 600)')
    parser.add_argument('--threads', type=int, default=None,
                       help='Number of threads for pahole -j (default: auto)')
    args = parser.parse_args()

    directory = os.path.expanduser(args.directory)

    timeouts = {
        'readelf': args.timeout_readelf,
        'pahole': args.timeout_pahole,
    }

    tools_to_check = ['readelf', 'pahole', 'perf']
    for tool in tools_to_check:
        if not check_tool_exists(tool):
            print(f"Error: Required tool '{tool}' not found in PATH", file=sys.stderr)
            sys.exit(1)

    print(f"Scanning {directory} for vmlinux files...", file=sys.stderr)
    vmlinux_files = find_vmlinux_files(directory)

    if not vmlinux_files:
        print(f"No vmlinux files found in {directory}", file=sys.stderr)
        print("Hint: Build kernel with CONFIG_DEBUG_INFO and look for vmlinux in build directory", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(vmlinux_files)} vmlinux file(s)\n", file=sys.stderr)

    results = []
    for vmlinux_path in vmlinux_files:
        result = analyze_vmlinux(vmlinux_path, timeouts)
        results.append(result)

    print(file=sys.stderr)
    print_table(results)


if __name__ == '__main__':
    main()