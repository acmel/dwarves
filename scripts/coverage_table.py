#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Generate an ASCII coverage table for pahole's own .c files.
#
# Usage:
#   # Auto-generate and display (uses build-coverage/ defaults):
#   scripts/coverage_table.py
#
#   # Or pass an existing llvm-cov report:
#   scripts/coverage_table.py /tmp/coverage_report.txt
#
#   # Override build directory:
#   scripts/coverage_table.py --build-dir=/path/to/build

import argparse
import glob
import os
import subprocess
import sys


BINARIES = ['pfunct', 'pdwtags', 'pglobal', 'codiff', 'prefcnt',
            'dtagnames', 'ctracer', 'scncopy', 'syscse']
LIBRARIES = ['libdwarves.so', 'libdwarves_emit.so', 'libdwarves_reorganize.so']


def check_staleness(build_dir):
    """Warn if source or test files are newer than the profdata."""
    repo_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    profdata = os.path.join(build_dir, 'coverage', 'pahole.profdata')
    if not os.path.isfile(profdata):
        return
    prof_mtime = os.path.getmtime(profdata)
    changed = []
    for pattern in [os.path.join(repo_dir, '*.[ch]'),
                    os.path.join(repo_dir, 'tests', '*.sh')]:
        for path in glob.glob(pattern):
            if os.path.getmtime(path) > prof_mtime:
                changed.append(os.path.relpath(path, repo_dir))
    if changed:
        print("warning: profdata is older than source/test changes, "
              "results may be stale.", file=sys.stderr)
        print("  hint: run 'make coverage' to rebuild and re-collect.",
              file=sys.stderr)
        print(f"  changed: {' '.join(changed[:5])}", file=sys.stderr)
        print(file=sys.stderr)


def generate_report(build_dir):
    """Run llvm-cov report and return the output as a string."""
    profdata = os.path.join(build_dir, 'coverage', 'pahole.profdata')
    if not os.path.isfile(profdata):
        print(f"error: {profdata} not found.\n"
              f"Run coverage/coverage-diff.sh first to generate profdata.",
              file=sys.stderr)
        sys.exit(1)

    check_staleness(build_dir)

    pahole = os.path.join(build_dir, 'pahole')
    if not os.path.isfile(pahole):
        print(f"error: {pahole} not found.", file=sys.stderr)
        sys.exit(1)

    llvm_cov = os.environ.get('LLVM_COV', 'llvm-cov')
    cmd = [llvm_cov, 'report', pahole]
    for b in BINARIES:
        p = os.path.join(build_dir, b)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            cmd += ['--object', p]
    for lib in LIBRARIES:
        p = os.path.join(build_dir, lib)
        if os.path.isfile(p):
            cmd += ['--object', p]
    cmd += ['--instr-profile', profdata]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        print("error: llvm-cov not found in PATH.", file=sys.stderr)
        sys.exit(1)

    if result.returncode != 0:
        print(f"error: llvm-cov report failed:\n{result.stderr}", file=sys.stderr)
        sys.exit(1)

    return result.stdout


def parse_report(text, exclude_vendored):
    files = []
    for line in text.splitlines():
        parts = line.split()
        if not parts or not parts[0].endswith('.c'):
            continue
        if exclude_vendored and 'lib/bpf/' in parts[0]:
            continue
        name = parts[0]
        vals = parts[1:]
        if len(vals) < 9:
            continue
        lines = int(vals[6])
        missed = int(vals[7])
        hit = lines - missed
        line_cov = vals[8]
        funcs = int(vals[3])
        funcs_missed = int(vals[4])
        funcs_hit = funcs - funcs_missed
        func_cov = vals[5]
        files.append((name, lines, hit, missed, line_cov, funcs, funcs_hit, func_cov))
    return files


def bar(pct_str, width=20):
    # llvm-cov outputs "-" for files with zero executable lines
    if pct_str == '-' or pct_str == '-%':
        return '░' * width
    pct = float(pct_str.rstrip('%'))
    filled = int(pct * width / 100)
    return '█' * filled + '░' * (width - filled)


def print_table(files):
    files.sort(key=lambda x: float(x[4].rstrip('%')) if x[4] not in ('-', '-%') else 0.0, reverse=True)

    tot_lines = sum(f[1] for f in files)
    tot_hit = sum(f[2] for f in files)
    tot_missed = sum(f[3] for f in files)
    tot_funcs = sum(f[5] for f in files)
    tot_funcs_hit = sum(f[6] for f in files)
    tot_line_pct = f"{100*tot_hit/tot_lines:.1f}%" if tot_lines else "0%"
    tot_func_pct = f"{100*tot_funcs_hit/tot_funcs:.1f}%" if tot_funcs else "0%"

    W = 24
    BAR_W = 20
    COV_W = BAR_W + 1 + 6
    print(f"┌{'─'*(W+2)}┬{'─'*8}┬{'─'*8}┬{'─'*8}┬{'─'*(COV_W+2)}┬{'─'*10}┬{'─'*10}┐")
    print(f"│ {'File':<{W}} │ {'Lines':>6} │ {'Hit':>6} │ {'Miss':>6} │ {'Line Coverage':^{COV_W}} │ {'Funcs':>8} │ {'FuncCov':>8} │")
    print(f"├{'─'*(W+2)}┼{'─'*8}┼{'─'*8}┼{'─'*8}┼{'─'*(COV_W+2)}┼{'─'*10}┼{'─'*10}┤")

    for name, lines, hit, missed, line_cov, funcs, funcs_hit, func_cov in files:
        pct = float(line_cov.rstrip('%')) if line_cov not in ('-', '-%') else 0.0
        b = bar(line_cov, BAR_W)
        print(f"│ {name:<{W}} │ {lines:>6} │ {hit:>6} │ {missed:>6} │ {b} {pct:>5.1f}% │ {funcs_hit:>3}/{funcs:<4} │ {func_cov:>8} │")

    print(f"├{'─'*(W+2)}┼{'─'*8}┼{'─'*8}┼{'─'*8}┼{'─'*(COV_W+2)}┼{'─'*10}┼{'─'*10}┤")
    tot_pct = float(tot_line_pct.rstrip('%')) if tot_line_pct not in ('-', '-%') else 0.0
    b = bar(tot_line_pct, BAR_W)
    print(f"│ {'TOTAL':<{W}} │ {tot_lines:>6} │ {tot_hit:>6} │ {tot_missed:>6} │ {b} {tot_pct:>5.1f}% │ {tot_funcs_hit:>3}/{tot_funcs:<4} │ {tot_func_pct:>8} │")
    print(f"└{'─'*(W+2)}┴{'─'*8}┴{'─'*8}┴{'─'*8}┴{'─'*(COV_W+2)}┴{'─'*10}┴{'─'*10}┘")


def main():
    parser = argparse.ArgumentParser(description='Generate ASCII coverage table from llvm-cov report')
    parser.add_argument('report', nargs='?', default=None,
                        help='Path to llvm-cov report (omit to auto-generate)')
    parser.add_argument('--build-dir', default='build-coverage',
                        help='Coverage build directory (default: build-coverage)')
    parser.add_argument('--exclude-vendored', action='store_true', default=True,
                        help='Exclude lib/bpf/ vendored files (default: true)')
    parser.add_argument('--include-vendored', action='store_true',
                        help='Include lib/bpf/ vendored files')
    args = parser.parse_args()

    exclude = not args.include_vendored

    if args.report:
        with open(args.report) as f:
            text = f.read()
    else:
        text = generate_report(args.build_dir)

    files = parse_report(text, exclude)
    if not files:
        print("No .c files found in report", file=sys.stderr)
        sys.exit(1)
    print_table(files)


if __name__ == '__main__':
    main()
