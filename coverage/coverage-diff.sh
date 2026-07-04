#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Full coverage workflow: rebuild with instrumentation, run tests,
# generate report, compare against baseline, and suggest targets.
#
# Usage:
#   coverage/coverage-diff.sh              # full rebuild + report + diff
#   coverage/coverage-diff.sh --skip-build # reuse existing build, just re-run tests
#   coverage/coverage-diff.sh --report-only # skip build+tests, regenerate from existing profdata
#
# The baseline file is stored at coverage-report.txt in the repo root.
# After each run, the new report becomes the baseline for next time.

set -e

SCRIPT_DIR=$(dirname "$0")
REPO_DIR=$(cd "$SCRIPT_DIR/.." 2>/dev/null && pwd)
BUILD_DIR=${BUILD_DIR:-$REPO_DIR/build-coverage}
BASELINE=${BASELINE:-$REPO_DIR/coverage-report.txt}
LLVM_PROFDATA=${LLVM_PROFDATA:-llvm-profdata}
LLVM_COV=${LLVM_COV:-llvm-cov}
MAKE_JOBS=${MAKE_JOBS:-32}

skip_build=false
report_only=false

for arg in "$@"; do
	case "$arg" in
	--skip-build) skip_build=true ;;
	--report-only) report_only=true; skip_build=true ;;
	--help|-h)
		echo "Usage: $0 [--skip-build] [--report-only]"
		echo ""
		echo "  --skip-build   Reuse existing build, just re-run tests and report"
		echo "  --report-only  Skip build and tests, regenerate report from existing profdata"
		echo ""
		echo "Environment:"
		echo "  BUILD_DIR      Build directory (default: build-coverage/)"
		echo "  BASELINE       Baseline report file (default: coverage-report.txt)"
		echo "  MAKE_JOBS      Parallel make jobs (default: 32)"
		exit 0
		;;
	esac
done

# extract_lines_pct FILE FILENAME
# Extracts lines coverage % for a file from an llvm-cov report.
# The 3rd percentage column is always lines coverage.
extract_lines_pct() {
	awk -v f="$2" '$1 == f {
		n = 0
		for (i = 1; i <= NF; i++) {
			if ($i ~ /[0-9]+\.[0-9]+%/) {
				n++
				if (n == 3) { gsub(/%/, "", $i); print $i; exit }
			}
		}
	}' "$1"
}

# extract_lines_missed FILE FILENAME
# Extracts missed lines count (the number before the 3rd percentage).
extract_lines_missed() {
	awk -v f="$2" '$1 == f {
		n = 0
		prev = ""
		for (i = 1; i <= NF; i++) {
			if ($i ~ /[0-9]+\.[0-9]+%/) {
				n++
				if (n == 3) { print prev; exit }
			}
			prev = $i
		}
	}' "$1"
}

# ── Step 1: Rebuild with instrumentation ──────────────────────────────

if [ "$skip_build" = false ]; then
	echo "=== Step 1: Rebuilding with coverage instrumentation ==="
	mkdir -p "$BUILD_DIR"
	# Capture both cmake and make output so any build failure is visible.
	# We can't use a simple || because both commands are in a subshell.
	(cd "$BUILD_DIR" && \
	 cmake -DCMAKE_C_COMPILER=clang \
		-DENABLE_COVERAGE=ON \
		-DCMAKE_BUILD_TYPE=Debug \
		"$REPO_DIR" > "$BUILD_DIR/.build.log" 2>&1 && \
	 make -j${MAKE_JOBS} >> "$BUILD_DIR/.build.log" 2>&1) || {
		echo "error: build failed:" >&2
		[ -f "$BUILD_DIR/.build.log" ] && tail -10 "$BUILD_DIR/.build.log" >&2
		exit 1
	}
	[ -f "$BUILD_DIR/.build.log" ] && tail -1 "$BUILD_DIR/.build.log"
	echo ""
fi

# ── Step 2: Run tests with coverage ──────────────────────────────────

COV_DIR="$BUILD_DIR/coverage"

if [ "$report_only" = false ]; then
	echo "=== Step 2: Running tests with coverage ==="
	rm -rf "$COV_DIR/raw" "$COV_DIR/pahole.profdata"
	mkdir -p "$COV_DIR/raw"

	set +e
	LLVM_PROFILE_FILE="$COV_DIR/raw/pahole-%p-%m.profraw" \
		PATH="$BUILD_DIR:$PATH" \
		"$REPO_DIR/tests/tests" 2>&1 | tail -3
	set -e

	profraw_count=$(find "$COV_DIR/raw" -name '*.profraw' | wc -l)
	if [ "$profraw_count" -eq 0 ]; then
		echo "error: no .profraw files generated" >&2
		exit 1
	fi

	echo ""
	echo "=== Merging $profraw_count profile files ==="
	"$LLVM_PROFDATA" merge -sparse "$COV_DIR/raw"/*.profraw \
		-o "$COV_DIR/pahole.profdata"
	echo ""
fi

# ── Staleness check ──────────────────────────────────────────────────

if [ ! -f "$COV_DIR/pahole.profdata" ]; then
	echo "error: $COV_DIR/pahole.profdata not found. Run without --report-only first." >&2
	exit 1
fi

if [ "$report_only" = true ]; then
	stale=$(find "$REPO_DIR" -maxdepth 1 \( -name '*.c' -o -name '*.h' \) \
		-newer "$COV_DIR/pahole.profdata" 2>/dev/null | head -5)
	stale_tests=$(find "$REPO_DIR/tests" -name '*.sh' \
		-newer "$COV_DIR/pahole.profdata" 2>/dev/null | head -5)
	stale="$stale $stale_tests"
	stale=$(echo "$stale" | xargs)
	if [ -n "$stale" ]; then
		echo "warning: profdata is older than source/test changes, results may be stale." >&2
		echo "  hint: run 'make coverage' to rebuild and re-collect." >&2
		echo "  changed: $stale" >&2
		echo "" >&2
	fi
fi

# ── Step 3: Build object list for llvm-cov ───────────────────────────

objects="$BUILD_DIR/pahole"
for bin in pfunct pdwtags pglobal codiff prefcnt dtagnames ctracer scncopy syscse; do
	[ -x "$BUILD_DIR/$bin" ] && objects="$objects --object=$BUILD_DIR/$bin"
done
for lib in libdwarves.so libdwarves_emit.so libdwarves_reorganize.so; do
	[ -f "$BUILD_DIR/$lib" ] && objects="$objects --object=$BUILD_DIR/$lib"
done

# ── Step 4: Generate report ──────────────────────────────────────────

echo "=== Step 3: Generating coverage report ==="
new_report="$COV_DIR/report.txt"

$LLVM_COV report $objects \
	--instr-profile="$COV_DIR/pahole.profdata" \
	> "$new_report" 2>/dev/null

# ── Step 5: Extract per-file table and compare ───────────────────────

echo ""
printf "%-26s  %8s  %8s  %9s\n" "File" "Previous" "Current" "Delta"
printf "%-26s  %8s  %8s  %9s\n" \
	"--------------------------" "--------" "--------" "---------"

# Collect .c and .h files from the new report, skip vendored lib/bpf/
grep -E '\.[ch]\b' "$new_report" | grep -v '^-\|^lib/' | awk '{print $1}' | while read -r file; do
	new_pct=$(extract_lines_pct "$new_report" "$file")
	[ -z "$new_pct" ] && continue

	old_pct=""
	delta=""
	if [ -f "$BASELINE" ]; then
		old_pct=$(extract_lines_pct "$BASELINE" "$file")
	fi

	if [ -n "$old_pct" ]; then
		delta=$(awk "BEGIN {d=$new_pct - $old_pct; printf \"%+.2f%%\", d}")
	else
		delta="(new)"
	fi

	printf "%-26s  %7s%%  %7s%%  %9s\n" \
		"$file" "${old_pct:---}" "$new_pct" "$delta"
done

# ── Step 6: Show all .c files sorted by coverage ─────────────────────

echo ""
echo "=== All .c files by coverage (ascending) ==="
echo ""
printf "  %-26s  %8s  %6s\n" "File" "Lines %" "Missed"
printf "  %-26s  %8s  %6s\n" "--------------------------" "--------" "------"

# Skip vendored lib/ — we only track our own code
grep '\.c\b' "$new_report" | grep -v '^-\|TOTAL\|^lib/' | awk '{print $1}' | while read -r file; do
	pct=$(extract_lines_pct "$new_report" "$file")
	missed=$(extract_lines_missed "$new_report" "$file")
	[ -z "$pct" ] && continue
	printf "  %-26s  %7s%%  %6s\n" "$file" "$pct" "${missed:--}"
done | sort -k2 -n

# ── Step 7: Update baseline ─────────────────────────────────────────

echo ""

# Save the raw llvm-cov report as the new baseline
grep -E '\.[ch]\b' "$new_report" | grep -v '^-\|^lib/' > "$BASELINE.new"

if [ -f "$BASELINE" ]; then
	mv "$BASELINE" "$BASELINE.prev"
fi
mv "$BASELINE.new" "$BASELINE"
echo "Baseline updated: $BASELINE"
if [ -f "$BASELINE.prev" ]; then
	echo "Previous baseline saved: $BASELINE.prev"
fi

# ── Step 8: Generate HTML report ────────────────────────────────────

echo ""
echo "=== Generating HTML report ==="
$LLVM_COV show $objects \
	--instr-profile="$COV_DIR/pahole.profdata" \
	--format=html \
	--output-dir="$COV_DIR/html" \
	--show-line-counts-or-regions \
	--show-branches=count 2>/dev/null
echo "HTML report: $COV_DIR/html/index.html"
echo "Done."
