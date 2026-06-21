#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Run tests with LLVM source-based coverage and generate HTML report.
#
# Prerequisites:
#   cmake -DCMAKE_C_COMPILER=clang -DENABLE_COVERAGE=ON -DCMAKE_BUILD_TYPE=Debug ..
#   make -j$(nproc)
#
# Usage:
#   coverage/coverage.sh             # run from repo root
#   BUILD_DIR=/path/to/build coverage/coverage.sh
#   COV_DIR=/tmp/cov coverage/coverage.sh

SCRIPT_DIR=$(dirname "$0")
REPO_DIR=$(cd "$SCRIPT_DIR/.." 2>/dev/null && pwd)
BUILD_DIR=${BUILD_DIR:-$(cd "$REPO_DIR/build" 2>/dev/null && pwd)}
BUILD_DIR=$(CDPATH= cd -- "$BUILD_DIR" 2>/dev/null && pwd) || true
COV_DIR=${COV_DIR:-$BUILD_DIR/coverage}
case "$COV_DIR" in /*) ;; *) COV_DIR="$PWD/$COV_DIR" ;; esac

LLVM_PROFDATA=${LLVM_PROFDATA:-llvm-profdata}
LLVM_COV=${LLVM_COV:-llvm-cov}

if [ ! -x "$BUILD_DIR/pahole" ]; then
	echo "error: $BUILD_DIR/pahole not found. Set BUILD_DIR to point to the build directory." >&2
	exit 1
fi

if ! command -v "$LLVM_PROFDATA" > /dev/null 2>&1; then
	echo "error: $LLVM_PROFDATA not found. Install llvm or set LLVM_PROFDATA." >&2
	exit 1
fi

if ! command -v "$LLVM_COV" > /dev/null 2>&1; then
	echo "error: $LLVM_COV not found. Install llvm or set LLVM_COV." >&2
	exit 1
fi

rm -rf "$COV_DIR/raw" "$COV_DIR/html" "$COV_DIR/merged.profdata"
mkdir -p "$COV_DIR/raw"

echo "=== Running tests with coverage instrumentation ==="
LLVM_PROFILE_FILE="$COV_DIR/raw/pahole-%p-%m.profraw" \
	PATH="$BUILD_DIR:$PATH" \
	"$REPO_DIR/tests/tests" "$@"

test_status=$?

profraw_count=$(find "$COV_DIR/raw" -name '*.profraw' | wc -l)
if [ "$profraw_count" -eq 0 ]; then
	echo "error: no .profraw files generated. Was pahole built with -DENABLE_COVERAGE=ON?" >&2
	exit 1
fi

echo ""
echo "=== Merging $profraw_count profile files ==="
"$LLVM_PROFDATA" merge -sparse "$COV_DIR/raw"/*.profraw -o "$COV_DIR/pahole.profdata"
if [ $? -ne 0 ]; then
	echo "error: llvm-profdata merge failed" >&2
	exit 1
fi

set -- "$BUILD_DIR/pahole"
for bin in pfunct pdwtags pglobal codiff prefcnt dtagnames scncopy syscse; do
	if [ -x "$BUILD_DIR/$bin" ]; then
		set -- "$@" "--object=$BUILD_DIR/$bin"
	fi
done
for lib in libdwarves.so libdwarves_emit.so libdwarves_reorganize.so; do
	if [ -f "$BUILD_DIR/$lib" ]; then
		set -- "$@" "--object=$BUILD_DIR/$lib"
	fi
done

echo "=== Generating HTML coverage report ==="
"$LLVM_COV" show "$@" \
	--instr-profile="$COV_DIR/pahole.profdata" \
	--format=html \
	--output-dir="$COV_DIR/html" \
	--show-line-counts-or-regions \
	--show-branches=count

echo ""
echo "=== Coverage Summary ==="
"$LLVM_COV" report "$@" \
	--instr-profile="$COV_DIR/pahole.profdata"

echo ""
echo "HTML report: $COV_DIR/html/index.html"
exit $test_status
