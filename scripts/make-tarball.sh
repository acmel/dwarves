#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright © 2026 Red Hat Inc, Arnaldo Carvalho de Melo <acme@redhat.com>
#
# Generate release tarball with version derived from CMakeLists.txt.
# Similar to Linux kernel's perf-tar-src-pkg targets.
# Includes a HEAD file with the git SHA for build containers.
#
# Usage: make-tarball.sh {xz|gz|bz2|tar}
#
# Run from the source root: the MANIFEST file lists the files to
# package, relative to the source root, and the tarball is created in
# the current directory by default (TARBALL_DIR to override), like the
# kernel's perf-tar-src-pkg targets.

set -e

if [ $# -ne 1 ]; then
	echo "Usage: $0 {xz|gz|bz2|tar}" >&2
	exit 1
fi

if [ ! -f MANIFEST ]; then
	echo "Error: MANIFEST not found, run this script from the source root" >&2
	exit 1
fi

compression="$1"

# Validate compression type
case "$compression" in
	xz|gz|bz2|tar)
		;;
	*)
		echo "Error: unknown compression type '$compression'" >&2
		echo "Valid types: xz, gz, bz2, tar" >&2
		exit 1
		;;
esac

# Calculate version from CMakeLists.txt so the tarball name matches
# the version pahole --version reports (DWARVES_MAJOR.MINOR_VERSION)
major=$(sed -n 's/.*DWARVES_MAJOR_VERSION=\([0-9][0-9]*\).*/\1/p' CMakeLists.txt | head -1)
minor=$(sed -n 's/.*DWARVES_MINOR_VERSION=\([0-9][0-9]*\).*/\1/p' CMakeLists.txt | head -1)
if [ -z "$major" ] || [ -z "$minor" ]; then
	echo "Error: couldn't determine version from CMakeLists.txt" >&2
	exit 1
fi
version="${major}.${minor}"

# Set up tarball output (current directory by default, like kernel)
tarball_dir="${TARBALL_DIR:-.}"
if [ "$tarball_dir" != "." ]; then
	mkdir -p "$tarball_dir"
fi

case "$compression" in
	xz)
		tarball="${tarball_dir}/dwarves-${version}.tar.xz"
		tar_opts="cvfJ"
		;;
	gz)
		tarball="${tarball_dir}/dwarves-${version}.tar.gz"
		tar_opts="cvfz"
		;;
	bz2)
		tarball="${tarball_dir}/dwarves-${version}.tar.bz2"
		tar_opts="cvfj"
		;;
	tar)
		tarball="${tarball_dir}/dwarves-${version}.tar"
		tar_opts="cvf"
		;;
esac

# Create temporary HEAD file with current git SHA
# This lets build containers know exactly what source they're building
git rev-parse HEAD > HEAD
trap 'rm -f HEAD' EXIT

# Get list of files from MANIFEST (paths relative to source root)
manifest_files=$(sed 's%^%./%g' MANIFEST)

echo "Creating $tarball from MANIFEST files + HEAD"
echo "Version: ${version} (from CMakeLists.txt)"
echo "HEAD: $(cat HEAD)"
echo ""

# Create tarball with version-prefixed directory structure
# Transform: ./foo -> dwarves-X.Y/foo
tar $tar_opts "$tarball" \
	--transform "s,^\./,dwarves-${version}/," \
	$manifest_files \
	./HEAD

rm -f HEAD

echo ""
echo "Created: $tarball"
ls -lh "$tarball" | awk '{print "Size:    " $5}'
echo ""
