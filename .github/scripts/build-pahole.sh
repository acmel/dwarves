#!/usr/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (c) 2025, Oracle and/or its affiliates.
#

function restore() {
	git checkout $SHA
	git submodule update
}

GITHUB_WORKSPACE=${GITHUB_WORKSPACE:-$(dirname $0)/../..}
BASELINE=${BASELINE:-next}

cd $GITHUB_WORKSPACE
git log --oneline -1
git config --global --add safe.directory $GITHUB_WORKSPACE
git submodule update --init
mkdir -p build
cd build
pwd
cmake -DGIT_SUBMODULE=OFF -DBUILD_SHARED_LIBS=OFF ..
make -j$((4*$(nproc))) all
make DESTDIR=../install install

# save sha to restore after building baseline
cd $GITHUB_WORKSPACE
export SHA=$(git log --format="%h" -1)
trap restore EXIT

git fetch origin ${BASELINE}:${BASELINE}
git checkout ${BASELINE}
git log --oneline -1
git submodule update
mkdir -p build.$BASELINE
cd build.$BASELINE
pwd
cmake -DGIT_SUBMODULE=OFF -DBUILD_SHARED_LIBS=OFF ..
make -j$((4*$(nproc))) all
make DESTDIR=../install.$BASELINE install
