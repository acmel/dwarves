#!/usr/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (c) 2025, Oracle and/or its affiliates.
#

GITHUB_WORKSPACE=${GITHUB_WORKSPACE:-$(dirname $0)/../..}
cd $GITHUB_WORKSPACE
git config --global --add safe.directory $GITHUB_WORKSPACE
git submodule update --init
mkdir -p build
cd build
pwd
cmake -DGIT_SUBMODULE=OFF -DBUILD_SHARED_LIBS=OFF ..
make -j$((4*$(nproc))) all
make DESTDIR=../install install

