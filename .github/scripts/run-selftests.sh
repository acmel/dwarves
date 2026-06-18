#!/usr/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (c) 2025, Oracle and/or its affiliates.
#

GITHUB_WORKSPACE=${GITHUB_WORKSPACE:-$(pwd)}
VMLINUX=${GITHUB_WORKSPACE}/.kernel/vmlinux
SELFTESTS=${GITHUB_WORKSPACE}/tests
cd $SELFTESTS
export PATH=${GITHUB_WORKSPACE}/install/usr/local/bin:${GITHUB_WORKSPACE}/install/usr/local/sbin:${PATH}
export LLVM_OBJCOPY=objcopy
which pahole
pahole --version
bpftool --version
vmlinux=$VMLINUX ./tests

