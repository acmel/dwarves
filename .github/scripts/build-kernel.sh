#!/usr/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (c) 2025, Oracle and/or its affiliates.
#

GITHUB_WORKSPACE=${GITHUB_WORKSPACE:-$(dirname $0)/../..}
INPUTS_ARCH=${INPUTS_ARCH:-$(uname -m)}
REPO=${REPO:-https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git}
REPO_BRANCH=${REPO_BRANCH:-master}
REPO_TARGET=${GITHUB_WORKSPACE}/.kernel

export PATH=${GITHUB_WORKSPACE}/install/usr/local/bin:${PATH}
export PAHOLE=${GITHUB_WORKSPACE}/install/usr/local/bin/pahole

which pahole
$PAHOLE --version

if [[ ! -d $REPO_TARGET ]]; then
	git clone $REPO $REPO_TARGET
fi
cd $REPO_TARGET
git checkout $REPO_BRANCH

cat tools/testing/selftests/bpf/config \
    tools/testing/selftests/bpf/config.${INPUTS_ARCH} > .config
# this file might or might not exist depending on kernel version
if [[ -f tools/testing/selftests/bpf/config.vm ]]; then
	cat tools/testing/selftests/bpf/config.vm >> .config
fi
make olddefconfig && make prepare
cat .config
make -j $((4*$(nproc))) all

