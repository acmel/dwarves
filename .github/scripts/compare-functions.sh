#!/usr/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (c) 2025, Oracle and/or its affiliates.
#

GITHUB_WORKSPACE=${GITHUB_WORKSPACE:-$(pwd)}
REPO_TARGET=${GITHUB_WORKSPACE}/.kernel
VMLINUX=${GITHUB_WORKSPACE}/.kernel/vmlinux
BASELINE=${BASELINE:-next}
GITHUB_STEP_SUMMARY=${GITHUB_STEP_SUMMARY:-/dev/null}

export PATH=${GITHUB_WORKSPACE}/install/usr/local/bin:${PATH}
which pahole
pahole --version
cd $REPO_TARGET
pfunct --all --format_path=btf $VMLINUX > functions

rm -f vmlinux vmlinux.o

# now use baseline branch of pahole for comparison
export PATH=${GITHUB_WORKSPACE}/install.${BASELINE}/usr/local/bin:${PATH}
export PAHOLE=${GITHUB_WORKSPACE}/install.${BASELINE}/usr/local/bin/pahole
which pahole
pahole --version
make oldconfig
make -j $((4*$(nproc))) all
pfunct --all --format_path=btf $VMLINUX > functions.${BASELINE}
echo "### Compare vmlinux BTF functions generated with this change vs baseline (none means no differences)." | tee -a $GITHUB_STEP_SUMMARY
diff functions.${BASELINE} functions | tee -a $GITHUB_STEP_SUMMARY
