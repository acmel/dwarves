#!/bin/sh

# Build the tools
./buildcmd.sh || exit 1

# Use quick mode for BTF functions test (~30ms instead of 2+ minutes)
# Full vmlinux validation is tested in CI with BTF_FUNCTIONS_QUICK=0
export BTF_FUNCTIONS_QUICK=1

# Run tests in verbose mode for better failure diagnosis
tests/tests -v
