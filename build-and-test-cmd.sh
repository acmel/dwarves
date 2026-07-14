#!/bin/sh

# Build the tools
./buildcmd.sh || exit 1

# Prepend build directory to PATH so tests use the just-built binaries
# (not installed versions or other build directories like build-coverage/)
export PATH="$(pwd)/build:$PATH"

# Use quick mode for BTF functions test (~30ms instead of 2+ minutes)
# Full vmlinux validation is tested in CI with BTF_FUNCTIONS_QUICK=0
export BTF_FUNCTIONS_QUICK=1

# Set artifact dump limits (tune based on actual failures)
# - 100KB limit: most test .o files are <50KB, this catches them
# - 5 files: enough to see the key artifacts without overwhelming output
export ARTIFACT_SIZE_LIMIT=100
export ARTIFACT_FILE_LIMIT=5

# Run tests in verbose mode with artifact dumping for better failure diagnosis
# --dump-artifacts captures DWARF/BTF info from binary files before they vanish
tests/tests -v --dump-artifacts
