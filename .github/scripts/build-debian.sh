#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (c) 2025, Oracle and/or its affiliates.
#

PHASES=(${@:-SETUP RUN CLEANUP})
DEBIAN_RELEASE="${DEBIAN_RELEASE:-testing}"
CONT_NAME="${CONT_NAME:-dwarves-debian-$DEBIAN_RELEASE}"
ENV_VARS="${ENV_VARS:-}"
DOCKER_RUN="${DOCKER_RUN:-docker run}"
REPO_ROOT="${REPO_ROOT:-$PWD}"
ADDITIONAL_DEPS=(pkgconf)
EXTRA_CFLAGS=""
EXTRA_LDFLAGS=""

function info() {
    echo -e "\033[33;1m$1\033[0m"
}

function error() {
    echo -e "\033[31;1m$1\033[0m"
}

function docker_exec() {
    docker exec $ENV_VARS $CONT_NAME "$@"
}

set -eu

source "$(dirname $0)/travis_wait.bash"

for phase in "${PHASES[@]}"; do
    case $phase in
        SETUP)
            info "Setup phase"
            info "Using Debian $DEBIAN_RELEASE"

            docker --version

            docker pull debian:$DEBIAN_RELEASE
            info "Starting container $CONT_NAME"
            $DOCKER_RUN -v $REPO_ROOT:/build:rw \
                        -w /build --privileged=true --name $CONT_NAME \
                        -dit --net=host debian:$DEBIAN_RELEASE /bin/bash
            echo -e "::group::Build Env Setup"

            docker_exec apt-get -y update
            docker_exec apt-get -y install aptitude
            docker_exec aptitude -y install make cmake libz-dev libelf-dev libdw-dev git
            docker_exec aptitude -y install "${ADDITIONAL_DEPS[@]}"
            echo -e "::endgroup::"
            ;;
        RUN|RUN_CLANG|RUN_CLANG16|RUN_GCC12)
            CC="cc"
            if [[ "$phase" =~ "RUN_CLANG(\d+)(_ASAN)?" ]]; then
                ENV_VARS="-e CC=clang-${BASH_REMATCH[1]} -e CXX=clang++-${BASH_REMATCH[1]}"
                CC="clang-${BASH_REMATCH[1]}"
            elif [[ "$phase" = *"CLANG"* ]]; then
                ENV_VARS="-e CC=clang -e CXX=clang++"
                CC="clang"
            elif [[ "$phase" =~ "RUN_GCC(\d+)(_ASAN)?" ]]; then
                ENV_VARS="-e CC=gcc-${BASH_REMATCH[1]} -e CXX=g++-${BASH_REMATCH[1]}"
                CC="gcc-${BASH_REMATCH[1]}"
            fi
            if [[ "$CC" != "cc" ]]; then
                docker_exec aptitude -y install "$CC"
            else
                docker_exec aptitude -y install gcc
            fi
	    git config --global --add safe.directory $REPO_ROOT
	    pushd $REPO_ROOT
	    git submodule update --init
	    popd
            docker_exec mkdir build install
            docker_exec ${CC} --version
            info "build"
            docker_exec cmake -DGIT_SUBMODULE=OFF .
	    docker_exec make -j$((4*$(nproc)))
            info "install"
            docker_exec make DESTDIR=../install install
            ;;
        CLEANUP)
            info "Cleanup phase"
            docker stop $CONT_NAME
            docker rm -f $CONT_NAME
            ;;
        *)
            echo >&2 "Unknown phase '$phase'"
            exit 1
    esac
done
