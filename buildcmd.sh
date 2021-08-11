#!/bin/sh

mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
cd ..
make -j $(getconf _NPROCESSORS_ONLN) -C build
