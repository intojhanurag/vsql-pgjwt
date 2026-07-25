#!/bin/bash
set -e

BUILD_DIR="build"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

cmake .. "$@"
make -j$(getconf _NPROCESSORS_ONLN)
