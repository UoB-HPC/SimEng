#!/bin/bash
# This script is not intended be to run direct but rather to be sourced from other scripts

## Set up file structure
export SIMENG_TOP="$PWD"
export SIMENG_BUILD="$PWD"/build
export SIMENG_INSTALL="$PWD"/install

debug () {
    echo "MODULES"
    module li
    echo "CURRENT DIRECTORY"
    echo "$PWD"
    echo "GIT BRANCH"
    git branch

    echo "SIMENG TOP $SIMENG_TOP"
    echo "SIMENG BUILD $SIMENG_BUILD"
    echo "SIMENG INSTALL $SIMENG_INSTALL"
}

# If source available clean and checkout, otherwise download
checkout () {
    cd "$SIMENG_TOP" || exit
    rm -rf build install
    mkdir build install

    cd external/capstone || exit
    git fetch
    git checkout next

    cd "$SIMENG_TOP" || exit
    git reset --hard
}

# Build common function
build () {
    cd "$SIMENG_TOP" || exit
    rm -rf build/* install/*

    cd "$SIMENG_BUILD" || exit
    echo "$PWD"
    cmake "$SIMENG_TOP" -DCMAKE_BUILD_TYPE=Debug -DCMAKE_INSTALL_PREFIX="$SIMENG_INSTALL"
    make -j
    make install
}

# Run tests common function
run () {
    cd "$SIMENG_BUILD" || exit
    ./test/unit/unittests --gtest_output=xml:unittests.xml || true
    ./test/regression/aarch64/regression-aarch64 --gtest_output=xml:regressiontests.xml || true
}
