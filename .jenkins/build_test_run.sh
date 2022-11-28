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
}

# Build common function
build () {
    cd "$SIMENG_TOP" || exit
    rm -rf build/* install/*

    cmake -B build -S . -DCMAKE_BUILD_TYPE=Debug -DCMAKE_INSTALL_PREFIX="$SIMENG_INSTALL" -DSIMENG_ENABLE_TESTS=ON -DSIMENG_USE_EXTERNAL_LLVM=ON -DLLVM_DIR=/home/br-simeng/llvm14.0.5/install-gcc7/lib/cmake/llvm/ -DCMAKE_C_COMPILER=$1 -DCMAKE_CXX_COMPILER=$2
    cmake --build build -j
    cmake --build build --target install
}

# Run tests
test () {
    cd "$SIMENG_BUILD" || exit
    ./test/unit/unittests --gtest_output=xml:unittests.xml || true
    ./test/regression/aarch64/regression-aarch64 --gtest_output=xml:regressiontests.xml || true
    ./test/regression/riscv/regression-riscv --gtest_output=xml:regressiontests.xml || true
}

# Run default program with and without specified configuration
run () {
    cd "$SIMENG_INSTALL" || exit

    ./bin/simeng > run
    echo "Simulation without configuration file argument:"
    cat run
    echo ""
    compare_outputs "$(grep "retired:" run | rev | cut -d ' ' -f1 | rev)" "3145731" "retired instructions"
    compare_outputs "$(grep "cycles:" run | rev | cut -d ' ' -f1 | rev)" "3145736" "simulated cycles"
    echo ""

    ./bin/simeng "$SIMENG_TOP"/configs/tx2.yaml > run
    echo "Simulation with configuration file argument:"
    cat run
    echo ""
    compare_outputs "$(grep "retired:" run | rev | cut -d ' ' -f1 | rev)" "3145732" "retired instructions"
    compare_outputs "$(grep "cycles:" run | rev | cut -d ' ' -f1 | rev)" "1048588" "simulated cycles"
    echo ""
}

# Helper function for checking outputs
compare_outputs() {
    if [[ $1 != $2 ]]
    then
        echo "ERROR: ${STAGE_NAME} run failed due to an incorrect number of $3."
        echo -e "\tExpect \"$2\""
        echo -e "\tGot \"$1\""
        exit 1
    fi
}
