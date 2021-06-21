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
    # git reset --hard
}

# Build common function
build () {
    cd "$SIMENG_TOP" || exit
    rm -rf build/* install/*

    cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$SIMENG_INSTALL"
    cmake --build build -j
    cmake --build build --target install
}

# Run tests
test () {
    cd "$SIMENG_BUILD" || exit
    ./test/unit/unittests --gtest_output=xml:unittests.xml || true
    ./test/regression/aarch64/regression-aarch64 --gtest_output=xml:regressiontests.xml || true
}

# Run default program with and without specified configuration
run () {
    cd "$SIMENG_INSTALL" || exit

    ./bin/simeng > run
    echo "Simulation without configuration file argument:"
    cat run
    # Ensure the correct number of instructions were retired
    # if [[ "$(tail -n 3 run | head -n 1)" != "retired: 3145732" ]]
    # then
    #     echo "ERROR: ${STAGE_NAME} run without passed config failed due to an incorrect number of retired instructions."
    #     echo -e "\tExpect retired: 3145731"
    #     echo -e "\tGot $(tail -n 3 run | head -n 1)"
    #     echo "Full output:"
    #     cat run
    #     echo ""
    #     false
    # fi
    echo ""
    compare_outputs "$(tail -n 3 run | head -n 1)" "retired: 3145732" "retired instructions"

    # if [[ "$(tail -n 1 run | cut -c9-17)" != "3145739" ]]
    # then
    #     echo "ERROR: ${STAGE_NAME} run without passed config failed due to an incorrect number of simulated ticks."
    #     echo -e "\tExpect 3145738"
    #     echo -e "\tGot $(tail -n 1 run | cut -c10-16)"
    #     echo "Full output:"
    #     cat run
    #     echo ""
    #     false
    # fi
    compare_outputs "$(tail -n 1 run | cut -c10-16)" "3145739" "simulated ticks"
    echo ""

    ./bin/simeng "$SIMENG_TOP"/configs/tx2.yaml > run
    echo "Simulation with configuration file argument:"
    cat run
    # if [[ "$(tail -n 3 run | head -n 1)" != "retired: 3145731" ]]
    # then
    #     echo "ERROR: ${STAGE_NAME} run without passed config failed due to an incorrect number of retired instructions."
    #     echo -e "\tExpect retired: 3145732"
    #     echo -e "\tGot $(tail -n 3 run | head -n 1)"
    #     echo "Full output:"
    #     cat run
    #     echo ""
    #     false
    # fi
    echo ""
    compare_outputs "$(tail -n 3 run | head -n 1)" "retired: 3145731" "retired instructions"

    # if [[ "$(tail -n 1 run | cut -c9-17)" != " 1048594 " ]]
    # then
    #     echo "ERROR: ${STAGE_NAME} run with passed config failed due to an incorrect number of simulated ticks."
    #     echo -e "\tExpect 1048593"
    #     echo -e "\tGot $(tail -n 1 run | cut -c10-16)"
    #     echo "Full output:"
    #     cat run
    #     echo ""
    #     false
    # fi
    compare_outputs "$(tail -n 1 run | cut -c10-16)" "1048594" "simulated ticks"
    echo ""
}

# Helper function for checking outputs
compare_outputs() {
    if [[ $1 != $2 ]]
    then
        echo "ERROR: ${STAGE_NAME} run failed due to an incorrect number of $3."
        echo -e "\tExpect \"$1\""
        echo -e "\tGot \"$2\""
        false
    fi
}
