#!/bin/bash


## Set up file structure
export SIMENG_TOP=$PWD
export SIMENG_BUILD=$PWD/build
export SIMENG_INSTALL=$PWD/install

debug () {
    echo "MODULES"
    module li
    echo "CURRENT DIRECTORY"
    echo $PWD
    echo "GIT BRANCH"
    git branch

    echo "SIMENG TOP $SIMENG_TOP"
    echo "SIMENG BUILD $SIMENG_BUILD"
    echo "SIMENG INSTALL $SIMENG_INSTALL"

}

# If source available clean and checkout, otherwise download
checkout () {

    cd $SIMENG_TOP
    rm -rf build install
    mkdir build install

    #git submodule update --init
    #git submodule sync --recursive

    cd external/capstone
    git fetch
    git checkout next

    cd $SIMENG_TOP

    git stash
    git stash drop
    #git checkout ${ghprbActualCommit}



    #if [ ! -d "$SIMENG_TOP" ]
    #then
    #    echo "No repository found, recusively cloning SimEng"
    #    cd /home/br-hwaugh/jenkins/workspace/
    #    git clone --recurse-submodules https://github.com/UoB-HPC/SimEng.git
    #    cd SimEngBuild
    #    ## Download and update submodules
    #    git submodule update --init
    #    git submodule sync --recursive

    #   cd external/capstone
    #    git fetch
    #    git checkout next

    #    cd $SIMENG_TOP
    #    mkdir -p build install
    #else
    #    echo "SimEngRepo Found, cleaning up"
    #    cd $SIMENG_TOP
    #    rm -rf build install
    #    mkdir build install

    #    git stash
    #    git checkout ${ghprbActualCommit}
    #fi
}

# Build common function
build () {
    cd $SIMENG_TOP
    rm -rf build/* install/*

    cd $SIMENG_BUILD
    echo $PWD
    cmake $SIMENG_TOP -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$SIMENG_INSTALL
    make -j
    make install
}


# Run tests common function
run () {
    cd $SIMENG_BUILD
    ./test/unit/unittests --gtest_output=xml:unittests.xml
    ./regression/aarch64/regression-aarch64 --gtest_output=xml:regressiontests.xml
}
