#!/bin/bash

source .jenkins/build_and_run.sh


if [ ! -d "$SIMENG_TOP" ]
then
    echo "No repository found, recusively cloning SimEng"
    cd /home/br-hwaugh/jenkins/workspace/
    git clone --recurse-submodules https://github.com/UoB-HPC/SimEng.git
    cd SimEngBuild
    ## Download and update submodules
    git submodule update --init
    git submodule sync --recursive

    cd external/capstone
    git fetch
    git checkout next

    cd $SIMENG_TOP
    mkdir -p build install
else
    echo "SimEngRepo Found, cleaning up and cloning fresh repo"
    cd $SIMENG_TOP
    rm -rf build/* install/*

    git stash
    git checkout ${ghprbActualCommit}
fi



## Setup environment
export CMAKE_C_COMPILER=cc
export CMAKE_CXX_COMPILER=CC


## Load compilers
echo "Compiler GCC 9"
module swap PrgEnv-cray PrgEnv-gnu
module swap gcc gcc/9.3.0
module load tools/cmake
build

