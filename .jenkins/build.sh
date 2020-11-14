#!/bin/bash




build_and_run () {
   rm -rf build/* install/*

   cd $SIMENG_BUILD
   cmake $SIMENG_TOP -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$SIMENG_INSTALL
   make -j
   make install
   make test
}

## Set up file structure
export SIMENG_TOP=$PWD
export SIMENG_BUILD=$PWD/build
export SIMENG_INSTALL=$PWD/install

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

echo "Compiler GCC 7"
module swap PrgEnv-cray PrgEnv-gnu
module swap gcc gcc/7.3.0
module load tools/cmake
build_and_run

echo "Compiler GCC 8"
module swap PrgEnv-cray PrgEnv-gnu
module swap gcc gcc/8.3.0
module load tools/cmake
build_and_run

echo "Compiler GCC 9"
module swap PrgEnv-cray PrgEnv-gnu
module swap gcc gcc/9.3.0
module load tools/cmake
build_and_run

