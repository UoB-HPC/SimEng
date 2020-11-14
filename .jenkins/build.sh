#!/bin/bash


## Set up file structure
mkdir -p build install
export SIMENG_TOP=$PWD
export SIMENG_BUILD=$PWD/build
export SIMENG_INSTALL=$PWD/install


build_and_run () {
   echo "Compiler version"
   cc -v

   cd $SIMENG_BUILD
   cmake $SIMENG_TOP -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$SIMENG_INSTALL
   make
   make install

   make tests
}


## Download and update submodules
git submodule update --init
git submodule sync --recursive

cd external/capstone
git fetch
git checkout next

## Setup environment
export CMAKE_C_COMPILER=cc
export CMAKE_CXX_COMPILER=CC

## Load GCC 7
module swap PrgEnv-cray PrgEnv-gnu
module swap gcc gcc/7.3.0
module load tools/cmake
build_and_run

## Load GCC 8
module swap PrgEnv-cray PrgEnv-gnu
module swap gcc gcc/8.3.0
module load tools/cmake
build_and_run

## Load GCC 9
module swap PrgEnv-cray PrgEnv-gnu
module swap gcc gcc/9.3.0
module load tools/cmake
build_and_run

