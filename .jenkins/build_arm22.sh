#!/bin/bash

source .jenkins/build_test_run.sh

## Download/clean and checkout pull request
checkout

## Load compilers/libraries
echo "Compiler Armclang 22.0.2"
module use /software/arm64/modulefiles
module load tools/arm-compiler-sles
module load tools/cmake

## Setup environment
export CMAKE_C_COMPILER=armclang
export CMAKE_CXX_COMPILER=armclang++

## Build, test, and run SimEng
build
test
run
