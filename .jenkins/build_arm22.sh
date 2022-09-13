#!/bin/bash

source .jenkins/build_test_run.sh

## Download/clean and checkout pull request
checkout

## Setup environment
export CMAKE_C_COMPILER=cc
export CMAKE_CXX_COMPILER=CC

## Load compilers/libraries
echo "Compiler Armclang 22.0.2"
module use /software/arm64/modulefiles
module load tools/arm-compiler-sles
module load tools/cmake

## Build, test, and run SimEng
build
test
run
