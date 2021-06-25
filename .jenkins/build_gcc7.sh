#!/bin/bash

source .jenkins/build_test_run.sh

## Download/clean and checkout pull request
checkout

## Setup environment
module load cdt/20.03
export CMAKE_C_COMPILER=cc
export CMAKE_CXX_COMPILER=CC

## Load compilers/libraries
echo "Compiler GCC 7"
module swap PrgEnv-cray PrgEnv-gnu
module swap gcc gcc/7.3.0
module load tools/cmake

## Build, test, and run SimEng
build
test
run
