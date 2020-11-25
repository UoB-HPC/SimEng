#!/bin/bash

source .jenkins/build_and_run.sh

## Download/clean and checkout pull request
checkout

## Setup environment
export CMAKE_C_COMPILER=cc
export CMAKE_CXX_COMPILER=CC

echo "Compiler GCC 8"
module swap PrgEnv-cray PrgEnv-gnu
module swap gcc gcc/8.3.0
module load tools/cmake
build
run
