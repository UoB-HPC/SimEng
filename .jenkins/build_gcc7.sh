#!/bin/bash

source .jenkins/build_test_run.sh

## Download/clean and checkout pull request
checkout

## Load compilers/libraries
echo "Compiler GCC 7"
module swap PrgEnv-cray PrgEnv-gnu
module swap gcc gcc/7.3.0
module load tools/cmake

## Setup environment
export CMAKE_C_COMPILER=gcc
export CMAKE_CXX_COMPILER=g++

## Build, test, and run SimEng
build
test
run
