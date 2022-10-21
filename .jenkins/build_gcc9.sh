#!/bin/bash

source .jenkins/build_test_run.sh

## Download/clean and checkout pull request
checkout

## Load compilers/libraries
echo "Compiler GCC 9"
module swap PrgEnv-cray PrgEnv-gnu
module swap gcc gcc/9.3.0
module load tools/cmake

## Build, test, and run SimEng
build("gcc", "g++")
test
run
