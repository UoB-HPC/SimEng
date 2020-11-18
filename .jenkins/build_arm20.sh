#!/bin/bash

source .jenkins/build_and_run.sh


## Download/clean and checkout pull request
checkout

## Setup environment
export CMAKE_C_COMPILER=cc
export CMAKE_CXX_COMPILER=CC


## Load compilers
echo "Compiler Armclang 20.0"
module swap PrgEnv-cray PrgEnv-allinea
module swap Generic-AArch64/SUSE/12/arm-linux-compiler/20.0 ThunderX2CN99/SUSE/12/arm-linux-compiler-20.0/armpl/20.0.0
module load tools/cmake
debug
build
run
