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

#echo "Compiler GCC 7"
#module swap PrgEnv-allinea PrgEnv-gnu
#module swap gcc gcc/7.3.0
#module load tools/cmake
#build_and_run

#echo "Compiler GCC 8"
#module swap gcc gcc/8.3.0
#module load tools/cmake
#build_and_run

#echo "Compiler GCC 9"
#module swap gcc gcc/9.3.0
#module load tools/cmake
#build_and_run

