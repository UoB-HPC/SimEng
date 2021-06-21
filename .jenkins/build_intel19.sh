#!/bin/bash

source .jenkins/build_test_run.sh

## Download/clean and checkout pull request
checkout

## Setup environment
PATH=/cm/shared/apps/intel_parallel_studio_xe_2019_update4/compilers_and_libraries_2019.4.243/linux/bin/intel64/:$PATH
export CMAKE_C_COMPILER=icc
export CC=icc
export CMAKE_CXX_COMPILER=icpc
export CXX=icpc

## Load compilers/libraries
echo "Compiler INTEL 19"
#module load intel-parallel-studio-xe/compilers/64/2019u4/19.0.4 intel-parallel-studio-xe/mpi/64/2019u4/4.243
export PATH=/home/br-hwaugh/installations/cmake-3.18.5/bin/:$PATH

## Build, test, and run SimEng
build
test
run
