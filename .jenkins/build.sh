#!/bin/bash
module swap PrgEnv-cray PrgEnv-gnu
module load tools/cmake/3.15.4

mkdir -p SimEngBuild/install
cd SimEngBuild
export SIMENG_TOP=$PWD


git clone --recurse-submodules https://github.com/UoB-HPC/SimEng.git
cd SimEng
git pull origin master
git submodule update --init
git checkout review
git submodule sync --recursive

cd external/capstone
git fetch
git checkout next

cd $SIMENG_TOP
export CMAKE_C_COMPILER=cc
export CMAKE_CXX_COMPILER=CC
cmake $SIMENG_TOP/SimEng -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$SIMENG_TOP/install
make
make install

make tests
