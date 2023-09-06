# Helper setup to build simeng binary

NPROC ?= 4
CMAKE ?= /data/tools/cmake/cmake-3.21.0-linux-x86_64/bin/cmake
BUILD_DIR ?= build
TYPE ?= Debug
INSTALLDIR ?= $(shell pwd)/install
TEST_FLAG ?= OFF
SST_FLAG ?= ON
SST_CORE_INSTALLDIR ?= $(SST_CORE_HOME)

all: configure build install

configure: clean
	$(CMAKE) -B $(BUILD_DIR) -S . -DCMAKE_BUILD_TYPE=$(TYPE) -DCMAKE_INSTALL_PREFIX=$(INSTALLDIR) -DSIMENG_ENABLE_TESTS=$(TEST_FLAG) -DSIMENG_USE_EXTERNAL_LLVM=ON -DSIMENG_ENABLE_SST=$(SST_FLAG) -DSST_INSTALL_DIR=$(SST_CORE_INSTALLDIR) -DLLVM_DIR=/usr/lib/llvm-12/lib/

build:
	$(CMAKE) --build $(BUILD_DIR) -j $(NPROC)

test:
	$(CMAKE) --build $(BUILD_DIR) -j $(NPROC) --target test

install:
	$(CMAKE) --build $(BUILD_DIR) -j $(NPROC) --target install

run_sst_example:
	sst sst/config/eacf_int_example_config.py

clean:
	rm -rf build

#.PHONY : all configure build test install run_sst_example clean
.PHONY : *
