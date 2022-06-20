CXX=$(shell sst-config --CXX)
# CXXFLAGS=$(shell sst-config --ELEMENT_CXXFLAGS)
CXXFLAGS=-std=c++17 -D__STDC_FORMAT_MACROS -fPIC -DHAVE_CONFIG_H -I/home/rahat/asimov/SST/sst-core-install/include
LDFLAGS=$(shell sst-config --ELEMENT_LDFLAGS)
OPTIMIZE_FLAGS=-O3
SIMENG_BUILD=/home/rahat/asimov/SimEng/build
SIMENG_INSTALL=/home/rahat/asimov/simeng-bin
SOURCES := $(wildcard *.cc)

CPPFLAGS=-I./include -I$(SIMENG_INSTALL)/include -I$(SIMENG_BUILD)/_deps/capstone-src/include -I$(SIMENG_BUILD)/_deps/yaml-cpp-src/include

all: libsstsimeng.so install

libsstsimeng.so: SimengCoreWrapper.o
	@echo $(LDFLAGS)
	$(CXX) $(OPTIMIZE_FLAGS) $(CXXFLAGS) $(CPPFLAGS) $(LDFLAGS) -L/home/rahat/asimov/simeng-bin/lib -o $@ *.o -lsimeng

SimengCoreWrapper.o: SimengCoreWrapper.cc
	$(CXX) $(OPTIMIZE_FLAGS) $(CXXFLAGS) $(CPPFLAGS) -L/home/rahat/asimov/simeng-bin/lib -c $<

install:
	sst-register sstsimeng sstsimeng_LIBDIR=$(CURDIR)
	sst-register SST_ELEMENT_SOURCE sstsimeng=$(CURDIR)

clean:
	rm -f *.o libsstsimeng.so