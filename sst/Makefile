CXX := $(shell sst-config --CXX)
CXXFLAGS := -std=c++17 -D__STDC_FORMAT_MACROS -fPIC -DHAVE_CONFIG_H -O3 -I/home/rahat/asimov/SST/sst-core-install/include
LDFLAGS := $(shell sst-config --ELEMENT_LDFLAGS)

SIMENG_ROOT = /home/rahat/asimov/SimEng
SIMENG_INSTALL := /home/rahat/asimov/simeng-sst-bin
SIMENG_BUILD := $(SIMENG_ROOT)/build

INC_DIR := -I$(SIMENG_ROOT)/sst/include -I$(SIMENG_INSTALL)/include -I$(SIMENG_BUILD)/_deps/capstone-src/include -I$(SIMENG_BUILD)/_deps/yaml-cpp-src/include
LIB_DIR := -L$(SIMENG_INSTALL)/lib

HEADER_SRCS := $(wildcard include/*.hh)
SRCS := ${wildcard *.cc}

OBJS := $(patsubst %.cc,%.o,$(SRCS))

all: install register
	
# libsstsimeng.so: $(OBJS)
# 	$(CXX) $(OPTIMIZE_FLAGS) $(CXXFLAGS) $(INC_DIR) $(LDFLAGS) $(LIB_DIR) -o $@ $< -lsimeng

libsstsimeng.so: SimengCoreWrapper.cc
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $(INC_DIR) $(LIB_DIR) -o $@ $< SimengMemInterface.cc -ldl -lsimeng

# %.o: %.cc
# 	$(CXX) $(CXXFLAGS) $(INC_DIR) -c $<

register: install clean
	sst-register sstsimeng sstsimeng_LIBDIR=$(SIMENG_INSTALL)/sst
	sst-register SST_ELEMENT_SOURCE sstsimeng=$(SIMENG_INSTALL)/sst

install: libsstsimeng.so
	mv libsstsimeng.so $(SIMENG_INSTALL)/sst

clean:
	rm -rf *.o

clean-target:
	rm -rf $(SIMENG_INSTALL)/sst/*.so

unregister:
	sst-register -u sstsimeng
