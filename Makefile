SRCDIR=./src
OBJDIR=./obj
BUILDDIR=./build

CXX=g++
CXXFLAGS=-Wall -std=c++17 -Ofast

SRCS=$(wildcard $(SRCDIR)/*.cc)
OBJS=$(SRCS:$(SRCDIR)/%.cc=$(OBJDIR)/%.o)

$(shell mkdir -p $(OBJDIR) $(BUILDDIR))

all: main

$(OBJDIR)/%.o: $(SRCDIR)/%.cc
	$(CXX) $(CXXFLAGS) -c $< -o $@

main: $(OBJS)
	$(CXX) -o $(BUILDDIR)/simeng $^

clean:
	rm $(OBJDIR)/*.o
