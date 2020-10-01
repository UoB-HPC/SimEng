#include "gtest/gtest.h"
#include "simeng/pipeline/A64FXPortAllocator.hh"

namespace simeng {
namespace pipeline {

std::vector<uint64_t> rsFreeEntires = {0, 20, 10, 10, 19};

void rsSizes(std::vector<uint64_t> &sizeVec){
  sizeVec = rsFreeEntires;
}

const std::vector<std::vector<std::vector<std::pair<uint16_t, uint8_t>>>> portArrangement = {
  {
    { {4, 0}, {1, 1}, {2, 1}, {3, 1} }
  }, // PORT 0
  {
    { {8, 0}, {0, 1}, {4, 1}, {3, 1}, {2, 1}, {1, 1} }
  }, // PORT 1
  {
    { {0, 0}, {1, 1}, {2, 1} }
  }, // PORT 2
  {
    { {4, 0}, {1, 1}, {2, 1} }
  }, // PORT 3
  {
    { {0, 0}, {1, 1}, {3, 1} }
  }, // PORT 4
  {
    { {5, 0}, {1, 1}, {4, 1} },
    { {6, 0}, {1, 1}, {4, 1} },      
    { {0, 0} }
  }, // PORT 5
  {
    { {5, 0}, {1, 1}, {4, 1} },
    { {6, 0}, {1, 1}, {4, 1} },        
    { {0, 0} }
  }, // PORT 6
  {      
    { {7, 0} }
  } // PORT 7
};

// Tests correct allocation when for RSE0/RSE1/BR attribute groups and stores
TEST(A64FXPortAllocatorTest, simpleAttributes) {
  auto portAllocator = A64FXPortAllocator(portArrangement);
  portAllocator.setRSSizeGetter([this](std::vector<uint64_t> &sizeVec) {rsSizes(sizeVec);});

  // RSE0
  portAllocator.tick();
  EXPECT_EQ(portAllocator.allocate(5), 2);
  EXPECT_EQ(portAllocator.allocate(7), 2);
  EXPECT_EQ(portAllocator.allocate(24), 0);
  EXPECT_EQ(portAllocator.allocate(26), 0);
  EXPECT_EQ(portAllocator.allocate(28), 0);
  EXPECT_EQ(portAllocator.allocate(30), 0);
  // RSE1
  rsFreeEntires = {20, 0, 10, 10, 19};
  portAllocator.tick();
  EXPECT_EQ(portAllocator.allocate(9), 4);
  EXPECT_EQ(portAllocator.allocate(11), 4);
  // Store
  rsFreeEntires = {20, 20, 10, 0, 19};
  portAllocator.tick();
  EXPECT_EQ(portAllocator.allocate(64), 5);
  EXPECT_EQ(portAllocator.allocate(66), 5);
  EXPECT_EQ(portAllocator.allocate(80), 5);
  EXPECT_EQ(portAllocator.allocate(82), 5);
  // BR
  rsFreeEntires = {20, 20, 10, 10, 0};
  portAllocator.tick();
  EXPECT_EQ(portAllocator.allocate(128), 7);
}

// Tests correct allocation when for RSX
TEST(A64FXPortAllocatorTest, RSX) {
  auto portAllocator = A64FXPortAllocator(portArrangement);
  portAllocator.setRSSizeGetter([this](std::vector<uint64_t> &sizeVec) {rsSizes(sizeVec);});
  rsFreeEntires = {4, 4, 2, 2, 19};
  portAllocator.tick();
  EXPECT_EQ(portAllocator.allocate(1), 2);
  rsFreeEntires[0]--;
  portAllocator.tick();
  EXPECT_EQ(portAllocator.allocate(1), 2);
  rsFreeEntires[0]--;
  portAllocator.tick();
  EXPECT_EQ(portAllocator.allocate(1), 5);
  rsFreeEntires[2]--;
  portAllocator.tick();
  EXPECT_EQ(portAllocator.allocate(1), 5);
  rsFreeEntires[2]--;
  portAllocator.tick();
  EXPECT_EQ(portAllocator.allocate(1), 4);
  rsFreeEntires[1]--;
  portAllocator.tick();
  EXPECT_EQ(portAllocator.allocate(1), 2);
  rsFreeEntires[0]--;
  portAllocator.tick();
  EXPECT_EQ(portAllocator.allocate(1), 6);
  rsFreeEntires[3]--;
  portAllocator.tick();
  EXPECT_EQ(portAllocator.allocate(1), 5);
  portAllocator.tick();
  EXPECT_EQ(portAllocator.allocate(1), 4);
  rsFreeEntires[1]--;
  portAllocator.tick();
  EXPECT_EQ(portAllocator.allocate(1), 2);
  rsFreeEntires[0]--;
  portAllocator.tick();
  EXPECT_EQ(portAllocator.allocate(1), 6);
  rsFreeEntires[3]--;
  portAllocator.tick();
  EXPECT_EQ(portAllocator.allocate(1), 6);
  portAllocator.tick();
  EXPECT_EQ(portAllocator.allocate(1), 4);
}

// Tests correct allocation when for RSE
TEST(A64FXPortAllocatorTest, RSE) {
  auto portAllocator = A64FXPortAllocator(portArrangement);
  portAllocator.setRSSizeGetter([this](std::vector<uint64_t> &sizeVec) {rsSizes(sizeVec);});
  rsFreeEntires = {4, 4, 10, 10, 19};
  portAllocator.tick();
  EXPECT_EQ(portAllocator.allocate(3), 2);
  rsFreeEntires[0]--;
  portAllocator.tick();
  EXPECT_EQ(portAllocator.allocate(16), 3);
  rsFreeEntires[1]--;
  portAllocator.tick();
  EXPECT_EQ(portAllocator.allocate(18), 0);
  rsFreeEntires[0]--;
  portAllocator.tick();
  EXPECT_EQ(portAllocator.allocate(20), 3);
  rsFreeEntires[1]--;
  portAllocator.tick();
  EXPECT_EQ(portAllocator.allocate(22), 0);
  rsFreeEntires = {0, 4, 10, 10, 19};
  portAllocator.tick();
  EXPECT_EQ(portAllocator.allocate(3), 4);
  rsFreeEntires[1]--;
  portAllocator.tick();
  EXPECT_EQ(portAllocator.allocate(16), 3);
  rsFreeEntires = {4, 0, 10, 10, 19};
  portAllocator.tick();
  EXPECT_EQ(portAllocator.allocate(3), 2);
  rsFreeEntires[0]--;
  portAllocator.tick();
  EXPECT_EQ(portAllocator.allocate(16), 0);
}

}  // namespace pipeline
}  // namespace simeng
