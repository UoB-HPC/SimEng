#include "gtest/gtest.h"
#include "simeng/pipeline/A64FXPortAllocator.hh"

namespace simeng {
namespace pipeline {

std::vector<uint64_t> rsFreeEntires = {0, 20, 10, 10, 19};

void rsSizes(std::vector<uint64_t> &sizeVec){
  sizeVec = rsFreeEntires;
}

std::vector<std::vector<std::vector<std::pair<uint16_t, uint8_t>>>> arrangement = {
  {{{4,0}, {1,1}, {2,1}, {3,1}}}, // PORT 0
  {{{0,0}, {1,1}, {2,1}}}, // PORT 1
  {{{4,0}, {1,1}, {2,1}}},  // PORT 2
  {{{0,0}, {1,1}, {3,1}}}, // PORT 3
  {{{5,0}, {1,1}, {4,1}},
   {{0,0}}}, // PORT 4
  {{{5,0}, {1,1}, {4,1}},
   {{6,0}, {1,1}, {4,1}},
   {{0,0}}}, // PORT 5
  {{{7,0}}} // PORT 6
};

// Tests correct allocation when for RSE0/RSE1/BR attribute groups and stores
TEST(A64FXPortAllocatorTest, simpleAttributes) {
  auto portAllocator = A64FXPortAllocator(arrangement);
  portAllocator.setRSSizeGetter([this](std::vector<uint64_t> &sizeVec) {rsSizes(sizeVec);});

  // RSE0
  EXPECT_EQ(portAllocator.allocate(5), 1);
  EXPECT_EQ(portAllocator.allocate(7), 1);
  EXPECT_EQ(portAllocator.allocate(24), 0);
  EXPECT_EQ(portAllocator.allocate(26), 0);
  EXPECT_EQ(portAllocator.allocate(28), 0);
  EXPECT_EQ(portAllocator.allocate(30), 0);
  // RSE1
  rsFreeEntires = {20, 0, 10, 10, 19};
  EXPECT_EQ(portAllocator.allocate(9), 3);
  EXPECT_EQ(portAllocator.allocate(11), 3);
  // Store
  rsFreeEntires = {20, 20, 10, 0, 19};
  EXPECT_EQ(portAllocator.allocate(64), 5);
  EXPECT_EQ(portAllocator.allocate(66), 5);
  EXPECT_EQ(portAllocator.allocate(80), 5);
  EXPECT_EQ(portAllocator.allocate(82), 5);
  // BR
  rsFreeEntires = {20, 20, 10, 10, 0};
  EXPECT_EQ(portAllocator.allocate(128), 6);
}

// Tests correct allocation when for RSX
TEST(A64FXPortAllocatorTest, RSX) {
  auto portAllocator = A64FXPortAllocator(arrangement);
  portAllocator.setRSSizeGetter([this](std::vector<uint64_t> &sizeVec) {rsSizes(sizeVec);});
  rsFreeEntires = {4, 4, 2, 2, 19};
  EXPECT_EQ(portAllocator.allocate(1), 1);
  rsFreeEntires[0]--;
  EXPECT_EQ(portAllocator.allocate(1), 3);
  rsFreeEntires[1]--;
  EXPECT_EQ(portAllocator.allocate(1), 1);
  rsFreeEntires[0]--;
  EXPECT_EQ(portAllocator.allocate(1), 3);
  rsFreeEntires[1]--;
  EXPECT_EQ(portAllocator.allocate(1), 1);
  rsFreeEntires[0]--;
  EXPECT_EQ(portAllocator.allocate(1), 4);
  rsFreeEntires[2]--;
  EXPECT_EQ(portAllocator.allocate(1), 1);
  rsFreeEntires[0]--;
  EXPECT_EQ(portAllocator.allocate(1), 4);
  rsFreeEntires[2]--;
  EXPECT_EQ(portAllocator.allocate(1), 5);
  rsFreeEntires[3]--;
  EXPECT_EQ(portAllocator.allocate(1), 3);
  rsFreeEntires[1]--;
  EXPECT_EQ(portAllocator.allocate(1), 4);
  EXPECT_EQ(portAllocator.allocate(1), 3);
  rsFreeEntires[1]--;
  EXPECT_EQ(portAllocator.allocate(1), 5);
  rsFreeEntires[3]--;
}

// Tests correct allocation when for RSE
TEST(A64FXPortAllocatorTest, RSE) {
  auto portAllocator = A64FXPortAllocator(arrangement);
  portAllocator.setRSSizeGetter([this](std::vector<uint64_t> &sizeVec) {rsSizes(sizeVec);});
  rsFreeEntires = {4, 4, 10, 10, 19};
  EXPECT_EQ(portAllocator.allocate(3), 1);
  rsFreeEntires[0]--;
  EXPECT_EQ(portAllocator.allocate(16), 2);
  rsFreeEntires[1]--;
  EXPECT_EQ(portAllocator.allocate(18), 0);
  rsFreeEntires[0]--;
  EXPECT_EQ(portAllocator.allocate(20), 2);
  rsFreeEntires[1]--;
  EXPECT_EQ(portAllocator.allocate(22), 0);
  rsFreeEntires[0]--;
  rsFreeEntires = {0, 4, 10, 10, 19};
  EXPECT_EQ(portAllocator.allocate(3), 3);
  rsFreeEntires[1]--;
  EXPECT_EQ(portAllocator.allocate(16), 2);
  rsFreeEntires[1]--;
  rsFreeEntires = {4, 0, 10, 10, 19};
  EXPECT_EQ(portAllocator.allocate(3), 1);
  rsFreeEntires[0]--;
  EXPECT_EQ(portAllocator.allocate(16), 0);
  rsFreeEntires[0]--;
}

}  // namespace pipeline
}  // namespace simeng
