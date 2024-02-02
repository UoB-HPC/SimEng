#include "gtest/gtest.h"
#include "simeng/pipeline/M1PortAllocator.hh"

namespace simeng {
namespace pipeline {

class M1PortAllocatorTest : public testing::Test {
 public:
  M1PortAllocatorTest() : portAllocator(portArrangement, rsArrangement) {
    portAllocator.setRSSizeGetter(
        [this](std::vector<uint64_t>& sizeVec) { rsSizes(sizeVec); });
  }

  void rsSizes(std::vector<uint64_t>& sizeVec) const {
    sizeVec = rsFreeEntries;
  }

 protected:
  // Representation of the M1 Firestorm reservation station layout
  std::vector<uint64_t> rsFreeEntries = {24, 26, 16, 12, 28, 28, 12,
                                         12, 12, 12, 36, 36, 36, 36};
  // Representation of the M1 Firestorm port layout
  const std::vector<std::vector<uint16_t>> portArrangement = {
      {0}, {1}, {2}, {3}, {4}, {5}, {6}, {7}, {8}, {9}, {10}, {11}, {12}, {13}};
  // Representation of the M1 Firestorm Reservation Station Arrangement
  // std::pair<uint8_t, uint64_t> = <rsIndex, rsSize>
  std::vector<std::pair<uint8_t, uint64_t>> rsArrangement = {
      {0, 24}, {1, 26}, {2, 16}, {3, 12},  {4, 28},  {5, 28},  {6, 12},
      {7, 12}, {8, 12}, {9, 12}, {10, 36}, {11, 36}, {12, 36}, {13, 36}};

  M1PortAllocator portAllocator;
};

// Tests correct allocation for single port groups (i.e. INT_DIV_OR_SQRT)
TEST_F(M1PortAllocatorTest, singlePortAllocation) {
  std::vector<uint16_t> ports = {4};
  EXPECT_EQ(portAllocator.allocate(ports), 4);
}

// Tests correct allocation of multiple INT_SIMPLE instructions
TEST_F(M1PortAllocatorTest, allocationIntSimple) {
  std::vector<uint16_t> ports = {0, 1, 2, 3, 4, 5};
  EXPECT_EQ(portAllocator.allocate(ports), 0);
  rsFreeEntries[0]--;
  EXPECT_EQ(portAllocator.allocate(ports), 1);
  rsFreeEntries[1]--;
  EXPECT_EQ(portAllocator.allocate(ports), 2);
  rsFreeEntries[2]--;
  EXPECT_EQ(portAllocator.allocate(ports), 3);
  rsFreeEntries[3]--;
  EXPECT_EQ(portAllocator.allocate(ports), 4);
  rsFreeEntries[4]--;
  EXPECT_EQ(portAllocator.allocate(ports), 5);
  rsFreeEntries[5]--;
  EXPECT_EQ(portAllocator.allocate(ports), 0);
  rsFreeEntries[0]--;

  // Ensure `issued()` logic works as expected
  portAllocator.issued(3);
  rsFreeEntries[3]++;
  EXPECT_EQ(portAllocator.allocate(ports), 3);
  rsFreeEntries[3]--;
}

// Tests correct allocation of multiple BRANCH instructions
TEST_F(M1PortAllocatorTest, allocationBranch) {
  std::vector<uint16_t> ports = {0, 1};
  EXPECT_EQ(portAllocator.allocate(ports), 0);
  rsFreeEntries[0]--;
  EXPECT_EQ(portAllocator.allocate(ports), 1);
  rsFreeEntries[1]--;
  EXPECT_EQ(portAllocator.allocate(ports), 0);
  rsFreeEntries[0]--;

  // Ensure `issued()` logic works as expected
  portAllocator.issued(0);
  rsFreeEntries[0]++;
  EXPECT_EQ(portAllocator.allocate(ports), 0);
  rsFreeEntries[0]--;
}

// Tests correct allocation of multiple INT_MUL instructions
TEST_F(M1PortAllocatorTest, allocationIntMul) {
  std::vector<uint16_t> ports = {4, 5};
  EXPECT_EQ(portAllocator.allocate(ports), 4);
  rsFreeEntries[4]--;
  EXPECT_EQ(portAllocator.allocate(ports), 5);
  rsFreeEntries[5]--;
  EXPECT_EQ(portAllocator.allocate(ports), 4);
  rsFreeEntries[4]--;

  // Ensure `issued()` logic works as expected
  portAllocator.issued(4);
  rsFreeEntries[4]++;
  EXPECT_EQ(portAllocator.allocate(ports), 4);
  rsFreeEntries[4]--;
}

// Tests correct allocation of multiple LOAD instructions
TEST_F(M1PortAllocatorTest, allocationLoad) {
  std::vector<uint16_t> ports = {7, 8, 9};
  EXPECT_EQ(portAllocator.allocate(ports), 7);
  rsFreeEntries[7]--;
  EXPECT_EQ(portAllocator.allocate(ports), 8);
  rsFreeEntries[8]--;
  EXPECT_EQ(portAllocator.allocate(ports), 9);
  rsFreeEntries[9]--;
  EXPECT_EQ(portAllocator.allocate(ports), 7);
  rsFreeEntries[7]--;

  // Ensure `issued()` logic works as expected
  portAllocator.issued(9);
  rsFreeEntries[9]++;
  EXPECT_EQ(portAllocator.allocate(ports), 9);
  rsFreeEntries[9]--;
}

// Tests correct allocation of multiple STORE instructions
TEST_F(M1PortAllocatorTest, allocationStore) {
  std::vector<uint16_t> ports = {6, 7};
  EXPECT_EQ(portAllocator.allocate(ports), 6);
  rsFreeEntries[6]--;
  EXPECT_EQ(portAllocator.allocate(ports), 7);
  rsFreeEntries[7]--;
  EXPECT_EQ(portAllocator.allocate(ports), 6);
  rsFreeEntries[6]--;

  // Ensure `issued()` logic works as expected
  portAllocator.issued(6);
  rsFreeEntries[6]++;
  EXPECT_EQ(portAllocator.allocate(ports), 6);
  rsFreeEntries[6]--;
}

// Tests correct allocation of multiple FP / VECTOR instructions
TEST_F(M1PortAllocatorTest, allocationFpVec) {
  std::vector<uint16_t> ports = {10, 11, 12, 13};
  EXPECT_EQ(portAllocator.allocate(ports), 10);
  rsFreeEntries[10]--;
  EXPECT_EQ(portAllocator.allocate(ports), 11);
  rsFreeEntries[11]--;
  EXPECT_EQ(portAllocator.allocate(ports), 12);
  rsFreeEntries[12]--;
  EXPECT_EQ(portAllocator.allocate(ports), 13);
  rsFreeEntries[13]--;
  EXPECT_EQ(portAllocator.allocate(ports), 10);
  rsFreeEntries[10]--;

  // Ensure `issued()` logic works as expected
  portAllocator.issued(12);
  rsFreeEntries[12]++;
  EXPECT_EQ(portAllocator.allocate(ports), 12);
  rsFreeEntries[12]--;
}

}  // namespace pipeline
}  // namespace simeng