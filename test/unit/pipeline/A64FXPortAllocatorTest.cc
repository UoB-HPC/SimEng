#include "gtest/gtest.h"
#include "simeng/pipeline/A64FXPortAllocator.hh"

// Several of these test refer to A64FX specific dispatch mechanism naming
// conventions. These can primarily be found in section 5.4 of
// https://github.com/fujitsu/A64FX/blob/master/doc/A64FX_Microarchitecture_Manual_en_1.4.pdf

namespace simeng {
namespace pipeline {

class A64FXPortAllocatorTest : public testing::Test {
 public:
  A64FXPortAllocatorTest() : portAllocator(portArrangement) {
    portAllocator.setRSSizeGetter(
        [this](std::vector<uint32_t>& sizeVec) { rsSizes(sizeVec); });
  }

  void rsSizes(std::vector<uint32_t>& sizeVec) const {
    sizeVec = rsFreeEntries;
  }

 protected:
  // Representation of the A64FX reservation station layout
  std::vector<uint32_t> rsFreeEntries = {20, 20, 10, 10, 19};
  // Representation of the A64FX port layout
  const std::vector<std::vector<uint16_t>> portArrangement = {
      {0}, {1}, {2}, {3}, {4}, {5}, {6}, {7}};

  A64FXPortAllocator portAllocator;
};

// Tests correct allocation for RSE0/RSE1/BR attribute groups
TEST_F(A64FXPortAllocatorTest, singlePortAllocation) {
  // Allocate in blocks of 4 to simulate dispatch width of 4 and test dispatch
  // slot logic

  // RSE0
  portAllocator.tick();
  EXPECT_EQ(portAllocator.allocate({0}), 0);
  rsFreeEntries[0]--;
  EXPECT_EQ(portAllocator.allocate({1}), 1);
  rsFreeEntries[0]--;
  EXPECT_EQ(portAllocator.allocate({2}), 2);
  rsFreeEntries[0]--;
  EXPECT_EQ(portAllocator.allocate({0}), 0);
  rsFreeEntries[0]--;
  // RSE1
  portAllocator.tick();
  EXPECT_EQ(portAllocator.allocate({3}), 3);
  rsFreeEntries[1]--;
  EXPECT_EQ(portAllocator.allocate({4}), 4);
  rsFreeEntries[1]--;
  EXPECT_EQ(portAllocator.allocate({3}), 3);
  rsFreeEntries[1]--;
  EXPECT_EQ(portAllocator.allocate({4}), 4);
  rsFreeEntries[1]--;
  // BR
  portAllocator.tick();
  EXPECT_EQ(portAllocator.allocate({7}), 7);
  rsFreeEntries[4]--;
  EXPECT_EQ(portAllocator.allocate({7}), 7);
  rsFreeEntries[4]--;
  EXPECT_EQ(portAllocator.allocate({7}), 7);
  rsFreeEntries[4]--;
  EXPECT_EQ(portAllocator.allocate({7}), 7);
  rsFreeEntries[4]--;
}

// Tests correct allocation when for RSX
TEST_F(A64FXPortAllocatorTest, RSX) {
  rsFreeEntries = {10, 10, 10, 10, 19};
  portAllocator.tick();
  EXPECT_EQ(portAllocator.allocate({2, 4, 5, 6}), 2);
  rsFreeEntries[0]--;
  EXPECT_EQ(portAllocator.allocate({2, 4, 5, 6}), 4);
  rsFreeEntries[1]--;
  EXPECT_EQ(portAllocator.allocate({2, 4, 5, 6}), 5);
  rsFreeEntries[2]--;
  EXPECT_EQ(portAllocator.allocate({2, 4, 5, 6}), 6);
  rsFreeEntries[3]--;
  portAllocator.tick();
  EXPECT_EQ(portAllocator.allocate({2, 4, 5, 6}), 2);
  rsFreeEntries[0]--;
  EXPECT_EQ(portAllocator.allocate({2, 4, 5, 6}), 4);
  rsFreeEntries[1]--;
  EXPECT_EQ(portAllocator.allocate({2, 4, 5, 6}), 5);
  rsFreeEntries[2]--;
  EXPECT_EQ(portAllocator.allocate({2, 4, 5, 6}), 6);
  rsFreeEntries[3]--;
}

// Tests correct allocation when for RSE/RSA
TEST_F(A64FXPortAllocatorTest, RSEA) {
  rsFreeEntries = {20, 20, 10, 10, 19};
  // RSE
  portAllocator.tick();
  EXPECT_EQ(portAllocator.allocate({2, 4}), 2);
  rsFreeEntries[0]--;
  EXPECT_EQ(portAllocator.allocate({2, 4}), 4);
  rsFreeEntries[1]--;
  EXPECT_EQ(portAllocator.allocate({2, 4}), 2);
  rsFreeEntries[0]--;
  EXPECT_EQ(portAllocator.allocate({2, 4}), 4);
  rsFreeEntries[1]--;
  portAllocator.tick();
  EXPECT_EQ(portAllocator.allocate({0, 3}), 0);
  rsFreeEntries[0]--;
  EXPECT_EQ(portAllocator.allocate({0, 3}), 3);
  rsFreeEntries[1]--;
  EXPECT_EQ(portAllocator.allocate({0, 3}), 0);
  rsFreeEntries[0]--;
  EXPECT_EQ(portAllocator.allocate({0, 3}), 3);
  rsFreeEntries[1]--;
  // RSA
  portAllocator.tick();
  EXPECT_EQ(portAllocator.allocate({5, 6}), 5);
  rsFreeEntries[2]--;
  EXPECT_EQ(portAllocator.allocate({5, 6}), 6);
  rsFreeEntries[3]--;
  EXPECT_EQ(portAllocator.allocate({5, 6}), 5);
  rsFreeEntries[2]--;
  EXPECT_EQ(portAllocator.allocate({5, 6}), 6);
  rsFreeEntries[3]--;
}

// Test correct allocation for Table 1 condition
TEST_F(A64FXPortAllocatorTest, table1) {
  rsFreeEntries = {20, 0, 0, 0, 19};
  portAllocator.tick();
  EXPECT_EQ(portAllocator.allocate({2, 4, 5, 6}), 2);
  rsFreeEntries[0]--;
  EXPECT_EQ(portAllocator.allocate({2, 4, 5, 6}), 2);
  rsFreeEntries[0]--;
  EXPECT_EQ(portAllocator.allocate({2, 4, 5, 6}), 2);
  rsFreeEntries[0]--;
  EXPECT_EQ(portAllocator.allocate({2, 4, 5, 6}), 2);
  rsFreeEntries[0]--;
  portAllocator.tick();
  EXPECT_EQ(portAllocator.allocate({2, 4, 5, 6}), 2);
  rsFreeEntries[0]--;
  EXPECT_EQ(portAllocator.allocate({2, 4, 5, 6}), 2);
  rsFreeEntries[0]--;
  EXPECT_EQ(portAllocator.allocate({2, 4, 5, 6}), 2);
  rsFreeEntries[0]--;
  EXPECT_EQ(portAllocator.allocate({2, 4, 5, 6}), 2);
  rsFreeEntries[0]--;
}

// Test correct allocation for Table 2 condition
TEST_F(A64FXPortAllocatorTest, table2) {
  rsFreeEntries = {20, 20, 0, 0, 19};
  portAllocator.tick();
  EXPECT_EQ(portAllocator.allocate({2, 4, 5, 6}), 2);
  rsFreeEntries[0]--;
  EXPECT_EQ(portAllocator.allocate({2, 4, 5, 6}), 4);
  rsFreeEntries[1]--;
  EXPECT_EQ(portAllocator.allocate({2, 4, 5, 6}), 2);
  rsFreeEntries[0]--;
  EXPECT_EQ(portAllocator.allocate({2, 4, 5, 6}), 4);
  rsFreeEntries[1]--;
  portAllocator.tick();
  EXPECT_EQ(portAllocator.allocate({2, 4, 5, 6}), 2);
  rsFreeEntries[0]--;
  EXPECT_EQ(portAllocator.allocate({2, 4, 5, 6}), 4);
  rsFreeEntries[1]--;
  EXPECT_EQ(portAllocator.allocate({2, 4, 5, 6}), 2);
  rsFreeEntries[0]--;
  EXPECT_EQ(portAllocator.allocate({2, 4, 5, 6}), 4);
  rsFreeEntries[1]--;
}

// Test correct allocation for Table 3 condition
TEST_F(A64FXPortAllocatorTest, table3) {
  rsFreeEntries = {0, 0, 10, 10, 19};
  portAllocator.tick();
  EXPECT_EQ(portAllocator.allocate({2, 4, 5, 6}), 5);
  rsFreeEntries[2]--;
  EXPECT_EQ(portAllocator.allocate({2, 4, 5, 6}), 6);
  rsFreeEntries[3]--;
  EXPECT_EQ(portAllocator.allocate({2, 4, 5, 6}), 5);
  rsFreeEntries[2]--;
  EXPECT_EQ(portAllocator.allocate({2, 4, 5, 6}), 6);
  rsFreeEntries[3]--;
  portAllocator.tick();
  EXPECT_EQ(portAllocator.allocate({2, 4, 5, 6}), 5);
  rsFreeEntries[2]--;
  EXPECT_EQ(portAllocator.allocate({2, 4, 5, 6}), 6);
  rsFreeEntries[3]--;
  EXPECT_EQ(portAllocator.allocate({2, 4, 5, 6}), 5);
  rsFreeEntries[2]--;
  EXPECT_EQ(portAllocator.allocate({2, 4, 5, 6}), 6);
  rsFreeEntries[3]--;
}

// Test correct allocation for Table 5  condition
TEST_F(A64FXPortAllocatorTest, table5) {
  rsFreeEntries = {9, 9, 10, 9, 19};
  portAllocator.tick();
  EXPECT_EQ(portAllocator.allocate({2, 4, 5, 6}), 5);
  rsFreeEntries[2]--;
  EXPECT_EQ(portAllocator.allocate({2, 4, 5, 6}), 6);
  rsFreeEntries[3]--;
  EXPECT_EQ(portAllocator.allocate({2, 4, 5, 6}), 2);
  rsFreeEntries[0]--;
  EXPECT_EQ(portAllocator.allocate({2, 4, 5, 6}), 4);
  rsFreeEntries[1]--;
  portAllocator.tick();
  EXPECT_EQ(portAllocator.allocate({2, 4, 5, 6}), 5);
  rsFreeEntries[2]--;
  EXPECT_EQ(portAllocator.allocate({2, 4, 5, 6}), 6);
  rsFreeEntries[3]--;
  EXPECT_EQ(portAllocator.allocate({2, 4, 5, 6}), 2);
  rsFreeEntries[0]--;
  EXPECT_EQ(portAllocator.allocate({2, 4, 5, 6}), 4);
  rsFreeEntries[1]--;
}

// Test correct allocation for Table 6 condition
TEST_F(A64FXPortAllocatorTest, table6) {
  rsFreeEntries = {20, 0, 10, 0, 19};
  portAllocator.tick();
  EXPECT_EQ(portAllocator.allocate({2, 4}), 2);
  rsFreeEntries[0]--;
  EXPECT_EQ(portAllocator.allocate({0, 3}), 0);
  rsFreeEntries[0]--;
  EXPECT_EQ(portAllocator.allocate({2, 4}), 2);
  rsFreeEntries[0]--;
  EXPECT_EQ(portAllocator.allocate({0, 3}), 0);
  rsFreeEntries[0]--;
  portAllocator.tick();
  EXPECT_EQ(portAllocator.allocate({5, 6}), 5);
  rsFreeEntries[2]--;
  EXPECT_EQ(portAllocator.allocate({5, 6}), 5);
  rsFreeEntries[2]--;
  EXPECT_EQ(portAllocator.allocate({5, 6}), 5);
  rsFreeEntries[2]--;
  EXPECT_EQ(portAllocator.allocate({5, 6}), 5);
  rsFreeEntries[2]--;
}

// Test adherence to the dispatch slot logic
TEST_F(A64FXPortAllocatorTest, dispatchSlots) {
  rsFreeEntries = {10, 10, 10, 10, 19};

  // With less than 4 instructions dispatched in a cycle, the next cycle should
  // reset the dispatchSlot to 0 and start the allocation logic at the
  // appropriate place in the mechanism
  portAllocator.tick();
  EXPECT_EQ(portAllocator.allocate({2, 4, 5, 6}), 2);
  rsFreeEntries[0]--;
  EXPECT_EQ(portAllocator.allocate({2, 4, 5, 6}), 4);
  rsFreeEntries[1]--;
  EXPECT_EQ(portAllocator.allocate({2, 4, 5, 6}), 5);
  rsFreeEntries[2]--;
  rsFreeEntries = {10, 10, 10, 10, 19};
  portAllocator.tick();
  // Should reset to dispatch slot 0 thus RSEm should be allocated as opposed
  // to RSAf in decode slot 3 of table 5-4
  EXPECT_EQ(portAllocator.allocate({2, 4, 5, 6}), 2);
  rsFreeEntries[0]--;

  // Dispatch slot values should be shared amongst all instruction attribute
  // dispatch mechanisms
  rsFreeEntries = {10, 10, 10, 10, 19};
  portAllocator.tick();
  EXPECT_EQ(portAllocator.allocate({7}), 7);
  rsFreeEntries[4]--;
  EXPECT_EQ(portAllocator.allocate({2, 4, 5, 6}), 4);
  rsFreeEntries[1]--;
  EXPECT_EQ(portAllocator.allocate({7}), 7);
  rsFreeEntries[4]--;
  EXPECT_EQ(portAllocator.allocate({5, 6}), 6);
  rsFreeEntries[3]--;
}

}  // namespace pipeline
}  // namespace simeng
