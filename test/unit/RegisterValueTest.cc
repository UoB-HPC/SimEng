#include "gtest/gtest.h"
#include "simeng/RegisterValue.hh"

namespace {

// Tests that we can create a RegisterValue
TEST(RegisterValueTest, Create) {
  auto registerValue = simeng::RegisterValue(0, 8);
  EXPECT_EQ(registerValue.get<int>(), 0);
}

// Tests that we can check that a RegisterValue holds no data
TEST(RegisterValueTest, False) { EXPECT_FALSE(simeng::RegisterValue()); }

// Tests that we can check that a RegisterValue holds data
TEST(RegisterValueTest, True) { EXPECT_TRUE(simeng::RegisterValue(0, 8)); }

// Tests that we can cast to different datatypes
TEST(RegisterValueTest, Cast) {
  uint32_t value = 1;
  auto registerValue = simeng::RegisterValue(value, 8);
  EXPECT_EQ(registerValue.get<uint8_t>(), 1);
}

// Tests that high bits are zeroed when initialised with a smaller datatype
TEST(RegisterValueTest, MismatchedSizesZeroed) {
  uint32_t value = 0;
  auto registerValue = simeng::RegisterValue(value, 8);
  EXPECT_EQ(registerValue.get<uint64_t>(), 0);
}

// Tests that low bits of stored values can be read correctly
TEST(RegisterValueTest, Reinterpret) {
  uint32_t value = 0x101;
  auto registerValue = simeng::RegisterValue(value, 8);
  EXPECT_EQ(registerValue.get<uint8_t>(), 1);
}

// Tests that larger datatypes can be read as vectors of smaller datatypes
TEST(RegisterValueTest, Vector) {
  uint64_t value = 0x0000000200000001;
  auto registerValue = simeng::RegisterValue(value, 8);
  auto vector = registerValue.getAsVector<uint32_t>();
  EXPECT_EQ(vector[0], 1);
  EXPECT_EQ(vector[1], 2);
}

// Tests a register value can be zero-extended
TEST(RegisterValueTest, ZeroExtend) {
  auto small = simeng::RegisterValue(1, 1);
  auto extended = small.zeroExtend(1, 8);
  EXPECT_EQ(extended.get<uint64_t>(), 1);
}

}  // namespace
