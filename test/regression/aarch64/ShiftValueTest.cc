#include "gtest/gtest.h"
#include "simeng/arch/aarch64/Instruction.hh"

namespace {

TEST(ShiftValueTest, MSL) {
  // 32-bit
  const uint32_t a = 0x0000FFFF;
  EXPECT_EQ(simeng::arch::aarch64::shiftValue(a, ARM64_SFT_MSL, 16),
            0xFFFFFFFF);

  const uint32_t b = 0xFFFF0000;
  EXPECT_EQ(simeng::arch::aarch64::shiftValue(b, ARM64_SFT_MSL, 31),
            0x7FFFFFFF);

  EXPECT_EQ(simeng::arch::aarch64::shiftValue(b, ARM64_SFT_MSL, 0), b);

  // 64-bit
  const uint64_t c = 0x00000000FFFFFFFF;
  EXPECT_EQ(simeng::arch::aarch64::shiftValue(c, ARM64_SFT_MSL, 32),
            0xFFFFFFFF00000000);

  const uint64_t d = 0xFFFFFFFF00000000;
  EXPECT_EQ(simeng::arch::aarch64::shiftValue(d, ARM64_SFT_MSL, 63),
            0xFFFFFFFE00000001);

  EXPECT_EQ(simeng::arch::aarch64::shiftValue(d, ARM64_SFT_MSL, 0), d);
}

TEST(ShiftValueTest, ROR) {
  // 32-bit
  const uint32_t a = 0x0000FFFF;
  EXPECT_EQ(simeng::arch::aarch64::shiftValue(a, ARM64_SFT_ROR, 16),
            0xFFFF0000);

  const uint32_t b = 0xFFFF0000;
  EXPECT_EQ(simeng::arch::aarch64::shiftValue(b, ARM64_SFT_ROR, 31),
            0xFFFE0001);

  EXPECT_EQ(simeng::arch::aarch64::shiftValue(b, ARM64_SFT_ROR, 0), b);

  // 64-bit
  const uint64_t c = 0x00000000FFFFFFFF;
  EXPECT_EQ(simeng::arch::aarch64::shiftValue(c, ARM64_SFT_ROR, 32),
            0xFFFFFFFF00000000);

  const uint64_t d = 0xFFFFFFFF00000000;
  EXPECT_EQ(simeng::arch::aarch64::shiftValue(d, ARM64_SFT_ROR, 63),
            0xFFFFFFFE00000001);

  EXPECT_EQ(simeng::arch::aarch64::shiftValue(d, ARM64_SFT_ROR, 0), d);
}

}  // namespace