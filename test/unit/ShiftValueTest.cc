#include "gtest/gtest.h"
#include "simeng/arch/aarch64/Instruction.hh"

namespace {

TEST(ShiftValueTest, ROR) {
  const auto ARM64_SFT_ROR = 5;

  // 32-bit
  const uint32_t a = 0x0000FFFF;
  EXPECT_EQ(simeng::arch::aarch64::shiftValue(a, ARM64_SFT_ROR, 16),
            0xFFFF0000);

  const uint32_t b = 0xFFFF0000;
  EXPECT_EQ(simeng::arch::aarch64::shiftValue(b, ARM64_SFT_ROR, 31),
            0xFFFE0001);

  EXPECT_EQ(simeng::arch::aarch64::shiftValue(b, ARM64_SFT_ROR, 0), 0xFFFF0000);

  // 64-bit
  const uint64_t c = 0x00000000FFFFFFFF;
  EXPECT_EQ(simeng::arch::aarch64::shiftValue(c, ARM64_SFT_ROR, 32),
            0xFFFFFFFF00000000);

  const uint64_t d = 0xFFFFFFFF00000000;
  EXPECT_EQ(simeng::arch::aarch64::shiftValue(d, ARM64_SFT_ROR, 63),
            0xFFFFFFFE00000001);

  EXPECT_EQ(simeng::arch::aarch64::shiftValue(d, ARM64_SFT_ROR, 0),
            0xFFFFFFFF00000000);
}

}  // namespace