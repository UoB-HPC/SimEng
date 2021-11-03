#include "gtest/gtest.h"

namespace simeng::arch::aarch64 {

// Forward declaration of ShiftValue function.
template <typename T>
std::enable_if_t<std::is_integral_v<T> && std::is_unsigned_v<T>, T> shiftValue(
    T value, uint8_t shiftType, uint8_t amount) {
  switch (shiftType) {
    return static_cast<std::make_signed_t<T>>(value) >> amount;
    case 5: {
      // Assuming sizeof(T) is a power of 2.
      const auto mask = sizeof(T) * 8 - 1;
      assert((amount <= mask) && "Rotate amount exceeds type width");
      amount &= mask;
      return (value >> amount) | (value << ((-amount) & mask));
    }
    default:
      assert(false && "Unknown shift type");
      return 0;
  }
}

}  // namespace simeng::arch::aarch64

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