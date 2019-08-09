#include "AArch64RegressionTest.hh"

namespace {

using InstBitmanip = AArch64RegressionTest;

TEST_P(InstBitmanip, extr) {
  // 32-bit
  initialHeapData_.resize(8);
  uint32_t* heap32 = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap32[0] = 0xDEADBEEF;
  heap32[1] = 0x12345678;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # Load values from heap
    ldr w1, [x0, #0]
    ldr w2, [x0, #4]

    extr w3, w1, w2, 0
    extr w4, w1, w2, 4
    extr w5, w1, w2, 24
    extr w6, w1, w2, 31
  )");
  EXPECT_EQ(getGeneralRegister<uint32_t>(3), 0x12345678);
  EXPECT_EQ(getGeneralRegister<uint32_t>(4), 0xF1234567);
  EXPECT_EQ(getGeneralRegister<uint32_t>(5), 0xADBEEF12);
  EXPECT_EQ(getGeneralRegister<uint32_t>(6), 0xBD5B7DDE);

  // 64-bit
  initialHeapData_.resize(16);
  uint64_t* heap64 = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  heap64[0] = 0x00000000DEADBEEF;
  heap64[1] = 0x1234567800000000;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # Load values from heap
    ldr x1, [x0, #0]
    ldr x2, [x0, #8]

    extr x3, x1, x2, 0
    extr x4, x1, x2, 12
    extr x5, x1, x2, 48
    extr x6, x1, x2, 63
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(3), 0x1234567800000000);
  EXPECT_EQ(getGeneralRegister<uint64_t>(4), 0xEEF1234567800000);
  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0x0000DEADBEEF1234);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0x00000001BD5B7DDE);
}

INSTANTIATE_TEST_SUITE_P(AArch64, InstBitmanip, ::testing::Values(EMULATION),
                         coreTypeToString);

}  // namespace
