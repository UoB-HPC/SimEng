#include "AArch64RegressionTest.hh"

namespace {

using InstBitmanip = AArch64RegressionTest;
using namespace simeng::arch::aarch64::InstructionGroups;

TEST_P(InstBitmanip, bfm) {
  // 32-bit
  RUN_AARCH64(R"(
    # Fill destination registers with 1s
    mov w0, wzr
    sub w1, w0, #1
    sub w2, w0, #1
    sub w3, w0, #1
    sub w4, w0, #1

    # Source = 0x007A0000
    movz w0, #0x7A, lsl 16

    bfm w1, w0, #12, #23
    bfm w2, w0, #16, #31
    bfm w3, w0, #28, #23
    bfm w4, w0, #30, #27
  )");
  EXPECT_EQ(getGeneralRegister<uint32_t>(1), 0xFFFFF7A0ull);
  EXPECT_EQ(getGeneralRegister<uint32_t>(2), 0xFFFF007Aull);
  EXPECT_EQ(getGeneralRegister<uint32_t>(3), 0xF7A0000Full);
  EXPECT_EQ(getGeneralRegister<uint32_t>(4), 0xC1E80003ull);

  // 64-bit
  RUN_AARCH64(R"(
    # Fill destination registers with 1s
    mov x0, xzr
    sub x1, x0, #1
    sub x2, x0, #1
    sub x3, x0, #1
    sub x4, x0, #1

    # Source = 0x00000000007A0000
    movz x0, #0x7A, lsl 16

    bfm x1, x0, #12, #23
    bfm x2, x0, #16, #63
    bfm x3, x0, #32, #23
    bfm x4, x0, #60, #55
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(1), 0xFFFFFFFFFFFFF7A0ull);
  EXPECT_EQ(getGeneralRegister<uint64_t>(2), 0xFFFF00000000007Aull);
  EXPECT_EQ(getGeneralRegister<uint64_t>(3), 0xFF7A0000FFFFFFFFull);
  EXPECT_EQ(getGeneralRegister<uint64_t>(4), 0xF000000007A0000Full);
}

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

TEST_P(InstBitmanip, rbit) {
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

    rbit w3, w1
    rbit w4, w2
  )");
  EXPECT_EQ(getGeneralRegister<uint32_t>(3), 0xF77DB57B);
  EXPECT_EQ(getGeneralRegister<uint32_t>(4), 0x1E6A2C48);

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

    rbit x3, x1
    rbit x4, x2
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(3), 0xF77DB57B00000000);
  EXPECT_EQ(getGeneralRegister<uint64_t>(4), 0x000000001E6A2C48);
}

TEST_P(InstBitmanip, rev) {
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

    rev x3, x1
    rev x4, x2
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(3), 0xEFBEADDE00000000);
  EXPECT_EQ(getGeneralRegister<uint64_t>(4), 0x0000000078563412);
}

TEST_P(InstBitmanip, sbfm) {
  // 32-bit
  RUN_AARCH64(R"(
    # Fill destination registers with 1s
    mov w0, wzr
    sub w1, w0, #1
    sub w2, w0, #1
    sub w3, w0, #1
    sub w4, w0, #1

    # Source = 0x007A0000
    movz w0, #0x7A, lsl 16

    sbfm w1, w0, #12, #23
    sbfm w2, w0, #16, #31
    sbfm w3, w0, #28, #23
    sbfm w4, w0, #30, #27

    # Test sign extension (select bitfield such that highest bit is set)
    sbfm w5, w0, #12, #22
    sbfm w6, w0, #28, #22

    # Test aliases
    movz w0, 0x1234
    sxtb w7, w0
    sxth w8, w0
  )");
  EXPECT_EQ(getGeneralRegister<uint32_t>(1), 0x000007A0ull);
  EXPECT_EQ(getGeneralRegister<uint32_t>(2), 0x0000007Aull);
  EXPECT_EQ(getGeneralRegister<uint32_t>(3), 0x07A00000ull);
  EXPECT_EQ(getGeneralRegister<uint32_t>(4), 0x01E80000ull);
  EXPECT_EQ(getGeneralRegister<uint32_t>(5), 0xFFFFFFA0ull);
  EXPECT_EQ(getGeneralRegister<uint32_t>(6), 0xFFA00000ull);
  EXPECT_EQ(getGeneralRegister<uint32_t>(7), 0x34);
  EXPECT_EQ(getGeneralRegister<uint32_t>(8), 0x1234);

  // 64-bit
  RUN_AARCH64(R"(
    # Fill destination registers with 1s
    mov x0, xzr
    sub x1, x0, #1
    sub x2, x0, #1
    sub x3, x0, #1
    sub x4, x0, #1

    # Source = 0x00000000007A0000
    movz x0, #0x7A, lsl 16

    sbfm x1, x0, #12, #23
    sbfm x2, x0, #16, #63
    sbfm x3, x0, #32, #23
    sbfm x4, x0, #60, #55

    # Test sign extension (select bitfield such that highest bit is set)
    sbfm x5, x0, #12, #22
    sbfm x6, x0, #32, #22

    # Test aliases
    movz x0, 0x1234
    lsl x0, x0, 16
    movk x0, 0x5678
    sxtb x7, w0
    sxth x8, w0
    sxtw x9, w0
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(1), 0x00000000000007A0ull);
  EXPECT_EQ(getGeneralRegister<uint64_t>(2), 0x000000000000007Aull);
  EXPECT_EQ(getGeneralRegister<uint64_t>(3), 0x007A000000000000ull);
  EXPECT_EQ(getGeneralRegister<uint64_t>(4), 0x0000000007A00000ull);
  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0xFFFFFFFFFFFFFFA0ull);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0xFFFA000000000000ull);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 0x78);
  EXPECT_EQ(getGeneralRegister<uint64_t>(8), 0x5678);
  EXPECT_EQ(getGeneralRegister<uint64_t>(9), 0x12345678);

  EXPECT_GROUP(R"(sbfm w4, w0, #30, #27)", INT_SIMPLE_ARTH_NOSHIFT);
  EXPECT_GROUP(R"(sbfm x6, x0, #32, #22)", INT_SIMPLE_ARTH_NOSHIFT);

  EXPECT_GROUP(R"(sxtb w7, w0)", INT_SIMPLE_ARTH_NOSHIFT);
  EXPECT_GROUP(R"(sxtb x7, w0)", INT_SIMPLE_ARTH_NOSHIFT);

  EXPECT_GROUP(R"(sxth w7, w0)", INT_SIMPLE_ARTH_NOSHIFT);
  EXPECT_GROUP(R"(sxth x7, w0)", INT_SIMPLE_ARTH_NOSHIFT);

  EXPECT_GROUP(R"(sxtw x7, w0)", INT_SIMPLE_ARTH_NOSHIFT);
}

TEST_P(InstBitmanip, ubfm) {
  // 32-bit
  RUN_AARCH64(R"(
    # Fill destination registers with 1s
    mov w0, wzr
    sub w1, w0, #1
    sub w2, w0, #1
    sub w3, w0, #1
    sub w4, w0, #1

    # Source = 0x007A0000
    movz w0, #0x7A, lsl 16

    ubfm w1, w0, #12, #23
    ubfm w2, w0, #16, #31
    ubfm w3, w0, #28, #23
    ubfm w4, w0, #30, #27
  )");
  EXPECT_EQ(getGeneralRegister<uint32_t>(1), 0x000007A0ull);
  EXPECT_EQ(getGeneralRegister<uint32_t>(2), 0x0000007Aull);
  EXPECT_EQ(getGeneralRegister<uint32_t>(3), 0x07A00000ull);
  EXPECT_EQ(getGeneralRegister<uint32_t>(4), 0x01E80000ull);

  RUN_AARCH64(R"(
    # Fill destination registers with 1s
    mov x0, xzr
    sub x1, x0, #1
    sub x2, x0, #1
    sub x3, x0, #1
    sub x4, x0, #1

    # Source = 0x00000000007A0000
    movz x0, #0x7A, lsl 16

    ubfm x1, x0, #12, #23
    ubfm x2, x0, #16, #63
    ubfm x3, x0, #32, #23
    ubfm x4, x0, #60, #55
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(1), 0x00000000000007A0ull);
  EXPECT_EQ(getGeneralRegister<uint64_t>(2), 0x000000000000007Aull);
  EXPECT_EQ(getGeneralRegister<uint64_t>(3), 0x007A000000000000ull);
  EXPECT_EQ(getGeneralRegister<uint64_t>(4), 0x0000000007A00000ull);
}

INSTANTIATE_TEST_SUITE_P(AArch64, InstBitmanip,
                         ::testing::Values(std::make_tuple(EMULATION, "{}")),
                         paramToString);

}  // namespace
