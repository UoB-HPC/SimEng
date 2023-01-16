#include "AArch64RegressionTest.hh"

namespace {

using InstComparison = AArch64RegressionTest;

// Test correct Value stored after comparison for CASAL (32 & 64 bit)
TEST_P(InstComparison, casal) {
  // 32-bit
  initialHeapData_.resize(16);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0xDEADBEEF;
  heap[1] = 0xDE;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # Values not-equal
    mov w1, #0xDE
    mov w2, #100
    casal w1, w2, [x0]

    # Values equal
    add x3, x0, #4
    casal w1, w2, [x3]

    # Using stack pointer
    mov w6, #0xDE
    mov w7, #89
    stlrb w6, [sp]
    casal w1, w7, [sp]
  )");
  EXPECT_EQ(getMemoryValue<uint32_t>(getGeneralRegister<uint64_t>(0)),
            0xDEADBEEF);
  EXPECT_EQ(getMemoryValue<uint32_t>(getGeneralRegister<uint64_t>(3)), 100);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer()), 89);

  // 64-bit
  initialHeapData_.resize(16);
  uint64_t* heap64 = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  heap64[0] = 0xDEADBEEF;
  heap64[1] = 0x4F;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # Values not-equal
    mov x1, #0x4F
    mov x2, #101
    casal x1, x2, [x0]

    # Values equal
    add x3, x0, #8
    casal x1, x2, [x3]

    # Using stack pointer
    mov w6, #0x4F
    mov x7, #76
    stlrb w6, [sp]
    casal x1, x7, [sp]
  )");
  EXPECT_EQ(getMemoryValue<uint64_t>(getGeneralRegister<uint64_t>(0)),
            0xDEADBEEF);
  EXPECT_EQ(getMemoryValue<uint64_t>(getGeneralRegister<uint64_t>(3)), 101);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer()), 76);
}

// Test that NZCV flags are set correctly by the 32-bit cmn instruction
TEST_P(InstComparison, cmnw) {
  // cmn 0, 0 = true
  RUN_AARCH64(R"(
    mov w0, wzr
    cmn w0, #0x0
  )");
  EXPECT_EQ(getNZCV(), 0b0100);

  // cmn 1, 1 = false
  RUN_AARCH64(R"(
    movz w0, #0x1
    cmn w0, #0x1
  )");
  EXPECT_EQ(getNZCV(), 0b0000);

  // cmn -1, 1 = true
  RUN_AARCH64(R"(
    mov w0, wzr
    sub w0, w0, #0x1
    cmn w0, #0x1
  )");
  EXPECT_EQ(getNZCV(), 0b0110);
}

// Test that NZCV flags are set correctly by the 64-bit cmn instruction
TEST_P(InstComparison, cmnx) {
  // cmn 0, 0 = true
  RUN_AARCH64(R"(
    mov x0, xzr
    cmn x0, #0x0
  )");
  EXPECT_EQ(getNZCV(), 0b0100);

  // cmn 1, 1 = false
  RUN_AARCH64(R"(
    movz x0, #0x1
    cmn x0, #0x1
  )");
  EXPECT_EQ(getNZCV(), 0b0000);

  // cmn -1, 1 = true
  RUN_AARCH64(R"(
    mov x0, xzr
    sub x0, x0, #0x1
    cmn x0, #0x1
  )");
  EXPECT_EQ(getNZCV(), 0b0110);
}

// Test that NZCV flags are set correctly by the 32-bit ccmn instruction
TEST_P(InstComparison, ccmnw) {
  // ccmn 0, 0, 0b0000, al => nzcv = 0b0100
  RUN_AARCH64(R"(
    mov w0, wzr
    ccmn w0, #0x0, #0b0000, al
  )");
  EXPECT_EQ(getNZCV(), 0b0100);

  // ccmn 0, 0, 0b1111, vs => nzcv = 0b1111
  RUN_AARCH64(R"(
    mov w0, wzr
    ccmn w0, #0x0, #0b1111, vs
  )");
  EXPECT_EQ(getNZCV(), 0b1111);

  // ccmn 1, 1, 0b1111, al => nzcv = 0b0000
  RUN_AARCH64(R"(
    mov w0, #0x1
    ccmn w0, #0x1, #0b1111, al
  )");
  EXPECT_EQ(getNZCV(), 0b0000);

  // ccmn 1, 1, 0b1111, vs => nzcv = 0b1111
  RUN_AARCH64(R"(
    mov w0, #0x1
    ccmn w0, #0x1, #0b1111, vs
  )");
  EXPECT_EQ(getNZCV(), 0b1111);

  // ccmn -1, 1, 0b0000, al => nzcv = 0b0110
  RUN_AARCH64(R"(
    mov w0, wzr
    sub w0, w0, #0x1
    ccmn w0, #0x1, #0b0000, al
  )");
  EXPECT_EQ(getNZCV(), 0b0110);

  // ccmn -1, 1, 0b0000, vs => nzcv = 0b0000
  RUN_AARCH64(R"(
    mov w0, wzr
    sub w0, w0, #0x1
    ccmn w0, #0x1, #0b0000, vs
  )");
  EXPECT_EQ(getNZCV(), 0b0000);
}

// Test that NZCV flags are set correctly by 32-bit tst
TEST_P(InstComparison, tstw) {
  // tst 0, 1 = false
  RUN_AARCH64(R"(
    tst wzr, #0x1
  )");
  EXPECT_EQ(getNZCV(), 0b0100);

  // tst 0b0110, 0b0010 = true
  RUN_AARCH64(R"(
    movk w0, #0x6
    tst w0, #0x2
  )");
  EXPECT_EQ(getNZCV(), 0b0000);

  // tst -1, 0b1000... = true, negative
  RUN_AARCH64(R"(
    mov w0, wzr
    sub w0, w0, #1
    tst w0, #0x80000000
  )");
  EXPECT_EQ(getNZCV(), 0b1000);
}

// Test that NZCV flags are set correctly by 32-bit cmp
TEST_P(InstComparison, cmpw) {
  // 0 - 0 = 0
  RUN_AARCH64(R"(
    mov w0, wzr
    cmp w0, #0
  )");
  EXPECT_EQ(getNZCV(), 0b0110);

  // 2 - 1 = 1
  RUN_AARCH64(R"(
    mov w0, #2
    cmp w0, #1
  )");
  EXPECT_EQ(getNZCV(), 0b0010);

  // 0 - 1 = -1
  RUN_AARCH64(R"(
    mov w0, wzr
    cmp w0, #1
  )");
  EXPECT_EQ(getNZCV(), 0b1000);

  // (2^31 -1) - -1 = 2^31
  RUN_AARCH64(R"(
    mov w0, wzr
    mov w1, #1
    add w1, w0, w1, lsl #31
    sub w1, w1, #1
    sub w2, w0, #1
    cmp w1, w2
  )");
  EXPECT_EQ(getNZCV(), 0b1001);

  // 2^31 - 0 = 2^31
  RUN_AARCH64(R"(
    mov w0, wzr
    add w1, w0, #1
    add w1, w0, w1, lsl #31
    cmp w1, #0
  )");
  EXPECT_EQ(getNZCV(), 0b1010);

  // 2^31 - 1 = 2^31 - 1
  RUN_AARCH64(R"(
    mov w0, wzr
    add w1, w0, #1
    add w1, w0, w1, lsl #31
    cmp w1, #1
  )");
  EXPECT_EQ(getNZCV(), 0b0011);
}

// Test that NZCV flags are set correctly by 64-bit cmp
TEST_P(InstComparison, cmpx) {
  // 0 - 0 = 0
  RUN_AARCH64(R"(
    mov x0, xzr
    cmp x0, #0
  )");
  EXPECT_EQ(getNZCV(), 0b0110);

  // 2 - 1 = 1
  RUN_AARCH64(R"(
    mov x0, #2
    cmp x0, #1
  )");
  EXPECT_EQ(getNZCV(), 0b0010);

  // 0 - 1 = -1
  RUN_AARCH64(R"(
    mov x0, xzr
    cmp x0, #1
  )");
  EXPECT_EQ(getNZCV(), 0b1000);

  // (2^63 -1) - -1 = 2^63
  RUN_AARCH64(R"(
    mov x0, xzr
    add x1, x0, #1
    add x1, x0, x1, lsl #63
    sub x1, x1, #1
    sub x2, x0, #1
    cmp x1, x2
  )");
  EXPECT_EQ(getNZCV(), 0b1001);

  // 2^63 - 0 = 2^63
  RUN_AARCH64(R"(
    mov x0, xzr
    add x1, x0, #1
    add x1, x0, x1, lsl #63
    cmp x1, #0
  )");
  EXPECT_EQ(getNZCV(), 0b1010);

  // 2^63 - 1 = 2^63 - 1
  RUN_AARCH64(R"(
    mov x0, xzr
    add x1, x0, #1
    add x1, x0, x1, lsl #63
    cmp x1, #1
  )");
  EXPECT_EQ(getNZCV(), 0b0011);

  // (7 << 48) - (15 << 33)
  RUN_AARCH64(R"(
    movz x0, #7, lsl #48
    movz x1, #15
    cmp x0, x1, lsl 33
  )");
  EXPECT_EQ(getNZCV(), 0b0010);

  // (7 << 48) - (-1) [8-bit sign-extended]
  RUN_AARCH64(R"(
    movz x0, #7, lsl #48
    movz x1, #15
    # 255 will be -1 when sign-extended from 8-bits
    mov w2, 255
    cmp x0, w2, sxtb
  )");
  EXPECT_EQ(getNZCV(), 0b0000);

  // (7 << 48) - (255 << 4)
  RUN_AARCH64(R"(
    movz x0, #7, lsl #48
    movz x1, #15
    mov w2, 255
    cmp x0, x2, uxtx 4
  )");
  EXPECT_EQ(getNZCV(), 0b0010);
}

// Test that NZCV flags are set correctly by 64-bit tst
TEST_P(InstComparison, tstx) {
  // tst 0, 1 = false
  RUN_AARCH64(R"(
    tst xzr, #0x1
  )");
  EXPECT_EQ(getNZCV(), 0b0100);

  // tst 0b0110, 0b0010 = true
  RUN_AARCH64(R"(
    movk x0, #0b0110
    tst x0, #0b0010
  )");
  EXPECT_EQ(getNZCV(), 0b0000);

  // tst -1, 0b1000... = true, negative
  RUN_AARCH64(R"(
    mov x0, xzr
    sub x0, x0, #1
    tst x0, #0x8000000000000000
  )");
  EXPECT_EQ(getNZCV(), 0b1000);
}

INSTANTIATE_TEST_SUITE_P(AArch64, InstComparison,
                         ::testing::Values(std::make_tuple(EMULATION,
                                                           YAML::Load("{}"))),
                         paramToString);

}  // namespace
