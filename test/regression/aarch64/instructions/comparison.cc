#include "AArch64RegressionTest.hh"

namespace {

using InstComparison = AArch64RegressionTest;

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

INSTANTIATE_TEST_SUITE_P(AArch64, InstComparison, ::testing::Values(EMULATION),
                         coreTypeToString);

}  // namespace
