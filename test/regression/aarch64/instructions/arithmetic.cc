#include "AArch64RegressionTest.hh"

namespace {

using InstArithmetic = AArch64RegressionTest;

TEST_P(InstArithmetic, add) {
  RUN_AARCH64(R"(
    mov w0, wzr
    add w1, w0, #2
    add w2, w0, #7, lsl #12
  )");
  EXPECT_EQ(getGeneralRegister<uint32_t>(1), 2u);
  EXPECT_EQ(getGeneralRegister<uint32_t>(2), (7u << 12));

  RUN_AARCH64(R"(
    mov x0, xzr
    add x1, x0, #3
    add x2, x0, #5, lsl #12
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(1), 3u);
  EXPECT_EQ(getGeneralRegister<uint64_t>(2), (5u << 12));
}

// Test that NZCV flags are set correctly by 32-bit subs
TEST_P(InstArithmetic, subsw) {
  // 0 - 0 = 0
  RUN_AARCH64(R"(
    mov w0, wzr
    subs w0, w0, #0
  )");
  EXPECT_EQ(getNZCV(), 0b0110);
  EXPECT_EQ(getGeneralRegister<uint32_t>(0), 0u);

  // 2 - 1 = 1
  RUN_AARCH64(R"(
    mov w0, #2
    subs w0, w0, #1
  )");
  EXPECT_EQ(getNZCV(), 0b0010);
  EXPECT_EQ(getGeneralRegister<uint32_t>(0), 1u);

  // 0 - 1 = -1
  RUN_AARCH64(R"(
    mov w0, wzr
    subs w0, w0, #1
  )");
  EXPECT_EQ(getNZCV(), 0b1000);
  EXPECT_EQ(getGeneralRegister<uint32_t>(0), -1);

  // (2^31 -1) - -1 = 2^31
  RUN_AARCH64(R"(
    mov w0, wzr
    mov w1, #1
    add w1, w0, w1, lsl #31
    sub w1, w1, #1
    sub w2, w0, #1
    subs w0, w1, w2
  )");
  EXPECT_EQ(getNZCV(), 0b1001);
  EXPECT_EQ(getGeneralRegister<uint32_t>(0), (1ul << 31));

  // 2^31 - 0 = 2^31
  RUN_AARCH64(R"(
    mov w0, wzr
    add w1, w0, #1
    add w1, w0, w1, lsl #31
    subs w0, w1, #0
  )");
  EXPECT_EQ(getNZCV(), 0b1010);
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), (1u << 31));

  // 2^31 - 1 = 2^31 - 1
  RUN_AARCH64(R"(
    mov w0, wzr
    add w1, w0, #1
    add w1, w0, w1, lsl #31
    subs w0, w1, #1
  )");
  EXPECT_EQ(getNZCV(), 0b0011);
  EXPECT_EQ(getGeneralRegister<uint32_t>(0), (1u << 31) - 1);
}

// Test that NZCV flags are set correctly by 64-bit subs
TEST_P(InstArithmetic, subsx) {
  // 0 - 0 = 0
  RUN_AARCH64(R"(
    mov x0, xzr
    subs x0, x0, #0
  )");
  EXPECT_EQ(getNZCV(), 0b0110);
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 0u);

  // 2 - 1 = 1
  RUN_AARCH64(R"(
    mov x0, #2
    subs x0, x0, #1
  )");
  EXPECT_EQ(getNZCV(), 0b0010);
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 1u);

  // 0 - 1 = -1
  RUN_AARCH64(R"(
    mov x0, xzr
    subs x0, x0, #1
  )");
  EXPECT_EQ(getNZCV(), 0b1000);
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), -1);

  // (2^63 -1) - -1 = 2^63
  RUN_AARCH64(R"(
    mov x0, xzr
    add x1, x0, #1
    add x1, x0, x1, lsl #63
    sub x1, x1, #1
    sub x2, x0, #1
    subs x0, x1, x2
  )");
  EXPECT_EQ(getNZCV(), 0b1001);
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), (1ul << 63));

  // 2^63 - 0 = 2^63
  RUN_AARCH64(R"(
    mov x0, xzr
    add x1, x0, #1
    add x1, x0, x1, lsl #63
    subs x0, x1, #0
  )");
  EXPECT_EQ(getNZCV(), 0b1010);
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), (1ul << 63));

  // 2^63 - 1 = 2^63 - 1
  RUN_AARCH64(R"(
    mov x0, xzr
    add x1, x0, #1
    add x1, x0, x1, lsl #63
    subs x0, x1, #1
  )");
  EXPECT_EQ(getNZCV(), 0b0011);
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), (1ul << 63) - 1);
}

INSTANTIATE_TEST_SUITE_P(AArch64, InstArithmetic, ::testing::Values(EMULATION),
                         coreTypeToString);

}  // namespace
