#include "AArch64RegressionTest.hh"

namespace {

using InstLogical = AArch64RegressionTest;

TEST_P(InstLogical, andw) {
  // 0 & 0 = 0
  RUN_AARCH64(R"(
    mov w0, wzr
    and w0, w0, wzr
  )");
  EXPECT_EQ(getGeneralRegister<uint32_t>(0), 0u);

  // 0b0010 & 0b0001 = 0
  RUN_AARCH64(R"(
    mov w0, #2
    and w0, w0, #1
  )");
  EXPECT_EQ(getGeneralRegister<uint32_t>(0), 0u);

  // 0b0111 & 0b1010 = 0b0010
  RUN_AARCH64(R"(
    movz w0, 0x7
    movz w1, 0xA
    and w0, w0, w1
  )");
  EXPECT_EQ(getGeneralRegister<uint32_t>(0), 0b0010);

  // 0b0111 & (0b1010 << 1) = 0b0100
  RUN_AARCH64(R"(
    movz w0, 0x7
    movz w1, 0xA
    and w0, w0, w1, lsl #1
  )");
  EXPECT_EQ(getGeneralRegister<uint32_t>(0), 0b0100);
}

TEST_P(InstLogical, andx) {
  // 0 & 0 = 0
  RUN_AARCH64(R"(
    mov x0, xzr
    and x0, x0, xzr
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 0u);

  // 0b0010 & 0b0001 = 0
  RUN_AARCH64(R"(
    mov x0, #2
    and x0, x0, #1
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 0u);

  // 0b0111 & 0b1010 = 0b0010
  RUN_AARCH64(R"(
    movz x0, 0x7
    movz x1, 0xA
    and x0, x0, x1
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 0b0010);

  // 0b0111 & (0b1010 << 1) = 0b0100
  RUN_AARCH64(R"(
    movz x0, 0x7
    movz x1, 0xA
    and x0, x0, x1, lsl #1
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 0b0100);

  // (0b0111 << 48) & (0b1010 << 47) = (0b101)<<48
  RUN_AARCH64(R"(
    movz x0, 0x7, lsl #48
    movz x1, 0xA
    and x0, x0, x1, lsl #47
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), (0b101ull) << 48);
}

TEST_P(InstLogical, andsw) {
  // 0 & 0 = 0
  RUN_AARCH64(R"(
    mov w0, wzr
    ands w0, w0, wzr
  )");
  EXPECT_EQ(getNZCV(), 0b0100);
  EXPECT_EQ(getGeneralRegister<uint32_t>(0), 0u);

  // 0b0010 & 0b0001 = 0
  RUN_AARCH64(R"(
    mov w0, #2
    ands w0, w0, #1
  )");
  EXPECT_EQ(getNZCV(), 0b0100);
  EXPECT_EQ(getGeneralRegister<uint32_t>(0), 0u);

  // 0b0111 & 0b1010 = 0b0010
  RUN_AARCH64(R"(
    movz w0, 0x7
    movz w1, 0xA
    ands w0, w0, w1
  )");
  EXPECT_EQ(getNZCV(), 0b0000);
  EXPECT_EQ(getGeneralRegister<uint32_t>(0), 0b0010);

  // 0b0111 & (0b1010 << 1) = 0b0100
  RUN_AARCH64(R"(
    movz w0, 0x7
    movz w1, 0xA
    ands w0, w0, w1, lsl #1
  )");
  EXPECT_EQ(getNZCV(), 0b0000);
  EXPECT_EQ(getGeneralRegister<uint32_t>(0), 0b0100);
}

TEST_P(InstLogical, andsx) {
  // 0 & 0 = 0
  RUN_AARCH64(R"(
    mov x0, xzr
    ands x0, x0, xzr
  )");
  EXPECT_EQ(getNZCV(), 0b0100);
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 0u);

  // 0b0010 & 0b0001 = 0
  RUN_AARCH64(R"(
    mov x0, #2
    ands x0, x0, #1
  )");
  EXPECT_EQ(getNZCV(), 0b0100);
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 0u);

  // 0b0111 & 0b1010 = 0b0010
  RUN_AARCH64(R"(
    movz x0, 0x7
    movz x1, 0xA
    ands x0, x0, x1
  )");
  EXPECT_EQ(getNZCV(), 0b0000);
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 0b0010);

  // 0b0111 & (0b1010 << 1) = 0b0100
  RUN_AARCH64(R"(
    movz x0, 0x7
    movz x1, 0xA
    ands x0, x0, x1, lsl #1
  )");
  EXPECT_EQ(getNZCV(), 0b0000);
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 0b0100);

  // (0b0111 << 48) & (0b1010 << 47) = (0b101)<<48
  RUN_AARCH64(R"(
    movz x0, 0x7, lsl #48
    movz x1, 0xA
    ands x0, x0, x1, lsl #47
  )");
  EXPECT_EQ(getNZCV(), 0b0000);
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), (0b101ull) << 48);
}

INSTANTIATE_TEST_SUITE_P(AArch64, InstLogical, ::testing::Values(EMULATION),
                         coreTypeToString);

}  // namespace
