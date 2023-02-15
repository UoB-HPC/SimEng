#include "AArch64RegressionTest.hh"

namespace {

using InstDiv = AArch64RegressionTest;

TEST_P(InstDiv, sdiv) {
  // 42 / 6 = 7
  RUN_AARCH64(R"(
    movz x0, #42
    movz x1, #6
    sdiv x2, x0, x1
    sdiv w3, w0, w1
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(2), 7u);
  EXPECT_EQ(getGeneralRegister<int32_t>(3), 7u);

  // 42 / -7 = -6
  RUN_AARCH64(R"(
    movz x0, #42
    mov x1, xzr
    sub x1, x1, #1
    movz x2, #7
    mul x1, x1, x2
    sdiv x2, x0, x1
    sdiv w3, w0, w1
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(2), -6);
  EXPECT_EQ(getGeneralRegister<int32_t>(3), -6);

  // Divide-by-zero should not crash
  // 42 / 0 = 0
  RUN_AARCH64(R"(
    movz x0, #42
    sdiv x2, x0, xzr
    sdiv w3, w0, wzr
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(2), 0u);
  EXPECT_EQ(getGeneralRegister<int32_t>(3), 0u);
}

TEST_P(InstDiv, udiv) {
  // 42 / 6 = 7
  RUN_AARCH64(R"(
    movz x0, #42
    movz x1, #6
    udiv x2, x0, x1
    udiv w3, w0, w1
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(2), 7u);
  EXPECT_EQ(getGeneralRegister<uint32_t>(3), 7u);

  // Divide-by-zero should not crash
  // 42 / 0 = 0
  RUN_AARCH64(R"(
    movz x0, #42
    udiv x2, x0, xzr
    udiv w3, w0, wzr
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(2), 0u);
  EXPECT_EQ(getGeneralRegister<uint32_t>(3), 0u);
}

INSTANTIATE_TEST_SUITE_P(AArch64, InstDiv,
                         ::testing::Values(std::make_tuple(EMULATION,
                                                           YAML::Load("{}"))),
                         paramToString);

}  // namespace
