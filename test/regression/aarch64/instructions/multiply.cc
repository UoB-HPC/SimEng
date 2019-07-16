#include "AArch64RegressionTest.hh"

namespace {

using InstMul = AArch64RegressionTest;

TEST_P(InstMul, maddw) {
  RUN_AARCH64(R"(
    movz w0, #7
    movz w1, #6
    movz w2, #5
    madd w3, w0, w1, w2
  )");
  EXPECT_EQ(getGeneralRegister<uint32_t>(3), 47u);
}

TEST_P(InstMul, mulw) {
  RUN_AARCH64(R"(
    movz w0, #7
    movz w1, #6
    mul w2, w0, w1
  )");
  EXPECT_EQ(getGeneralRegister<uint32_t>(2), 42u);
}

INSTANTIATE_TEST_SUITE_P(AArch64, InstMul, ::testing::Values(EMULATION),
                         coreTypeToString);

}  // namespace
