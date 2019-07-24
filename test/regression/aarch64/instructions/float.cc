#include "AArch64RegressionTest.hh"

namespace {

using InstFloat = AArch64RegressionTest;

TEST_P(InstFloat, fmov) {
  RUN_AARCH64(R"(
    fmov d0, 1.0
    fmov d1, -0.125
  )");
  EXPECT_EQ((getVectorRegisterElement<double, 0>(0)), 1.0);
  EXPECT_EQ((getVectorRegisterElement<double, 1>(0)), 0.0);
  EXPECT_EQ((getVectorRegisterElement<double, 0>(1)), -0.125);
  EXPECT_EQ((getVectorRegisterElement<double, 1>(1)), 0.0);
}

INSTANTIATE_TEST_SUITE_P(AArch64, InstFloat, ::testing::Values(EMULATION),
                         coreTypeToString);

}  // namespace
