#include "AArch64RegressionTest.hh"

namespace {

using InstMisc = AArch64RegressionTest;

TEST_P(InstMisc, adr) {
  RUN_AARCH64(R"(
    adr x0, #0
    adr x1, #4
    adr x2, #-4
  )");
  EXPECT_EQ(getGeneralRegister<uint32_t>(0), 0u);
  EXPECT_EQ(getGeneralRegister<uint32_t>(1), 8u);
  EXPECT_EQ(getGeneralRegister<uint32_t>(2), 4u);
}

INSTANTIATE_TEST_SUITE_P(AArch64, InstMisc, ::testing::Values(EMULATION),
                         coreTypeToString);

}  // namespace
