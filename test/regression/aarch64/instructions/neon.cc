#include "AArch64RegressionTest.hh"

namespace {

using InstNeon = AArch64RegressionTest;

TEST_P(InstNeon, movi) {
  RUN_AARCH64(R"(
    movi v0.4s, 42
    movi v1.4s, 42, lsl #8
    movi v2.4s, 3, lsl #24
  )");
  EXPECT_EQ((getVectorRegisterElement<uint32_t, 0>(0)), 42u);
  EXPECT_EQ((getVectorRegisterElement<uint32_t, 1>(0)), 42u);
  EXPECT_EQ((getVectorRegisterElement<uint32_t, 2>(0)), 42u);
  EXPECT_EQ((getVectorRegisterElement<uint32_t, 3>(0)), 42u);

  EXPECT_EQ((getVectorRegisterElement<uint32_t, 0>(1)), (42u << 8));
  EXPECT_EQ((getVectorRegisterElement<uint32_t, 1>(1)), (42u << 8));
  EXPECT_EQ((getVectorRegisterElement<uint32_t, 2>(1)), (42u << 8));
  EXPECT_EQ((getVectorRegisterElement<uint32_t, 3>(1)), (42u << 8));

  EXPECT_EQ((getVectorRegisterElement<uint32_t, 0>(2)), (3u << 24));
  EXPECT_EQ((getVectorRegisterElement<uint32_t, 1>(2)), (3u << 24));
  EXPECT_EQ((getVectorRegisterElement<uint32_t, 2>(2)), (3u << 24));
  EXPECT_EQ((getVectorRegisterElement<uint32_t, 3>(2)), (3u << 24));
}

INSTANTIATE_TEST_SUITE_P(AArch64, InstNeon, ::testing::Values(EMULATION),
                         coreTypeToString);

}  // namespace
