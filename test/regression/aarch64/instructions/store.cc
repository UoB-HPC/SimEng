#include "AArch64RegressionTest.hh"

namespace {

using InstStore = AArch64RegressionTest;

TEST_P(InstStore, stpwi) {
  RUN_AARCH64(R"(
    movz w0, #7
    movz w1, #42
    stp w0, w1, [sp, -8]
  )");
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() - 8), 7u);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() - 4), 42u);
}

TEST_P(InstStore, stur) {
  RUN_AARCH64(R"(
    movz w0, #42
    stur w0, [sp, #-4]
  )");
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() - 4), 42u);

  RUN_AARCH64(R"(
    movz x0, #42
    stur x0, [sp, #-8]
  )");
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 8), 42u);
}

INSTANTIATE_TEST_SUITE_P(AArch64, InstStore, ::testing::Values(EMULATION),
                         coreTypeToString);

}  // namespace
