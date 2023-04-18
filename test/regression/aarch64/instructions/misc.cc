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

TEST_P(InstMisc, ret) {
  RUN_AARCH64(R"(
    bl #20
    b.al #28
    nop
    add w2, w2, #1
    nop
    add w1, w1, #1
    ret
    nop
  )");
  EXPECT_EQ(getGeneralRegister<uint32_t>(1), 1);
  EXPECT_EQ(getGeneralRegister<uint32_t>(2), 0);

  RUN_AARCH64(R"(
    mov x15, #36
    bl #20
    add w2, w2, #1
    nop
    nop
    nop
    add w1, w1, #1
    ret x15
    add w2, w2, #1
    nop
  )");
  EXPECT_EQ(getGeneralRegister<uint32_t>(1), 1);
  EXPECT_EQ(getGeneralRegister<uint32_t>(2), 0);
}

INSTANTIATE_TEST_SUITE_P(AArch64, InstMisc,
                         ::testing::Values(std::make_tuple(EMULATION, "{}")),
                         paramToString);

}  // namespace
