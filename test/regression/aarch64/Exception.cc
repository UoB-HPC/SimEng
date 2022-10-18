#include "AArch64RegressionTest.hh"

namespace {

using Exception = AArch64RegressionTest;

// Test that branching to an address that is misaligned raises an exception.
TEST_P(Exception, misaligned_pc) {
  RUN_AARCH64(R"(
    mov x0, 5
    br x0
  )");
  const char err[] =
      "\n[SimEng:ExceptionHandler] Encountered misaligned program counter "
      "exception";
  EXPECT_EQ(stdout_.substr(0, sizeof(err) - 1), err);
}

/** WARNING: Need to `smstop` at the end of each test, on its own, so non-sme
 * tests have the correct VL in execution stage. */
#if SIMENG_LLVM_VERSION >= 14
// Test that performing an SME instruction in the wrong context mode raises an
// exception.
TEST_P(Exception, SME_context_modes) {
  RUN_AARCH64(R"(
  smstart za
  fmopa	za0.s, p2/m, p0/m, z1.s, z2.s
  )");
  const char err0[] =
      "\n[SimEng:ExceptionHandler] Encountered SME execution attempt when "
      "streaming mode disabled";
  EXPECT_EQ(stdout_.substr(0, sizeof(err0) - 1), err0);
  // Reset SVCR in AArch64_Architecture to
  RUN_AARCH64(R"(
  smstop
  )");

  RUN_AARCH64(R"(
  smstart sm
  fmopa	za0.s, p2/m, p0/m, z1.s, z2.s
  )");
  const char err1[] =
      "\n[SimEng:ExceptionHandler] Encountered ZA register access attempt when "
      "disabled";
  EXPECT_EQ(stdout_.substr(0, sizeof(err1) - 1), err1);
  // Reset SVCR in AArch64_Architecture to
  RUN_AARCH64(R"(
  smstop
  )");

  RUN_AARCH64(R"(
  smstart sm
  zero {za}
  )");
  const char err2[] =
      "\n[SimEng:ExceptionHandler] Encountered ZA register access attempt when "
      "disabled";
  EXPECT_EQ(stdout_.substr(0, sizeof(err2) - 1), err2);
  // Reset SVCR in AArch64_Architecture to
  RUN_AARCH64(R"(
  smstop
  )");
}
#endif

INSTANTIATE_TEST_SUITE_P(
    AArch64, Exception,
    ::testing::Values(std::make_tuple(EMULATION, YAML::Load("{}")),
                      std::make_tuple(INORDER, YAML::Load("{}")),
                      std::make_tuple(OUTOFORDER, YAML::Load("{}"))),
    paramToString);

}  // namespace
