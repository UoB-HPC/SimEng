#include <algorithm>
#include <limits>

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

  RUN_AARCH64(R"(
  smstart sm
  fmopa	za0.s, p2/m, p0/m, z1.s, z2.s
  )");
  const char err1[] =
      "\n[SimEng:ExceptionHandler] Encountered ZA register access attempt when "
      "disabled";
  EXPECT_EQ(stdout_.substr(0, sizeof(err1) - 1), err1);

  RUN_AARCH64(R"(
  smstart sm
  zero {za}
  )");
  const char err2[] =
      "\n[SimEng:ExceptionHandler] Encountered ZA register access attempt when "
      "disabled";
  EXPECT_EQ(stdout_.substr(0, sizeof(err2) - 1), err2);
}

TEST_P(Exception, svcr) {
  // Check that smstart and smstop correctly change value of SVCR system
  // register, verified by the correctly performed behaviour
  RUN_AARCH64(R"(
    # Ensure vector length changes from SVE's to SME's
    cntb x0
    smstart
    cntb x1
    smstop
    cntb x2
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), VL / 8);
  EXPECT_EQ(getGeneralRegister<uint64_t>(1), SVL / 8);
  EXPECT_EQ(getGeneralRegister<uint64_t>(2), VL / 8);
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), getGeneralRegister<uint64_t>(2));
  EXPECT_GT(getGeneralRegister<uint64_t>(1), getGeneralRegister<uint64_t>(0));
  EXPECT_GT(SVL, VL);

  RUN_AARCH64(R"(
    # Ensure z regs get zeroed out when SM enabled
    dup z0.d, #3
    smstart
  )");
  CHECK_NEON(0, uint64_t, fillNeon<uint64_t>({0}, VL / 8));

  RUN_AARCH64(R"(
    # Ensure z regs get zeroed out when SM disabled
    smstart
    dup z0.d, #3
    smstop
  )");
  CHECK_NEON(0, uint64_t, fillNeon<uint64_t>({0}, VL / 8));

  RUN_AARCH64(R"(
    # Ensure za reg gets zeroed out when ZA enabled
    smstart
    dup z0.s, #2
    dup z1.s, #3
    ptrue p0.s
    ptrue p1.s
    fmopa za0.s, p0/m, p1/m, z0.s, z1.s
    smstop
    smstart
  )");
  for (int i = 0; i < (SVL / 8); i++) {
    CHECK_MAT_ROW(ARM64_REG_ZA, i, uint32_t, fillNeon<uint32_t>({0}, SVL / 8));
  }
}
#endif

INSTANTIATE_TEST_SUITE_P(
    AArch64, Exception,
    ::testing::Values(
        std::make_tuple(
            EMULATION,
            YAML::Load("{Vector-Length: 512, Streaming-Vector-Length: 1024}")),
        std::make_tuple(
            INORDER,
            YAML::Load("{Vector-Length: 512, Streaming-Vector-Length: 1024}")),
        std::make_tuple(
            OUTOFORDER,
            YAML::Load("{Vector-Length: 512, Streaming-Vector-Length: 1024}"))),
    paramToString);

}  // namespace
