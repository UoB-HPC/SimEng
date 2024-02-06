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

// Ensure that calling smstart/smstop such that the values in SVCR.SMZA do not
// change doesn't cause a flush of the associated register files
TEST_P(Exception, Null_Smstart_smstop_calls) {
  RUN_AARCH64(R"(
    smstart
    dup z0.d, #3
    smstart
  )");
  CHECK_NEON(0, uint64_t, fillNeon<uint64_t>({3}, SVL / 8));

  RUN_AARCH64(R"(
    smstart
    dup z0.d, #4
    smstart sm
  )");
  CHECK_NEON(0, uint64_t, fillNeon<uint64_t>({4}, SVL / 8));

  RUN_AARCH64(R"(
    smstart
    dup z0.d, #5
    smstart za
  )");
  CHECK_NEON(0, uint64_t, fillNeon<uint64_t>({5}, SVL / 8));

  RUN_AARCH64(R"(
    dup z0.d, #6
    smstop
  )");
  CHECK_NEON(0, uint64_t, fillNeon<uint64_t>({6}, VL / 8));

  RUN_AARCH64(R"(
    dup z0.d, #7
    smstop sm
  )");
  CHECK_NEON(0, uint64_t, fillNeon<uint64_t>({7}, VL / 8));

  RUN_AARCH64(R"(
    dup z0.d, #8
    smstop za
  )");
  CHECK_NEON(0, uint64_t, fillNeon<uint64_t>({8}, VL / 8));
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
    # Ensure z regs get enabled when SM enabled
    smstart sm
    dup z0.d, #3
  )");
  CHECK_NEON(0, uint64_t, fillNeon<uint64_t>({3}, SVL / 8));

  RUN_AARCH64(R"(
    # Ensure z regs get zeroed out when SM disabled
    smstart
    dup z0.d, #3
    smstop
  )");
  CHECK_NEON(0, uint64_t, fillNeon<uint64_t>({0}, VL / 8));

  RUN_AARCH64(R"(
    # Ensure z regs do not get zeroed out when ZA is disabled
    smstart
    dup z0.d, #3
    smstop za
  )");
  CHECK_NEON(0, uint64_t, fillNeon<uint64_t>({3}, SVL / 8));

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

  // Check that changes to SVCR using msr svcr, xn work correctly
  RUN_AARCH64(R"(
    mov x4, #3
    mov x5, #0
    # Ensure vector length changes from SVE's to SME's
    cntb x0
    msr svcr, x4
    cntb x1
    msr svcr, x5
    cntb x2
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), VL / 8);
  EXPECT_EQ(getGeneralRegister<uint64_t>(1), SVL / 8);
  EXPECT_EQ(getGeneralRegister<uint64_t>(2), VL / 8);
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), getGeneralRegister<uint64_t>(2));
  EXPECT_GT(getGeneralRegister<uint64_t>(1), getGeneralRegister<uint64_t>(0));
  EXPECT_GT(SVL, VL);

  RUN_AARCH64(R"(
    mov x4, #3
    # Ensure z regs get zeroed out when SM enabled
    dup z0.d, #3
    msr svcr, x4
  )");
  CHECK_NEON(0, uint64_t, fillNeon<uint64_t>({0}, VL / 8));

  RUN_AARCH64(R"(
    mov x4, #1
    # Ensure z regs get enabled when SM enabled
    msr svcr, x4
    dup z0.d, #3
  )");
  CHECK_NEON(0, uint64_t, fillNeon<uint64_t>({3}, SVL / 8));

  RUN_AARCH64(R"(
    mov x4, #3
    mov x5, #0
    # Ensure z regs get zeroed out when SM disabled
    msr svcr, x4
    dup z0.d, #3
    msr svcr, x5
  )");
  CHECK_NEON(0, uint64_t, fillNeon<uint64_t>({0}, VL / 8));

  RUN_AARCH64(R"(
    # enable SM and ZA
    mov x4, #3
    # just disable ZA
    mov x5, #1
    # Ensure z regs do not get zeroed out when ZA is disabled
    msr svcr, x4
    dup z0.d, #3
    msr svcr, x5
  )");
  CHECK_NEON(0, uint64_t, fillNeon<uint64_t>({3}, SVL / 8));

  RUN_AARCH64(R"(
    mov x4, #3
    mov x5, #0
    # Ensure za reg gets zeroed out when ZA enabled
    msr svcr, x4
    dup z0.s, #2
    dup z1.s, #3
    ptrue p0.s
    ptrue p1.s
    fmopa za0.s, p0/m, p1/m, z0.s, z1.s
    msr svcr, x5
    msr svcr, x4
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
            "{Core: {Vector-Length: 512, Streaming-Vector-Length: 1024}, "
            "LSQ-L1-Interface: {Load-Bandwidth: 256, Store-Bandwidth: 256}}"),
        std::make_tuple(
            INORDER,
            "{Core: {Vector-Length: 512, Streaming-Vector-Length: 1024}, "
            "LSQ-L1-Interface: {Load-Bandwidth: 256, Store-Bandwidth: 256}}"),
        std::make_tuple(
            OUTOFORDER,
            "{Core: {Vector-Length: 512, Streaming-Vector-Length: 1024}, "
            "LSQ-L1-Interface: {Load-Bandwidth: 256, Store-Bandwidth: 256}}")),
    paramToString);

}  // namespace
