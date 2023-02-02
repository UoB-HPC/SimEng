#include "AArch64RegressionTest.hh"

namespace {

using SystemRegister = AArch64RegressionTest;

TEST_P(SystemRegister, sysreg_access) {
  maxTicks_ = 100;

  // Simple system register write and read.
  RUN_AARCH64(R"(
    mov x0, 42
    msr TPIDR_EL0, x0
    mrs x2, TPIDR_EL0
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(2), 42);

  // Test system register WAW hazard.
  // The first write will be delayed by the prior sequence of instructions.
  // The second write should not execute until the first has retired.
  RUN_AARCH64(R"(
    mov x0, 7
    mov x1, 6
    mul x0, x0, x1
    msr TPIDR_EL0, x1
    msr TPIDR_EL0, x0
    mrs x2, TPIDR_EL0
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(2), 42);
  EXPECT_EQ(getSystemRegister(0xde82), 42);

  // Test system register RAW hazard.
  // The first write will be delayed by the prior sequence of instructions.
  // The second write should not execute until the read has retired.
  RUN_AARCH64(R"(
    mov x0, 7
    mov x1, 6
    mul x0, x0, x1
    msr TPIDR_EL0, x0
    mrs x2, TPIDR_EL0
    msr TPIDR_EL0, x1
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(2), 42);
  EXPECT_EQ(getSystemRegister(0xde82), 6);

  // Test writing and reading multiple system registers.
  RUN_AARCH64(R"(
    mov x0, 42
    mov x1, 7
    msr TPIDR_EL0, x0
    msr FPCR, x1
    mrs x2, TPIDR_EL0
    mrs x3, FPCR
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(2), 42);
  EXPECT_EQ(getGeneralRegister<uint64_t>(3), 7);

  // Test that writing to a system register isn't done speculatively.
  // The system register is initially set to 42.
  // We perform a load which will cause a data abort exception, and then write
  // the value 7 to the system register.
  // This second write should not happen due to the exception.
  RUN_AARCH64(R"(
    mov x0, 42
    msr TPIDR_EL0, x0
    mov x1, 7
    sub x2, x1, 100
    ldr x2, [x2]
    msr TPIDR_EL0, x1
  )");
  EXPECT_EQ(getSystemRegister(0xde82), 42);
}

TEST_P(SystemRegister, counter_timers) {
  // Ensure that the VCT is incremented at correct rate : once per ((2.5 * 1e9)
  // / (100 * 1e6)) cycles (i.e. once per 25 cycles).
  RUN_AARCH64(R"(
    mov x2, xzr
    mov x1, #16
    # Loop of 3 instructions * 16 iterations = 48, + 2 mov instructions = 50 total instructions & ~50 cycles
    sub x1, x1, #1
    cmp x1, x2
    b.ne #-8
  )");
  EXPECT_EQ(getSystemRegister(0xdf02), 2);
}

INSTANTIATE_TEST_SUITE_P(
    AArch64, SystemRegister,
    ::testing::Values(std::make_tuple(EMULATION, YAML::Load("{}")),
                      std::make_tuple(INORDER, YAML::Load("{}")),
                      std::make_tuple(OUTOFORDER, YAML::Load("{}"))),
    paramToString);

}  // namespace
