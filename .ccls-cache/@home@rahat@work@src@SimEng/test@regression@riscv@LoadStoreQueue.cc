#include "RISCVRegressionTest.hh"

namespace {

using LoadStoreQueue = RISCVRegressionTest;

// Test reading from an address immediately after storing to it.
TEST_P(LoadStoreQueue, RAW) {
  initialHeapData_.resize(8);
  reinterpret_cast<uint64_t*>(initialHeapData_.data())[0] = -1;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    # Write a value and try to read it immediately.
    addi t1, t1, 42
    sd t1, 0(a0)
    ld t2, 0(a0)
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 42u);
}

// Test multiple simulteneous RAW violations are flushed correctly.
TEST_P(LoadStoreQueue, RAWx2) {
  initialHeapData_.resize(8);
  reinterpret_cast<uint64_t*>(initialHeapData_.data())[0] = -1;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    # Write a value and try to read it immediately, twice.
    addi t1, t1, 42
    sd t1, 0(a0)
    ld t2, 0(a0)
    ld t3, 0(a0)
   )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 42u);
  EXPECT_EQ(getGeneralRegister<uint64_t>(28), 42u);
}

// Test with two load instructions that will complete on the same cycle.
TEST_P(LoadStoreQueue, SimultaneousLoadCompletion) {
  initialHeapData_.resize(8);
  reinterpret_cast<uint32_t*>(initialHeapData_.data())[0] = 0xDEADBEEF;
  reinterpret_cast<uint32_t*>(initialHeapData_.data())[1] = 0x12345678;

  maxTicks_ = 30;
  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    # Perform two loads that should complete on the same cycle
    # (assuming superscalar core with at least two load units)
    lw t2, 0(a0)
    lw t3, 4(a0)
   )");
  EXPECT_EQ(getGeneralRegister<uint32_t>(7), 0xDEADBEEF);
  EXPECT_EQ(getGeneralRegister<uint32_t>(28), 0x12345678);
}

// Test that a speculative load from an invalid address does not crash.
TEST_P(LoadStoreQueue, SpeculativeInvalidLoad) {
  initialHeapData_.resize(16);
  reinterpret_cast<double*>(initialHeapData_.data())[0] = 0.0;
  reinterpret_cast<double*>(initialHeapData_.data())[1] = 0.0;

  RUN_RISCV(R"(
    # Fill pipelines to delay branch execution
    lui a0, 0xFFFF0
    add t3, t2, t1
    add t3, t2, t1
    add t3, t2, t1
    add t3, t2, t1
    add t3, t2, t1
    add t3, t2, t1
    add t3, t2, t1
    add t3, t2, t1
    add t3, t2, t1
    add t3, t2, t1
    add t3, t2, t1
    add t3, t2, t1
    add t3, t2, t1
    beq t1, t2, .end

    # Load from an invalid address
    ld t1, 0(a0)

    .end:
    # Only reachable if data abort exception not thrown
    addi t0, t0, 12
   )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 12u);
}

INSTANTIATE_TEST_SUITE_P(
    RISCV, LoadStoreQueue,
    ::testing::Values(std::make_tuple(EMULATION, YAML::Load("{}")),
                      std::make_tuple(INORDER, YAML::Load("{}")),
                      std::make_tuple(OUTOFORDER, YAML::Load("{}"))),
    paramToString);

}  // namespace