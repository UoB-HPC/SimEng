#include "RISCVRegressionTest.hh"

namespace {

using SmokeTest = RISCVRegressionTest;

// Test that a trivial instruction will execute
TEST_P(SmokeTest, instruction) {
  RUN_RISCV(R"(
    addi a5,a5,32
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(15), 32u);
}

//
//// Test a loop executing 1024 times, adding 3 to w1 each time
//TEST_P(SmokeTest, loop) {
//  RUN_AARCH64(R"(
//    orr w0, wzr, #1024
//    mov w1, wzr
//    add w1, w1, #3
//    subs w0, w0, #1
//    b.ne -8
//  )");
//  EXPECT_TRUE(getZeroFlag());
//  EXPECT_EQ(getGeneralRegister<uint32_t>(0), 0u);
//  EXPECT_EQ(getGeneralRegister<uint32_t>(1), 1024 * 3u);
//}
//
//// Test that we can store values to the stack
//TEST_P(SmokeTest, stack) {
//  RUN_AARCH64(R"(
//    mov w0, #7
//    mov w1, #42
//    str w0, [sp, -4]
//    str w1, [sp, -8]
//  )");
//  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() - 4), 7u);
//  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() - 8), 42u);
//}
//
//// Test that we can store values to the heap
//TEST_P(SmokeTest, heap) {
//  RUN_AARCH64(R"(
//    # Use brk syscall to move program brk by eight bytes
//    mov w0, 0
//    mov w8, 214
//    svc #0
//    add w0, w0, 8
//    svc #0
//    # Write a couple of values into the allocated region
//    mov w1, #7
//    mov w2, #42
//    str w1, [x0, -8]
//    str w2, [x0, -4]
//  )");
//  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getHeapStart()), 7u);
//  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getHeapStart() + 4), 42u);
//}
//
INSTANTIATE_TEST_SUITE_P(RISCV, SmokeTest,
                         ::testing::Values(EMULATION, INORDER),
                         coreTypeToString);

}  // namespace
