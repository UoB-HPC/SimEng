#include "RISCVRegressionTest.hh"

namespace {

using LoadStoreQueue = RISCVRegressionTest;

//// Test reading from an address immediately after storing to it.
//TEST_P(LoadStoreQueue, RAW) {
//  initialHeapData_.resize(8);
//  reinterpret_cast<uint64_t*>(initialHeapData_.data())[0] = -1;
//
//  RUN_AARCH64(R"(
//    # Get heap address
//    mov x0, 0
//    mov x8, 214
//    svc #0
//
//    # Write a value and try to read it immediately.
//    mov x1, #42
//    str x1, [x0]
//    ldr x2, [x0]
//  )");
//  EXPECT_EQ(getGeneralRegister<uint64_t>(2), 42u);
//}
//
//// Test multiple simulteneous RAW violations are flushed correctly.
//TEST_P(LoadStoreQueue, RAWx2) {
//  initialHeapData_.resize(8);
//  reinterpret_cast<uint64_t*>(initialHeapData_.data())[0] = -1;
//
//  RUN_AARCH64(R"(
//    # Get heap address
//    mov x0, 0
//    mov x8, 214
//    svc #0
//
//    # Write a value and try to read it immediately, twice.
//    mov x1, #42
//    str x1, [x0]
//    ldr x2, [x0]
//    ldr x3, [x0]
//  )");
//  EXPECT_EQ(getGeneralRegister<uint64_t>(2), 42u);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(3), 42u);
//}
//
//// Test with two load instructions that will complete on the same cycle.
//TEST_P(LoadStoreQueue, SimultaneousLoadCompletion) {
//  initialHeapData_.resize(8);
//  reinterpret_cast<uint32_t*>(initialHeapData_.data())[0] = 0xDEADBEEF;
//  reinterpret_cast<uint32_t*>(initialHeapData_.data())[1] = 0x12345678;
//
//  maxTicks_ = 30;
//  RUN_AARCH64(R"(
//    # Get heap address
//    mov x0, 0
//    mov x8, 214
//    svc #0
//
//    # Perform two loads that should complete on the same cycle
//    # (assuming superscalar core with at least two load units)
//    ldr w1, [x0]
//    ldr w2, [x0, 4]
//  )");
//  EXPECT_EQ(getGeneralRegister<uint32_t>(1), 0xDEADBEEF);
//  EXPECT_EQ(getGeneralRegister<uint32_t>(2), 0x12345678);
//}
//
//// Test that a speculative load from an invalid address does not crash.
//TEST_P(LoadStoreQueue, SpeculativeInvalidLoad) {
//  initialHeapData_.resize(16);
//  reinterpret_cast<double*>(initialHeapData_.data())[0] = 0.0;
//  reinterpret_cast<double*>(initialHeapData_.data())[1] = 0.0;
//
//  RUN_AARCH64(R"(
//    # Fill pipelines to delay branch execution
//    fadd v1.2d, v1.2d, v1.2d
//    fadd v2.2d, v2.2d, v2.2d
//    fadd v1.2d, v1.2d, v1.2d
//    fadd v2.2d, v2.2d, v2.2d
//    fcmp d0, d0
//    b.eq .end
//
//    # Load from an invalid address
//    movk x0, 0xFFFF, lsl 48
//    ldr x1, [x0]
//
//    .end:
//    nop
//  )");
//}
//
//INSTANTIATE_TEST_SUITE_P(AArch64, LoadStoreQueue, ::testing::Values(OUTOFORDER),
//                         coreTypeToString);

}  // namespace
