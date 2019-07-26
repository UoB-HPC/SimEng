#include "AArch64RegressionTest.hh"

namespace {

using LoadStoreQueue = AArch64RegressionTest;

// Test reading from an address immediately after storing to it.
TEST_P(LoadStoreQueue, RAW) {
  initialHeapData_.resize(8);
  reinterpret_cast<uint64_t*>(initialHeapData_.data())[0] = -1;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # Write a value and try to read it immediately.
    mov x1, #42
    str x1, [x0]
    ldr x2, [x0]
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(2), 42u);
}

INSTANTIATE_TEST_SUITE_P(AArch64, LoadStoreQueue, ::testing::Values(OUTOFORDER),
                         coreTypeToString);

}  // namespace
