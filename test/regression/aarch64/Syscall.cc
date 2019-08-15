#include "AArch64RegressionTest.hh"

#include <cstring>

namespace {

using Syscall = AArch64RegressionTest;

TEST_P(Syscall, ioctl) {
  // TIOCGWINSZ: test it returns zero and sets the output to anything
  initialHeapData_.resize(8);
  memset(initialHeapData_.data(), -1, 8);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # ioctl(fd=1, request=0x5413, argp=x0)
    mov x2, x0
    mov x1, 0x5413
    mov x0, #1
    mov x8, #29
    svc #0
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(0), 0);
  EXPECT_NE(getMemoryValue<uint16_t>(process_->getHeapStart() + 0), -1);
  EXPECT_NE(getMemoryValue<uint16_t>(process_->getHeapStart() + 2), -1);
  EXPECT_NE(getMemoryValue<uint16_t>(process_->getHeapStart() + 4), -1);
  EXPECT_NE(getMemoryValue<uint16_t>(process_->getHeapStart() + 6), -1);
}

INSTANTIATE_TEST_SUITE_P(AArch64, Syscall,
                         ::testing::Values(EMULATION, INORDER, OUTOFORDER),
                         coreTypeToString);

}  // namespace
