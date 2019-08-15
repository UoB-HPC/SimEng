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

TEST_P(Syscall, writev) {
  const char str[] = "Hello, World!\n";
  for (char c : str) {
    initialHeapData_.push_back(c);
  }
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # iovec = {{x0, 10}, {x0+10, 4}}
    str x0, [sp, #-32]
    mov x1, 10
    str x1, [sp, #-24]
    add x0, x0, 10
    str x0, [sp, #-16]
    mov x1, 4
    str x1, [sp, #-8]

    # writev(fd=1, iov=iovec, iovcnt=2)
    mov x0, #1
    sub x1, sp, 32
    mov x2, #2
    mov x8, #66
    svc #0
  )");
  EXPECT_EQ(stdout_.substr(0, sizeof(str) - 1), str);
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), sizeof(str) - 1);
}

INSTANTIATE_TEST_SUITE_P(AArch64, Syscall,
                         ::testing::Values(EMULATION, INORDER, OUTOFORDER),
                         coreTypeToString);

}  // namespace
