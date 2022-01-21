#include <stdlib.h>
#include <sys/syscall.h>

#include <cstring>
#include <fstream>
#include <string>

#include "AArch64RegressionTest.hh"

namespace {

using MicroOp = AArch64RegressionTest;

TEST_P(MicroOp, ldr) {
  initialHeapData_.resize(24);
  uint64_t* heap64 = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  heap64[0] = 0xABBACAFEABBACAFE;
  heap64[1] = 0x1234567898765432;
  heap64[2] = 0xABCDEFABCDEFABCD;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr x1, [x0], #8
    ldr x2, [x0, #0]
    ldr x3, [x0, #-8]!
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(1), 0xABBACAFEABBACAFE);
  EXPECT_EQ(getGeneralRegister<uint64_t>(2), 0x1234567898765432);
  EXPECT_EQ(getGeneralRegister<uint64_t>(3), 0xABBACAFEABBACAFE);
}

TEST_P(MicroOp, str) {
  RUN_AARCH64(R"(
    mov x0, #12
    mov x1, #24
    mov x2, #36

    sub sp, sp, #1024

    str x0, [sp], #16
    str x1, [sp, #0]
    str x2, [sp, #-8]!
  )");
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 1024), 12);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 1008), 24);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 1016), 36);
}

INSTANTIATE_TEST_SUITE_P(
    AArch64, MicroOp,
    ::testing::Values(
        std::make_tuple(EMULATION, YAML::Load("{Micro-Operations: True}")),
        std::make_tuple(INORDER, YAML::Load("{Micro-Operations: True}")),
        std::make_tuple(OUTOFORDER, YAML::Load("{Micro-Operations: True}"))),
    paramToString);

}  // namespace
