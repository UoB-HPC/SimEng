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

    ldr x1, [x0, #0]
    ldr x2, [x0, #8]!
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(1), 0xABBACAFEABBACAFE);
  EXPECT_EQ(getGeneralRegister<uint64_t>(2), 0x1234567898765432);
}

INSTANTIATE_TEST_SUITE_P(
    AArch64, MicroOp,
    ::testing::Values(
        std::make_tuple(EMULATION, YAML::Load("{Micro-Operations: True}")),
        std::make_tuple(INORDER, YAML::Load("{Micro-Operations: True}")),
        std::make_tuple(OUTOFORDER, YAML::Load("{Micro-Operations: True}"))),
    paramToString);

}  // namespace
