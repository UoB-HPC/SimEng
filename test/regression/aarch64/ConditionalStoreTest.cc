#include <stdlib.h>
#include <sys/syscall.h>

#include <cstring>
#include <fstream>
#include <string>

#include "AArch64RegressionTest.hh"

namespace {

using CondStr = AArch64RegressionTest;

TEST_P(CondStr, validAddr) {
  initialHeapData_.resize(16);
  uint64_t* heap = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  heap[0] = 0xDEADBEEF98765432;
  heap[1] = 0xABBACAFEAABBCCDD;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # 32-bit
    mov w6, #66
    mov w7, #-1
    stlxr w6, w7, [x0]

    # 64-bit
    mov x1, x0
    add x1, x1, #8
    mov w8, #67
    mov x9, #-1
    stlxr w8, x9, [x1]
  )");
  EXPECT_EQ(getGeneralRegister<uint32_t>(6), 0);
  EXPECT_EQ(getGeneralRegister<uint32_t>(7), 0xFFFFFFFF);
  EXPECT_EQ(getMemoryValue<uint64_t>(getGeneralRegister<uint64_t>(0)),
            0xDEADBEEFFFFFFFFF);
  EXPECT_EQ(getGeneralRegister<uint32_t>(8), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(9), 0xFFFFFFFFFFFFFFFF);
  EXPECT_EQ(getMemoryValue<uint64_t>(getGeneralRegister<uint64_t>(1)),
            0xFFFFFFFFFFFFFFFF);
}

TEST_P(CondStr, faultyAddr) {
  initialHeapData_.resize(16);
  uint64_t* heap = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  heap[0] = 0xDEADBEEF98765432;
  heap[1] = 0xABBACAFEAABBCCDD;
  RUN_AARCH64(R"(
    # create faulty address
    mov x1, #-1

    # 32-bit
    mov w6, #66
    mov w7, #-1
    stlxr w6, w7, [x1]

    # 64-bit
    mov w8, #67
    mov x9, #-1
    stlxr w8, x9, [x1]
  )");
  EXPECT_EQ(getGeneralRegister<uint32_t>(6), 1u);
  EXPECT_EQ(getGeneralRegister<uint32_t>(7), 0xFFFFFFFF);
  EXPECT_EQ(getGeneralRegister<uint32_t>(8), 1u);
  EXPECT_EQ(getGeneralRegister<uint64_t>(9), 0xFFFFFFFFFFFFFFFF);
}

INSTANTIATE_TEST_SUITE_P(
    AArch64, CondStr,
    ::testing::Values(std::make_tuple(EMULATION, YAML::Load("{}")),
                      std::make_tuple(INORDER, YAML::Load("{}")),
                      std::make_tuple(OUTOFORDER, YAML::Load("{}"))),
    paramToString);

}  // namespace
