#include <stdlib.h>
#include <sys/syscall.h>

#include <cstring>
#include <fstream>
#include <string>

#include "RISCVRegressionTest.hh"

namespace {

using CondStr = RISCVRegressionTest;

TEST_P(CondStr, validAddr) {
  initialHeapData_.resize(16);
  uint64_t* heap = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  heap[0] = 0xDEADBEEF98765432;
  heap[1] = 0xABBACAFEAABBCCDD;
  RUN_RISCV(R"(
    li a7, 214
    ecall

    # 32-bit
    li t0, 66
    li t1, -1
    sc.w t0, t1, (a0)

    #64-bit
    mv a1, a0 
    addi a1, a1, 8
    li t2, 67
    li t3, -1
    sc.d t2, t3, (a1)
  )");
  EXPECT_EQ(getGeneralRegister<uint32_t>(5), 0);
  EXPECT_EQ(getGeneralRegister<uint32_t>(6), 0xFFFFFFFF);
  EXPECT_EQ(getMemoryValue<uint64_t>(getGeneralRegister<uint64_t>(10)),
            0xDEADBEEFFFFFFFFF);
  EXPECT_EQ(getGeneralRegister<uint32_t>(7), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(28), 0xFFFFFFFFFFFFFFFF);
  EXPECT_EQ(getMemoryValue<uint64_t>(getGeneralRegister<uint64_t>(11)),
            0xFFFFFFFFFFFFFFFF);
}

TEST_P(CondStr, faultyAddr) {
  initialHeapData_.resize(16);
  uint64_t* heap = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  heap[0] = 0xDEADBEEF98765432;
  heap[1] = 0xABBACAFEAABBCCDD;
  RUN_RISCV(R"(
    # create faulty address
    li a1, -1

    # 32-bit
    li t0, 66
    li t1, -1
    sc.w t0, t1, (a1)

    # 64-bit
    li t2, 67
    li t3, -1
    sc.d t2, t3, (a1)
  )");
  EXPECT_EQ(getGeneralRegister<uint32_t>(5), 1u);
  EXPECT_EQ(getGeneralRegister<uint32_t>(6), 0xFFFFFFFF);
  EXPECT_EQ(getGeneralRegister<uint32_t>(7), 1u);
  EXPECT_EQ(getGeneralRegister<uint64_t>(28), 0xFFFFFFFFFFFFFFFF);
}

INSTANTIATE_TEST_SUITE_P(
    RISCV, CondStr,
    ::testing::Values(std::make_tuple(EMULATION, YAML::Load("{}")),
                      std::make_tuple(INORDER, YAML::Load("{}")),
                      std::make_tuple(OUTOFORDER, YAML::Load("{}"))),
    paramToString);

}  // namespace
