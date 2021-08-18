#include "RISCVRegressionTest.hh"

namespace {

using InstAtomic = RISCVRegressionTest;

TEST_P(InstAtomic, lr) {
  initialHeapData_.resize(16);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0xDEADBEEF;
  heap[1] = 0x12345678;
  heap[2] = 0xFEEBDAED;
  heap[3] = 0x87654321;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    lr.w t6, (a0)

  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 0xFFFFFFFFDEADBEEF);
}

TEST_P(InstAtomic, sc) {
  initialHeapData_.resize(16);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0xDEADBEEF;
  heap[1] = 0x12345678;
  heap[2] = 0xFEEBDAED;
  heap[3] = 0x87654321;
  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    li t5, 15
    li t6, 987

    sc.w.aq t5, t6, (a0)
  )");

  auto heapStart = process_->getHeapStart();

  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 987);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart), 987);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 4), 0x12345678);
}

TEST_P(InstAtomic, amoswap) {
  initialHeapData_.resize(16);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0xDEADBEEF;
  heap[1] = 0x12345678;
  heap[2] = 0xFEEBDAED;
  heap[3] = 0x77654321;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    li t0, 21
    li t1, 84

    amoswap.w t0, t1, (a0)

    li t5, 34
    li t6, 987
    addi a0, a0, 12

    amoswap.w t5, t6, (a0)
  )");

  auto heapStart = process_->getHeapStart();

  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0xFFFFFFFFDEADBEEF);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 84);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart), 84);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 4), 0x12345678);

  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0x0000000077654321);
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 987);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 8), 0xFEEBDAED);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 12), 987);
}

INSTANTIATE_TEST_SUITE_P(RISCV, InstAtomic,
    ::testing::Values(EMULATION, INORDER),
    coreTypeToString);

}  // namespace
