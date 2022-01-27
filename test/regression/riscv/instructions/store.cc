#include "RISCVRegressionTest.hh"

namespace {

using InstStore = RISCVRegressionTest;

TEST_P(InstStore, sb) {
  initialHeapData_.resize(16);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0x12345678;

  RUN_RISCV(R"(
      # Get heap address
      li a7, 214
      ecall

      addi t6, t6, 0xAA
      sb t6, 2(a0)
      addi t6, t6, 0xAA  # 0xAA + 0xAA = 0x154
      sb t6, 6(a0)
  )");

  EXPECT_EQ(getGeneralRegister<uint64_t>(10), 32);
  EXPECT_EQ(getMemoryValue<uint32_t>(33), 0x0012AA56);
  EXPECT_EQ(getMemoryValue<uint32_t>(37), 0x00005400);
}

TEST_P(InstStore, sh) {
  initialHeapData_.resize(16);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0x12345678;

  RUN_RISCV(R"(
      # Get heap address
      li a7, 214
      ecall

      li t6, 0xAA
      sh t6, 1(a0)
      addi t6, t6, 0xAA  # 0xAA + 0xAA = 154
      sh t6, 6(a0)

      slli t6, t6, 8
      addi t6, t6, 0xAA  # 154AA
      sh t6, 10(a0)
  )");

  EXPECT_EQ(getGeneralRegister<uint64_t>(10), 64);
  EXPECT_EQ(getMemoryValue<uint32_t>(64), 0x1200AA78);
  EXPECT_EQ(getMemoryValue<uint32_t>(69), 0x00015400);
  EXPECT_EQ(getMemoryValue<uint32_t>(73), 0x0054AA00);
}

TEST_P(InstStore, sw) {
  initialHeapData_.resize(16);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0x12345678;
  heap[1] = 0xDEADBEEF;
  heap[2] = 0x87654321;

  RUN_RISCV(R"(
      # Get heap address
      li a7, 214
      ecall

      li t6, 0xAA
      sw t6, 1(a0)

      addi t6, t6, 0xAA  # 0xAA + 0xAA = 154
      slli t6, t6, 16
      addi t6, t6, 0xAA  # 0x15400AA
      sw t6, 7(a0)

      slli t6, t6, 8
      sw t6, 0(sp)
  )");

  EXPECT_EQ(getGeneralRegister<uint64_t>(10), 64);
  EXPECT_EQ(getMemoryValue<uint64_t>(64), 0xAAADBE000000AA78);
  EXPECT_EQ(getMemoryValue<uint64_t>(69), 0x0087015400AAADBE);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer()), 0x5400AA00);
}

TEST_P(InstStore, sd) {
  initialHeapData_.resize(16);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0x12345678;
  heap[1] = 0xDEADBEEF;
  heap[2] = 0x87654321;

  RUN_RISCV(R"(
      # Get heap address
      li a7, 214
      ecall

      addi t6, t6, 0xAA
      addi t6, t6, 0xAA
      slli t6, t6, 32
      addi t6, t6, 0xAA  # 0x00000154000000AA
      addi a0, a0, 4
      sd t6, -2(a0)

      slli t6, t6, 8 # 0x000154000000AA01
      addi t6, t6, 1
      sd t6, 4(sp)
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(10), 68);
  EXPECT_EQ(getMemoryValue<uint64_t>(64), 0x0154000000AA5678);
  EXPECT_EQ(getMemoryValue<uint64_t>(68), 0x8765000001540000);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() + 4),
            0x000154000000AA01);
}

INSTANTIATE_TEST_SUITE_P(
    RISCV, InstStore,
    ::testing::Values(std::make_tuple(EMULATION, YAML::Load("{}")),
                      std::make_tuple(INORDER, YAML::Load("{}")),
                      std::make_tuple(OUTOFORDER, YAML::Load("{}"))),
    paramToString);

}  // namespace
