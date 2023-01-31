#include "RISCVRegressionTest.hh"

namespace {

using InstStore = RISCVRegressionTest;

TEST_P(InstStore, sb) {
  RUN_RISCV(R"(
      # Get heap address
      li a7, 214
      ecall

      mv t6, a0
      addi t5, t5, 32
      sb t5, 0(t6)
      addi t5, t5, 32
      sb t5, 4(t6)
  )");

  EXPECT_EQ(getGeneralRegister<uint64_t>(10), process_->getHeapStart());
  EXPECT_EQ(getMemoryValue<uint8_t>(process_->getHeapStart()), 32);
  EXPECT_EQ(getMemoryValue<uint8_t>(process_->getHeapStart() + 4), 64);
}

TEST_P(InstStore, sh) {
  RUN_RISCV(R"(
      # Get heap address
      li a7, 214
      ecall

      li t6, 0x8
      sh t6, 0(a0)
      addi t6, t6, 0x8
      sh t6, 6(a0)

      slli t6, t6, 8
      sh t6, 10(a0)
  )");

  EXPECT_EQ(getGeneralRegister<uint64_t>(10), process_->getHeapStart());
  EXPECT_EQ(getMemoryValue<uint16_t>(process_->getHeapStart()), 8);
  EXPECT_EQ(getMemoryValue<uint16_t>(process_->getHeapStart() + 6), 16);
  EXPECT_EQ(getMemoryValue<uint16_t>(process_->getHeapStart() + 10), 4096);
}

TEST_P(InstStore, sw) {
  RUN_RISCV(R"(
      # Get heap address
      li a7, 214
      ecall

      li t6, 0x10
      sw t6, 1(a0)

      slli t6, t6, 8
      sw t6, 7(a0)

      slli t6, t6, 8
      sw t6, 0(sp)
  )");

  EXPECT_EQ(getGeneralRegister<uint64_t>(10), process_->getHeapStart());
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getHeapStart() + 1), 16);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getHeapStart() + 7), 4096);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer()),
            (uint32_t)4096 << 8);
}

TEST_P(InstStore, sd) {
  RUN_RISCV(R"(
      # Get heap address
      li a7, 214
      ecall

      li t6, 0x10
      slli t6, t6, 8
      sd t6, 0(a0)

      slli t6, t6, 8
      sd t6, 8(a0)

      slli t6, t6, 8
      sd t6, 4(sp)
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(10), process_->getHeapStart());
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getHeapStart()), 0x1000);
  uint64_t res = 0x1000 << 8;
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getHeapStart() + 8), res);
  res <<= 8;
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() + 4), res);
}

INSTANTIATE_TEST_SUITE_P(RISCV, InstStore,
                         ::testing::Values(std::make_tuple(EMULATION,
                                                           YAML::Load("{}"))),
                         paramToString);

}  // namespace
