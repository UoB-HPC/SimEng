#include "RISCVRegressionTest.hh"

namespace {

using InstStore = RISCVRegressionTest;

TEST_P(InstStore, sb) {
  RUN_RISCV(R"(
      # Get heap address
      li a7, 214
      ecall

      mv t6, a0
      addi t5, t5, 0x7AA # Store a value greater than 2^8
      sb t5, 0(t6)
      addi t5, t5, 32 #0x7CA
      sb t5, 1(t6)
  )");

  EXPECT_EQ(getGeneralRegister<uint64_t>(10), process_->getHeapStart());
  EXPECT_EQ(getMemoryValue<uint8_t>(process_->getHeapStart()), 0xAA);
  EXPECT_EQ(getMemoryValue<uint8_t>(process_->getHeapStart() + 1), 0xCA);
}

TEST_P(InstStore, sh) {
  RUN_RISCV(R"(
      # Get heap address
      li a7, 214
      ecall

      li t6, 0xDEADBEEF
      sh t6, 0(a0) # Store a value greater than than 2^16
      addi t6, t6, 0x8 # 0xDEADBEF7
      sh t6, 2(a0)

      slli t6, t6, 2 # 7AB6FBDC
      sh t6, 4(a0)
  )");

  EXPECT_EQ(getGeneralRegister<uint64_t>(10), process_->getHeapStart());
  EXPECT_EQ(getMemoryValue<uint16_t>(process_->getHeapStart()), 0xBEEF);
  EXPECT_EQ(getMemoryValue<uint16_t>(process_->getHeapStart() + 2), 0xBEF7);
  EXPECT_EQ(getMemoryValue<uint16_t>(process_->getHeapStart() + 4), 0xFBDC);
}

TEST_P(InstStore, sw) {
  RUN_RISCV(R"(
      # Get heap address
      li a7, 214
      ecall

      li t6, 0xADEADBEEF # Store a value greater than 2^32
      sw t6, 0(a0)

      addi t6, t6, 8
      sw t6, 4(a0)

      slli t6, t6, 4 #ADEADBEF70
      sw t6, 0(sp)
  )");

  EXPECT_EQ(getGeneralRegister<uint64_t>(10), process_->getHeapStart());
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getHeapStart()), 0xDEADBEEF);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getHeapStart() + 4), 0xDEADBEF7);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer()), 0xEADBEF70);
}

TEST_P(InstStore, sd) {
  RUN_RISCV(R"(
      # Get heap address
      li a7, 214
      ecall

      li t6, 0xDEADBEEFDEADBEEF
      sd t6, 0(a0)

      slli t6, t6, 32
      sd t6, 8(a0)

      addi t6, t6, 8
      sd t6, 4(sp)
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(10), process_->getHeapStart());
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getHeapStart()),
            0xDEADBEEFDEADBEEF);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getHeapStart() + 8),
            0xDEADBEEF00000000);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() + 4),
            0xDEADBEEF00000000 + 0x8);
}

INSTANTIATE_TEST_SUITE_P(RISCV, InstStore,
                         ::testing::Values(std::make_tuple(EMULATION,
                                                           YAML::Load("{}"))),
                         paramToString);

}  // namespace
