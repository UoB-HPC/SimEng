#include "RISCVRegressionTest.hh"

namespace {

using InstStore = RISCVRegressionTest;

TEST_P(InstStore, sb) {
  RUN_RISCV(R"(
      addi t6, t6, 0xAA
      sb t6, 32(t5)
      addi t6, t6, 0xAA  # 0xAA + 0xAA = 154
      sb t6, 0(sp)
  )");
  EXPECT_EQ(getMemoryValue<uint8_t>(32), 0xAA);
  EXPECT_EQ(getMemoryValue<uint8_t>(process_->getStackPointer()), 0x54);
}

TEST_P(InstStore, sh) {
RUN_RISCV(R"(
      addi t6, t6, 0xAA
      sh t6, 32(t5)
      addi t6, t6, 0xAA  # 0xAA + 0xAA = 154
      sh t6, 0(sp)

      slli t6, t6, 8
      addi t6, t6, 0xAA  # 154AA
      sh t6, 34(zero)
  )");
EXPECT_EQ(getMemoryValue<uint16_t>(32), 0x00AA);
EXPECT_EQ(getGeneralRegister<uint64_t>(31), 0x154AA);
EXPECT_EQ(getMemoryValue<uint16_t>(34), 0x54AA);
EXPECT_EQ(getMemoryValue<uint16_t>(process_->getStackPointer()), 0x0154);
}

TEST_P(InstStore, sw) {
RUN_RISCV(R"(
      addi t6, t6, 0xAA
      sw t6, 32(t5)

      addi t6, t6, 0xAA
      slli t6, t6, 16
      addi t6, t6, 0xAA
      sw t6, 36(zero)

      slli t6, t6, 8
      sw t6, 0(sp)
  )");
EXPECT_EQ(getMemoryValue<uint32_t>(32), 0x000000AA);
EXPECT_EQ(getGeneralRegister<uint64_t>(31), 0x15400AA00);
EXPECT_EQ(getMemoryValue<uint32_t>(36), 0x015400AA);
EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer()), 0x5400AA00);
}

TEST_P(InstStore, sd) {
RUN_RISCV(R"(
      addi t6, t6, 0xAA
      addi t6, t6, 0xAA
      slli t6, t6, 32
      addi t6, t6, 0xAA
      sd t6, 32(zero)

      slli t6, t6, 8
      addi t6, t6, 1
      sd t6, 4(sp)
  )");
EXPECT_EQ(getMemoryValue<uint64_t>(32), 0x0154000000AA);
EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() + 4), 0x0154000000AA01);
}

INSTANTIATE_TEST_SUITE_P(RISCV, InstStore,
    ::testing::Values(EMULATION, INORDER),
    coreTypeToString);

}  // namespace
