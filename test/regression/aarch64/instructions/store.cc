#include "AArch64RegressionTest.hh"

namespace {

using InstStore = AArch64RegressionTest;

TEST_P(InstStore, strb) {
  RUN_AARCH64(R"(
    mov w0, 0xAB
    mov w1, 0x12
    mov w2, 0xCD
    mov w3, 0x34
    sub sp, sp, #4
    strb w0, [sp], 1
    strb w1, [sp]
    strb w2, [sp, 1]!
    strb w3, [sp, 1]
    mov w5, 2
    strb w0, [sp, w5, uxtw]
    mov x6, -16
    strb w1, [sp, x6, sxtx]
  )");
  EXPECT_EQ(getMemoryValue<uint8_t>(process_->getStackPointer() - 4), 0xAB);
  EXPECT_EQ(getMemoryValue<uint8_t>(process_->getStackPointer() - 3), 0x12);
  EXPECT_EQ(getMemoryValue<uint8_t>(process_->getStackPointer() - 2), 0xCD);
  EXPECT_EQ(getMemoryValue<uint8_t>(process_->getStackPointer() - 1), 0x34);
  EXPECT_EQ(getMemoryValue<uint8_t>(process_->getStackPointer()), 0xAB);
  EXPECT_EQ(getMemoryValue<uint8_t>(process_->getStackPointer() - 18), 0x12);
}

TEST_P(InstStore, strd) {
  // immediate offset
  RUN_AARCH64(R"(
    fmov d0, 2.0
    sub sp, sp, #16
    str d0, [sp, #8]
  )");
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 8), 2.0);

  // post increment
  RUN_AARCH64(R"(
    fmov d0, 2.0
    sub sp, sp, 8
    str d0, [sp], -8
  )");
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 8), 2.0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), process_->getStackPointer() - 16);
}

TEST_P(InstStore, strq) {
  RUN_AARCH64(R"(
    fmov v0.2d, 0.125
    sub sp, sp, 16
    str q0, [sp], -16
  )");
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 8), 0.125);
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 16), 0.125);
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), process_->getStackPointer() - 32);
}

TEST_P(InstStore, stpwi) {
  RUN_AARCH64(R"(
    movz w0, #7
    movz w1, #42
    stp w0, w1, [sp, -8]
  )");
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() - 8), 7u);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() - 4), 42u);
}

TEST_P(InstStore, stur) {
  RUN_AARCH64(R"(
    movz w0, #42
    stur w0, [sp, #-4]
  )");
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() - 4), 42u);

  RUN_AARCH64(R"(
    movz x0, #42
    stur x0, [sp, #-8]
  )");
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 8), 42u);
}

INSTANTIATE_TEST_SUITE_P(AArch64, InstStore, ::testing::Values(EMULATION),
                         coreTypeToString);

}  // namespace
