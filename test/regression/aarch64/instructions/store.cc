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

TEST_P(InstStore, strh) {
  RUN_AARCH64(R"(
    mov w0, 0xABAB
    mov w1, 0x1234
    mov w2, 0xCD89
    mov w3, 0x3401
    sub sp, sp, #8
    strh w0, [sp], 2
    strh w1, [sp]
    strh w2, [sp, 2]!
    strh w3, [sp, 2]
    mov w5, 4
    strh w0, [sp, w5, uxtw]
    mov x6, -16
    strh w1, [sp, x6, sxtx]
  )");
  EXPECT_EQ(getMemoryValue<uint16_t>(process_->getStackPointer() - 8), 0xABAB);
  EXPECT_EQ(getMemoryValue<uint16_t>(process_->getStackPointer() - 6), 0x1234);
  EXPECT_EQ(getMemoryValue<uint16_t>(process_->getStackPointer() - 4), 0xCD89);
  EXPECT_EQ(getMemoryValue<uint16_t>(process_->getStackPointer() - 2), 0x3401);
  EXPECT_EQ(getMemoryValue<uint16_t>(process_->getStackPointer()), 0xABAB);
  EXPECT_EQ(getMemoryValue<uint16_t>(process_->getStackPointer() - 20), 0x1234);
}

TEST_P(InstStore, strd) {
  RUN_AARCH64(R"(
    fmov d0, 2.0
    fmov d1, -0.125
    fmov d2, 7.5
    fmov d3, 16.0
    sub sp, sp, #40
    str d0, [sp], 8
    str d1, [sp]
    str d2, [sp, 8]!
    str d3, [sp, 8]
    mov w5, 16
    str d0, [sp, w5, uxtw]
    sub sp, sp, 16
    mov x6, -16
    str d1, [sp, x6, sxtx]
  )");
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 40), 2.0);
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 32), -0.125);
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 24), 7.5);
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 16), 16.0);
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 8), 2.0);
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 56), -0.125);
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

TEST_P(InstStore, strs) {
  RUN_AARCH64(R"(
    fmov s0, 2.0
    fmov s1, -0.125
    fmov s2, 7.5
    fmov s3, 16.0
    sub sp, sp, #20
    str s0, [sp], 4
    str s1, [sp]
    str s2, [sp, 4]!
    str s3, [sp, 4]
    mov w5, 8
    str s0, [sp, w5, uxtw]
    sub sp, sp, 8
    mov x6, -8
    str s1, [sp, x6, sxtx]
  )");
  EXPECT_EQ(getMemoryValue<float>(process_->getStackPointer() - 20), 2.f);
  EXPECT_EQ(getMemoryValue<float>(process_->getStackPointer() - 16), -0.125f);
  EXPECT_EQ(getMemoryValue<float>(process_->getStackPointer() - 12), 7.5f);
  EXPECT_EQ(getMemoryValue<float>(process_->getStackPointer() - 8), 16.f);
  EXPECT_EQ(getMemoryValue<float>(process_->getStackPointer() - 4), 2.f);
  EXPECT_EQ(getMemoryValue<float>(process_->getStackPointer() - 28), -0.125f);
}

TEST_P(InstStore, strw) {
  RUN_AARCH64(R"(
    movz w0, 0xABAB, lsl 16
    movz w1, 0x1234, lsl 16
    movz w2, 0xCD89, lsl 16
    movz w3, 0x3401, lsl 16
    sub sp, sp, #16
    str w0, [sp], 4
    str w1, [sp]
    str w2, [sp, 4]!
    str w3, [sp, 4]
    mov w5, 8
    str w0, [sp, w5, uxtw]
    mov x6, -16
    str w1, [sp, x6, sxtx]
  )");
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() - 16),
            0xABABull << 16);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() - 12),
            0x1234ull << 16);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() - 8),
            0xCD89ull << 16);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() - 4),
            0x3401ull << 16);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer()),
            0xABABull << 16);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() - 24),
            0x1234ull << 16);
}

TEST_P(InstStore, strx) {
  RUN_AARCH64(R"(
    movz x0, 0xABAB, lsl 32
    movz x1, 0x1234, lsl 32
    movz x2, 0xCD89, lsl 32
    movz x3, 0x3401, lsl 32
    sub sp, sp, #32
    str x0, [sp], 8
    str x1, [sp]
    str x2, [sp, 8]!
    str x3, [sp, 8]
    mov w5, 16
    str x0, [sp, w5, uxtw]
    sub sp, sp, 16
    mov x6, -16
    str x1, [sp, x6, sxtx]
  )");
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 32),
            0xABABull << 32);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 24),
            0x1234ull << 32);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 16),
            0xCD89ull << 32);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 8),
            0x3401ull << 32);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer()),
            0xABABull << 32);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 48),
            0x1234ull << 32);
}

TEST_P(InstStore, stps) {
  RUN_AARCH64(R"(
    fmov s0, 2.0
    fmov s1, -0.125
    fmov s2, 7.5
    fmov s3, 16.0
    sub sp, sp, #32
    stp s0, s1, [sp], 8
    stp s1, s2, [sp]
    stp s2, s3, [sp, 8]!
    stp s3, s0, [sp, 8]
  )");
  EXPECT_EQ(getMemoryValue<float>(process_->getStackPointer() - 32), 2.f);
  EXPECT_EQ(getMemoryValue<float>(process_->getStackPointer() - 28), -0.125f);
  EXPECT_EQ(getMemoryValue<float>(process_->getStackPointer() - 24), -0.125f);
  EXPECT_EQ(getMemoryValue<float>(process_->getStackPointer() - 20), 7.5f);
  EXPECT_EQ(getMemoryValue<float>(process_->getStackPointer() - 16), 7.5f);
  EXPECT_EQ(getMemoryValue<float>(process_->getStackPointer() - 12), 16.f);
  EXPECT_EQ(getMemoryValue<float>(process_->getStackPointer() - 8), 16.f);
  EXPECT_EQ(getMemoryValue<float>(process_->getStackPointer() - 4), 2.f);
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

  RUN_AARCH64(R"(
    fmov d0, -0.125
    stur d0, [sp, #-8]
  )");
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 8), -0.125);
}

INSTANTIATE_TEST_SUITE_P(AArch64, InstStore, ::testing::Values(EMULATION),
                         coreTypeToString);

}  // namespace
