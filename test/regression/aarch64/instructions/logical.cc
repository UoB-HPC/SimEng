#include "AArch64RegressionTest.hh"

namespace {

using InstLogical = AArch64RegressionTest;
using namespace simeng::arch::aarch64::InstructionGroups;

TEST_P(InstLogical, andw) {
  // 0 & 0 = 0
  RUN_AARCH64(R"(
    mov w0, wzr
    and w0, w0, wzr
  )");
  EXPECT_EQ(getGeneralRegister<uint32_t>(0), 0u);

  // 0b0010 & 0b0001 = 0
  RUN_AARCH64(R"(
    mov w0, #2
    and w0, w0, #1
  )");
  EXPECT_EQ(getGeneralRegister<uint32_t>(0), 0u);

  // 0b0111 & 0b1010 = 0b0010
  RUN_AARCH64(R"(
    movz w0, 0x7
    movz w1, 0xA
    and w0, w0, w1
  )");
  EXPECT_EQ(getGeneralRegister<uint32_t>(0), 0b0010);

  // 0b0111 & (0b1010 << 1) = 0b0100
  RUN_AARCH64(R"(
    movz w0, 0x7
    movz w1, 0xA
    and w0, w0, w1, lsl #1
  )");
  EXPECT_EQ(getGeneralRegister<uint32_t>(0), 0b0100);
}

TEST_P(InstLogical, andx) {
  // 0 & 0 = 0
  RUN_AARCH64(R"(
    mov x0, xzr
    and x0, x0, xzr
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 0u);

  // 0b0010 & 0b0001 = 0
  RUN_AARCH64(R"(
    mov x0, #2
    and x0, x0, #1
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 0u);

  // 0b0111 & 0b1010 = 0b0010
  RUN_AARCH64(R"(
    movz x0, 0x7
    movz x1, 0xA
    and x0, x0, x1
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 0b0010);

  // 0b0111 & (0b1010 << 1) = 0b0100
  RUN_AARCH64(R"(
    movz x0, 0x7
    movz x1, 0xA
    and x0, x0, x1, lsl #1
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 0b0100);

  // (0b0111 << 48) & (0b1010 << 47) = (0b101)<<48
  RUN_AARCH64(R"(
    movz x0, 0x7, lsl #48
    movz x1, 0xA
    and x0, x0, x1, lsl #47
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), (0b101ull) << 48);
}

TEST_P(InstLogical, andsw) {
  // 0 & 0 = 0
  RUN_AARCH64(R"(
    mov w0, wzr
    ands w0, w0, wzr
  )");
  EXPECT_EQ(getNZCV(), 0b0100);
  EXPECT_EQ(getGeneralRegister<uint32_t>(0), 0u);

  // 0b0010 & 0b0001 = 0
  RUN_AARCH64(R"(
    mov w0, #2
    ands w0, w0, #1
  )");
  EXPECT_EQ(getNZCV(), 0b0100);
  EXPECT_EQ(getGeneralRegister<uint32_t>(0), 0u);

  // 0b0111 & 0b1010 = 0b0010
  RUN_AARCH64(R"(
    movz w0, 0x7
    movz w1, 0xA
    ands w0, w0, w1
  )");
  EXPECT_EQ(getNZCV(), 0b0000);
  EXPECT_EQ(getGeneralRegister<uint32_t>(0), 0b0010);

  // 0b0111 & (0b1010 << 1) = 0b0100
  RUN_AARCH64(R"(
    movz w0, 0x7
    movz w1, 0xA
    ands w0, w0, w1, lsl #1
  )");
  EXPECT_EQ(getNZCV(), 0b0000);
  EXPECT_EQ(getGeneralRegister<uint32_t>(0), 0b0100);
}

TEST_P(InstLogical, andsx) {
  // 0 & 0 = 0
  RUN_AARCH64(R"(
    mov x0, xzr
    ands x0, x0, xzr
  )");
  EXPECT_EQ(getNZCV(), 0b0100);
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 0u);

  // 0b0010 & 0b0001 = 0
  RUN_AARCH64(R"(
    mov x0, #2
    ands x0, x0, #1
  )");
  EXPECT_EQ(getNZCV(), 0b0100);
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 0u);

  // 0b0111 & 0b1010 = 0b0010
  RUN_AARCH64(R"(
    movz x0, 0x7
    movz x1, 0xA
    ands x0, x0, x1
  )");
  EXPECT_EQ(getNZCV(), 0b0000);
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 0b0010);

  // 0b0111 & (0b1010 << 1) = 0b0100
  RUN_AARCH64(R"(
    movz x0, 0x7
    movz x1, 0xA
    ands x0, x0, x1, lsl #1
  )");
  EXPECT_EQ(getNZCV(), 0b0000);
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 0b0100);

  // (0b0111 << 48) & (0b1010 << 47) = (0b101)<<48
  RUN_AARCH64(R"(
    movz x0, 0x7, lsl #48
    movz x1, 0xA
    ands x0, x0, x1, lsl #47
  )");
  EXPECT_EQ(getNZCV(), 0b0000);
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), (0b101ull) << 48);
}

TEST_P(InstLogical, asrw) {
  // 1 >> 0 = 1
  RUN_AARCH64(R"(
    mov w0, #1
    asr w0, w0, wzr
  )");
  EXPECT_EQ(getGeneralRegister<int32_t>(0), 1);

  // 3 >> 1 = 1
  RUN_AARCH64(R"(
    mov w0, #3
    asr w0, w0, #1
  )");
  EXPECT_EQ(getGeneralRegister<int32_t>(0), 1);

  // -16 >> 2 = -4
  RUN_AARCH64(R"(
    mov w0, wzr
    sub w0, w0, #16
    asr w0, w0, #2
  )");
  EXPECT_EQ(getGeneralRegister<int32_t>(0), -4);

  // -16 >> 33 = -8 (since shift amount is mod 32)
  RUN_AARCH64(R"(
    mov w0, wzr
    mov w1, #33
    sub w0, w0, #16
    asr w0, w0, w1
  )");
  EXPECT_EQ(getGeneralRegister<int32_t>(0), -8);

  // TODO being noshift seems incorrect - but potentially aliasing to SBF
  EXPECT_GROUP(R"(asr w0, w0, wzr)", INT_SIMPLE_ARTH_NOSHIFT);
  EXPECT_GROUP(R"(asr w0, w0, #1)", INT_SIMPLE_ARTH_NOSHIFT);
}

TEST_P(InstLogical, asrx) {
  // 1 >> 0 = 1
  RUN_AARCH64(R"(
    mov x0, #1
    asr x0, x0, xzr
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(0), 1);

  // 3 >> 1 = 1
  RUN_AARCH64(R"(
    mov x0, #3
    asr x0, x0, #1
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(0), 1);

  // -16 >> 2 = -4
  RUN_AARCH64(R"(
    mov x0, xzr
    sub x0, x0, #16
    asr x0, x0, #2
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(0), -4);

  // -16 >> 65 = -8 (since shift amount is mod 64)
  RUN_AARCH64(R"(
    mov x0, xzr
    mov x1, #65
    sub x0, x0, #16
    asr x0, x0, x1
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(0), -8);

  // TODO noshift seems incorrect - but potentially aliasing to SBF
  EXPECT_GROUP(R"(asr x0, x0, xzr)", INT_SIMPLE_ARTH_NOSHIFT);
  EXPECT_GROUP(R"(asr x0, x0, #2)", INT_SIMPLE_ARTH_NOSHIFT);
}

TEST_P(InstLogical, bic) {
  // 32-bit
  // 0 & ~0 = 0
  // 0b0010 & ~0b0001 = 0b0010
  // 0b0111 & ~0b1010 = 0b0101
  // 0b0111 & ~(0b1010 << 1) = 0b0011
  RUN_AARCH64(R"(
    mov w0, wzr
    bic w2, w0, wzr

    mov w0, #2
    bic w3, w0, #1

    movz w0, 0x7
    movz w1, 0xA
    bic w4, w0, w1
    bic w5, w0, w1, lsl #1
  )");
  EXPECT_EQ(getGeneralRegister<uint32_t>(2), 0u);
  EXPECT_EQ(getGeneralRegister<uint32_t>(3), 0b0010);
  EXPECT_EQ(getGeneralRegister<uint32_t>(4), 0b0101);
  EXPECT_EQ(getGeneralRegister<uint32_t>(5), 0b0011);

  // 64-bit
  // 0 & ~0 = 0
  // 0b0010 & ~0b0001 = 0b0010
  // 0b0111 & ~0b1010 = 0b0101
  // 0b0111 & ~(0b1010 << 1) = 0b0011
  // (0b0111 << 48) & ~(0b1010 << 47) = 0b0010 << 48
  RUN_AARCH64(R"(
    mov x0, xzr
    bic x2, x0, xzr

    mov x0, #2
    bic x3, x0, #1

    movz x0, 0x7
    movz x1, 0xA
    bic x4, x0, x1
    bic x5, x0, x1, lsl #1

    movz x0, 0x7, lsl #48
    bic x6, x0, x1, lsl #47
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(2), UINT64_C(0));
  EXPECT_EQ(getGeneralRegister<uint64_t>(3), UINT64_C(0b0010));
  EXPECT_EQ(getGeneralRegister<uint64_t>(4), UINT64_C(0b0101));
  EXPECT_EQ(getGeneralRegister<uint64_t>(5), UINT64_C(0b0011));
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), UINT64_C(0b0010) << 48);
}

TEST_P(InstLogical, eorw) {
  // 0 ^ 0 = 0
  RUN_AARCH64(R"(
    mov w0, wzr
    eor w0, w0, wzr
  )");
  EXPECT_EQ(getGeneralRegister<uint32_t>(0), 0u);

  // 0b0010 ^ 0b0001 = 0b0011
  RUN_AARCH64(R"(
    mov w0, #2
    eor w0, w0, #1
  )");
  EXPECT_EQ(getGeneralRegister<uint32_t>(0), 0b0011);

  // 0b0111 ^ 0b1010 = 0b1101
  RUN_AARCH64(R"(
    movz w0, 0x7
    movz w1, 0xA
    eor w0, w0, w1
  )");
  EXPECT_EQ(getGeneralRegister<uint32_t>(0), 0b1101);

  // 0b0111 ^ (0b1010 << 1) = 0b10011
  RUN_AARCH64(R"(
    movz w0, 0x7
    movz w1, 0xA
    eor w0, w0, w1, lsl #1
  )");
  EXPECT_EQ(getGeneralRegister<uint32_t>(0), 0b10011);
}

TEST_P(InstLogical, eorx) {
  // 0 ^ 0 = 0
  RUN_AARCH64(R"(
    mov x0, xzr
    eor x0, x0, xzr
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 0u);

  // 0b0010 ^ 0b0001 = 0b0011
  RUN_AARCH64(R"(
    mov x0, #2
    eor x0, x0, #1
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 0b0011);

  // 0b0111 ^ 0b1010 = 0b1101
  RUN_AARCH64(R"(
    movz x0, 0x7
    movz x1, 0xA
    eor x0, x0, x1
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 0b1101);

  // 0b0111 ^ (0b1010 << 1) = 0b10011
  RUN_AARCH64(R"(
    movz x0, 0x7
    movz x1, 0xA
    eor x0, x0, x1, lsl #1
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 0b10011);

  // (0b0111 << 48) ^ (0b1010 << 47) = (0b0010)<<48
  RUN_AARCH64(R"(
    movz x0, 0x7, lsl #48
    movz x1, 0xA
    eor x0, x0, x1, lsl #47
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), (0b0010ull) << 48);
}

TEST_P(InstLogical, lslv) {
  // 32-bit
  RUN_AARCH64(R"(
    mov w0, #7
    mov w1, #3
    mov w2, #36
    lslv w3, w0, wzr
    lslv w4, w0, w1
    lslv w5, w0, w2
    # Check lsl alias as well
    lsl w6, w1, w0
  )");
  EXPECT_EQ(getGeneralRegister<uint32_t>(3), 7u);
  EXPECT_EQ(getGeneralRegister<uint32_t>(4), 7u << 3);
  EXPECT_EQ(getGeneralRegister<uint32_t>(5), 7u << 4);
  EXPECT_EQ(getGeneralRegister<uint32_t>(6), 3u << 7);

  // 64-bit
  RUN_AARCH64(R"(
    mov x0, #7
    mov x1, #31
    mov x2, #70
    lslv x3, x0, xzr
    lslv x4, x0, x1
    lslv x5, x0, x2
    # Check lsl alias as xell
    lsl x6, x1, x0
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(3), 7ull);
  EXPECT_EQ(getGeneralRegister<uint64_t>(4), 7ull << 31);
  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 7ull << 6);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 31ull << 7);
}

TEST_P(InstLogical, lsrv) {
  // 32-bit
  RUN_AARCH64(R"(
    mov w0, #7
    mov w1, #3
    mov w2, #36
    lsrv w3, w0, wzr
    lsrv w4, w0, w1
    lsrv w5, w0, w2
    # Check lsr alias as well
    lsr w6, w1, w0
  )");
  EXPECT_EQ(getGeneralRegister<uint32_t>(3), 7u);
  EXPECT_EQ(getGeneralRegister<uint32_t>(4), 7u >> 3);
  EXPECT_EQ(getGeneralRegister<uint32_t>(5), 7u >> 4);
  EXPECT_EQ(getGeneralRegister<uint32_t>(6), 3u >> 7);

  // 64-bit
  RUN_AARCH64(R"(
    mov x0, #7
    mov x1, #31
    mov x2, #70
    lsrv x3, x0, xzr
    lsrv x4, x0, x1
    lsrv x5, x0, x2
    # Check lsr alias as well
    lsr x6, x1, x0
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(3), 7ull);
  EXPECT_EQ(getGeneralRegister<uint64_t>(4), 7ull >> 31);
  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 7ull >> 6);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 31ull >> 7);

  EXPECT_GROUP(R"(lsr w6, w1, w0)", INT_SIMPLE_ARTH_NOSHIFT);
  EXPECT_GROUP(R"(lsr x6, x1, x0)", INT_SIMPLE_ARTH_NOSHIFT);
  EXPECT_GROUP(R"(lsr w6, w1, #1)", INT_SIMPLE_ARTH_NOSHIFT);
  EXPECT_GROUP(R"(lsr x6, x1, #1)", INT_SIMPLE_ARTH_NOSHIFT);
}

TEST_P(InstLogical, orn) {
  // 32-bit
  // 0 | ~0 = 0xFFFFFFFF
  // 0b0010 | ~0b0001 = 1111..1110
  // 0b0111 | ~0b1010 = 1111..0111
  // 0b0111 | ~(0b1010 << 4) = 1111..01011111
  RUN_AARCH64(R"(
    mov w0, wzr
    orn w2, w0, wzr

    mov w0, #2
    orn w3, w0, #1

    movz w0, 0x7
    movz w1, 0xA
    orn w4, w0, w1
    orn w5, w0, w1, lsl #4

    # Check mvn alias
    mvn w6, w0
    mvn w7, w0, lsl #28
  )");
  EXPECT_EQ(getGeneralRegister<uint32_t>(2), 0xFFFFFFFF);
  EXPECT_EQ(getGeneralRegister<uint32_t>(3), 0xFFFFFFFE);
  EXPECT_EQ(getGeneralRegister<uint32_t>(4), 0xFFFFFFF7);
  EXPECT_EQ(getGeneralRegister<uint32_t>(5), 0xFFFFFF5F);
  EXPECT_EQ(getGeneralRegister<uint32_t>(6), 0xFFFFFFF8);
  EXPECT_EQ(getGeneralRegister<uint32_t>(7), 0x8FFFFFFF);

  // 64-bit
  // 0 | ~0 = 1111...1111
  // 0b0010 | ~0b0001 = 1111..1110
  // 0b0111 | ~0b1010 = 1111..0111
  // (0b0111 << 48) | ~(0b0101 << 50) = 1111..11010111..1111
  RUN_AARCH64(R"(
    mov x0, xzr
    orn x2, x0, xzr

    mov x0, #2
    orn x3, x0, #1

    movz x0, 0x7
    movz x1, 0xA
    orn x4, x0, x1

    movz x0, 0x7, lsl #48
    movz x1, 0x5
    orn x5, x0, x1, lsl #51

    # Check mvn alias
    mvn x6, x1
    mvn x7, x1, lsl #60
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(2), UINT64_C(-1));
  EXPECT_EQ(getGeneralRegister<uint64_t>(3), UINT64_C(-1) & ~UINT64_C(0b0001));
  EXPECT_EQ(getGeneralRegister<uint64_t>(4), UINT64_C(-1) & ~UINT64_C(0b1000));
  EXPECT_EQ(getGeneralRegister<uint64_t>(5),
            UINT64_C(-1) & ~(UINT64_C(0b00101000) << 48));
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), UINT64_C(-1) & ~UINT64_C(0b0101));
  EXPECT_EQ(getGeneralRegister<uint64_t>(7),
            UINT64_C(-1) & ~(UINT64_C(0b0101) << 60));

  EXPECT_GROUP(R"(mvn w6, w0)", INT_SIMPLE_LOGICAL_NOSHIFT);
  EXPECT_GROUP(R"(mvn w7, w0, lsl #28)", INT_SIMPLE_LOGICAL);
  EXPECT_GROUP(R"(mvn x6, x1)", INT_SIMPLE_LOGICAL_NOSHIFT);
  EXPECT_GROUP(R"(mvn x7, x1, lsl #60)", INT_SIMPLE_LOGICAL);
}

TEST_P(InstLogical, rorv) {
  // 32-bit
  RUN_AARCH64(R"(
    mov w0, #36
    mov w1, #-66
    mov w2, #13
    mov w3, #27

    rorv w4, w2, w0
    rorv w5, w3, w1
  )");
  EXPECT_EQ(getGeneralRegister<uint32_t>(4),
            0b11010000000000000000000000000000);
  EXPECT_EQ(getGeneralRegister<uint32_t>(5),
            0b00000000000000000000000001101100);

  // 64-bit
  RUN_AARCH64(R"(
      mov x0, #260
      mov x1, #-130
      mov x2, #13
      mov x3, #27

      rorv x4, x2, x0
      rorv x5, x3, x1
    )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(4),
            0b1101000000000000000000000000000000000000000000000000000000000000);
  EXPECT_EQ(getGeneralRegister<uint64_t>(5),
            0b0000000000000000000000000000000000000000000000000000000001101100);
}

INSTANTIATE_TEST_SUITE_P(AArch64, InstLogical,
                         ::testing::Values(std::make_tuple(EMULATION, "{}")),
                         paramToString);

}  // namespace
