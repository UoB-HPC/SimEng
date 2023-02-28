#include "AArch64RegressionTest.hh"

namespace {

using InstStore = AArch64RegressionTest;

TEST_P(InstStore, stlr) {
  // stlrb
  RUN_AARCH64(R"(
    mov w0, 0xAB
    mov w1, 0x12
    mov w2, 0xCD
    mov w3, 0x34
    sub sp, sp, #4
    stlrb w0, [sp]
    add sp, sp, #1
    stlrb w1, [sp]
    add sp, sp, #1
    stlrb w2, [sp]
    add sp, sp, #1
    stlrb w3, [sp]
    add sp, sp, #1
  )");
  EXPECT_EQ(getMemoryValue<uint8_t>(process_->getStackPointer() - 4), 0xAB);
  EXPECT_EQ(getMemoryValue<uint8_t>(process_->getStackPointer() - 3), 0x12);
  EXPECT_EQ(getMemoryValue<uint8_t>(process_->getStackPointer() - 2), 0xCD);
  EXPECT_EQ(getMemoryValue<uint8_t>(process_->getStackPointer() - 1), 0x34);

  // stlr
  RUN_AARCH64(R"(
    mov x0, xzr
    sub x0, x0, #1
    mov x1, #0xBEEF
    mov w2, wzr
    sub w2, w2, #1
    mov w3, #0xBABA

    sub sp, sp, #24
    stlr x0, [sp]
    add sp, sp, #8
    stlr x1, [sp]
    add sp, sp, #8
    stlr w2, [sp]
    add sp, sp, #4
    stlr w3, [sp]
    add sp, sp, #4
  )");

  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 24),
            0xFFFFFFFFFFFFFFFF);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 16), 0xBEEF);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() - 8),
            0xFFFFFFFF);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() - 4), 0xBABA);
}

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
    fmov v1.2d, 0.25
    sub sp, sp, 16
    str q0, [sp], -32
    str q1, [sp, #16]!
  )");
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 8), 0.125);
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 16), 0.125);
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 24), 0.25);
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 32), 0.25);
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

TEST_P(InstStore, st1_single_struct) {
  // 8-bit
  RUN_AARCH64(R"(
    # preparing values
    mov w0, #1
    mov w1, #2
    mov w2, #3
    mov w3, #4
    mov x4, #16

    # inserting values to vector
    mov v0.b[0], w0
    mov v0.b[3], w1
    mov v0.b[8], w2
    mov v0.b[12], w3

    # storing vector elements
    sub sp, sp, #64
    st1 {v0.b}[0], [sp], #1
    add sp, sp, #15
    st1 {v0.b}[3], [sp], x4
    st1 {v0.b}[8], [sp], #1
    add sp, sp, #15
    st1 {v0.b}[12], [sp]
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), process_->getStackPointer() - 16);
  EXPECT_EQ(getMemoryValue<uint8_t>(getGeneralRegister<uint64_t>(31) - 48),
            static_cast<uint8_t>(1));
  EXPECT_EQ(getMemoryValue<uint8_t>(getGeneralRegister<uint64_t>(31) - 32),
            static_cast<uint8_t>(2));
  EXPECT_EQ(getMemoryValue<uint8_t>(getGeneralRegister<uint64_t>(31) - 16),
            static_cast<uint8_t>(3));
  EXPECT_EQ(getMemoryValue<uint8_t>(getGeneralRegister<uint64_t>(31)),
            static_cast<uint8_t>(4));

  // 16-bit
  RUN_AARCH64(R"(
    # preparing values
    mov w0, #0xab
    mov w1, #0xcd
    mov w2, #0xef
    mov w3, #0x12
    mov x4, #16

    # inserting values to vector
    mov v0.h[2], w0
    mov v0.h[3], w1
    mov v0.h[5], w2
    mov v0.h[7], w3
    sub sp, sp, #64

    # storing vector elements
    st1 {v0.h}[2], [sp], #2
    add sp, sp, #14
    st1 {v0.h}[3], [sp], x4
    st1 {v0.h}[5], [sp], #2
    add sp, sp, #14
    st1 {v0.h}[7], [sp]
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), process_->getStackPointer() - 16);
  EXPECT_EQ(getMemoryValue<uint16_t>(getGeneralRegister<uint64_t>(31) - 48),
            0xab);
  EXPECT_EQ(getMemoryValue<uint16_t>(getGeneralRegister<uint64_t>(31) - 32),
            0xcd);
  EXPECT_EQ(getMemoryValue<uint16_t>(getGeneralRegister<uint64_t>(31) - 16),
            0xef);
  EXPECT_EQ(getMemoryValue<uint16_t>(getGeneralRegister<uint64_t>(31)), 0x12);

  // 32-bit
  RUN_AARCH64(R"(
    # preparing values
    mov w1, #1
    mov w2, #2
    mov w3, #3
    mov x4, #16

    # inserting values to vector
    fmov s0, #0.5
    mov v0.s[1], w1
    mov v0.s[2], w2
    mov v0.s[3], w3

    # storing vector elements
    sub sp, sp, #64
    st1 {v0.s}[0], [sp], #4
    add sp, sp, #12
    st1 {v0.s}[1], [sp], x4
    st1 {v0.s}[2], [sp], #4
    add sp, sp, #12
    st1 {v0.s}[3], [sp]
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), process_->getStackPointer() - 16);
  EXPECT_EQ(getMemoryValue<float>(getGeneralRegister<uint64_t>(31) - 48), 0.5f);
  EXPECT_EQ(getMemoryValue<uint32_t>(getGeneralRegister<uint64_t>(31) - 32), 1);
  EXPECT_EQ(getMemoryValue<uint32_t>(getGeneralRegister<uint64_t>(31) - 16), 2);
  EXPECT_EQ(getMemoryValue<uint32_t>(getGeneralRegister<uint64_t>(31) - 0), 3);

  // 64-bit
  RUN_AARCH64(R"(
    # preparing values
    mov x1, #1000
    mov x2, #2000
    mov x4, #16

    # inserting values to vector
    fmov d0, #0.5
    mov v0.d[1], x1
    mov v1.d[0], x2

    # storing vector elements
    sub sp, sp, #48
    st1 {v0.d}[0], [sp], #8
    add sp, sp, #8
    st1 {v0.d}[1], [sp], x4
    st1 {v1.d}[0], [sp]
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), process_->getStackPointer() - 16);
  EXPECT_EQ(getMemoryValue<double>(getGeneralRegister<uint64_t>(31) - 32), 0.5);
  EXPECT_EQ(getMemoryValue<uint64_t>(getGeneralRegister<uint64_t>(31) - 16),
            1000UL);
  EXPECT_EQ(getMemoryValue<uint64_t>(getGeneralRegister<uint64_t>(31)), 2000UL);
}

TEST_P(InstStore, st1twov) {
  // V.16B
  RUN_AARCH64(R"(
    movi v0.16b, #1
    movi v1.16b, #2
    sub sp, sp, #32
    st1 {v0.16b, v1.16b}, [sp]
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), process_->getStackPointer() - 32);
  for (int i = 0; i < 16; i++) {
    EXPECT_EQ(getMemoryValue<uint8_t>(getGeneralRegister<uint64_t>(31) + i),
              (static_cast<uint8_t>(1)));
  }
  for (uint64_t i = 16; i < 32; i++) {
    EXPECT_EQ(getMemoryValue<uint8_t>(getGeneralRegister<uint64_t>(31) + i),
              (static_cast<uint8_t>(2)));
  }

  // V.4S
  RUN_AARCH64(R"(
    movi v0.4s, #1
    movi v1.4s, #2
    sub sp, sp, #32
    st1 {v0.4s, v1.4s}, [sp]
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), process_->getStackPointer() - 32);
  for (int i = 0; i < 4; i++) {
    EXPECT_EQ(
        getMemoryValue<uint32_t>(getGeneralRegister<uint64_t>(31) + (i * 4)),
        (static_cast<uint32_t>(1)));
  }
  for (uint64_t i = 4; i < 8; i++) {
    EXPECT_EQ(
        getMemoryValue<uint32_t>(getGeneralRegister<uint64_t>(31) + (i * 4)),
        (static_cast<uint32_t>(2)));
  }
}

TEST_P(InstStore, st1fourv_post) {
  // V.2S
  RUN_AARCH64(R"(
      movi v0.2s, #1
      movi v1.2s, #2
      movi v2.2s, #3
      movi v3.2s, #4

      sub sp, sp, #64
      mov x0, sp

      st1 {v0.2s, v1.2s, v2.2s, v3.2s}, [x0], #32

      movi v4.2s, #5
      movi v5.2s, #6
      movi v6.2s, #7
      movi v7.2s, #8
      mov x1, x0
      mov x2, #17

      st1 {v4.2s, v5.2s, v6.2s, v7.2s}, [x1], x2
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), process_->getStackPointer() - 64);
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), process_->getStackPointer() - 32);
  EXPECT_EQ(getGeneralRegister<uint64_t>(1), process_->getStackPointer() - 15);
  for (int i = 0; i < 2; i++) {
    EXPECT_EQ(
        getMemoryValue<uint32_t>(getGeneralRegister<uint64_t>(31) + (i * 4)),
        (static_cast<uint32_t>(1)));
    EXPECT_EQ(getMemoryValue<uint32_t>(getGeneralRegister<uint64_t>(31) + 8 +
                                       (i * 4)),
              (static_cast<uint32_t>(2)));
    EXPECT_EQ(getMemoryValue<uint32_t>(getGeneralRegister<uint64_t>(31) + 16 +
                                       (i * 4)),
              (static_cast<uint32_t>(3)));
    EXPECT_EQ(getMemoryValue<uint32_t>(getGeneralRegister<uint64_t>(31) + 24 +
                                       (i * 4)),
              (static_cast<uint32_t>(4)));
    EXPECT_EQ(getMemoryValue<uint32_t>(getGeneralRegister<uint64_t>(31) + 32 +
                                       (i * 4)),
              (static_cast<uint32_t>(5)));
    EXPECT_EQ(getMemoryValue<uint32_t>(getGeneralRegister<uint64_t>(31) + 40 +
                                       (i * 4)),
              (static_cast<uint32_t>(6)));
    EXPECT_EQ(getMemoryValue<uint32_t>(getGeneralRegister<uint64_t>(31) + 48 +
                                       (i * 4)),
              (static_cast<uint32_t>(7)));
    EXPECT_EQ(getMemoryValue<uint32_t>(getGeneralRegister<uint64_t>(31) + 56 +
                                       (i * 4)),
              (static_cast<uint32_t>(8)));
  }

  // V.4S
  RUN_AARCH64(R"(
      movi v0.4s, #1
      movi v1.4s, #2
      movi v2.4s, #3
      movi v3.4s, #4

      sub sp, sp, #128
      mov x0, sp

      st1 {v0.4s, v1.4s, v2.4s, v3.4s}, [x0], #64

      movi v4.4s, #5
      movi v5.4s, #6
      movi v6.4s, #7
      movi v7.4s, #8
      mov x1, x0
      mov x2, #17

      st1 {v4.4s, v5.4s, v6.4s, v7.4s}, [x1], x2
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(31),
            process_->getStackPointer() - 128);
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), process_->getStackPointer() - 64);
  EXPECT_EQ(getGeneralRegister<uint64_t>(1), process_->getStackPointer() - 47);
  for (int i = 0; i < 4; i++) {
    EXPECT_EQ(
        getMemoryValue<uint32_t>(getGeneralRegister<uint64_t>(31) + (i * 4)),
        (static_cast<uint32_t>(1)));
    EXPECT_EQ(getMemoryValue<uint32_t>(getGeneralRegister<uint64_t>(31) + 16 +
                                       (i * 4)),
              (static_cast<uint32_t>(2)));
    EXPECT_EQ(getMemoryValue<uint32_t>(getGeneralRegister<uint64_t>(31) + 32 +
                                       (i * 4)),
              (static_cast<uint32_t>(3)));
    EXPECT_EQ(getMemoryValue<uint32_t>(getGeneralRegister<uint64_t>(31) + 48 +
                                       (i * 4)),
              (static_cast<uint32_t>(4)));
    EXPECT_EQ(getMemoryValue<uint32_t>(getGeneralRegister<uint64_t>(31) + 64 +
                                       (i * 4)),
              (static_cast<uint32_t>(5)));
    EXPECT_EQ(getMemoryValue<uint32_t>(getGeneralRegister<uint64_t>(31) + 80 +
                                       (i * 4)),
              (static_cast<uint32_t>(6)));
    EXPECT_EQ(getMemoryValue<uint32_t>(getGeneralRegister<uint64_t>(31) + 96 +
                                       (i * 4)),
              (static_cast<uint32_t>(7)));
    EXPECT_EQ(getMemoryValue<uint32_t>(getGeneralRegister<uint64_t>(31) + 112 +
                                       (i * 4)),
              (static_cast<uint32_t>(8)));
  }
}

TEST_P(InstStore, st2_multi_struct) {
  // V.4S (float)
  RUN_AARCH64(R"(
    fmov v0.4s, #-0.5
    fmov v1.4s, #2.0
    fmov v2.4s, #1.5
    fmov v3.4s, -3.0
    mov x1, #48
    sub sp, sp, #80
    st2 {v2.4s, v3.4s}, [sp], x1
    st2 {v0.4s, v1.4s}, [sp], #32
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), process_->getStackPointer());
  for (int i = 0; i < 4; i++) {
    EXPECT_EQ(
        getMemoryValue<float>(getGeneralRegister<uint64_t>(31) - 32 + 8 * i),
        -0.5);
    EXPECT_EQ(
        getMemoryValue<float>(getGeneralRegister<uint64_t>(31) - 28 + 8 * i),
        2.0);
  }
  for (int i = 0; i < 4; i++) {
    EXPECT_EQ(
        getMemoryValue<float>(getGeneralRegister<uint64_t>(31) - 80 + 8 * i),
        1.5);
    EXPECT_EQ(
        getMemoryValue<float>(getGeneralRegister<uint64_t>(31) - 76 + 8 * i),
        -3.0);
  }
}

TEST_P(InstStore, stpd) {
  RUN_AARCH64(R"(
    fmov d0, 2.0
    fmov d1, -0.125
    fmov d2, 7.5
    fmov d3, 16.0
    sub sp, sp, #64
    stp d0, d1, [sp], 16
    stp d1, d2, [sp]
    stp d2, d3, [sp, 16]!
    stp d3, d0, [sp, 16]
  )");

  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 64), 2.0);
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 56), -0.125);
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 48), -0.125);
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 40), 7.5);
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 32), 7.5);
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 24), 16.0);
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 16), 16.0);
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 8), 2.0);
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

TEST_P(InstStore, stpq) {
  RUN_AARCH64(R"(
    fmov v0.2d, 2.0
    fmov v1.2d, -0.125
    fmov v2.2d, 7.5
    fmov v3.2d, 16.0 
    sub sp, sp, #128
    stp q0, q1, [sp], 32
    stp q1, q2, [sp]
    stp q2, q3, [sp, 32]!
    stp q3, q0, [sp, 32] 
  )");
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 128), 2.f);
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 120), 2.f);
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 112), -0.125f);
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 104), -0.125f);
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 96), -0.125f);
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 88), -0.125f);
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 80), 7.5f);
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 72), 7.5f);
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 64), 7.5f);
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 56), 7.5f);
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 48), 16.f);
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 40), 16.f);
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 32), 16.f);
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 24), 16.f);
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 16), 2.f);
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 8), 2.f);
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), process_->getStackPointer() - 64);
}

TEST_P(InstStore, stpx) {
  RUN_AARCH64(R"(
    movz x0, #7
    movz x1, #42
    movz x2, #8
    movz x3, #43
    movz x4, #9
    movz x5, #44

    sub sp, sp, #1024

    stp x0, x1, [sp], #16
    stp x2, x3, [sp]
    stp x4, x5, [sp, #16]!
  )");
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 1024), 7u);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 1016), 42u);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 1008), 8u);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 1000), 43u);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 992), 9u);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 984), 44u);
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
    fmov s0, -0.125
    stur s0, [sp, #-4]
  )");
  EXPECT_EQ(getMemoryValue<float>(process_->getStackPointer() - 4), -0.125);

  RUN_AARCH64(R"(
    fmov d0, -0.125
    stur d0, [sp, #-8]
  )");
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 8), -0.125);

  RUN_AARCH64(R"(
    fmov v0.2d, -0.125
    stur q0, [sp, #-16]
  )");
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 16), -0.125);
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 8), -0.125);
}

TEST_P(InstStore, sturh) {
  RUN_AARCH64(R"(
    movz w0, #42
    sturh w0, [sp, #-2]
    movz w1, #128
    sturh w1, [sp, #-4]
  )");
  EXPECT_EQ(getMemoryValue<uint16_t>(process_->getStackPointer() - 2), 42u);
  EXPECT_EQ(getMemoryValue<uint16_t>(process_->getStackPointer() - 4), 128u);
}

INSTANTIATE_TEST_SUITE_P(AArch64, InstStore,
                         ::testing::Values(std::make_tuple(EMULATION,
                                                           YAML::Load("{}"))),
                         paramToString);

}  // namespace