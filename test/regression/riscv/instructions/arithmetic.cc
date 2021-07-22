#include "RISCVRegressionTest.hh"

namespace {

using InstArithmetic = RISCVRegressionTest;

TEST_P(InstArithmetic, sll) {
RUN_RISCV(R"(
      addi t3, t3, 3
      addi t4, t4, 6
      sll t5, t4, t3
      slli t6, t4, 5
  )");
EXPECT_EQ(getGeneralRegister<uint64_t>(30), 48);
EXPECT_EQ(getGeneralRegister<uint64_t>(31), 192);
}

TEST_P(InstArithmetic, sllw) {
RUN_RISCV(R"(
      addi t4, t4, 6
      slliw t5, t4, 28
      slliw t6, t4, 30
      slliw t1, t4, 31
  )");
EXPECT_EQ(getGeneralRegister<uint64_t>(30), 1610612736);
EXPECT_EQ(getGeneralRegister<uint64_t>(31), -2147483648);
EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0);

RUN_RISCV(R"(
      addi t3, t3, 28
      addi t4, t4, 6
      sllw t5, t4, t3
      addi t3, t3, 2
      sllw t6, t4, t3
      addi t3, t3, 1
      sllw t1, t4, t3
      addi t3, t3, 1
      sllw t2, t4, t3
  )");
EXPECT_EQ(getGeneralRegister<uint64_t>(30), 1610612736);
EXPECT_EQ(getGeneralRegister<uint64_t>(31), -2147483648);
EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 0); // TODO check if > 32 shamt allowed
}

TEST_P(InstArithmetic, srl) {
RUN_RISCV(R"(
      addi t3, t3, 60
      addi t4, t4, -4
      srl t5, t4, t3
      srli t6, t4, 61
  )");
EXPECT_EQ(getGeneralRegister<uint64_t>(30), 15);
EXPECT_EQ(getGeneralRegister<uint64_t>(31), 7);
}

TEST_P(InstArithmetic, srlw) {
RUN_RISCV(R"(
      addi t3, t3, 1
      addi t4, t4, -7
      srlw t5, t4, t2
      srlw t1, t4, t3
      srliw t6, t4, 1
      srliw t2, t4, 0
  )");
EXPECT_EQ(getGeneralRegister<uint64_t>(30), -7);
EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0b01111111111111111111111111111100);
EXPECT_EQ(getGeneralRegister<uint64_t>(31), 0b01111111111111111111111111111100);
EXPECT_EQ(getGeneralRegister<uint64_t>(7), -7);
}

TEST_P(InstArithmetic, sra) {
RUN_RISCV(R"(
      addi t3, t3, 2
      addi t4, t4, -4
      sra t5, t4, t3
      srai t6, t4, 1
      addi t4, t4, 8
      sra t1, t4, t3
      srai t2, t4, 1
  )");
EXPECT_EQ(getGeneralRegister<uint64_t>(30), -1);
EXPECT_EQ(getGeneralRegister<uint64_t>(31), -2);
EXPECT_EQ(getGeneralRegister<uint64_t>(6), 1);
EXPECT_EQ(getGeneralRegister<uint64_t>(7), 2);
}

TEST_P(InstArithmetic, sraw) {
RUN_RISCV(R"(
      addi t3, t3, 2
      addi t4, t4, 1
      slli t5, t4, 31
      sraiw t5, t5, 31
      slli t6, t4, 30
      sraiw t6, t6, 30
  )");
EXPECT_EQ(getGeneralRegister<uint64_t>(30), -1);
EXPECT_EQ(getGeneralRegister<uint64_t>(31), 1);
}

TEST_P(InstArithmetic, add) {
RUN_RISCV(R"(
      addi t3, t3, 3
      addi t4, t4, 6
      add t5, t3, t4
      addi zero, t4, 16
  )");
EXPECT_EQ(getGeneralRegister<uint64_t>(28), 3u);
EXPECT_EQ(getGeneralRegister<uint64_t>(29), 6u);
EXPECT_EQ(getGeneralRegister<uint64_t>(30), 9u);
EXPECT_EQ(getGeneralRegister<uint64_t>(0), 0);
}

TEST_P(InstArithmetic, addw) {
RUN_RISCV(R"(
    addi t2, t2, -7
    addi t3, t3, 3
    addi t4, t4, 6
    addw t5, t3, t4
    addw t6, t2, t3
  )");
EXPECT_EQ(getGeneralRegister<uint64_t>(28), 3u);
EXPECT_EQ(getGeneralRegister<uint64_t>(29), 6u);
EXPECT_EQ(getGeneralRegister<uint64_t>(30), 9u);
EXPECT_EQ(getGeneralRegister<uint64_t>(31), -4);

//  RUN_RISCV(R"(
//      addi t1, t1, 2147483647
//      addi t2, t2, 100
//      addw t3, t1, t2
//    )");
//  EXPECT_EQ(getGeneralRegister<uint64_t>(28), 2147483747);

}

TEST_P(InstArithmetic, addiw) {
RUN_RISCV(R"(
    addi t3, t3, 91
    slli t3, t3, 28
    addi t4, t4, -5
    addiw t5, t3, -5
    addiw t6, t2, -5
  )");
EXPECT_EQ(getGeneralRegister<uint64_t>(28), 24427626496);
EXPECT_EQ(getGeneralRegister<int64_t>(29), -5);
EXPECT_EQ(getGeneralRegister<int32_t>(30), -1342177285);
EXPECT_EQ(getGeneralRegister<int64_t>(31), -5);
}

TEST_P(InstArithmetic, sub) {
RUN_RISCV(R"(
    addi t3, t3, 3
    addi t4, t4, 6
    sub t5, t3, t4
    sub t6, t4, t3
  )");
EXPECT_EQ(getGeneralRegister<uint64_t>(30), -3);
EXPECT_EQ(getGeneralRegister<uint64_t>(31), 3);

// TODO SUBW
}

TEST_P(InstArithmetic, xor) {
RUN_RISCV(R"(
      addi t3, t3, 3
      addi t4, t4, 5
      xor t5, t3, t4
      xori t6, t5, 5
      xori t1, t3, -1
      xori t2, t3, -7
    )");
EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0b0110);
EXPECT_EQ(getGeneralRegister<uint64_t>(31), 0b0011);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(6), -4);
EXPECT_EQ(getGeneralRegister<uint64_t>(7), -6);
}

TEST_P(InstArithmetic, or) {
RUN_RISCV(R"(
    addi t3, t3, 3
    addi t4, t4, 5
    or t5, t3, t4
    ori t6, t5, 9
    ori t2, t3, -7
  )");
EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0b0111);
EXPECT_EQ(getGeneralRegister<uint64_t>(31), 0b1111);
EXPECT_EQ(getGeneralRegister<uint64_t>(7), -5);
}

TEST_P(InstArithmetic, and) {
RUN_RISCV(R"(
    addi t3, t3, 3
    addi t4, t4, 5
    and t5, t3, t4
    andi t6, t5, 9
    andi t2, t3, -7
  )");
EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0b0001);
EXPECT_EQ(getGeneralRegister<uint64_t>(31), 0b0001);
EXPECT_EQ(getGeneralRegister<uint64_t>(7), 1);
}

TEST_P(InstArithmetic, slt) {
RUN_RISCV(R"(
    addi t3, t3, -3
    addi t4, t4, 5
    slt t5, t3, t4
    slt t6, t4, t3
    sltu t1, t3, t4
    sltu t2, t4, t3
  )");
EXPECT_EQ(getGeneralRegister<uint64_t>(30), 1);
EXPECT_EQ(getGeneralRegister<uint64_t>(31), 0);
EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0);
EXPECT_EQ(getGeneralRegister<uint64_t>(7), 1);
// TODO SNEZ
//    stlu s0, x0, t1
}

TEST_P(InstArithmetic, slti) {
RUN_RISCV(R"(
    addi t3, t3, -3
    addi t4, t4, 5
    slti t5, t3, 5
    slti t6, t4, -3
    sltiu t1, t3, 5
    sltiu t2, t4, -3
  )");
EXPECT_EQ(getGeneralRegister<uint64_t>(30), 1);
EXPECT_EQ(getGeneralRegister<uint64_t>(31), 0);
EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0);
EXPECT_EQ(getGeneralRegister<uint64_t>(7), 1);
}

TEST_P(InstArithmetic, addiPseudoinstructions) {
RUN_RISCV(R"(
      nop
      addi t1, t1, 5
      mv t2, t1
      addi t3, t3, -5
      sext.w t4, t3
  )");
EXPECT_EQ(getGeneralRegister<uint64_t>(6), 5);
EXPECT_EQ(getGeneralRegister<uint64_t>(7), 5);
EXPECT_EQ(getGeneralRegister<uint64_t>(0), 0);
EXPECT_EQ(getGeneralRegister<int64_t>(28), -5);
EXPECT_EQ(getGeneralRegister<int64_t>(29), -5);
}

TEST_P(InstArithmetic, subwPseudoinstructions) {
RUN_RISCV(R"(
      addi t3, t3, 91
      neg t4, t3
      addi t5, t5, 181
      slli t5, t5, 28
      sext.w t2, t5
      negw t6, t5
  )");
EXPECT_EQ(getGeneralRegister<uint64_t>(28), 91);
EXPECT_EQ(getGeneralRegister<int64_t>(29), -91);
EXPECT_EQ(getGeneralRegister<uint64_t>(30), 48586817536);
EXPECT_EQ(getGeneralRegister<int64_t>(7), 1342177280);
EXPECT_EQ(getGeneralRegister<int64_t>(31), -1342177280);
}

TEST_P(InstArithmetic, setPseudoinstructions) {
RUN_RISCV(R"(
      addi t1, t1, 1
      seqz t2, t0
      seqz t3, t1
      snez t4, t0
      snez t5, t1
  )");
EXPECT_EQ(getGeneralRegister<uint64_t>(7), 1);
EXPECT_EQ(getGeneralRegister<uint64_t>(28), 0);
EXPECT_EQ(getGeneralRegister<uint64_t>(29), 0);
EXPECT_EQ(getGeneralRegister<uint64_t>(30), 1);

RUN_RISCV(R"(
      addi t1, t1, 1
      addi t6, t6, -1
      sltz t2, t0
      sltz t3, t1
      sltz t4, t6
      sgtz t5, t0
      sgtz s0, t1
      sgtz s1, t6
  )");
EXPECT_EQ(getGeneralRegister<uint64_t>(7), 0);
EXPECT_EQ(getGeneralRegister<uint64_t>(28), 0);
EXPECT_EQ(getGeneralRegister<uint64_t>(29), 1);
EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0);
EXPECT_EQ(getGeneralRegister<uint64_t>(8), 1);
EXPECT_EQ(getGeneralRegister<uint64_t>(9), 0);


}

//TEST_P(InstArithmetic, addi) {
//  RUN_RISCV(R"(
//    addi,x28,x28,3
//  )");
//  EXPECT_EQ(getGeneralRegister<uint64_t>(28), 3u);
//}

//TEST_P(InstArithmetic, add) {
//  RUN_AARCH64(R"(
//    mov w0, wzr
//    add w1, w0, #2
//    add w2, w0, #7, lsl #12
//  )");
//  EXPECT_EQ(getGeneralRegister<uint32_t>(1), 2u);
//  EXPECT_EQ(getGeneralRegister<uint32_t>(2), (7u << 12));
//
//  RUN_AARCH64(R"(
//    mov x0, xzr
//    add x1, x0, #3
//    add x2, x0, #5, lsl #12
//  )");
//  EXPECT_EQ(getGeneralRegister<uint64_t>(1), 3u);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(2), (5u << 12));
//}
//
//// Test that NZCV flags are set correctly by 32-bit adds
//TEST_P(InstArithmetic, addsw) {
//  // 0 + 0 = 0
//  RUN_AARCH64(R"(
//    mov w0, wzr
//    adds w0, w0, #0
//  )");
//  EXPECT_EQ(getNZCV(), 0b0100);
//  EXPECT_EQ(getGeneralRegister<uint32_t>(0), 0u);
//
//  // 2 + 1 = 3
//  RUN_AARCH64(R"(
//    mov w0, #2
//    adds w0, w0, #1
//  )");
//  EXPECT_EQ(getNZCV(), 0b0000);
//  EXPECT_EQ(getGeneralRegister<uint32_t>(0), 3u);
//
//  // -1 + 0 = -1
//  RUN_AARCH64(R"(
//    mov w0, wzr
//    sub w0, w0, #1
//    adds w0, w0, #0
//  )");
//  EXPECT_EQ(getNZCV(), 0b1000);
//  EXPECT_EQ(getGeneralRegister<uint32_t>(0), UINT32_MAX);
//
//  // -1 + 1 = 0
//  RUN_AARCH64(R"(
//    mov w0, wzr
//    sub w0, w0, #1
//    adds w0, w0, #1
//  )");
//  EXPECT_EQ(getNZCV(), 0b0110);
//  EXPECT_EQ(getGeneralRegister<uint32_t>(0), 0);
//
//  // (2^31 -1) + 1 = 2^31
//  RUN_AARCH64(R"(
//    mov w0, wzr
//    mov w1, #1
//    add w1, w0, w1, lsl #31
//    sub w1, w1, #1
//    add w2, w0, #1
//    adds w0, w1, w2
//  )");
//  EXPECT_EQ(getNZCV(), 0b1001);
//  EXPECT_EQ(getGeneralRegister<uint32_t>(0), (1ul << 31));
//
//  // 2^31 + 0 = 2^31
//  RUN_AARCH64(R"(
//    mov w0, wzr
//    mov w1, #1
//    add w1, w0, w1, lsl #31
//    adds w0, w1, #0
//  )");
//  EXPECT_EQ(getNZCV(), 0b1000);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(0), (1u << 31));
//
//  // 2^31 + -1 = 2^31 - 1
//  RUN_AARCH64(R"(
//    mov w0, wzr
//    add w1, w0, #1
//    add w1, w0, w1, lsl #31
//    sub w2, w0, #1
//    adds w0, w1, w2
//  )");
//  EXPECT_EQ(getNZCV(), 0b0011);
//  EXPECT_EQ(getGeneralRegister<uint32_t>(0), (1u << 31) - 1);
//
//  // (7 << 16) + (-1) [8-bit sign-extended]
//  RUN_AARCH64(R"(
//    movz w0, #7, lsl #16
//    # 255 will be -1 when sign-extended from 8-bits
//    mov w2, 255
//    adds w3, w0, w2, sxtb
//  )");
//  EXPECT_EQ(getNZCV(), 0b0010);
//  EXPECT_EQ(getGeneralRegister<uint32_t>(3), (7u << 16) - 1);
//
//  // (7 << 16) + (255 << 4)
//  RUN_AARCH64(R"(
//    movz w0, #7, lsl #16
//    mov w2, 255
//    adds w3, w0, w2, uxtx 4
//  )");
//  EXPECT_EQ(getNZCV(), 0b0000);
//  EXPECT_EQ(getGeneralRegister<uint32_t>(3), (7u << 16) + (255u << 4));
//}
//
//// Test that NZCV flags are set correctly by 64-bit adds
//TEST_P(InstArithmetic, addsx) {
//  // 0 - 0 = 0
//  RUN_AARCH64(R"(
//    mov x0, xzr
//    adds x0, x0, #0
//  )");
//  EXPECT_EQ(getNZCV(), 0b0100);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 0u);
//
//  // 2 + 1 = 3
//  RUN_AARCH64(R"(
//    mov x0, #2
//    adds x0, x0, #1
//  )");
//  EXPECT_EQ(getNZCV(), 0b0000);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 3u);
//
//  // -1 + 0 = -1
//  RUN_AARCH64(R"(
//    mov x0, xzr
//    sub x0, x0, #1
//    adds x0, x0, #0
//  )");
//  EXPECT_EQ(getNZCV(), 0b1000);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(0), UINT64_MAX);
//
//  // -1 + 1 = 0
//  RUN_AARCH64(R"(
//    mov x0, xzr
//    sub x0, x0, #1
//    adds x0, x0, #1
//  )");
//  EXPECT_EQ(getNZCV(), 0b0110);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 0);
//
//  // (2^63 -1) + -1 = 2^63
//  RUN_AARCH64(R"(
//    mov x0, xzr
//    mov x1, #1
//    add x1, x0, x1, lsl #63
//    sub x1, x1, #1
//    add x2, x0, #1
//    adds x0, x1, x2
//  )");
//  EXPECT_EQ(getNZCV(), 0b1001);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(0), (1ul << 63));
//
//  // 2^63 + 0 = 2^63
//  RUN_AARCH64(R"(
//    mov x0, xzr
//    mov x1, #1
//    add x1, x0, x1, lsl #63
//    adds x0, x1, #0
//  )");
//  EXPECT_EQ(getNZCV(), 0b1000);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(0), (1ul << 63));
//
//  // 2^63 + -1 = 2^63 - 1
//  RUN_AARCH64(R"(
//    mov x0, xzr
//    add x1, x0, #1
//    add x1, x0, x1, lsl #63
//    sub x2, x0, #1
//    adds x0, x1, x2
//  )");
//  EXPECT_EQ(getNZCV(), 0b0011);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(0), (1ul << 63) - 1);
//
//  // (7 << 48) + (15 << 33)
//  RUN_AARCH64(R"(
//    movz x0, #7, lsl #48
//    movz x1, #15
//    adds x2, x0, x1, lsl 33
//  )");
//  EXPECT_EQ(getNZCV(), 0b0000);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(2), (7ul << 48) + (15ul << 33));
//
//  // (7 << 48) + (-1) [8-bit sign-extended]
//  RUN_AARCH64(R"(
//    movz x0, #7, lsl #48
//    # 255 will be -1 when sign-extended from 8-bits
//    mov w2, 255
//    adds x3, x0, w2, sxtb
//  )");
//  EXPECT_EQ(getNZCV(), 0b0010);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(3), (7ul << 48) - 1);
//
//  // (7 << 48) + (255 << 4)
//  RUN_AARCH64(R"(
//    movz x0, #7, lsl #48
//    mov w2, 255
//    adds x3, x0, x2, uxtx 4
//  )");
//  EXPECT_EQ(getNZCV(), 0b0000);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(3), (7ul << 48) + (255ul << 4));
//}
//
//TEST_P(InstArithmetic, movk) {
//  // 32-bit
//  RUN_AARCH64(R"(
//    mov w0, wzr
//    sub w0, w0, #1
//    mov w1, w0
//
//    movk w0, #0
//    movk w1, #0, lsl 16
//  )");
//  EXPECT_EQ(getGeneralRegister<uint32_t>(0), 0xFFFF0000);
//  EXPECT_EQ(getGeneralRegister<uint32_t>(1), 0x0000FFFF);
//
//  // 64-bit
//  RUN_AARCH64(R"(
//    mov x0, xzr
//    sub x0, x0, #1
//    mov x1, x0
//    mov x2, x0
//    mov x3, x0
//
//    movk x0, #0
//    movk x1, #0, lsl 16
//    movk x2, #0, lsl 32
//    movk x3, #0, lsl 48
//  )");
//  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 0xFFFFFFFFFFFF0000);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(1), 0xFFFFFFFF0000FFFF);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(2), 0xFFFF0000FFFFFFFF);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(3), 0x0000FFFFFFFFFFFF);
//}
//
//// Test that NZCV flags are set correctly by 32-bit negs
//TEST_P(InstArithmetic, negsw) {
//  // - 0
//  RUN_AARCH64(R"(
//    mov w0, wzr
//    negs w0, w0
//  )");
//  EXPECT_EQ(getNZCV(), 0b0110);
//  EXPECT_EQ(getGeneralRegister<uint32_t>(0), 0u);
//
//  // - 1
//  RUN_AARCH64(R"(
//    mov w0, 1
//    negs w0, w0
//  )");
//  EXPECT_EQ(getNZCV(), 0b1000);
//  EXPECT_EQ(getGeneralRegister<uint32_t>(0), -1);
//
//  // - -1
//  RUN_AARCH64(R"(
//    mov w0, wzr
//    sub w0, w0, #1
//    negs w0, w0
//  )");
//  EXPECT_EQ(getNZCV(), 0b0000);
//  EXPECT_EQ(getGeneralRegister<uint32_t>(0), 1);
//
//  // - (2^31 - 1)
//  RUN_AARCH64(R"(
//    mov w0, wzr
//    mov w1, #1
//    add w1, w0, w1, lsl #31
//    sub w1, w1, #1
//    negs w0, w1
//  )");
//  EXPECT_EQ(getNZCV(), 0b1000);
//  EXPECT_EQ(getGeneralRegister<uint32_t>(0),
//            static_cast<uint32_t>(-((1ul << 31) - 1)));
//
//  // - (2^31)
//  RUN_AARCH64(R"(
//    mov w0, wzr
//    mov w1, #1
//    negs w0, w1, lsl 31
//  )");
//  EXPECT_EQ(getNZCV(), 0b1001);
//  EXPECT_EQ(getGeneralRegister<uint32_t>(0), static_cast<uint32_t>(1ul << 31));
//}
//
//// Test that NZCV flags are set correctly by 64-bit negs
//TEST_P(InstArithmetic, negsx) {
//  // - 0
//  RUN_AARCH64(R"(
//    mov x0, xzr
//    negs x0, x0
//  )");
//  EXPECT_EQ(getNZCV(), 0b0110);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 0u);
//
//  // - 1
//  RUN_AARCH64(R"(
//    mov x0, 1
//    negs x0, x0
//  )");
//  EXPECT_EQ(getNZCV(), 0b1000);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(0), -1);
//
//  // - -1
//  RUN_AARCH64(R"(
//    mov x0, xzr
//    sub x0, x0, #1
//    negs x0, x0
//  )");
//  EXPECT_EQ(getNZCV(), 0b0000);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 1);
//
//  // - (2^63 - 1)
//  RUN_AARCH64(R"(
//    mov x0, xzr
//    mov x1, #1
//    add x1, x0, x1, lsl #63
//    sub x1, x1, #1
//    negs x0, x1
//  )");
//  EXPECT_EQ(getNZCV(), 0b1000);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(0),
//            static_cast<uint64_t>(-((1ul << 63) - 1)));
//
//  // - (2^63)
//  RUN_AARCH64(R"(
//    mov x0, xzr
//    mov x1, #1
//    negs x0, x1, lsl 63
//  )");
//  EXPECT_EQ(getNZCV(), 0b1001);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(0), static_cast<uint64_t>(1ul << 63));
//}
//
//TEST_P(InstArithmetic, sbc) {
//  // 32-bit
//  RUN_AARCH64(R"(
//    mov w0, wzr
//    mov w1, #1
//    sub w2, w0, w1
//    sbc w2, w2, w1
//
//    movz w0, #7, lsl #16
//    movz w1, #15
//    sub w3, w0, w1, lsl 3
//    sbc w3, w3, w1
//  )");
//  EXPECT_EQ(getGeneralRegister<int32_t>(2), -3);
//  EXPECT_EQ(getGeneralRegister<uint32_t>(3),
//            (7u << 16) - (15u << 3) - 15u - 1u);
//
//  // 64-bit
//  RUN_AARCH64(R"(
//    mov x0, xzr
//    mov x1, #1
//    sub x2, x0, x1
//    sbc x2, x2, x1
//
//    movz x0, #7, lsl #48
//    movz x1, #15
//    sub x3, x0, x1, lsl 33
//    sbc x3, x3, x1
//  )");
//  EXPECT_EQ(getGeneralRegister<int64_t>(2), -3);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(3),
//            (7ul << 48) - (15ul << 33) - 15ul - 1ul);
//}
//
//TEST_P(InstArithmetic, sub) {
//  // 32-bit
//  RUN_AARCH64(R"(
//    mov w0, wzr
//    sub w2, w0, #2
//
//    movk w0, #7, lsl #16
//    movz w1, #15
//    sub w3, w0, w1, lsl 3
//  )");
//  EXPECT_EQ(getGeneralRegister<int32_t>(2), -2);
//  EXPECT_EQ(getGeneralRegister<uint32_t>(3), (7u << 16) - (15u << 3));
//
//  // 64-bit
//  RUN_AARCH64(R"(
//    mov x0, xzr
//    sub x2, x0, #2
//
//    movk x0, #7, lsl #48
//    movz x1, #15
//    sub x3, x0, x1, lsl 33
//  )");
//  EXPECT_EQ(getGeneralRegister<int64_t>(2), -2);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(3), (7ul << 48) - (15ul << 33));
//}
//
//// Test that NZCV flags are set correctly by 32-bit subs
//TEST_P(InstArithmetic, subsw) {
//  // 0 - 0 = 0
//  RUN_AARCH64(R"(
//    mov w0, wzr
//    subs w0, w0, #0
//  )");
//  EXPECT_EQ(getNZCV(), 0b0110);
//  EXPECT_EQ(getGeneralRegister<uint32_t>(0), 0u);
//
//  // 2 - 1 = 1
//  RUN_AARCH64(R"(
//    mov w0, #2
//    subs w0, w0, #1
//  )");
//  EXPECT_EQ(getNZCV(), 0b0010);
//  EXPECT_EQ(getGeneralRegister<uint32_t>(0), 1u);
//
//  // 0 - 1 = -1
//  RUN_AARCH64(R"(
//    mov w0, wzr
//    subs w0, w0, #1
//  )");
//  EXPECT_EQ(getNZCV(), 0b1000);
//  EXPECT_EQ(getGeneralRegister<uint32_t>(0), -1);
//
//  // (2^31 -1) - -1 = 2^31
//  RUN_AARCH64(R"(
//    mov w0, wzr
//    mov w1, #1
//    add w1, w0, w1, lsl #31
//    sub w1, w1, #1
//    sub w2, w0, #1
//    subs w0, w1, w2
//  )");
//  EXPECT_EQ(getNZCV(), 0b1001);
//  EXPECT_EQ(getGeneralRegister<uint32_t>(0), (1ul << 31));
//
//  // 2^31 - 0 = 2^31
//  RUN_AARCH64(R"(
//    mov w0, wzr
//    add w1, w0, #1
//    add w1, w0, w1, lsl #31
//    subs w0, w1, #0
//  )");
//  EXPECT_EQ(getNZCV(), 0b1010);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(0), (1u << 31));
//
//  // 2^31 - 1 = 2^31 - 1
//  RUN_AARCH64(R"(
//    mov w0, wzr
//    add w1, w0, #1
//    add w1, w0, w1, lsl #31
//    subs w0, w1, #1
//  )");
//  EXPECT_EQ(getNZCV(), 0b0011);
//  EXPECT_EQ(getGeneralRegister<uint32_t>(0), (1u << 31) - 1);
//
//  // (7 << 16) - (-1) [8-bit sign-extended]
//  RUN_AARCH64(R"(
//    movz w0, #7, lsl #16
//    movz w1, #15
//    # 255 will be -1 when sign-extended from 8-bits
//    mov w2, 255
//    subs w3, w0, w2, sxtb
//  )");
//  EXPECT_EQ(getNZCV(), 0b0000);
//  EXPECT_EQ(getGeneralRegister<uint32_t>(3), (7u << 16) + 1);
//
//  // (7 << 16) - (255 << 4)
//  RUN_AARCH64(R"(
//    movz w0, #7, lsl #16
//    movz w1, #15
//    mov w2, 255
//    subs w3, w0, w2, uxtx 4
//  )");
//  EXPECT_EQ(getNZCV(), 0b0010);
//  EXPECT_EQ(getGeneralRegister<uint32_t>(3), (7u << 16) - (255u << 4));
//}
//
//// Test that NZCV flags are set correctly by 64-bit subs
//TEST_P(InstArithmetic, subsx) {
//  // 0 - 0 = 0
//  RUN_AARCH64(R"(
//    mov x0, xzr
//    subs x0, x0, #0
//  )");
//  EXPECT_EQ(getNZCV(), 0b0110);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 0u);
//
//  // 2 - 1 = 1
//  RUN_AARCH64(R"(
//    mov x0, #2
//    subs x0, x0, #1
//  )");
//  EXPECT_EQ(getNZCV(), 0b0010);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 1u);
//
//  // 0 - 1 = -1
//  RUN_AARCH64(R"(
//    mov x0, xzr
//    subs x0, x0, #1
//  )");
//  EXPECT_EQ(getNZCV(), 0b1000);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(0), -1);
//
//  // (2^63 -1) - -1 = 2^63
//  RUN_AARCH64(R"(
//    mov x0, xzr
//    add x1, x0, #1
//    add x1, x0, x1, lsl #63
//    sub x1, x1, #1
//    sub x2, x0, #1
//    subs x0, x1, x2
//  )");
//  EXPECT_EQ(getNZCV(), 0b1001);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(0), (1ul << 63));
//
//  // 2^63 - 0 = 2^63
//  RUN_AARCH64(R"(
//    mov x0, xzr
//    add x1, x0, #1
//    add x1, x0, x1, lsl #63
//    subs x0, x1, #0
//  )");
//  EXPECT_EQ(getNZCV(), 0b1010);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(0), (1ul << 63));
//
//  // 2^63 - 1 = 2^63 - 1
//  RUN_AARCH64(R"(
//    mov x0, xzr
//    add x1, x0, #1
//    add x1, x0, x1, lsl #63
//    subs x0, x1, #1
//  )");
//  EXPECT_EQ(getNZCV(), 0b0011);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(0), (1ul << 63) - 1);
//
//  // (7 << 48) - (15 << 33)
//  RUN_AARCH64(R"(
//    movz x0, #7, lsl #48
//    movz x1, #15
//    subs x2, x0, x1, lsl 33
//  )");
//  EXPECT_EQ(getNZCV(), 0b0010);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(2), (7ul << 48) - (15ul << 33));
//
//  // (7 << 48) - (-1) [8-bit sign-extended]
//  RUN_AARCH64(R"(
//    movz x0, #7, lsl #48
//    movz x1, #15
//    # 255 will be -1 when sign-extended from 8-bits
//    mov w2, 255
//    subs x3, x0, w2, sxtb
//  )");
//  EXPECT_EQ(getNZCV(), 0b0000);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(3), (7ul << 48) + 1);
//
//  // (7 << 48) - (255 << 4)
//  RUN_AARCH64(R"(
//    movz x0, #7, lsl #48
//    movz x1, #15
//    mov w2, 255
//    subs x3, x0, x2, uxtx 4
//  )");
//  EXPECT_EQ(getNZCV(), 0b0010);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(3), (7ul << 48) - (255ul << 4));
//}

INSTANTIATE_TEST_SUITE_P(RISCV, InstArithmetic, ::testing::Values(EMULATION, INORDER),
                         coreTypeToString);

}  // namespace
