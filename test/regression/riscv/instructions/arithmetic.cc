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
  //  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 0); // TODO check if > 32 shamt
  //  allowed
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
  EXPECT_EQ(getGeneralRegister<uint64_t>(6),
            0b01111111111111111111111111111100);
  EXPECT_EQ(getGeneralRegister<uint64_t>(31),
            0b01111111111111111111111111111100);
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
      li t2, 31
      sraw t5, t5, t2

      li t2, 30
      slli t6, t4, 30
      sraw t6, t6, t2
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(30), -1);
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 1);

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
}

TEST_P(InstArithmetic, subw) {
  RUN_RISCV(R"(
    addi t3, t3, 3
    addi t4, t4, 6
    subw t5, t3, t4
    subw t6, t4, t3

    li t3, -1
    addi t4, t4, -8
    subw t1, t3, t4

  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(30), -3);
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 3);

  EXPECT_EQ(getGeneralRegister<uint64_t>(28), 0xFFFFFFFFFFFFFFFF);
  EXPECT_EQ(getGeneralRegister<uint64_t>(29), -2);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0x0000000000000001);
}

TEST_P(InstArithmetic, lui) {
  RUN_RISCV(R"(
      lui t3, 4
      lui t4, 0xFFFFC
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(28), 4 << 12);
  EXPECT_EQ(getGeneralRegister<uint64_t>(29), -4ull << 12);
}

TEST_P(InstArithmetic, auipc) {
  RUN_RISCV(R"(
      auipc t3, 4
      auipc t4, 1048572
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(28), 4 << 12);
  EXPECT_EQ(getGeneralRegister<uint64_t>(29), (-4ull << 12) + 4);
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
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), -4);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), -6);

  RUN_RISCV(R"(
      addi t3, t3, 3
      not t1, t3
    )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), -4);
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

TEST_P(InstArithmetic, liPseudoinstruction) {
  RUN_RISCV(R"(
      addi a5, a5, 12
      li a5, 0
      addi a4, a4, 12
      li a4, 192
      addi a3, a3, 12
      li a3, -180
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(15), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(14), 192);
  EXPECT_EQ(getGeneralRegister<int64_t>(13), -180);
}

INSTANTIATE_TEST_SUITE_P(RISCV, InstArithmetic,
                         ::testing::Values(EMULATION, INORDER),
                         coreTypeToString);

}  // namespace
