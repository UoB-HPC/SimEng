#include "RISCVRegressionTest.hh"

namespace {

using InstBranch = RISCVRegressionTest;

TEST_P(InstBranch, BEQ) {
  RUN_RISCV(R"(
      addi t0, t0, 5
      addi t1, t1, 5
      beq t0, t1, 8
      addi t5, t5, 8
      addi t6, t6, 8
      beq zero, t4, 8
      j 16
      addi t4, t4, 7
      beqz s0, -8
      addi t2, t2, 4
      addi t3, t3, 5
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 8);
  EXPECT_EQ(getGeneralRegister<uint64_t>(29), 7);
  EXPECT_EQ(getGeneralRegister<uint64_t>(28), 5);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 0);
}

TEST_P(InstBranch, BNE) {
  RUN_RISCV(R"(
      addi t0, t0, 5
      addi t1, t1, 5
      bne t0, t1, 8
      addi t6, t6, 7
      bne t6, t0, 8
      addi t5, t5, 7
      bnez t0, 4      # Jumps by 8 when 0 register not accounted for in InstructionMetadata.cc
      addi t4, t4, 19
      addi t3, t3, 17
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 7);
  EXPECT_EQ(getGeneralRegister<uint64_t>(29), 19);
  EXPECT_EQ(getGeneralRegister<uint64_t>(28), 17);
}

TEST_P(InstBranch, BLT) {
  RUN_RISCV(R"(
      addi t0, t0, 5
      addi t1, t1, 5
      blt t0, t1, 8
      addi t6, t6, 7
      blt t5, t0, 8
      addi t5, t5, 7
      blt t0, t5, 8
      addi t4, t4, -19
      bltz t4, 8
      addi t3, t3, 17
      addi t2, t2, 17
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 7);
  EXPECT_EQ(getGeneralRegister<uint64_t>(29), -19);
  EXPECT_EQ(getGeneralRegister<uint64_t>(28), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 17);

  RUN_RISCV(R"(
      addi t0, t0, -5
      addi t1, t1, 5
      bgtz t0, 8
      addi t6, t6, 18
      bgtz t1, 8
      addi t5, t5, 14
      bgtz t3, 8
      addi t4, t4, 13
      addi t2, t2, 12
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 18);
  EXPECT_EQ(getGeneralRegister<uint64_t>(29), 13);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 12);

  RUN_RISCV(R"(
      addi t0, t0, -5
      addi t1, t1, 5
      bgt t0, t1, 8       # blt t1, t0, 8
      addi t6, t6, 18
      bgt t1, t0, 8       # blt t0, t1, 8
      addi t5, t5, 14
      bgt t3, t3, 8       # blt t3, t3, 8
      addi t4, t4, 13
      addi t2, t2, 12
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 18);
  EXPECT_EQ(getGeneralRegister<uint64_t>(29), 13);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 12);
}

TEST_P(InstBranch, BLTU) {
  RUN_RISCV(R"(
      addi t0, t0, -5
      addi t1, t1, 5
      bltu t0, t1, 8
      addi t6, t6, 7
      bltu t1, t0, 8
      addi t5, t5, 7
      bgtu t1, t0, 8   # bltu t0, t1, 8
      addi t4, t4, 16
      addi t3, t3, 15
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 7);
  EXPECT_EQ(getGeneralRegister<uint64_t>(29), 16);
  EXPECT_EQ(getGeneralRegister<uint64_t>(28), 15);
}

TEST_P(InstBranch, BGE) {
  RUN_RISCV(R"(
      addi t0, t0, 5
      addi t1, t1, 5
      bge t0, t1, 8
      addi t6, t6, 17
      addi t0, t0, 1
      bge t1, t0, 8
      addi t5, t5, 17
      bge t0, t1, 8
      addi t4, t4, 16
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 17);
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(29), 0);

  RUN_RISCV(R"(
      addi t0, t0, -5
      addi t1, t1, 5
      blez t0, 8
      addi t6, t6, 18
      blez t1, 8
      addi t5, t5, 14
      blez t3, 8
      addi t4, t4, 13
      addi t2, t2, 12
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 14);
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(29), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 12);

  RUN_RISCV(R"(
      addi t0, t0, -5
      addi t1, t1, 5
      bgez t0, 8
      addi t6, t6, 18
      bgez t1, 8
      addi t5, t5, 14
      bgez t3, 8
      addi t4, t4, 13
      addi t2, t2, 12
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 18);
  EXPECT_EQ(getGeneralRegister<uint64_t>(29), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 12);

  RUN_RISCV(R"(
      addi t0, t0, -5
      addi t1, t1, 5
      ble t1, t0, 8     # bge t0, t1, 8
      addi t6, t6, 18
      ble t0, t1, 8     # bge t1, t0, 8
      addi t5, t5, 14
      ble t3, t3, 8     # bge t3, t3, 8
      addi t4, t4, 13
      addi t2, t2, 12
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 18);
  EXPECT_EQ(getGeneralRegister<uint64_t>(29), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 12);
}

TEST_P(InstBranch, BGEU) {
  RUN_RISCV(R"(
      addi t0, t0, -5
      addi t1, t1, 5
      bgeu t0, t1, 8
      addi t6, t6, 17
      addi t3, t3, 14
      bgeu t1, t0, 8
      addi t5, t5, 17
      bgeu t0, t0, 8
      addi t4, t4, 16
      addi t2, t2, 11
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 17);
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(29), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(28), 14);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 11);

  RUN_RISCV(R"(
      addi t0, t0, -5
      addi t1, t1, 5
      bleu t1, t0, 8     # bgeu t0, t1, 8
      addi t6, t6, 18
      bleu t0, t1, 8     # bgeu t1, t0, 8
      addi t5, t5, 14
      bleu t3, t3, 8     # bgeu t3, t3, 8
      addi t4, t4, 13
      addi t2, t2, 12
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 14);
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(29), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 12);
}

INSTANTIATE_TEST_SUITE_P(RISCV, InstBranch,
                         ::testing::Values(EMULATION, INORDER),
                         coreTypeToString);

}  // namespace
