#include "RISCVRegressionTest.hh"

namespace {

using SmokeTest = RISCVRegressionTest;

// Test that a trivial instruction will execute
TEST_P(SmokeTest, instruction) {
  RUN_RISCV(R"(
    addi a5,a5,32
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(15), 32u);
}

TEST_P(SmokeTest, sll) {
  RUN_RISCV(R"(
      addi t3, t3, 3
      addi t4, t4, 6
      sll t5, t4, t3
      slli t6, t4, 5
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 48);
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 192);
}

TEST_P(SmokeTest, sllw) {
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

TEST_P(SmokeTest, srl) {
  RUN_RISCV(R"(
      addi t3, t3, 60
      addi t4, t4, -4
      srl t5, t4, t3
      srli t6, t4, 61
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 15);
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 7);
}

TEST_P(SmokeTest, srlw) {
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

TEST_P(SmokeTest, sra) {
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

TEST_P(SmokeTest, sraw) {
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

TEST_P(SmokeTest, add) {
  RUN_RISCV(R"(
      addi t3, t3, 3
      addi t4, t4, 6
      add t5, t3, t4
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(28), 3u);
  EXPECT_EQ(getGeneralRegister<uint64_t>(29), 6u);
  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 9u);
}

TEST_P(SmokeTest, addw) {
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

TEST_P(SmokeTest, sub) {
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

TEST_P(SmokeTest, xor) {
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

TEST_P(SmokeTest, or) {
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

TEST_P(SmokeTest, and) {
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

TEST_P(SmokeTest, slt) {
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

TEST_P(SmokeTest, slti) {
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

//
//// Test a loop executing 1024 times, adding 3 to w1 each time
//TEST_P(SmokeTest, loop) {
//  RUN_AARCH64(R"(
//    orr w0, wzr, #1024
//    mov w1, wzr
//    add w1, w1, #3
//    subs w0, w0, #1
//    b.ne -8
//  )");
//  EXPECT_TRUE(getZeroFlag());
//  EXPECT_EQ(getGeneralRegister<uint32_t>(0), 0u);
//  EXPECT_EQ(getGeneralRegister<uint32_t>(1), 1024 * 3u);
//}
//
//// Test that we can store values to the stack
//TEST_P(SmokeTest, stack) {
//  RUN_AARCH64(R"(
//    mov w0, #7
//    mov w1, #42
//    str w0, [sp, -4]
//    str w1, [sp, -8]
//  )");
//  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() - 4), 7u);
//  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() - 8), 42u);
//}
//
//// Test that we can store values to the heap
//TEST_P(SmokeTest, heap) {
//  RUN_AARCH64(R"(
//    # Use brk syscall to move program brk by eight bytes
//    mov w0, 0
//    mov w8, 214
//    svc #0
//    add w0, w0, 8
//    svc #0
//    # Write a couple of values into the allocated region
//    mov w1, #7
//    mov w2, #42
//    str w1, [x0, -8]
//    str w2, [x0, -4]
//  )");
//  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getHeapStart()), 7u);
//  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getHeapStart() + 4), 42u);
//}
//
INSTANTIATE_TEST_SUITE_P(RISCV, SmokeTest,
                         ::testing::Values(EMULATION, INORDER),
                         coreTypeToString);

}  // namespace
