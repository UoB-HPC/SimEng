#include "RISCVRegressionTest.hh"

namespace {

using InstCompressed = RISCVRegressionTest;
using namespace simeng::arch::riscv::InstructionGroups;

TEST_P(InstCompressed, lwsp) {
  //  Load word from mem[stack pointer + imm]
  initialHeapData_.resize(16);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0xDEADBEEF;
  heap[1] = 0x12345678;
  heap[2] = 0xFEEBDAED;
  heap[3] = 0x87654321;

  RUN_RISCV_COMP(R"(
      li a7, 214
      ecall

      li x2, 0
      add x2, x2, a0
      c.lwsp t6, 0(x2)
      c.lwsp t4, 4(x2)
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 0xFFFFFFFFDEADBEEF);
  EXPECT_EQ(getGeneralRegister<uint64_t>(29), 0x0000000012345678);

  EXPECT_GROUP_COMP(R"(c.lwsp t4, 4(x2))", LOAD_INT);
}

TEST_P(InstCompressed, ldsp) {
  //  Load double word from mem[stack pointer + imm]
  initialHeapData_.resize(16);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0xDEADBEEF;
  heap[1] = 0x12345678;
  heap[2] = 0xFEEBDAED;
  heap[3] = 0x87654321;

  RUN_RISCV_COMP(R"(
      li a7, 214
      ecall

      li x2, 0
      add x2, x2, a0
      c.ldsp t6, 0(x2)
      addi x2, x2, -4
      c.ldsp t4, 8(x2)
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 0x12345678DEADBEEF);
  EXPECT_EQ(getGeneralRegister<uint64_t>(29), 0xFEEBDAED12345678);

  EXPECT_GROUP_COMP(R"(c.ldsp t4, 8(x2))", LOAD_INT);
}

TEST_P(InstCompressed, fldsp) {
  //  Load double precision float from mem[stack pointer + imm]
  initialHeapData_.resize(32);
  double* heap = reinterpret_cast<double*>(initialHeapData_.data());
  heap[0] = 1.0;
  heap[1] = 123.456;
  heap[2] = -0.00032;
  heap[3] = 123456;

  RUN_RISCV_COMP(R"(
    # Get heap address
    li a7, 214
    ecall

    li x2, 0
    add x2, x2, a0
    c.fldsp ft0, 0(x2)
    c.fldsp ft1, 8(x2)
    c.fldsp ft2, 16(x2)
    c.fldsp ft3, 24(x2)
  )");

  EXPECT_EQ(getFPRegister<double>(0), 1.0);
  EXPECT_EQ(getFPRegister<double>(1), 123.456);
  EXPECT_EQ(getFPRegister<double>(2), -0.00032);
  EXPECT_EQ(getFPRegister<double>(3), 123456);

  EXPECT_GROUP_COMP(R"(c.fldsp ft3, 24(x2))", LOAD_FLOAT);
}

TEST_P(InstCompressed, swsp) {
  //  Store word at mem[stack pointer + imm]
  RUN_RISCV_COMP(R"(
      li t6, 0xAA
      c.swsp t6, 0(sp)

      addi t6, t6, 0xAA  # 0xAA + 0xAA = 154
      slli t6, t6, 16
      addi t6, t6, 0xAA  # 0x15400AA
      c.swsp t6, 4(sp)
  )");
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getInitialStackPointer()),
            0x000000AA);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialStackPointer()),
            0x15400AA000000AA);

  EXPECT_GROUP_COMP(R"(c.swsp t6, 4(sp))", STORE_INT);
}

TEST_P(InstCompressed, sdsp) {
  //  Store double word at mem[stack pointer + imm]
  RUN_RISCV_COMP(R"(
      li t6, 0xAA
      c.sdsp t6, 0(sp)

      addi t6, t6, 0xAA  # 0xAA + 0xAA = 154
      slli t6, t6, 16
      addi t6, t6, 0xAA  # 0x15400AA
      c.sdsp t6, 8(sp)
  )");
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialStackPointer()),
            0x00000000000000AA);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialStackPointer() + 8),
            0x00000000015400AA);

  EXPECT_GROUP_COMP(R"(c.sdsp t6, 8(sp))", STORE_INT);
}

TEST_P(InstCompressed, fsdsp) {
  //  Store double precision float at mem[stack pointer + imm]
  RUN_RISCV_COMP(R"(
      li t6, 0xAA
      fmv.d.x f8, t6
      c.fsdsp f8, 0(sp)

      addi t6, t6, 0xAA  # 0xAA + 0xAA = 154
      slli t6, t6, 16
      addi t6, t6, 0xAA  # 0x15400AA
      fmv.d.x f8, t6
      c.fsdsp f8, 8(sp)
  )");
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialStackPointer()),
            0x00000000000000AA);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialStackPointer() + 8),
            0x00000000015400AA);

  EXPECT_GROUP_COMP(R"(c.fsdsp f8, 8(sp))", STORE_FLOAT);
}

TEST_P(InstCompressed, lw) {
  // Compressed load word
  initialHeapData_.resize(16);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0xDEADBEEF;
  heap[1] = 0x12345678;
  heap[2] = 0xFEEBDAED;
  heap[3] = 0x87654321;

  RUN_RISCV_COMP(R"(
      li a7, 214
      ecall

      add x8, x8, a0
      c.lw x15, 0(x8)
      c.lw x13, 4(x8)
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(15), 0xFFFFFFFFDEADBEEF);
  EXPECT_EQ(getGeneralRegister<uint64_t>(13), 0x0000000012345678);

  EXPECT_GROUP_COMP(R"(c.lw x13, 4(x8))", LOAD_INT);
}

TEST_P(InstCompressed, ld) {
  // Compressed store word
  initialHeapData_.resize(16);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0xDEADBEEF;
  heap[1] = 0x12345678;
  heap[2] = 0xFEEBDAED;
  heap[3] = 0x87654321;

  RUN_RISCV_COMP(R"(
      li a7, 214
      ecall

      add x8, x8, a0
      c.ld x15, 0(x8)
      addi x8, x8, -4
      c.ld x13, 8(x8)
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(15), 0x12345678DEADBEEF);
  EXPECT_EQ(getGeneralRegister<uint64_t>(13), 0xFEEBDAED12345678);

  EXPECT_GROUP_COMP(R"(c.ld x13, 8(x8))", LOAD_INT);
}

TEST_P(InstCompressed, fld) {
  // Compressed load double precision float
  initialHeapData_.resize(32);
  double* heap = reinterpret_cast<double*>(initialHeapData_.data());
  heap[0] = 1.0;
  heap[1] = 123.456;
  heap[2] = -0.00032;
  heap[3] = 123456;

  RUN_RISCV_COMP(R"(
    # Get heap address
    li a7, 214
    ecall

    c.fld f8, 0(a0)
    c.fld f9, 8(a0)
    c.fld f10, 16(a0)
    c.fld f11, 24(a0)
  )");

  EXPECT_EQ(getFPRegister<double>(8), 1.0);
  EXPECT_EQ(getFPRegister<double>(9), 123.456);
  EXPECT_EQ(getFPRegister<double>(10), -0.00032);
  EXPECT_EQ(getFPRegister<double>(11), 123456);

  EXPECT_GROUP_COMP(R"(c.fld f11, 24(a0))", LOAD_FLOAT);
}

TEST_P(InstCompressed, sw) {
  // Compressed store word
  initialHeapData_.resize(16);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0x12345678;
  heap[1] = 0xDEADBEEF;
  heap[2] = 0x87654321;

  RUN_RISCV_COMP(R"(
      # Get heap address
      li a7, 214
      ecall

      li x8, 0xAA
      c.sw x8, 0(a0)

      addi x8, x8, 0xAA  # 0xAA + 0xAA = 154
      slli x8, x8, 16
      addi x8, x8, 0xAA  # 0x15400AA
      c.sw x8, 4(a0)
  )");

  EXPECT_EQ(getGeneralRegister<uint64_t>(10), 32);
  EXPECT_EQ(getMemoryValue<uint64_t>(32), 0x015400AA000000AA);
  EXPECT_EQ(getMemoryValue<uint64_t>(36), 0x87654321015400AA);

  EXPECT_GROUP_COMP(R"(c.sw x8, 4(a0))", STORE_INT);
}

TEST_P(InstCompressed, sd) {
  // Compressed store double word
  initialHeapData_.resize(16);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0x12345678;
  heap[1] = 0xDEADBEEF;
  heap[2] = 0x87654321;

  RUN_RISCV_COMP(R"(
      # Get heap address
      li a7, 214
      ecall

      li x8, 0xAA
      c.sd x8, 0(a0)

      addi x8, x8, 0xAA  # 0xAA + 0xAA = 154
      slli x8, x8, 16
      addi x8, x8, 0xAA  # 0x15400AA
      c.sd x8, 8(a0)
  )");

  EXPECT_EQ(getGeneralRegister<uint64_t>(10), 32);
  EXPECT_EQ(getMemoryValue<uint64_t>(32), 0x00000000000000AA);
  EXPECT_EQ(getMemoryValue<uint64_t>(40), 0x00000000015400AA);

  EXPECT_GROUP_COMP(R"(c.sd x8, 8(a0))", STORE_INT);
}

TEST_P(InstCompressed, fsd) {
  // Compressed store double precision float
  initialHeapData_.resize(32);
  double* heap = reinterpret_cast<double*>(initialHeapData_.data());
  heap[0] = 1.0;
  heap[1] = 123.456;
  heap[2] = -0.00032;
  heap[3] = 123456;

  RUN_RISCV_COMP(R"(
     # Get heap address
     li a7, 214
     ecall

     fld fa0, 0(a0)
     fld fa1, 8(a0)
     fld fa2, 16(a0)
     fld fa3, 24(a0)

     c.fsd fa3, 0(a0)
     c.fsd fa2, 8(a0)
     c.fsd fa1, 16(a0)
     c.fsd fa0, 24(a0)
   )");

  EXPECT_EQ(getFPRegister<double>(10), 1.0);
  EXPECT_EQ(getFPRegister<double>(11), 123.456);
  EXPECT_EQ(getFPRegister<double>(12), -0.00032);
  EXPECT_EQ(getFPRegister<double>(13), 123456);

  EXPECT_EQ(getGeneralRegister<uint64_t>(10), 32);

  EXPECT_EQ(getMemoryValue<double>(32), 123456);
  EXPECT_EQ(getMemoryValue<double>(40), -0.00032);
  EXPECT_EQ(getMemoryValue<double>(48), 123.456);
  EXPECT_EQ(getMemoryValue<double>(56), 1.0);

  EXPECT_GROUP_COMP(R"(c.fsd fa3, 0(a0))", STORE_FLOAT);
}

TEST_P(InstCompressed, j) {
  // Compressed jump
  // Labels needed as LLVM eagerly uses compressed instructions e.g. addi ->
  // c.addi causing manual jump offsets to become seemingly misaligned with the
  // values used in the tests
  RUN_RISCV_COMP(R"(
    c.j jump              #c.j 0xc
    jumpa:
    addi t6, t6, 10
    jal t1, jumpc        #jal t1, 0xc
    jump:
    addi t5, t5, 5
    jal jumpa           #jal -0xc
    jumpc:
    addi t4, t4, 3
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 5);
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 10);
  EXPECT_EQ(getGeneralRegister<uint64_t>(29), 3);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 8);
  EXPECT_EQ(getGeneralRegister<uint64_t>(1), 14);
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 0);

  EXPECT_GROUP_COMP(R"(c.j jump)", BRANCH);
}

TEST_P(InstCompressed, jr) {
  // Compressed jump to address in register
  RUN_RISCV_COMP(R"(
    c.addi x9, 8
    c.jr x9
    c.addi x8, 4
    c.j end
    c.addi x8, 5
    end:
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(8), 5);

  EXPECT_GROUP_COMP(R"(c.jr x9)", BRANCH);
}

TEST_P(InstCompressed, jalr) {
  // Compressed jump to address in rs1, save pc+2 in link register
  RUN_RISCV_COMP(R"(
    li x8, 12
    c.jalr x8
    mv t0, ra
    addi t6, t6, 10
    li x8, 20
    c.jalr x8
    mv t1, ra
    addi t5, t5, 5
    li x8, 4
    c.jalr x8
    mv t2, ra
    addi t4, t4, 3
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 5);
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 10);
  EXPECT_EQ(getGeneralRegister<uint64_t>(29), 3);
  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 20);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 4);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 12);
  EXPECT_EQ(getGeneralRegister<uint64_t>(1), 12);

  EXPECT_GROUP_COMP(R"(c.jalr x8)", BRANCH);
}

TEST_P(InstCompressed, beqz) {
  // Compressed branch if rs1 equal to zero
  RUN_RISCV_COMP(R"(
    addi x8, x8, 2
    c.beqz x8, b1
    addi x10, x10, 10
    li x9, 0
    c.beqz x9, b2
    j b3
    b1:
    addi x10, x10, 5
    b2:
    addi x11, x11, 10
    j b4
    b3:
    addi x11, x11, 5
    b4:
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(10), 10);
  EXPECT_EQ(getGeneralRegister<uint64_t>(11), 10);

  EXPECT_GROUP_COMP(R"(c.beqz x9, b2)", BRANCH);
}

TEST_P(InstCompressed, bnez) {
  // Compressed branch if rs1 not equal to zero
  RUN_RISCV_COMP(R"(
    addi x8, x8, 0
    c.bnez x8, b1
    addi x10, x10, 10
    li x9, 2
    c.bnez x9, b2
    j b3
    b1:
    addi x10, x10, 5
    b2:
    addi x11, x11, 10
    j b4
    b3:
    addi x11, x11, 5
    b4:
  )");

  EXPECT_GROUP_COMP(R"(c.bnez x9, b2)", BRANCH);
}

TEST_P(InstCompressed, li) {
  // Compressed load immediate
  RUN_RISCV_COMP(R"(
    addi a5, a5, 12
    c.li a5, 0
    addi a4, a4, 12
    c.li a4, -32
    addi a3, a3, 12
    c.li a3, 31
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(15), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(14), -32);
  EXPECT_EQ(getGeneralRegister<int64_t>(13), 31);

  EXPECT_GROUP_COMP(R"(c.li a3, 31)", INT_SIMPLE_ARTH);
}

TEST_P(InstCompressed, lui) {
  // Compressed load immediate into bits 17-12, clear bottom 12 and sign extend
  // high bits
  RUN_RISCV_COMP(R"(
      c.lui t3, 4
      c.lui t4, 0xFFFFC
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(28), 4 << 12);
  EXPECT_EQ(getGeneralRegister<uint64_t>(29), -4ull << 12);

  EXPECT_GROUP_COMP(R"(c.lui t4, 0xFFFFC)", INT_SIMPLE_ARTH);
}

TEST_P(InstCompressed, addi) {
  // Compressed add immediate
  RUN_RISCV_COMP(R"(
    c.addi t3, 3
    c.addi t4, 6
    c.addi t3, 30
    c.addi zero, 16
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(29), 6u);
  EXPECT_EQ(getGeneralRegister<uint64_t>(28), 33u);
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 0);

  EXPECT_GROUP_COMP(R"(c.addi zero, 16)", INT_SIMPLE_ARTH);
}

TEST_P(InstCompressed, addiw) {
  // Compressed add immediate. Produces 32 bit result and sign extends
  RUN_RISCV_COMP(R"(
    addi t3, t3, 91
    slli t3, t3, 28
    addiw t5, t3, -5
    addiw t6, t2, -5
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(28), 24427626496);
  EXPECT_EQ(getGeneralRegister<int32_t>(30), -1342177285);
  EXPECT_EQ(getGeneralRegister<int64_t>(31), -5);

  EXPECT_GROUP_COMP(R"(addiw t6, t2, -5)", INT_SIMPLE_ARTH);
}

TEST_P(InstCompressed, addi16sp) {
  // Add immediate (multiple of 16) to stack pointer
  RUN_RISCV_COMP(R"(
    mv x8, sp
    c.addi16sp x2, 16
    mv x9, x2
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(8),
            process_->getInitialStackPointer());
  EXPECT_EQ(getGeneralRegister<uint64_t>(9),
            process_->getInitialStackPointer() + 16);

  EXPECT_GROUP_COMP(R"(mv x9, x2)", INT_SIMPLE_ARTH);
}

TEST_P(InstCompressed, addi4spn) {
  // Add immediate to stack pointer
  RUN_RISCV_COMP(R"(
    c.addi4spn x8, x2, 4
    c.addi4spn x9, x2, 12
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(8),
            process_->getInitialStackPointer() + 4);
  EXPECT_EQ(getGeneralRegister<uint64_t>(9),
            process_->getInitialStackPointer() + 12);

  EXPECT_GROUP_COMP(R"(c.addi4spn x9, x2, 12)", INT_SIMPLE_ARTH);
}

TEST_P(InstCompressed, slli) {
  // Compressed shift left logical by immediate. rs1 = rd
  RUN_RISCV_COMP(R"(
      addi t4, t4, 6
      c.slli t4, 5
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(29), 192);

  EXPECT_GROUP_COMP(R"(c.slli t4, 5)", INT_SIMPLE_SHIFT);
}

TEST_P(InstCompressed, srli) {
  // Compressed shift right logical by immediate. rs1 = rd
  RUN_RISCV_COMP(R"(
      addi x8, x8, -4
      c.srli x8, 61
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(8), 7);

  EXPECT_GROUP_COMP(R"(c.srli x8, 61)", INT_SIMPLE_SHIFT);
}

TEST_P(InstCompressed, srai) {
  // Compressed shift right arithmetic by immediate. rs1 = rd
  RUN_RISCV_COMP(R"(
    addi x8, x8, -4
    add t0, t0, x8
    c.srai x8, 1
    addi x9, t0, 8
    c.srai x9, 1
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(8), -2);
  EXPECT_EQ(getGeneralRegister<uint64_t>(9), 2);

  EXPECT_GROUP_COMP(R"(c.srai x9, 1)", INT_SIMPLE_SHIFT);
}

TEST_P(InstCompressed, andi) {
  // Compressed AND with sign extended immediate. rs1 = rd
  RUN_RISCV_COMP(R"(
    addi x9, x9, 3
    addi t4, t4, 5
    and x8, x9, t4
    c.andi x8, 9
    c.andi x9, -7
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(8), 0b0001);
  EXPECT_EQ(getGeneralRegister<uint64_t>(9), 1);

  EXPECT_GROUP_COMP(R"(c.andi x9, -7)", INT_SIMPLE_LOGICAL);
}

TEST_P(InstCompressed, mv) {
  // Compressed move
  RUN_RISCV_COMP(R"(
     addi x8, x8, 3
     addi x9, x9, 6
     c.mv x8, x9
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(8), 6u);
  EXPECT_EQ(getGeneralRegister<uint64_t>(9), 6u);

  EXPECT_GROUP_COMP(R"(c.mv x8, x9)", INT_SIMPLE_ARTH);
}

TEST_P(InstCompressed, add) {
  // Compressed add. rs1 = rd
  RUN_RISCV_COMP(R"(
     addi x8, x8, 3
     addi x9, x9, 6
     c.add x8, x9
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(8), 9u);
  EXPECT_EQ(getGeneralRegister<uint64_t>(9), 6u);

  EXPECT_GROUP_COMP(R"(c.add x8, x9)", INT_SIMPLE_ARTH);
}

TEST_P(InstCompressed, and) {
  // Compressed AND. rs1 = rd
  RUN_RISCV_COMP(R"(
    addi x8, x8, 3
    addi x9, x9, 5
    c.and x8, x9
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(8), 0b0001);

  EXPECT_GROUP_COMP(R"(c.and x8, x9)", INT_SIMPLE_LOGICAL);
}

TEST_P(InstCompressed, or) {
  // Compressed OR. rs1 = rd
  RUN_RISCV_COMP(R"(
    addi x8, x8, 3
    addi x9, x9, 5
    c.or x8, x9
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(8), 0b0111);

  EXPECT_GROUP_COMP(R"(c.or x8, x9)", INT_SIMPLE_LOGICAL);
}

TEST_P(InstCompressed, xor) {
  // Compressed XOR. rs1 = rd
  RUN_RISCV_COMP(R"(
    addi x8, x8, 3
    addi x9, x9, 5
    c.xor x8, x9
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(8), 0b0110);

  EXPECT_GROUP_COMP(R"(c.xor x8, x9)", INT_SIMPLE_LOGICAL);
}

TEST_P(InstCompressed, sub) {
  // Compressed subtract. rs1 = rd
  RUN_RISCV_COMP(R"(
    addi x8, x8, 3
    addi x9, x9, 6
    mv x10, x8
    c.sub x8, x9
    c.sub x9, x10
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(8), -3);
  EXPECT_EQ(getGeneralRegister<uint64_t>(9), 3);

  EXPECT_GROUP_COMP(R"(c.sub x9, x10)", INT_SIMPLE_ARTH);
}

TEST_P(InstCompressed, addw) {
  // Compressed add word. Adds rd and rs2 then sign extends lower 32 bits. rs1 =
  // rd
  RUN_RISCV_COMP(R"(
    addi x9, x9, -7
    addi x8, x8, 3
    mv x11, x8
    addi x10, x10, 6
    c.addw x8, x10
    c.addw x9, x11
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(8), 9u);
  EXPECT_EQ(getGeneralRegister<uint64_t>(9), -4);

  EXPECT_GROUP_COMP(R"(c.addw x9, x11)", INT_SIMPLE_ARTH);
}

TEST_P(InstCompressed, subw) {
  // Compressed subtract word. Subtracts rs2 from rd then sign extends lower 32
  // bits. rs1 = rd
  RUN_RISCV_COMP(R"(
    addi x9, x9, 3
    addi x10, x10, 6
    mv x11, x10
    mv x12, x9
    c.subw x9, x10
    c.subw x10, x12

    li x12, -1
    addi x11, x11, -8
    c.subw x12, x11
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(9), -3);
  EXPECT_EQ(getGeneralRegister<uint64_t>(10), 3);

  EXPECT_EQ(getGeneralRegister<uint64_t>(11), -2);
  EXPECT_EQ(getGeneralRegister<uint64_t>(12), 0x0000000000000001);

  EXPECT_GROUP_COMP(R"(c.subw x12, x11)", INT_SIMPLE_ARTH);
}

TEST_P(InstCompressed, nop) {
  // Ensure that a nop doesn't change the state of the processor
  // Load a register and check initial architectural state
  RUN_RISCV_COMP(R"(
    li x8, 1234
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(1), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(2),
            process_->getInitialStackPointer());
  EXPECT_EQ(getGeneralRegister<uint64_t>(3), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(4), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(8), 1234);
  EXPECT_EQ(getGeneralRegister<uint64_t>(9), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(10), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(11), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(12), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(13), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(14), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(15), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(16), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(17), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(18), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(19), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(20), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(21), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(22), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(23), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(24), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(25), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(26), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(27), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(28), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(29), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 0);
  EXPECT_EQ(numTicks_, 2);  // 1 insn + 1 for unimplemented final insn

  numTicks_ = 0;

  // Run some no operations
  RUN_RISCV_COMP(R"(
    c.nop
    c.nop
    c.nop
    c.nop
    c.nop
  )");

  // Ensure state hasn't changed except the number of ticks
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(1), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(2),
            process_->getInitialStackPointer());
  EXPECT_EQ(getGeneralRegister<uint64_t>(3), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(4), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(8), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(9), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(10), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(11), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(12), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(13), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(14), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(15), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(16), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(17), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(18), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(19), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(20), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(21), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(22), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(23), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(24), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(25), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(26), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(27), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(28), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(29), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 0);
  EXPECT_EQ(numTicks_, 6);  // 5 insns + 1 for unimplemented final insn

  EXPECT_GROUP_COMP(R"(c.nop)", INT_SIMPLE_ARTH);
}

TEST_P(InstCompressed, ebreak) {
  // Currently not implemented so ensure this produces an exception

  RUN_RISCV_COMP(R"(
    c.ebreak
  )");

  const char err1[] =
      "\n[SimEng:ExceptionHandler] Encountered execution not-yet-implemented "
      "exception\n[SimEng:ExceptionHandler]  Generated by instruction: "
      "\n[SimEng:ExceptionHandler]    0x0000000000000000: 02 90     c.ebreak";
  EXPECT_EQ(stdout_.substr(0, sizeof(err1) - 1), err1);

  EXPECT_GROUP_COMP(R"(c.ebreak)", INT_SIMPLE_ARTH);
}

INSTANTIATE_TEST_SUITE_P(
    RISCV, InstCompressed,
    ::testing::Values(std::make_tuple(EMULATION, "{Core: {Compressed: True}}")),
    paramToString);

}  // namespace
