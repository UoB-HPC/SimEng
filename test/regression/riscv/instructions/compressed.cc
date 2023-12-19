#include "RISCVRegressionTest.hh"

namespace {

using InstCompressed = RISCVRegressionTest;

TEST_P(InstCompressed, lwsp) {
  initialHeapData_.resize(16);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0xDEADBEEF;
  heap[1] = 0x12345678;
  heap[2] = 0xFEEBDAED;
  heap[3] = 0x87654321;

  RUN_RISCV(R"(
      li a7, 214
      ecall

      li x2, 0
      add x2, x2, a0
      c.lwsp t6, 0(x2)
      c.lwsp t4, 4(x2)
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 0xFFFFFFFFDEADBEEF);
  EXPECT_EQ(getGeneralRegister<uint64_t>(29), 0x0000000012345678);
}

TEST_P(InstCompressed, ldsp) {
  initialHeapData_.resize(16);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0xDEADBEEF;
  heap[1] = 0x12345678;
  heap[2] = 0xFEEBDAED;
  heap[3] = 0x87654321;

  RUN_RISCV(R"(
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
}

TEST_P(InstCompressed, flwsp) {
  initialHeapData_.resize(32);
  double* heap = reinterpret_cast<double*>(initialHeapData_.data());
  heap[0] = 1.0;
  heap[1] = 123.456;
  heap[2] = -0.00032;
  heap[3] = 123456;

  RUN_RISCV(R"(
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
}

TEST_P(InstCompressed, swsp) {
  RUN_RISCV(R"(
      li t6, 0xAA
      c.swsp t6, 0(sp)

      addi t6, t6, 0xAA  # 0xAA + 0xAA = 154
      slli t6, t6, 16
      addi t6, t6, 0xAA  # 0x15400AA
      c.swsp t6, 4(sp)
  )");
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer()), 0x000000AA);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer()), 0x15400AA000000AA);
}

TEST_P(InstCompressed, sdsp) {
  RUN_RISCV(R"(
      li t6, 0xAA
      c.sdsp t6, 0(sp)

      addi t6, t6, 0xAA  # 0xAA + 0xAA = 154
      slli t6, t6, 16
      addi t6, t6, 0xAA  # 0x15400AA
      c.sdsp t6, 8(sp)
  )");
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer()), 0x00000000000000AA);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() + 8), 0x00000000015400AA);
}

TEST_P(InstCompressed, fsdsp) {
  RUN_RISCV(R"(
      li t6, 0xAA
      fmv.d.x f8, t6
      c.fsdsp f8, 0(sp)

      addi t6, t6, 0xAA  # 0xAA + 0xAA = 154
      slli t6, t6, 16
      addi t6, t6, 0xAA  # 0x15400AA
      fmv.d.x f8, t6
      c.fsdsp f8, 8(sp)
  )");
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer()), 0x00000000000000AA);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() + 8), 0x00000000015400AA);
}

TEST_P(InstCompressed, lw) {
  initialHeapData_.resize(16);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0xDEADBEEF;
  heap[1] = 0x12345678;
  heap[2] = 0xFEEBDAED;
  heap[3] = 0x87654321;

  RUN_RISCV(R"(
      li a7, 214
      ecall

      add x8, x8, a0
      c.lw x15, 0(x8)
      c.lw x13, 4(x8)
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(15), 0xFFFFFFFFDEADBEEF);
  EXPECT_EQ(getGeneralRegister<uint64_t>(13), 0x0000000012345678);
}

TEST_P(InstCompressed, ld) {
  initialHeapData_.resize(16);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0xDEADBEEF;
  heap[1] = 0x12345678;
  heap[2] = 0xFEEBDAED;
  heap[3] = 0x87654321;

  RUN_RISCV(R"(
      li a7, 214
      ecall

      add x8, x8, a0
      c.ld x15, 0(x8)
      addi x8, x8, -4
      c.ld x13, 8(x8)
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(15), 0x12345678DEADBEEF);
  EXPECT_EQ(getGeneralRegister<uint64_t>(13), 0xFEEBDAED12345678);
}

TEST_P(InstCompressed, fld) {
  initialHeapData_.resize(32);
  double* heap = reinterpret_cast<double*>(initialHeapData_.data());
  heap[0] = 1.0;
  heap[1] = 123.456;
  heap[2] = -0.00032;
  heap[3] = 123456;

  RUN_RISCV(R"(
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
}

TEST_P(InstCompressed, addi4spn) {
  RUN_RISCV(R"(
    c.addi4spn
  )");
}


TEST_P(InstCompressed, sw) {
  RUN_RISCV(R"(
    c.sw
  )");
}


TEST_P(InstCompressed, sd) {
  RUN_RISCV(R"(
    c.sd
  )");
}


TEST_P(InstCompressed, fsd) {
  RUN_RISCV(R"(
    c.fsd
  )");
}


TEST_P(InstCompressed, j) {
  RUN_RISCV(R"(
    c.j
  )");
}

TEST_P(InstCompressed, jalr) {
  RUN_RISCV(R"(
    c.jalr
  )");
}


TEST_P(InstCompressed, beqz) {
  RUN_RISCV(R"(
    c.beqz
  )");
}


TEST_P(InstCompressed, bnez) {
  RUN_RISCV(R"(
    c.bnez
  )");
}


TEST_P(InstCompressed, li) {
  RUN_RISCV(R"(
    c.li
  )");
}

TEST_P(InstCompressed, lui) {
  RUN_RISCV(R"(
    c.lui
  )");
}

TEST_P(InstCompressed, addi) {
  RUN_RISCV(R"(
    c.addi
  )");
}

TEST_P(InstCompressed, addiw) {
  RUN_RISCV(R"(
    c.addiw
  )");
}


TEST_P(InstCompressed, addi16sp) {
  RUN_RISCV(R"(
    c.addi16sp
  )");
}



TEST_P(InstCompressed, slli) {
  RUN_RISCV(R"(
    c.slli
  )");
}


TEST_P(InstCompressed, srli) {
  RUN_RISCV(R"(
    c.srli
  )");
}


TEST_P(InstCompressed, srai) {
  RUN_RISCV(R"(
    c.srai
  )");
}

TEST_P(InstCompressed, andi) {
  RUN_RISCV(R"(
    c.andi
  )");
}

TEST_P(InstCompressed, add) {
  RUN_RISCV(R"(
    c.add
  )");
}

TEST_P(InstCompressed, and) {
  RUN_RISCV(R"(
    c.and
  )");
}

TEST_P(InstCompressed, or) {
  RUN_RISCV(R"(
    c.or
  )");
}


TEST_P(InstCompressed, xor) {
  RUN_RISCV(R"(
    c.xor
  )");
}

TEST_P(InstCompressed, sub) {
  RUN_RISCV(R"(
    c.sub
  )");
}

TEST_P(InstCompressed, addw) {
  RUN_RISCV(R"(
    c.addw
  )");
}

TEST_P(InstCompressed, subw) {
  RUN_RISCV(R"(
    c.subw
  )");
}

TEST_P(InstCompressed, nop) {
  RUN_RISCV(R"(
    c.nop
  )");
}

TEST_P(InstCompressed, ebreak) {
  RUN_RISCV(R"(
    c.ebreak
  )");
}

INSTANTIATE_TEST_SUITE_P(RISCV, InstCompressed,
                         ::testing::Values(std::make_tuple(EMULATION,
                                                           YAML::Load("{}"))),
                         paramToString);

}  // namespace
