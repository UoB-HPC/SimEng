#include "RISCVRegressionTest.hh"

namespace {

using InstMulDiv = RISCVRegressionTest;

TEST_P(InstMulDiv, mul) {
  initialHeapData_.resize(16);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = -1;
  heap[1] = -1;
  heap[2] = 0x00000000;
  heap[3] = 0x00000001;

  RUN_RISCV(R"(
    li a7, 214
    ecall

    add t5, t5, a0
    ld t6, 0(t5)
    mul t4, t6, t6
    li t3, 12
    mul t3, t6, zero
    ld t2, 8(t5)
    mul t1, t2, t2
    srli s2, t2, 1 #2^31
    mul s3, s2, t2
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(31), -1);
  EXPECT_EQ(getGeneralRegister<uint64_t>(29), 1);  // -1 * -1
  EXPECT_EQ(getGeneralRegister<uint64_t>(28), 0);  // -1 * 0
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0);   // 2^32^2 = 0 (overflow)
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 0x100000000);
  EXPECT_EQ(getGeneralRegister<uint64_t>(18), 0x80000000);
  EXPECT_EQ(getGeneralRegister<uint64_t>(19),
            0x8000000000000000);  // 2^31 * 2^32 = 2^63 (NO overflow)
}

// TODO NYI, tests should fail
// TEST_P(InstMulDiv, mulh) {
//  initialHeapData_.resize(16);
//  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
//  heap[0] = -1;
//  heap[1] = -1;
//
//  RUN_RISCV(R"(
//    li a7, 214
//    li a7, 214
//    ecall
//
//    ld t6, 0(a0)
//    mulh t4, t6, t6
//  )");
//  EXPECT_EQ(getGeneralRegister<uint64_t>(31), -1);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(29), 0);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(28), 1);
//}

TEST_P(InstMulDiv, mulhu) {
  initialHeapData_.resize(16);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = -1;
  heap[1] = -1;

  RUN_RISCV(R"(
    li a7, 214
    ecall

    ld t6, 0(a0)
    mulhu t4, t6, t6
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), -1);
  EXPECT_EQ(getGeneralRegister<uint64_t>(29), 0xFFFFFFFFFFFFFFFE);
}

// TODO NYI, tests should fail
// TEST_P(InstMulDiv, mulhsu) {
//   initialHeapData_.resize(16);
//   uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
//   heap[0] = -1;
//   heap[1] = -1;
//
//  RUN_RISCV(R"(
//    li a7, 214
//    ecall
//
//    ld t6, 0(a0)
//    mulhsu t4, t6, t6
//  )");
//  EXPECT_EQ(getGeneralRegister<uint64_t>(31), -1);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(29), -1);
//}

TEST_P(InstMulDiv, mulw) {
  initialHeapData_.resize(16);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = -1;
  heap[1] = -1;

  RUN_RISCV(R"(
    li a7, 214
    ecall

    ld t6, 0(a0)
    mulw t5, t6, t6
    li t4, 6
    slli t3, t5, 30
    mulw t2, t4, t3

  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), -1);
  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 1);
  EXPECT_EQ(getGeneralRegister<uint64_t>(28), 1 << 30);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 0xFFFFFFFF80000000);
}

TEST_P(InstMulDiv, div) {
  initialHeapData_.resize(16);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = -1;
  heap[1] = -1;
  heap[2] = 0;
  heap[3] = 0x80000000;  // most negative integer

  RUN_RISCV(R"(
    li a7, 214
    ecall

    ld t6, 0(a0)
    div t5, t6, t6
    div t4, t6, zero
    li s1, 4
    div t3, t6, s1
    li s2, -16
    li s3, -2
    div t2, s2, s3
    ld t1, 8(a0)
    div s4, t1, t6

  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), -1);
  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 1);  //-1/-1 = 1
  EXPECT_EQ(getGeneralRegister<uint64_t>(29),
            -1);  // div by zero -1/0 = all bits set
  EXPECT_EQ(getGeneralRegister<uint64_t>(28), 0);  //-1/4 = 0
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 8);   //-16/-2 = 8
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0x8000000000000000);
  EXPECT_EQ(getGeneralRegister<uint64_t>(20),
            0x8000000000000000);  // division overflow
}

TEST_P(InstMulDiv, divw) {
  initialHeapData_.resize(16);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = -1;
  heap[1] = -1;
  heap[2] = 5;
  heap[3] = 0x80000000;  // most negative integer

  RUN_RISCV(R"(
    li a7, 214
    ecall

    ld t6, 0(a0)
    divw t5, t6, t6
    divw t4, t6, zero
    li s1, 4
    divw t3, t6, s1
    li s2, -16
    li s3, -2
    divw t2, s2, s3
    lw t1, 12(a0)
    divw s4, t1, t6
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), -1);
  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 1);  //-1/-1 = 1
  EXPECT_EQ(getGeneralRegister<uint64_t>(29),
            -1);  // div by zero -1/0 = all bits set
  EXPECT_EQ(getGeneralRegister<uint64_t>(28), 0);  //-1/4 = 0
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 8);   //-16/-2 = 8
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0xFFFFFFFF80000000);
  EXPECT_EQ(getGeneralRegister<uint64_t>(20),
            0xFFFFFFFF80000000);  // division overflow
}

TEST_P(InstMulDiv, divu) {
  initialHeapData_.resize(16);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = -1;
  heap[1] = -1;
  heap[2] = 0;
  heap[3] = 0x80000000;  // most negative integer

  RUN_RISCV(R"(
    li a7, 214
    ecall

    ld t6, 0(a0)
    divu t5, t6, t6
    divu t4, t5, zero
    li s1, 4
    li s5, 1
    divu t3, s5, s1
    li s2, 16
    li s3, 2
    divu t2, s2, s3
    ld t1, 8(a0)
    li s4, 5
    divu s4, t1, t6
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), -1);
  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 1);  // max pos/max pos = 1
  EXPECT_EQ(getGeneralRegister<uint64_t>(29),
            -1);                                   // div by zero 1/0 = -1
  EXPECT_EQ(getGeneralRegister<uint64_t>(28), 0);  // 1/4 = 0
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 8);   // 16/2 = 8
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0x8000000000000000);
  EXPECT_EQ(getGeneralRegister<uint64_t>(20), 0);  // big / max pos = 0
}

TEST_P(InstMulDiv, divuw) {
  initialHeapData_.resize(16);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = -1;
  heap[1] = -1;
  heap[2] = 5;
  heap[3] = 0x80000000;  // most negative integer

  RUN_RISCV(R"(
    li a7, 214
    ecall

    ld t6, 0(a0)
    divuw t5, t6, t6
    divuw t4, t5, zero
    li s1, 4
    li s5, 1
    divuw t3, s5, s1
    li s2, 16
    li s3, 2
    divuw t2, s2, s3
    lw t1, 12(a0)
    li s4, 5
    divuw s4, t1, t6
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), -1);
  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 1);  // max pos / max pos = 1
  EXPECT_EQ(getGeneralRegister<uint64_t>(29),
            -1);                                   // div by zero 1/0 = -1
  EXPECT_EQ(getGeneralRegister<uint64_t>(28), 0);  // 1/4 = 0
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 8);   // 16/2 = 8
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0xFFFFFFFF80000000);
  EXPECT_EQ(getGeneralRegister<uint64_t>(20), 0);  // // big pos / max pos = 0
}

TEST_P(InstMulDiv, rem) {
  initialHeapData_.resize(16);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = -1;
  heap[1] = -1;
  heap[2] = 0;
  heap[3] = 0x80000000;  // most negative integer

  RUN_RISCV(R"(
    li a7, 214
    ecall

    ld t6, 0(a0)
    rem t5, t6, t6
    li t3, -7
    rem t4, t3, zero
    li s1, 4
    li s5, 1
    rem t3, s5, s1
    li s2, -16
    li s3, -7
    rem t2, s2, s3
    ld t1, 8(a0)
    li s4, 5
    rem s4, t1, t6
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), -1);
  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0);  // rem -1,-1 = 0
  EXPECT_EQ(getGeneralRegister<uint64_t>(29),
            -7);                                   // rem by zero -7/0 = -7
  EXPECT_EQ(getGeneralRegister<uint64_t>(28), 1);  // 1/4 = 1
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), -2);  // -16/-7 = -2
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0x8000000000000000);
  EXPECT_EQ(getGeneralRegister<uint64_t>(20), 0);  // max pos/-1 = 0
}

TEST_P(InstMulDiv, remw) {
  initialHeapData_.resize(16);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = -1;
  heap[1] = -1;
  heap[2] = 0;
  heap[3] = 0x80000000;  // most negative integer

  RUN_RISCV(R"(
    li a7, 214
    ecall

    ld t6, 0(a0)
    remw t5, t6, t6
    li t3, -7
    remw t4, t3, zero
    li t3, 8
    remw s6, t3, zero
    li s1, 4
    li s5, 1
    remw t3, s5, s1
    li s2, -16
    li s3, -7
    remw t2, s2, s3
    lw t1, 12(a0)
    li s4, 5
    remw s4, t1, t6
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), -1);
  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0);  // rem -1,-1 = 0
  EXPECT_EQ(getGeneralRegister<uint64_t>(29),
            -7);  // rem by zero -7/0 = -7   0xFF..F9
  EXPECT_EQ(getGeneralRegister<uint64_t>(22),
            8);  // rem by zero 8/0 = 8 0x00..08
  EXPECT_EQ(getGeneralRegister<uint64_t>(28), 1);  // 1/4 = 1
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), -2);  // -16/-7 = 2
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0xFFFFFFFF80000000);
  EXPECT_EQ(getGeneralRegister<uint64_t>(20), 0);  // big pos/max pos = 0
}

TEST_P(InstMulDiv, remu) {
  initialHeapData_.resize(16);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = -1;
  heap[1] = -1;
  heap[2] = 0;
  heap[3] = 0x80000000;  // most negative integer

  RUN_RISCV(R"(
    li a7, 214
    ecall

    ld t6, 0(a0)
    remu t5, t6, t6
    li t3, 7
    remu t4, t3, zero
    li s1, 4
    li s5, 1
    remu t3, s5, s1
    li s2, 16
    li s3, 7
    remu t2, s2, s3
    ld t1, 8(a0)
    li s4, 5
    remu s4, t1, t6
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), -1);
  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0);  // rem big pos,big pos = 0
  EXPECT_EQ(getGeneralRegister<uint64_t>(29),
            7);                                    // rem by zero 7/0 = 7
  EXPECT_EQ(getGeneralRegister<uint64_t>(28), 1);  // 1/4 = 1
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 2);   // 16/7 = 2
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0x8000000000000000);
  EXPECT_EQ(getGeneralRegister<uint64_t>(20),
            0x8000000000000000);  // big pos/max pos = big pos
}

TEST_P(InstMulDiv, remuw) {
  initialHeapData_.resize(16);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = -1;
  heap[1] = -1;
  heap[2] = 0;
  heap[3] = 0x80000000;  // most negative integer

  RUN_RISCV(R"(
    li a7, 214
    ecall

    ld t6, 0(a0)
    remuw t5, t6, t6
    li t3, 7
    remuw t4, t3, zero
    li t3, 8
    remuw s6, t3, zero
    li s1, 4
    li s5, 1
    remuw t3, s5, s1
    li s2, 16
    li s3, 7
    remuw t2, s2, s3
    lw t1, 12(a0)
    li s4, 5
    remuw s4, t1, t6
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), -1);
  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0);  // rem max pos,max pos = 0
  EXPECT_EQ(getGeneralRegister<uint64_t>(29),
            7);  // rem by zero 7/0 = 7
  EXPECT_EQ(getGeneralRegister<uint64_t>(22),
            8);  // rem by zero 8/0 = 8 0x00..08
  EXPECT_EQ(getGeneralRegister<uint64_t>(28), 1);  // 1/4 = 1
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 2);   // 16/7 = 2
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0xFFFFFFFF80000000);
  EXPECT_EQ(getGeneralRegister<uint64_t>(20),
            0xFFFFFFFF80000000);  // big pos/max pos = 0
}

INSTANTIATE_TEST_SUITE_P(RISCV, InstMulDiv,
                         ::testing::Values(std::make_tuple(EMULATION,
                                                           YAML::Load("{}"))),
                         paramToString);

}  // namespace
