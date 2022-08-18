#include <algorithm>
#include <limits>

#include "AArch64RegressionTest.hh"

namespace {

using InstSve = AArch64RegressionTest;

TEST_P(InstSve, addvl) {
  // 64-bits
  RUN_AARCH64(R"(
    mov x0, #42
    mov x1, #8
    mov x2, #1024

    addvl x3, x0, #4
    addvl x4, x1, #31
    addvl x5, x2, #-32
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(3), (42 + ((VL / 8) * 4)));
  EXPECT_EQ(getGeneralRegister<int64_t>(4), (8 + ((VL / 8) * 31)));
  EXPECT_EQ(getGeneralRegister<int64_t>(5), (1024 + ((VL / 8) * -32)));
}

TEST_P(InstSve, adr) {
  // Packed Offsets
  RUN_AARCH64(R"(
    # 32-bit
    dup z0.s, #15
    dup z1.s, #4

    adr z2.s, [z0.s, z1.s]
    adr z3.s, [z0.s, z1.s, lsl #1]
    adr z4.s, [z0.s, z1.s, lsl #2]
    adr z5.s, [z0.s, z1.s, lsl #3]

    # 64-bit
    dup z6.d, #15
    dup z7.d, #4

    adr z8.d, [z6.d, z7.d]
    adr z9.d, [z6.d, z7.d, lsl #1]
    adr z10.d, [z6.d, z7.d, lsl #2]
    adr z11.d, [z6.d, z7.d, lsl #3]
  )");
  CHECK_NEON(2, uint32_t, fillNeon<uint32_t>({19}, VL / 8));
  CHECK_NEON(3, uint32_t, fillNeon<uint32_t>({23}, VL / 8));
  CHECK_NEON(4, uint32_t, fillNeon<uint32_t>({31}, VL / 8));
  CHECK_NEON(5, uint32_t, fillNeon<uint32_t>({47}, VL / 8));

  CHECK_NEON(8, uint64_t, fillNeon<uint64_t>({19}, VL / 8));
  CHECK_NEON(9, uint64_t, fillNeon<uint64_t>({23}, VL / 8));
  CHECK_NEON(10, uint64_t, fillNeon<uint64_t>({31}, VL / 8));
  CHECK_NEON(11, uint64_t, fillNeon<uint64_t>({47}, VL / 8));
}

TEST_P(InstSve, and) {
  // Predicates, Predicated
  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #8
    addvl x0, x0, #1
    sdiv x0, x0, x1

    ptrue p0.s
    ptrue p1.s
    whilelo p2.s, xzr, x0

    and p3.b, p0/z, p1.b, p0.b
    and p4.b, p2/z, p1.b, p0.b
  )");
  CHECK_PREDICATE(3, uint64_t, fillPred(VL / 8, {1}, 4));
  CHECK_PREDICATE(4, uint64_t, fillPred(VL / 16, {1}, 4));

  // Vector, immediate
  RUN_AARCH64(R"(
    dup z0.b, #15
    dup z1.h, #7
    dup z2.s, #5
    dup z3.d, #11

    and z0.b, z0.b, #1
    and z1.h, z1.h, #1
    and z2.s, z2.s, #1
    and z3.d, z3.d, #1

    dup z11.b, #15
    and z11.b, z11.b, #254
  )");
  CHECK_NEON(0, uint64_t, fillNeon<uint64_t>({0x0101010101010101}, VL / 8));
  CHECK_NEON(1, uint64_t, fillNeon<uint64_t>({0x0001000100010001}, VL / 8));
  CHECK_NEON(2, uint64_t, fillNeon<uint64_t>({0x0000000100000001}, VL / 8));
  CHECK_NEON(3, uint64_t, fillNeon<uint64_t>({0x0000000000000001}, VL / 8));
  CHECK_NEON(11, uint64_t, fillNeon<uint64_t>({0x0e0e0e0e0e0e0e0e}, VL / 8));

  // Vectors, Predicated
  RUN_AARCH64(R"(
    # 8-bit
    mov x0, #0
    mov x1, #2
    addvl x0, x0, #1
    sdiv x0, x0, x1

    ptrue p0.b
    whilelo p1.b, xzr, x0

    index z0.b, #8, #2
    dup z1.b, #15
    dup z2.b, #3

    and z0.b, p0/m, z0.b, z1.b
    and z1.b, p1/m, z1.b, z2.b 

    # 16-bit
    mov x0, #0
    mov x1, #4
    addvl x0, x0, #1
    sdiv x0, x0, x1

    index z3.h, #8, #2
    dup z4.h, #15
    dup z5.h, #3

    ptrue p0.h
    whilelo p1.h, xzr, x0

    and z3.h, p0/m, z3.h, z4.h
    and z4.h, p1/m, z4.h, z5.h 

    # 32-bit
    mov x0, #0
    mov x1, #8
    addvl x0, x0, #1
    sdiv x0, x0, x1

    index z6.s, #8, #2
    dup z7.s, #15
    dup z8.s, #3

    ptrue p0.s
    whilelo p1.s, xzr, x0

    and z6.s, p0/m, z6.s, z7.s
    and z7.s, p1/m, z7.s, z8.s 

    # 64-bit
    mov x0, #0
    mov x1, #16
    addvl x0, x0, #1
    sdiv x0, x0, x1

    index z9.d, #8, #2
    dup z10.d, #15
    dup z11.d, #3

    ptrue p0.d
    whilelo p1.d, xzr, x0

    and z9.d, p0/m, z9.d, z10.d
    and z10.d, p1/m, z10.d, z11.d 
  )");
  std::vector<uint8_t> results8_0 = {8, 10, 12, 14, 0, 2, 4, 6};
  CHECK_NEON(0, uint8_t, fillNeon<uint8_t>(results8_0, VL / 8));
  CHECK_NEON(1, uint8_t, fillNeonCombined<uint8_t>({3}, {15}, VL / 8));

  std::vector<uint16_t> results16_0 = {8, 10, 12, 14, 0, 2, 4, 6};
  CHECK_NEON(3, uint16_t, fillNeon<uint16_t>(results16_0, VL / 8));
  CHECK_NEON(4, uint16_t, fillNeonCombined<uint16_t>({3}, {15}, VL / 8));

  std::vector<uint32_t> results32_0 = {8, 10, 12, 14, 0, 2, 4, 6};
  CHECK_NEON(6, uint32_t, fillNeon<uint32_t>(results32_0, VL / 8));
  CHECK_NEON(7, uint32_t, fillNeonCombined<uint32_t>({3}, {15}, VL / 8));

  std::vector<uint64_t> results64_0 = {8, 10, 12, 14, 0, 2, 4, 6};
  CHECK_NEON(9, uint64_t, fillNeon<uint64_t>(results64_0, VL / 8));
  CHECK_NEON(10, uint64_t, fillNeonCombined<uint64_t>({3}, {15}, VL / 8));
}

TEST_P(InstSve, cmpne) {
  // 8-bit
  RUN_AARCH64(R"(
    ptrue p0.b
    dup z0.b, #-3
    dup z1.b, #0

    cmpne p2.b, p0/z, z0.b, z1.b
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(VL / 8, {1}, 1));
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    ptrue p0.b
    dup z0.b, #0

    cmpne p2.b, p0/z, z0.b, z0.b
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(0, {1}, 1));
  EXPECT_EQ(getNZCV(), 0b0110);

  RUN_AARCH64(R"(
    ptrue p0.b
    dup z0.b, #3
    dup z1.b, #0

    cmpne p2.b, p0/z, z0.b, z1.b
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(VL / 8, {1}, 1));
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #2
    addvl x0, x0, #1
    sdiv x0, x0, x1

    whilelo p0.b, xzr, x0
    dup z0.b, #-3
    dup z1.b, #0

    cmpne p2.b, p0/z, z0.b, z1.b
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(VL / 16, {1}, 1));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #2
    addvl x0, x0, #1
    sdiv x0, x0, x1

    whilelo p0.b, xzr, x0
    dup z0.b, #0

    cmpne p2.b, p0/z, z0.b, z0.b
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(0, {1}, 1));
  EXPECT_EQ(getNZCV(), 0b0110);

  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #2
    addvl x0, x0, #1
    sdiv x0, x0, x1

    whilelo p0.b, xzr, x0
    dup z0.b, #3
    dup z1.b, #0

    cmpne p2.b, p0/z, z0.b, z1.b
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(VL / 16, {1}, 1));
  EXPECT_EQ(getNZCV(), 0b1010);

  // 16-bit
  RUN_AARCH64(R"(
    ptrue p0.h
    dup z0.h, #-3
    dup z1.h, #0

    cmpne p2.h, p0/z, z0.h, z1.h
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(VL / 8, {1}, 2));
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    ptrue p0.h
    dup z0.h, #0

    cmpne p2.h, p0/z, z0.h, z0.h
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(0, {1}, 2));
  EXPECT_EQ(getNZCV(), 0b0110);

  RUN_AARCH64(R"(
    ptrue p0.h
    dup z0.h, #3
    dup z1.h, #0

    cmpne p2.h, p0/z, z0.h, z1.h
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(VL / 8, {1}, 2));
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #4
    addvl x0, x0, #1
    sdiv x0, x0, x1

    whilelo p0.h, xzr, x0
    dup z0.h, #-3
    dup z1.h, #0

    cmpne p2.h, p0/z, z0.h, z1.h
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(VL / 16, {1}, 2));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #4
    addvl x0, x0, #1
    sdiv x0, x0, x1

    whilelo p0.h, xzr, x0
    dup z0.h, #0

    cmpne p2.h, p0/z, z0.h, z0.h
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(0, {1}, 2));
  EXPECT_EQ(getNZCV(), 0b0110);

  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #4
    addvl x0, x0, #1
    sdiv x0, x0, x1

    whilelo p0.h, xzr, x0
    dup z0.h, #3
    dup z1.h, #0

    cmpne p2.h, p0/z, z0.h, z1.h
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(VL / 16, {1}, 2));
  EXPECT_EQ(getNZCV(), 0b1010);

  // 32-bit
  RUN_AARCH64(R"(
    ptrue p0.s
    dup z0.s, #-3
    dup z1.s, #0

    cmpne p2.s, p0/z, z0.s, z1.s
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(VL / 8, {1}, 4));
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    ptrue p0.s
    dup z0.s, #0

    cmpne p2.s, p0/z, z0.s, z0.s
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(0, {1}, 4));
  EXPECT_EQ(getNZCV(), 0b0110);

  RUN_AARCH64(R"(
    ptrue p0.s
    dup z0.s, #3
    dup z1.s, #0

    cmpne p2.s, p0/z, z0.s, z1.s
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(VL / 8, {1}, 4));
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #8
    addvl x0, x0, #1
    sdiv x0, x0, x1

    whilelo p0.s, xzr, x0
    dup z0.s, #-3
    dup z1.s, #0

    cmpne p2.s, p0/z, z0.s, z1.s
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(VL / 16, {1}, 4));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #8
    addvl x0, x0, #1
    sdiv x0, x0, x1

    whilelo p0.s, xzr, x0
    dup z0.s, #0

    cmpne p2.s, p0/z, z0.s, z0.s
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(0, {1}, 4));
  EXPECT_EQ(getNZCV(), 0b0110);

  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #8
    addvl x0, x0, #1
    sdiv x0, x0, x1

    whilelo p0.s, xzr, x0
    dup z0.s, #3
    dup z1.s, #0

    cmpne p2.s, p0/z, z0.s, z1.s
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(VL / 16, {1}, 4));
  EXPECT_EQ(getNZCV(), 0b1010);

  // 64-bit
  RUN_AARCH64(R"(
    ptrue p0.d
    dup z0.d, #-3
    dup z1.d, #0

    cmpne p2.d, p0/z, z0.d, z1.d
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(VL / 8, {1}, 8));
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    ptrue p0.d
    dup z0.d, #0

    cmpne p2.d, p0/z, z0.d, z0.d
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(0, {1}, 8));
  EXPECT_EQ(getNZCV(), 0b0110);

  RUN_AARCH64(R"(
    ptrue p0.d
    dup z0.d, #3
    dup z1.d, #0

    cmpne p2.d, p0/z, z0.d, z1.d
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(VL / 8, {1}, 8));
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #16
    addvl x0, x0, #1
    sdiv x0, x0, x1

    whilelo p0.d, xzr, x0
    dup z0.d, #-3
    dup z1.d, #0

    cmpne p2.d, p0/z, z0.d, z1.d
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(VL / 16, {1}, 8));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #16
    addvl x0, x0, #1
    sdiv x0, x0, x1

    whilelo p0.d, xzr, x0
    dup z0.d, #0

    cmpne p2.d, p0/z, z0.d, z0.d
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(0, {1}, 8));
  EXPECT_EQ(getNZCV(), 0b0110);

  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #16
    addvl x0, x0, #1
    sdiv x0, x0, x1

    whilelo p0.d, xzr, x0
    dup z0.d, #3
    dup z1.d, #0

    cmpne p2.d, p0/z, z0.d, z1.d
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(VL / 16, {1}, 8));
  EXPECT_EQ(getNZCV(), 0b1010);
}

TEST_P(InstSve, cmpne_imm) {
  // 8-bit
  RUN_AARCH64(R"(
    ptrue p0.b
    dup z0.b, #-3

    cmpne p2.b, p0/z, z0.b, #0
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(VL / 8, {1}, 1));
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    ptrue p0.b
    dup z0.b, #0

    cmpne p2.b, p0/z, z0.b, #0
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(0, {1}, 1));
  EXPECT_EQ(getNZCV(), 0b0110);

  RUN_AARCH64(R"(
    ptrue p0.b
    dup z0.b, #3

    cmpne p2.b, p0/z, z0.b, #0
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(VL / 8, {1}, 1));
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #2
    addvl x0, x0, #1
    sdiv x0, x0, x1

    whilelo p0.b, xzr, x0
    dup z0.b, #-3

    cmpne p2.b, p0/z, z0.b, #0
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(VL / 16, {1}, 1));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #2
    addvl x0, x0, #1
    sdiv x0, x0, x1

    whilelo p0.b, xzr, x0
    dup z0.b, #0

    cmpne p2.b, p0/z, z0.b, #0
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(0, {1}, 1));
  EXPECT_EQ(getNZCV(), 0b0110);

  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #2
    addvl x0, x0, #1
    sdiv x0, x0, x1

    whilelo p0.b, xzr, x0
    dup z0.b, #3

    cmpne p2.b, p0/z, z0.b, #0
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(VL / 16, {1}, 1));
  EXPECT_EQ(getNZCV(), 0b1010);

  // 16-bit
  RUN_AARCH64(R"(
    ptrue p0.h
    dup z0.h, #-3

    cmpne p2.h, p0/z, z0.h, #0
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(VL / 8, {1}, 2));
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    ptrue p0.h
    dup z0.h, #0

    cmpne p2.h, p0/z, z0.h, #0
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(0, {1}, 2));
  EXPECT_EQ(getNZCV(), 0b0110);

  RUN_AARCH64(R"(
    ptrue p0.h
    dup z0.h, #3

    cmpne p2.h, p0/z, z0.h, #0
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(VL / 8, {1}, 2));
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #4
    addvl x0, x0, #1
    sdiv x0, x0, x1

    whilelo p0.h, xzr, x0
    dup z0.h, #-3

    cmpne p2.h, p0/z, z0.h, #0
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(VL / 16, {1}, 2));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #4
    addvl x0, x0, #1
    sdiv x0, x0, x1

    whilelo p0.h, xzr, x0
    dup z0.h, #0

    cmpne p2.h, p0/z, z0.h, #0
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(0, {1}, 2));
  EXPECT_EQ(getNZCV(), 0b0110);

  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #4
    addvl x0, x0, #1
    sdiv x0, x0, x1

    whilelo p0.h, xzr, x0
    dup z0.h, #3

    cmpne p2.h, p0/z, z0.h, #0
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(VL / 16, {1}, 2));
  EXPECT_EQ(getNZCV(), 0b1010);

  // 32-bit
  RUN_AARCH64(R"(
    ptrue p0.s
    dup z0.s, #-3

    cmpne p2.s, p0/z, z0.s, #0
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(VL / 8, {1}, 4));
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    ptrue p0.s
    dup z0.s, #0

    cmpne p2.s, p0/z, z0.s, #0
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(0, {1}, 4));
  EXPECT_EQ(getNZCV(), 0b0110);

  RUN_AARCH64(R"(
    ptrue p0.s
    dup z0.s, #3

    cmpne p2.s, p0/z, z0.s, #0
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(VL / 8, {1}, 4));
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #8
    addvl x0, x0, #1
    sdiv x0, x0, x1

    whilelo p0.s, xzr, x0
    dup z0.s, #-3

    cmpne p2.s, p0/z, z0.s, #0
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(VL / 16, {1}, 4));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #8
    addvl x0, x0, #1
    sdiv x0, x0, x1

    whilelo p0.s, xzr, x0
    dup z0.s, #0

    cmpne p2.s, p0/z, z0.s, #0
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(0, {1}, 4));
  EXPECT_EQ(getNZCV(), 0b0110);

  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #8
    addvl x0, x0, #1
    sdiv x0, x0, x1

    whilelo p0.s, xzr, x0
    dup z0.s, #3

    cmpne p2.s, p0/z, z0.s, #0
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(VL / 16, {1}, 4));
  EXPECT_EQ(getNZCV(), 0b1010);

  // 64-bit
  RUN_AARCH64(R"(
    ptrue p0.d
    dup z0.d, #-3

    cmpne p2.d, p0/z, z0.d, #0
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(VL / 8, {1}, 8));
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    ptrue p0.d
    dup z0.d, #0

    cmpne p2.d, p0/z, z0.d, #0
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(0, {1}, 8));
  EXPECT_EQ(getNZCV(), 0b0110);

  RUN_AARCH64(R"(
    ptrue p0.d
    dup z0.d, #3

    cmpne p2.d, p0/z, z0.d, #0
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(VL / 8, {1}, 8));
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #16
    addvl x0, x0, #1
    sdiv x0, x0, x1

    whilelo p0.d, xzr, x0
    dup z0.d, #-3

    cmpne p2.d, p0/z, z0.d, #0
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(VL / 16, {1}, 8));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #16
    addvl x0, x0, #1
    sdiv x0, x0, x1

    whilelo p0.d, xzr, x0
    dup z0.d, #0

    cmpne p2.d, p0/z, z0.d, #0
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(0, {1}, 8));
  EXPECT_EQ(getNZCV(), 0b0110);

  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #16
    addvl x0, x0, #1
    sdiv x0, x0, x1

    whilelo p0.d, xzr, x0
    dup z0.d, #3

    cmpne p2.d, p0/z, z0.d, #0
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(VL / 16, {1}, 8));
  EXPECT_EQ(getNZCV(), 0b1010);
}

TEST_P(InstSve, cmpeq_imm) {
  // 8-bit
  RUN_AARCH64(R"(
    ptrue p0.b
    dup z0.b, #-5

    cmpeq p1.b, p0/z, z0.b, #-5
  )");
  CHECK_PREDICATE(1, uint64_t, fillPred(VL / 8, {1}, 1));
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #2
    addvl x0, x0, #1
    sdiv x0, x0, x1

    whilelo p0.b, xzr, x0
    dup z0.b, #4

    cmpeq p1.b, p0/z, z0.b, #4
  )");
  CHECK_PREDICATE(1, uint64_t, fillPred(VL / 16, {1}, 1));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    ptrue p0.b
    dup z0.b, #-5

    cmpeq p1.b, p0/z, z0.b, #4
  )");
  CHECK_PREDICATE(1, uint64_t, {0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b0110);

  // 16-bit
  RUN_AARCH64(R"(
    ptrue p0.h
    dup z0.h, #-5

    cmpeq p1.h, p0/z, z0.h, #-5
  )");
  CHECK_PREDICATE(1, uint64_t, fillPred(VL / 8, {1}, 2));
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #4
    addvl x0, x0, #1
    sdiv x0, x0, x1

    whilelo p0.h, xzr, x0
    dup z0.h, #4

    cmpeq p1.h, p0/z, z0.h, #4
  )");
  CHECK_PREDICATE(1, uint64_t, fillPred(VL / 16, {1}, 2));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    ptrue p0.h
    dup z0.h, #-5

    cmpeq p1.h, p0/z, z0.h, #4
  )");
  CHECK_PREDICATE(1, uint64_t, {0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b0110);

  // // 32-bit
  RUN_AARCH64(R"(
    ptrue p0.s
    dup z0.s, #-5

    cmpeq p1.s, p0/z, z0.s, #-5
  )");
  CHECK_PREDICATE(1, uint64_t, fillPred(VL / 8, {1}, 4));
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #8
    addvl x0, x0, #1
    sdiv x0, x0, x1

    whilelo p0.s, xzr, x0
    dup z0.s, #4

    cmpeq p1.s, p0/z, z0.s, #4
  )");
  CHECK_PREDICATE(1, uint64_t, fillPred(VL / 16, {1}, 4));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    ptrue p0.s
    dup z0.s, #-5

    cmpeq p1.s, p0/z, z0.s, #4
  )");
  CHECK_PREDICATE(1, uint64_t, {0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b0110);

  // // 64-bit
  RUN_AARCH64(R"(
    ptrue p0.d
    dup z0.d, #-5

    cmpeq p1.d, p0/z, z0.d, #-5
  )");
  CHECK_PREDICATE(1, uint64_t, fillPred(VL / 8, {1}, 8));
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #16
    addvl x0, x0, #1
    sdiv x0, x0, x1

    whilelo p0.d, xzr, x0
    dup z0.d, #4

    cmpeq p1.d, p0/z, z0.d, #4
  )");
  CHECK_PREDICATE(1, uint64_t, fillPred(VL / 16, {1}, 8));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    ptrue p0.d
    dup z0.d, #-5

    cmpeq p1.d, p0/z, z0.d, #4
  )");
  CHECK_PREDICATE(1, uint64_t, {0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b0110);
}

TEST_P(InstSve, cmpeq_vec) {
  // 8-bit
  RUN_AARCH64(R"(
    ptrue p0.b
    dup z0.b, #-5

    cmpeq p1.b, p0/z, z0.b, z0.b
  )");
  CHECK_PREDICATE(1, uint64_t, fillPred(VL / 8, {1}, 1));
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #2
    addvl x0, x0, #1
    sdiv x0, x0, x1

    whilelo p0.b, xzr, x0
    dup z0.b, #4

    cmpeq p1.b, p0/z, z0.b, z0.b
  )");
  CHECK_PREDICATE(1, uint64_t, fillPred(VL / 16, {1}, 1));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    ptrue p0.b
    dup z0.b, #-5
    dup z2.b, #4

    cmpeq p1.b, p0/z, z0.b, z2.b
  )");
  CHECK_PREDICATE(1, uint64_t, {0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b0110);

  // 16-bit
  RUN_AARCH64(R"(
    ptrue p0.h
    dup z0.h, #-5

    cmpeq p1.h, p0/z, z0.h, z0.h
  )");
  CHECK_PREDICATE(1, uint64_t, fillPred(VL / 8, {1}, 2));
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #4
    addvl x0, x0, #1
    sdiv x0, x0, x1

    whilelo p0.h, xzr, x0
    dup z0.h, #4

    cmpeq p1.h, p0/z, z0.h, z0.h
  )");
  CHECK_PREDICATE(1, uint64_t, fillPred(VL / 16, {1}, 2));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    ptrue p0.h
    dup z0.h, #-5
    dup z2.h, #4

    cmpeq p1.h, p0/z, z0.h, z2.h
  )");
  CHECK_PREDICATE(1, uint64_t, {0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b0110);

  // 32-bit
  RUN_AARCH64(R"(
    ptrue p0.s
    dup z0.s, #-5

    cmpeq p1.s, p0/z, z0.s, z0.s
  )");
  CHECK_PREDICATE(1, uint64_t, fillPred(VL / 8, {1}, 4));
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #8
    addvl x0, x0, #1
    sdiv x0, x0, x1

    whilelo p0.s, xzr, x0
    dup z0.s, #4

    cmpeq p1.s, p0/z, z0.s, z0.s
  )");
  CHECK_PREDICATE(1, uint64_t, fillPred(VL / 16, {1}, 4));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    ptrue p0.s
    dup z0.s, #-5
    dup z2.s, #4

    cmpeq p1.s, p0/z, z0.s, z2.s
  )");
  CHECK_PREDICATE(1, uint64_t, {0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b0110);

  // 64-bit
  RUN_AARCH64(R"(
    ptrue p0.d
    dup z0.d, #-5

    cmpeq p1.d, p0/z, z0.d, z0.d
  )");
  CHECK_PREDICATE(1, uint64_t, fillPred(VL / 8, {1}, 8));
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #16
    addvl x0, x0, #1
    sdiv x0, x0, x1
    
    whilelo p0.d, xzr, x0
    dup z0.d, #4

    cmpeq p1.d, p0/z, z0.d, z0.d
  )");
  CHECK_PREDICATE(1, uint64_t, fillPred(VL / 16, {1}, 8));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    ptrue p0.d
    dup z0.d, #-5
    dup z2.d, #4

    cmpeq p1.d, p0/z, z0.d, z2.d
  )");
  CHECK_PREDICATE(1, uint64_t, {0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b0110);
}

TEST_P(InstSve, cmpgt_vec) {
  // 8-bit
  RUN_AARCH64(R"(
    ptrue p0.b
    dup z0.b, #5
    dup z1.b, #-4

    cmpgt p1.b, p0/z, z0.b, z1.b
  )");
  CHECK_PREDICATE(1, uint64_t, fillPred(VL / 8, {1}, 1));
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #2
    addvl x0, x0, #1
    sdiv x0, x0, x1

    whilelo p0.b, xzr, x0
    dup z0.b, #5
    dup z1.b, #-4

    cmpgt p1.b, p0/z, z0.b, z1.b
  )");
  CHECK_PREDICATE(1, uint64_t, fillPred(VL / 16, {1}, 1));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    ptrue p0.b
    dup z0.b, #5
    dup z1.b, #-4

    cmpgt p1.b, p0/z, z1.b, z0.b
  )");
  CHECK_PREDICATE(1, uint64_t, {0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b0110);

  // 16-bit
  RUN_AARCH64(R"(
    ptrue p0.h
    dup z0.h, #5
    dup z1.h, #-4

    cmpgt p1.h, p0/z, z0.h, z1.h
  )");
  CHECK_PREDICATE(1, uint64_t, fillPred(VL / 8, {1}, 2));
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #4
    addvl x0, x0, #1
    sdiv x0, x0, x1

    whilelo p0.h, xzr, x0
    dup z0.h, #5
    dup z1.h, #-4

    cmpgt p1.h, p0/z, z0.h, z1.h
  )");
  CHECK_PREDICATE(1, uint64_t, fillPred(VL / 16, {1}, 2));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    ptrue p0.h
    dup z0.h, #5
    dup z1.h, #-4

    cmpgt p1.h, p0/z, z1.h, z0.h
  )");
  CHECK_PREDICATE(1, uint64_t, {0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b0110);

  // 32-bit
  RUN_AARCH64(R"(
    ptrue p0.s
    dup z0.s, #5
    dup z1.s, #-4

    cmpgt p1.s, p0/z, z0.s, z1.s
  )");
  CHECK_PREDICATE(1, uint64_t, fillPred(VL / 8, {1}, 4));
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #8
    addvl x0, x0, #1
    sdiv x0, x0, x1

    whilelo p0.s, xzr, x0
    dup z0.s, #5
    dup z1.s, #-4

    cmpgt p1.s, p0/z, z0.s, z1.s
  )");
  CHECK_PREDICATE(1, uint64_t, fillPred(VL / 16, {1}, 4));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    ptrue p0.s
    dup z0.s, #5
    dup z1.s, #-4

    cmpgt p1.s, p0/z, z1.s, z0.s
  )");
  CHECK_PREDICATE(1, uint64_t, {0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b0110);

  // 64-bit
  RUN_AARCH64(R"(
    ptrue p0.d
    dup z0.d, #5
    dup z1.d, #-4

    cmpgt p1.d, p0/z, z0.d, z1.d
  )");
  CHECK_PREDICATE(1, uint64_t, fillPred(VL / 8, {1}, 8));
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #16
    addvl x0, x0, #1
    sdiv x0, x0, x1

    whilelo p0.d, xzr, x0
    dup z0.d, #5
    dup z1.d, #-4

    cmpgt p1.d, p0/z, z0.d, z1.d
  )");
  CHECK_PREDICATE(1, uint64_t, fillPred(VL / 16, {1}, 8));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    ptrue p0.d
    dup z0.d, #5
    dup z1.d, #-4

    cmpgt p1.d, p0/z, z1.d, z0.d
  )");
  CHECK_PREDICATE(1, uint64_t, {0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b0110);
}

TEST_P(InstSve, cmphi_vec) {
  // 8-bit
  RUN_AARCH64(R"(
    ptrue p0.b
    dup z0.b, #-5
    dup z1.b, #4

    cmphi p1.b, p0/z, z0.b, z1.b
  )");
  CHECK_PREDICATE(1, uint64_t, fillPred(VL / 8, {1}, 1));
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #2
    addvl x0, x0, #1
    sdiv x0, x0, x1

    whilelo p0.b, xzr, x0
    dup z0.b, #-5
    dup z1.b, #4

    cmphi p1.b, p0/z, z0.b, z1.b
  )");
  CHECK_PREDICATE(1, uint64_t, fillPred(VL / 16, {1}, 1));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    ptrue p0.b
    dup z0.b, #-5
    dup z1.b, #4

    cmphi p1.b, p0/z, z1.b, z0.b
  )");
  CHECK_PREDICATE(1, uint64_t, {0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b0110);

  // 16-bit
  RUN_AARCH64(R"(
    ptrue p0.h
    dup z0.h, #-5
    dup z1.h, #4

    cmphi p1.h, p0/z, z0.h, z1.h
  )");
  CHECK_PREDICATE(1, uint64_t, fillPred(VL / 8, {1}, 2));
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #4
    addvl x0, x0, #1
    sdiv x0, x0, x1

    whilelo p0.h, xzr, x0
    dup z0.h, #-5
    dup z1.h, #4

    cmphi p1.h, p0/z, z0.h, z1.h
  )");
  CHECK_PREDICATE(1, uint64_t, fillPred(VL / 16, {1}, 2));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    ptrue p0.h
    dup z0.h, #-5
    dup z1.h, #4

    cmphi p1.h, p0/z, z1.h, z0.h
  )");
  CHECK_PREDICATE(1, uint64_t, {0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b0110);

  // 32-bit
  RUN_AARCH64(R"(
    ptrue p0.s
    dup z0.s, #-5
    dup z1.s, #4

    cmphi p1.s, p0/z, z0.s, z1.s
  )");
  CHECK_PREDICATE(1, uint64_t, fillPred(VL / 8, {1}, 4));
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #8
    addvl x0, x0, #1
    sdiv x0, x0, x1

    whilelo p0.s, xzr, x0
    dup z0.s, #-5
    dup z1.s, #4

    cmphi p1.s, p0/z, z0.s, z1.s
  )");
  CHECK_PREDICATE(1, uint64_t, fillPred(VL / 16, {1}, 4));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    ptrue p0.s
    dup z0.s, #-5
    dup z1.s, #4

    cmphi p1.s, p0/z, z1.s, z0.s
  )");
  CHECK_PREDICATE(1, uint64_t, {0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b0110);

  // 64-bit
  RUN_AARCH64(R"(
    ptrue p0.d
    dup z0.d, #-5
    dup z1.d, #4

    cmphi p1.d, p0/z, z0.d, z1.d
  )");
  CHECK_PREDICATE(1, uint64_t, fillPred(VL / 8, {1}, 8));
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #16
    addvl x0, x0, #1
    sdiv x0, x0, x1

    whilelo p0.d, xzr, x0
    dup z0.d, #-5
    dup z1.d, #4

    cmphi p1.d, p0/z, z0.d, z1.d
  )");
  CHECK_PREDICATE(1, uint64_t, fillPred(VL / 16, {1}, 8));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    ptrue p0.d
    dup z0.d, #-5
    dup z1.d, #4

    cmphi p1.d, p0/z, z1.d, z0.d
  )");
  CHECK_PREDICATE(1, uint64_t, {0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b0110);
}

TEST_P(InstSve, cnt) {
  // pattern = all
  RUN_AARCH64(R"(
    cntb x0
    cnth x1
    cntw x2
    cntd x3
    cntb x4, all, mul #3
    cnth x5, all, mul #3
    cntw x6, all, mul #3
    cntd x7, all, mul #3
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), VL / 8);
  EXPECT_EQ(getGeneralRegister<uint64_t>(1), VL / 16);
  EXPECT_EQ(getGeneralRegister<uint64_t>(2), VL / 32);
  EXPECT_EQ(getGeneralRegister<uint64_t>(3), VL / 64);
  EXPECT_EQ(getGeneralRegister<uint64_t>(4), (VL / 8) * 3);
  EXPECT_EQ(getGeneralRegister<uint64_t>(5), (VL / 16) * 3);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), (VL / 32) * 3);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), (VL / 64) * 3);

  // pattern != all
  RUN_AARCH64(R"(
    cntb x0, pow2, mul #2
    cnth x1, vl1, mul #2
    cntw x2, vl2, mul #2
    cntd x3, vl5, mul #2
    cntb x4, vl7, mul #2
    cnth x5, vl32, mul #2
    cntw x6, vl128, mul #2
    cntd x7, mul4, mul #2
  )");
  uint16_t maxElemsB = VL / 8;
  uint16_t maxElemsH = VL / 16;
  uint16_t maxElemsS = VL / 32;
  uint16_t maxElemsD = VL / 64;
  uint16_t n = 1;
  while (maxElemsB >= std::pow(2, n)) {
    n = n + 1;
  }
  uint16_t pow2B = std::pow(2, n - 1);

  EXPECT_EQ(getGeneralRegister<uint64_t>(0), pow2B * 2);
  EXPECT_EQ(getGeneralRegister<uint64_t>(1), maxElemsH >= 1 ? (1 * 2) : 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(2), maxElemsS >= 2 ? (2 * 2) : 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(3), maxElemsD >= 5 ? (5 * 2) : 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(4), maxElemsB >= 7 ? (7 * 2) : 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(5), maxElemsH >= 32 ? (32 * 2) : 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), maxElemsS >= 128 ? (128 * 2) : 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), (maxElemsD - (maxElemsD % 4)) * 2);
}

TEST_P(InstSve, cntp) {
  RUN_AARCH64(R"(
    # 8-bit
    mov x0, #0
    mov x1, #2
    addvl x0, x0, #1
    sdiv x0, x0, x1

    ptrue p0.b
    whilelo p1.b, xzr, x0
    cntp x10, p0, p0.b
    cntp x11, p1, p0.b

    # 16-bit
    mov x0, #0
    mov x1, #4
    addvl x0, x0, #1
    sdiv x0, x0, x1

    ptrue p0.h
    whilelo p2.h, xzr, x0
    cntp x12, p0, p0.h
    cntp x13, p2, p0.h

    # 32-bit
    mov x0, #0
    mov x1, #8
    addvl x0, x0, #1
    sdiv x0, x0, x1

    ptrue p0.s
    whilelo p3.s, xzr, x0
    cntp x14, p0, p0.s
    cntp x15, p3, p0.s

    # 64-bit
    mov x0, #0
    mov x1, #16
    addvl x0, x0, #1
    sdiv x0, x0, x1

    ptrue p0.d
    whilelo p4.d, xzr, x0
    cntp x16, p0, p0.d
    cntp x17, p4, p0.d
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(10), (VL / 8));
  EXPECT_EQ(getGeneralRegister<uint64_t>(11), (VL / 16));
  EXPECT_EQ(getGeneralRegister<uint64_t>(12), (VL / 16));
  EXPECT_EQ(getGeneralRegister<uint64_t>(13), (VL / 32));
  EXPECT_EQ(getGeneralRegister<uint64_t>(14), (VL / 32));
  EXPECT_EQ(getGeneralRegister<uint64_t>(15), (VL / 64));
  EXPECT_EQ(getGeneralRegister<uint64_t>(16), (VL / 64));
  EXPECT_EQ(getGeneralRegister<uint64_t>(17), (VL / 128));
}

TEST_P(InstSve, cpy) {
  // Immediate, Zeroing
  // 8-bit
  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #2
    addvl x0, x0, #1
    sdiv x0, x0, x1

    ptrue p0.b
    whilelo p1.b, xzr, x0

    cpy z0.b, p0/z, #10
    cpy z1.b, p0/z, #-8
    cpy z2.b, p1/z, #12
    cpy z3.b, p1/z, #-16

    # Test Alias
    mov z4.b, p0/z, #12
    mov z5.b, p1/z, #-8
  )");
  CHECK_NEON(0, int8_t, fillNeon<int8_t>({10}, VL / 8));
  CHECK_NEON(1, int8_t, fillNeon<int8_t>({-8}, VL / 8));
  CHECK_NEON(2, int8_t, fillNeon<int8_t>({12}, VL / 16));
  CHECK_NEON(3, int8_t, fillNeon<int8_t>({-16}, VL / 16));
  CHECK_NEON(4, int8_t, fillNeon<int8_t>({12}, VL / 8));
  CHECK_NEON(5, int8_t, fillNeon<int8_t>({-8}, VL / 16));

  // 16-bit
  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #4
    addvl x0, x0, #1
    sdiv x0, x0, x1

    ptrue p0.h
    whilelo p1.h, xzr, x0

    cpy z0.h, p0/z, #10
    cpy z1.h, p0/z, #8, lsl #8
    cpy z2.h, p1/z, #-12
    cpy z3.h, p1/z, #-16, lsl #8

    # Test Alias
    mov z4.h, p0/z, #12
    mov z5.h, p1/z, #-8, lsl #8
  )");
  CHECK_NEON(0, int16_t, fillNeon<int16_t>({10}, VL / 8));
  CHECK_NEON(1, int16_t,
             fillNeon<int16_t>({static_cast<int16_t>(2048)}, VL / 8));
  CHECK_NEON(2, int16_t, fillNeon<int16_t>({-12}, VL / 16));
  CHECK_NEON(3, int16_t,
             fillNeon<int16_t>({static_cast<int16_t>(-4096)}, VL / 16));
  CHECK_NEON(4, int16_t, fillNeon<int16_t>({12}, VL / 8));
  CHECK_NEON(5, int16_t,
             fillNeon<int16_t>({static_cast<int16_t>(-2048)}, VL / 16));

  // 32-bit
  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #8
    addvl x0, x0, #1
    sdiv x0, x0, x1

    ptrue p0.s
    whilelo p1.s, xzr, x0

    cpy z0.s, p0/z, #10
    cpy z1.s, p0/z, #8, lsl #8
    cpy z2.s, p1/z, #-12
    cpy z3.s, p1/z, #-16, lsl #8

    # Test Alias
    mov z4.S, p0/z, #12
    mov z5.S, p1/z, #-8, lsl #8
  )");
  CHECK_NEON(0, int32_t, fillNeon<int32_t>({10}, VL / 8));
  CHECK_NEON(1, int32_t,
             fillNeon<int32_t>({static_cast<int16_t>(2048)}, VL / 8));
  CHECK_NEON(2, int32_t, fillNeon<int32_t>({-12}, VL / 16));
  CHECK_NEON(3, int32_t,
             fillNeon<int32_t>({static_cast<int16_t>(-4096)}, VL / 16));
  CHECK_NEON(4, int32_t, fillNeon<int32_t>({12}, VL / 8));
  CHECK_NEON(5, int32_t,
             fillNeon<int32_t>({static_cast<int16_t>(-2048)}, VL / 16));

  // 64-bit
  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #16
    addvl x0, x0, #1
    sdiv x0, x0, x1

    ptrue p0.d
    whilelo p1.d, xzr, x0

    cpy z0.d, p0/z, #10
    cpy z1.d, p0/z, #8, lsl #8
    cpy z2.d, p1/z, #-12
    cpy z3.d, p1/z, #-16, lsl #8

    # Test Alias
    mov z4.d, p0/z, #12
    mov z5.d, p1/z, #-8, lsl #8
  )");
  CHECK_NEON(0, int64_t, fillNeon<int64_t>({10}, VL / 8));
  CHECK_NEON(1, int64_t,
             fillNeon<int64_t>({static_cast<int16_t>(2048)}, VL / 8));
  CHECK_NEON(2, int64_t, fillNeon<int64_t>({-12}, VL / 16));
  CHECK_NEON(3, int64_t,
             fillNeon<int64_t>({static_cast<int16_t>(-4096)}, VL / 16));
  CHECK_NEON(4, int64_t, fillNeon<int64_t>({12}, VL / 8));
  CHECK_NEON(5, int64_t,
             fillNeon<int64_t>({static_cast<int16_t>(-2048)}, VL / 16));
}

TEST_P(InstSve, fcpy) {
  // Immediate
  // 32-bit
  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #8
    addvl x0, x0, #1
    sdiv x0, x0, x1

    ptrue p0.s
    whilelo p1.s, xzr, x0

    fdup z0.s, #3.0
    fdup z1.s, #3.0
    fdup z2.s, #3.0
    fdup z3.s, #3.0
    fdup z4.s, #3.0
    fdup z5.s, #3.0

    fcpy z0.s, p0/m, #0.25
    fcpy z1.s, p0/m, #-0.25
    fcpy z2.s, p1/m, #1.5
    fcpy z3.s, p1/m, #-1.5

    # Test Alias
    fmov z4.s, p0/m, #0.25
    fmov z5.s, p1/m, #-0.25
  )");
  CHECK_NEON(0, float, fillNeon<float>({0.25}, VL / 8));
  CHECK_NEON(1, float, fillNeon<float>({-0.25}, VL / 8));
  CHECK_NEON(2, float, fillNeonCombined<float>({1.5}, {3}, VL / 8));
  CHECK_NEON(3, float, fillNeonCombined<float>({-1.5}, {3}, VL / 8));
  CHECK_NEON(4, float, fillNeon<float>({0.25}, VL / 8));
  CHECK_NEON(5, float, fillNeonCombined<float>({-0.25}, {3}, VL / 8));

  // 64-bit
  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #16
    addvl x0, x0, #1
    sdiv x0, x0, x1

    ptrue p0.d
    whilelo p1.d, xzr, x0

    fdup z0.d, #3.0
    fdup z1.d, #3.0
    fdup z2.d, #3.0
    fdup z3.d, #3.0
    fdup z4.d, #3.0
    fdup z5.d, #3.0

    fcpy z0.d, p0/m, #0.25
    fcpy z1.d, p0/m, #-0.25
    fcpy z2.d, p1/m, #1.5
    fcpy z3.d, p1/m, #-1.5

    # Test Alias
    fmov z4.d, p0/m, #0.25
    fmov z5.d, p1/m, #-0.25
  )");
  CHECK_NEON(0, double, fillNeon<double>({0.25}, VL / 8));
  CHECK_NEON(1, double, fillNeon<double>({-0.25}, VL / 8));
  CHECK_NEON(2, double, fillNeonCombined<double>({1.5}, {3}, VL / 8));
  CHECK_NEON(3, double, fillNeonCombined<double>({-1.5}, {3}, VL / 8));
  CHECK_NEON(4, double, fillNeon<double>({0.25}, VL / 8));
  CHECK_NEON(5, double, fillNeonCombined<double>({-0.25}, {3}, VL / 8));
}

TEST_P(InstSve, dec) {
  // pattern = all
  RUN_AARCH64(R"(
    mov x0, #512
    mov x1, #512
    mov x2, #512
    mov x3, #512

    # 8-bit
    decb x0
    decb x1, all, mul #3

    # 64-bit
    decd x2
    decd x3, all, mul #3
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 512 - (VL / 8));
  EXPECT_EQ(getGeneralRegister<uint64_t>(1), 512 - (VL / 8) * 3);

  EXPECT_EQ(getGeneralRegister<uint64_t>(2), 512 - (VL / 64));
  EXPECT_EQ(getGeneralRegister<uint64_t>(3), 512 - (VL / 64) * 3);

  // pattern != all
  RUN_AARCH64(R"(
    mov x0, #44
    mov x1, #20
    mov x2, #71
    mov x3, #56

    decb x0, pow2, mul #2
    decd x1, vl5, mul #2
    decb x2, vl128, mul #2
    decd x3, mul4, mul #2
  )");
  uint16_t maxElemsB = VL / 8;
  uint16_t maxElemsD = VL / 64;
  uint16_t n = 1;
  while (maxElemsB >= std::pow(2, n)) {
    n = n + 1;
  }
  uint16_t pow2B = std::pow(2, n - 1);

  EXPECT_EQ(getGeneralRegister<int64_t>(0), 44 - (pow2B * 2));
  EXPECT_EQ(getGeneralRegister<int64_t>(1),
            (maxElemsD >= 5) ? (20 - (5 * 2)) : 20);
  EXPECT_EQ(getGeneralRegister<int64_t>(2),
            (maxElemsB >= 128) ? 71 - (128 * 2) : 71);
  EXPECT_EQ(getGeneralRegister<int64_t>(3),
            56 - ((maxElemsD - (maxElemsD % 4)) * 2));
}

TEST_P(InstSve, dupm) {
  RUN_AARCH64(R"(
    # 2-bit
    mov z0.d, #0x1
    mov z1.d, #0x3

    # 4-bit
    mov z2.d, #0x7
    mov z3.d, #0xf
    
    # 8-bit
    mov z4.d, #0x1f
    mov z5.d, #0xff
    
    # 16-bit
    mov z6.d, #0x1ff
    mov z7.d, #0xffff
    
    # 32-bit
    mov z8.d, #0x1ffff
    mov z9.d, #0xffffffff

    # 64-bit
    mov z10.d, #0x1ffffffff
    mov z11.d, #0xefffffffffffffff
  )");

  CHECK_NEON(0, uint64_t, fillNeon<uint64_t>({0x1}, VL / 8));
  CHECK_NEON(1, uint64_t, fillNeon<uint64_t>({0x3}, VL / 8));
  CHECK_NEON(2, uint64_t, fillNeon<uint64_t>({0x7}, VL / 8));
  CHECK_NEON(3, uint64_t, fillNeon<uint64_t>({0xf}, VL / 8));
  CHECK_NEON(4, uint64_t, fillNeon<uint64_t>({0x1f}, VL / 8));
  CHECK_NEON(5, uint64_t, fillNeon<uint64_t>({0xff}, VL / 8));
  CHECK_NEON(6, uint64_t, fillNeon<uint64_t>({0x1ff}, VL / 8));
  CHECK_NEON(7, uint64_t, fillNeon<uint64_t>({0xffff}, VL / 8));
  CHECK_NEON(8, uint64_t, fillNeon<uint64_t>({0x1ffff}, VL / 8));
  CHECK_NEON(9, uint64_t, fillNeon<uint64_t>({0xffffffff}, VL / 8));
  CHECK_NEON(10, uint64_t, fillNeon<uint64_t>({0x1ffffffff}, VL / 8));
  CHECK_NEON(11, uint64_t, fillNeon<uint64_t>({0xefffffffffffffff}, VL / 8));
}

TEST_P(InstSve, dups) {
  // 8-bit arrangement
  RUN_AARCH64(R"(
    dup z0.b, #7
    dup z1.b, #-7
    #fdup z2.d, #0.5
    #fdup z3.d, #-0.5

    #fmov s4, #14.5
    #fmov s5, #-14.5
    # check for alias
    #mov z6.s, s4
    #mov z7.s, s5
    mov z8.b, #3
    mov z9.b, #-3
  )");

  CHECK_NEON(0, int8_t, fillNeon<int8_t>({7}, VL / 8));
  CHECK_NEON(1, int8_t, fillNeon<int8_t>({-7}, VL / 8));
  // CHECK_NEON(2, float, {0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f});
  // CHECK_NEON(3, float, {-0.5f, -0.5f, -0.5f, -0.5f, -0.5f, -0.5f, -0.5f,
  // -0.5f}); CHECK_NEON(6, float, {14.5f, 14.5f, 14.5f, 14.5f, 14.5f,
  // 14.5f, 14.5f, 14.5f, 14.5f, 14.5f, 14.5f, 14.5f, 14.5f, 14.5f,
  // 14.5f, 14.5f});
  // CHECK_NEON(7, float, {-14.5f, -14.5f, -14.5f, -14.5f, -14.5f, -14.5f,
  // -14.5f, -14.5f, -14.5f, -14.5f, -14.5f, -14.5f, -14.5f, -14.5f, -14.5f,
  // -14.5f});
  CHECK_NEON(8, int8_t, fillNeon<int8_t>({3}, VL / 8));
  CHECK_NEON(9, int8_t, fillNeon<int8_t>({-3}, VL / 8));

  // 16-bit arrangement
  RUN_AARCH64(R"(
    dup z0.h, #7
    dup z1.h, #-7
    #fdup z2.h, #0.5
    #fdup z3.h, #-0.5

    #fmov d4, #14.5
    #fmov d5, #-14.5
    # check for alias
    #mov z6.h, d4
    #mov z7.h, d5
    mov z8.h, #3
    mov z9.h, #-3
  )");

  CHECK_NEON(0, int16_t, fillNeon<int16_t>({7}, VL / 8));
  CHECK_NEON(1, int16_t, fillNeon<int16_t>({-7}, VL / 8));
  // CHECK_NEON(2, float,
  //            {0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f,
  //            0.5f,
  //             0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f,
  //             0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f,
  //             0.5f});
  // CHECK_NEON(3, float,
  //            {-0.5f, -0.5f, -0.5f, -0.5f, -0.5f, -0.5f, -0.5f, -0.5f,
  //             -0.5f, -0.5f, -0.5f, -0.5f, -0.5f, -0.5f, -0.5f, -0.5f,
  //             -0.5f, -0.5f, -0.5f, -0.5f, -0.5f, -0.5f, -0.5f, -0.5f,
  //             -0.5f, -0.5f, -0.5f, -0.5f, -0.5f, -0.5f, -0.5f, -0.5f});
  // CHECK_NEON(6, float,
  //            {14.5f, 14.5f, 14.5f, 14.5f, 14.5f, 14.5f, 14.5f, 14.5f,
  //             14.5f, 14.5f, 14.5f, 14.5f, 14.5f, 14.5f, 14.5f, 14.5f,
  //             14.5f, 14.5f, 14.5f, 14.5f, 14.5f, 14.5f, 14.5f, 14.5f,
  //             14.5f, 14.5f, 14.5f, 14.5f, 14.5f, 14.5f, 14.5f, 14.5f});
  // CHECK_NEON(7, float,
  //            {-14.5f, -14.5f, -14.5f, -14.5f, -14.5f, -14.5f, -14.5f,
  //            -14.5f,
  //             -14.5f, -14.5f, -14.5f, -14.5f, -14.5f, -14.5f, -14.5f,
  //             -14.5f, -14.5f, -14.5f, -14.5f, -14.5f, -14.5f, -14.5f,
  //             -14.5f, -14.5f, -14.5f, -14.5f, -14.5f, -14.5f, -14.5f,
  //             -14.5f, -14.5f, -14.5f});
  CHECK_NEON(8, int16_t, fillNeon<int16_t>({3}, VL / 8));
  CHECK_NEON(9, int16_t, fillNeon<int16_t>({-3}, VL / 8));

  // 32-bit arrangement
  RUN_AARCH64(R"(
    dup z0.s, #7
    dup z1.s, #-7
    fdup z2.s, #0.5
    fdup z3.s, #-0.5

    mov w0, #9
    mov w1, #-9
    fmov s4, #14.5
    fmov s5, #-14.5
    # check for alias
    mov z6.s, s4
    mov z7.s, s5
    mov z8.s, #3
    mov z9.s, #-3
    mov z10.s, w0
    mov z11.s, w1
  )");
  CHECK_NEON(0, int32_t, fillNeon<int32_t>({7}, VL / 8));
  CHECK_NEON(1, int32_t, fillNeon<int32_t>({-7}, VL / 8));
  CHECK_NEON(2, float, fillNeon<float>({0.5f}, VL / 8));
  CHECK_NEON(3, float, fillNeon<float>({-0.5f}, VL / 8));
  CHECK_NEON(6, float, fillNeon<float>({14.5f}, VL / 8));
  CHECK_NEON(7, float, fillNeon<float>({-14.5f}, VL / 8));
  CHECK_NEON(8, int32_t, fillNeon<int32_t>({3}, VL / 8));
  CHECK_NEON(9, int32_t, fillNeon<int32_t>({-3}, VL / 8));
  CHECK_NEON(10, int32_t, fillNeon<int32_t>({9}, VL / 8));
  CHECK_NEON(11, int32_t, fillNeon<int32_t>({-9}, VL / 8));

  // 64-bit arrangement
  RUN_AARCH64(R"(
    dup z0.d, #7
    dup z1.d, #-7
    fdup z2.d, #0.5
    fdup z3.d, #-0.5

    fmov d4, #14.5
    fmov d5, #-14.5
    # check for alias
    mov z6.d, d4
    mov z7.d, d5
    mov z8.d, #3
    mov z9.d, #-3
  )");
  CHECK_NEON(0, int64_t, fillNeon<int64_t>({7}, VL / 8));
  CHECK_NEON(1, int64_t, fillNeon<int64_t>({-7}, VL / 8));
  CHECK_NEON(2, double, fillNeon<double>({0.5f}, VL / 8));
  CHECK_NEON(3, double, fillNeon<double>({-0.5f}, VL / 8));
  CHECK_NEON(6, double, fillNeon<double>({14.5f}, VL / 8));
  CHECK_NEON(7, double, fillNeon<double>({-14.5f}, VL / 8));
  CHECK_NEON(8, int64_t, fillNeon<int64_t>({3}, VL / 8));
  CHECK_NEON(9, int64_t, fillNeon<int64_t>({-3}, VL / 8));

  // Quadword
  initialHeapData_.resize(48);
  uint64_t* heap = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  heap[0] = 0xDEADBEEF01234567u;
  heap[1] = 0xABCDEF01ABCDEF01u;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]

    dup z1.q, z0.q[0]

    # Check Alias
    mov z2.q, q0
  )");
  std::vector<uint64_t> dresults = {0xDEADBEEF01234567u, 0xABCDEF01ABCDEF01};
  CHECK_NEON(1, uint64_t, fillNeon<uint64_t>(dresults, VL / 8));
  CHECK_NEON(2, uint64_t, fillNeon<uint64_t>(dresults, VL / 8));
}

TEST_P(InstSve, eor) {
  // Predicate, Predicated
  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #2
    addvl x0, x0, #1
    sdiv x0, x0, x1

    ptrue p0.b
    whilelo p1.b, xzr, x0

    eor p2.b, p0/z, p0.b, p1.b
    eor p3.b, p0/z, p1.b, p1.b

    # Test alias of not
    not p4.b, p0/z, p1.b
  )");
  auto p0 = fillPred(VL / 8, {1}, 1);
  auto p1 = fillPred(VL / 16, {1}, 1);
  auto res_p2 = fillPred(VL / 8, {0}, 1);
  for (int i = 0; i < 4; i++) {
    res_p2[i] = p0[i] ^ p1[i];
  }
  CHECK_PREDICATE(2, uint64_t, res_p2);
  CHECK_PREDICATE(3, uint64_t, {0, 0, 0, 0});
  auto res_p4 = fillPred(VL / 8, {0}, 1);
  for (int i = 0; i < (VL / 8); i++) {
    uint64_t shifted_active = 1ull << (i % 64);
    res_p4[i / 64] |=
        (p1[i / 64] & shifted_active) == shifted_active ? 0 : shifted_active;
  }
  CHECK_PREDICATE(4, uint64_t, res_p4);

  // Vectors, Predicated
  RUN_AARCH64(R"(
    # 8-bit
    mov x0, #0
    mov x1, #2
    addvl x0, x0, #1
    sdiv x0, x0, x1
    
    index z0.b, #8, #2
    dup z1.b, #15
    dup z2.b, #3
    ptrue p0.b
    whilelo p1.b, xzr, x0

    eor z0.b, p0/m, z0.b, z1.b
    eor z1.b, p1/m, z1.b, z2.b 

    # 16-bit
    mov x0, #0
    mov x1, #4
    addvl x0, x0, #1
    sdiv x0, x0, x1

    index z3.h, #8, #2
    dup z4.h, #15
    dup z5.h, #3
    ptrue p0.h
    whilelo p1.h, xzr, x0

    eor z3.h, p0/m, z3.h, z4.h
    eor z4.h, p1/m, z4.h, z5.h 

    # 32-bit
    mov x0, #0
    mov x1, #8
    addvl x0, x0, #1
    sdiv x0, x0, x1

    index z6.s, #8, #2
    dup z7.s, #15
    dup z8.s, #3
    ptrue p0.s
    whilelo p1.s, xzr, x0

    eor z6.s, p0/m, z6.s, z7.s
    eor z7.s, p1/m, z7.s, z8.s 

    # 64-bit
    mov x0, #0
    mov x1, #16
    addvl x0, x0, #1
    sdiv x0, x0, x1

    index z9.d, #8, #2
    dup z10.d, #15
    dup z11.d, #3
    ptrue p0.d
    whilelo p1.d, xzr, x0

    eor z9.d, p0/m, z9.d, z10.d
    eor z10.d, p1/m, z10.d, z11.d 
  )");
  auto res_0 = fillNeon<uint8_t>({0}, VL / 8);
  int val = 8;
  for (int i = 0; i < (VL / 8); i++) {
    res_0[i] = val ^ 15;
    val += 2;
  }
  CHECK_NEON(0, uint8_t, res_0);
  CHECK_NEON(1, uint8_t, fillNeonCombined<uint8_t>({12}, {15}, VL / 8));

  auto res_3 = fillNeon<uint16_t>({0}, VL / 8);
  val = 8;
  for (int i = 0; i < (VL / 16); i++) {
    res_3[i] = val ^ 15;
    val += 2;
  }
  CHECK_NEON(3, uint16_t, res_3);
  CHECK_NEON(4, uint16_t, fillNeonCombined<uint16_t>({12}, {15}, VL / 8));

  auto res_6 = fillNeon<uint32_t>({0}, VL / 8);
  val = 8;
  for (int i = 0; i < (VL / 32); i++) {
    res_6[i] = val ^ 15;
    val += 2;
  }
  CHECK_NEON(6, uint32_t, res_6);
  CHECK_NEON(7, uint32_t, fillNeonCombined<uint32_t>({12}, {15}, VL / 8));

  auto res_9 = fillNeon<uint64_t>({0}, VL / 8);
  val = 8;
  for (int i = 0; i < (VL / 64); i++) {
    res_9[i] = val ^ 15;
    val += 2;
  }
  CHECK_NEON(9, uint64_t, res_9);
  CHECK_NEON(10, uint64_t, fillNeonCombined<uint64_t>({12}, {15}, VL / 8));
}

TEST_P(InstSve, inc) {
  // pattern = all
  RUN_AARCH64(R"(
    mov x0, #64
    mov x1, #96
    mov x2, #128
    mov x3, #160
    mov x4, #64
    mov x5, #96
    mov x6, #128
    mov x7, #160
    incb x0
    incd x1
    inch x2
    incw x3
    incb x4, all, mul #3
    incd x5, all, mul #3
    inch x6, all, mul #3
    incw x7, all, mul #3
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 64 + (VL / 8));
  EXPECT_EQ(getGeneralRegister<uint64_t>(1), 96 + (VL / 64));
  EXPECT_EQ(getGeneralRegister<uint64_t>(2), 128 + (VL / 16));
  EXPECT_EQ(getGeneralRegister<uint64_t>(3), 160 + (VL / 32));
  EXPECT_EQ(getGeneralRegister<uint64_t>(4), 64 + (VL / 8) * 3);
  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 96 + (VL / 64) * 3);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 128 + (VL / 16) * 3);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 160 + (VL / 32) * 3);

  // pattern != all
  RUN_AARCH64(R"(
    mov x0, #64
    mov x1, #96
    mov x2, #128
    mov x3, #160
    mov x4, #64
    mov x5, #96
    mov x6, #128
    mov x7, #160
    incb x0, pow2, mul #2
    incd x1, vl16, mul #2
    inch x2, vl6, mul #2
    incw x3, vl7, mul #2
    incb x4, vl256, mul #2
    incd x5, vl64, mul #2
    inch x6, vl2, mul #2
    incw x7, mul3, mul #2
  )");
  uint16_t maxElemsB = VL / 8;
  uint16_t maxElemsH = VL / 16;
  uint16_t maxElemsS = VL / 32;
  uint16_t maxElemsD = VL / 64;
  uint16_t n = 1;
  while (maxElemsB >= std::pow(2, n)) {
    n = n + 1;
  }
  uint16_t pow2B = std::pow(2, n - 1);

  EXPECT_EQ(getGeneralRegister<int64_t>(0), 64 + (pow2B * 2));
  EXPECT_EQ(getGeneralRegister<int64_t>(1),
            (maxElemsD >= 16) ? (96 + (16 * 2)) : 96);
  EXPECT_EQ(getGeneralRegister<int64_t>(2),
            (maxElemsH >= 6) ? (128 + (6 * 2)) : 128);
  EXPECT_EQ(getGeneralRegister<int64_t>(3),
            (maxElemsS >= 7) ? (160 + (7 * 2)) : 160);
  EXPECT_EQ(getGeneralRegister<int64_t>(4),
            (maxElemsB >= 256) ? (64 + (256 * 2)) : 64);
  EXPECT_EQ(getGeneralRegister<int64_t>(5),
            (maxElemsD >= 64) ? (96 + (64 * 2)) : 96);
  EXPECT_EQ(getGeneralRegister<int64_t>(6),
            (maxElemsH >= 2) ? (128 + (2 * 2)) : 128);
  EXPECT_EQ(getGeneralRegister<int64_t>(7),
            160 + ((maxElemsS - (maxElemsS % 3)) * 2));

  // pattern = all
  // Vector Variants
  RUN_AARCH64(R"(
    dup z0.s, #15
    dup z1.s, #37
    dup z2.h, #25
    dup z3.h, #19
    dup z4.d, #3
    dup z5.d, #84

    incw z0.s
    incw z1.s, all, mul #3
    inch z2.h
    inch z3.h, all, mul #2
    incd z4.d
    incd z5.d, all, mul #5
  )");
  CHECK_NEON(0, int32_t,
             fillNeon<int32_t>({(int32_t)(15 + ((VL / 32)))}, (VL / 8)));
  CHECK_NEON(1, int32_t,
             fillNeon<int32_t>({(int32_t)(37 + ((VL / 32) * 3))}, (VL / 8)));
  CHECK_NEON(2, int16_t,
             fillNeon<int16_t>({(int16_t)(25 + ((VL / 16)))}, (VL / 8)));
  CHECK_NEON(3, int16_t,
             fillNeon<int16_t>({(int16_t)(19 + ((VL / 16) * 2))}, (VL / 8)));
  CHECK_NEON(4, int64_t,
             fillNeon<int64_t>({(int64_t)(3 + ((VL / 64)))}, (VL / 8)));
  CHECK_NEON(5, int64_t,
             fillNeon<int64_t>({(int64_t)(84 + ((VL / 64) * 5))}, (VL / 8)));

  // pattern != all
  // Vector Variants
  RUN_AARCH64(R"(
    dup z0.s, #15
    dup z1.s, #37
    dup z2.h, #25
    dup z3.h, #19
    dup z4.d, #3
    dup z5.d, #84

    incw z0.s, pow2, mul #3
    incw z1.s, mul3, mul #2
    inch z2.h, vl2, mul #3
    inch z3.h, vl128, mul #3
    incd z4.d, vl7, mul #3
    incd z5.d, vl1, mul#3 
  )");
  n = 1;
  while (maxElemsS >= std::pow(2, n)) {
    n = n + 1;
  }
  uint16_t pow2S = std::pow(2, n - 1);

  CHECK_NEON(0, int32_t,
             fillNeon<int32_t>({(int32_t)(15 + (pow2S * 3))}, (VL / 8)));
  CHECK_NEON(
      1, int32_t,
      fillNeon<int32_t>({(int32_t)(37 + ((maxElemsS - (maxElemsS % 3)) * 2))},
                        (VL / 8)));
  CHECK_NEON(
      2, int16_t,
      fillNeon<int16_t>({(int16_t)((maxElemsH >= 2) ? (25 + (2 * 3)) : 25)},
                        (VL / 8)));
  CHECK_NEON(
      3, int16_t,
      fillNeon<int16_t>({(int16_t)((maxElemsH >= 128) ? (19 + (128 * 3)) : 19)},
                        (VL / 8)));
  CHECK_NEON(4, int64_t,
             fillNeon<int64_t>(
                 {(int64_t)((maxElemsD >= 7) ? (3 + (7 * 3)) : 3)}, (VL / 8)));
  CHECK_NEON(
      5, int64_t,
      fillNeon<int64_t>({(int64_t)((maxElemsD >= 1) ? (84 + (1 * 3)) : 84)},
                        (VL / 8)));
}

TEST_P(InstSve, fabs) {
  // float
  initialHeapData_.resize(VL / 4);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  std::vector<float> src_f = {
      1.0f,    -42.76f, -0.125f, 0.0f,   40.26f,   -684.72f, -0.15f,  107.86f,
      -34.71f, -0.917f, 0.0f,    80.72f, -125.67f, -0.01f,   701.90f, 7.0f};
  fillHeap<float>(fheap, src_f, VL / 32);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #0
    mov x3, #8
    addvl x2, x2, #1
    sdiv x2, x2, x3
    whilelo p0.s, xzr, x2
    ptrue p1.s

    ld1w {z0.s}, p1/z, [x0, x1, lsl #2]
    ld1w {z1.s}, p0/z, [x0, x2, lsl #2]

    fabs z2.s, p1/m, z0.s
    fabs z3.s, p0/m, z1.s
  )");

  std::vector<float> results = {
      1.0f,   42.76f, 0.125f, 0.0f,   40.26f,  684.72f, 0.15f,   107.86f,
      34.71f, 0.917f, 0.0f,   80.72f, 125.67f, 0.01f,   701.90f, 7.0f};
  CHECK_NEON(2, float, fillNeon<float>(results, VL / 8));
  std::rotate(results.begin(), results.begin() + ((VL / 64) % 16),
              results.end());
  CHECK_NEON(3, float, fillNeon<float>(results, VL / 16));

  // double
  initialHeapData_.resize(VL / 4);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  std::vector<double> dsrcA = {1.0, -42.76, -0.125, 0.0};
  std::vector<double> dsrcB = {-34.71, -0.917, 0.0, 80.72};
  fillHeapCombined<double>(dheap, dsrcA, dsrcB, VL / 64);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #0
    mov x3, #16
    addvl x2, x2, #1
    sdiv x2, x2, x3

    whilelo p0.d, xzr, x2
    ptrue p1.d

    ld1d {z0.d}, p1/z, [x0, x1, lsl #3]
    ld1d {z1.d}, p0/z, [x0, x2, lsl #3]

    fdup z3.d, #3.0

    fabs z2.d, p1/m, z0.d
    fabs z3.d, p0/m, z1.d
  )");
  std::vector<double> res_2_0 = {1.0, 42.76, 0.125, 0.0};
  std::vector<double> res_2_1 = {34.71, 0.917, 0.0, 80.72};
  CHECK_NEON(2, double, fillNeonCombined<double>(res_2_0, res_2_1, VL / 8));

  std::vector<double> src_3 = {34.71, 0.917, 0.0, 80.72};
  CHECK_NEON(3, double, fillNeonCombined<double>(src_3, {3.0}, VL / 8));
}

TEST_P(InstSve, add) {
  // Unpredicated
  RUN_AARCH64(R"(
    dup z0.b, #8
    dup z1.h, #7
    dup z2.s, #6
    dup z3.d, #5

    add z0.b, z0.b, z0.b
    add z1.h, z1.h, z1.h
    add z2.s, z2.s, z2.s
    add z3.d, z3.d, z3.d
  )");
  CHECK_NEON(0, uint8_t, fillNeon<uint8_t>({16}, VL / 8));
  CHECK_NEON(1, uint16_t, fillNeon<uint16_t>({14}, VL / 8));
  CHECK_NEON(2, uint32_t, fillNeon<uint32_t>({12}, VL / 8));
  CHECK_NEON(3, uint64_t, fillNeon<uint64_t>({10}, VL / 8));

  // Predicated
  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #0
    mov x2, #0
    mov x3, #0
    mov x4, #2
    mov x5, #4
    mov x6, #8
    mov x7, #16

    addvl x0, x0, #1
    sdiv x0, x0, x4
    addvl x1, x1, #1
    sdiv x1, x1, x5
    addvl x2, x2, #1
    sdiv x2, x2, x6
    addvl x3, x3, #1
    sdiv x3, x3, x7

    ptrue p0.b
    ptrue p1.h
    ptrue p2.s
    ptrue p3.d
    whilelo p4.b, xzr, x0
    whilelo p5.h, xzr, x1
    whilelo p6.s, xzr, x2
    whilelo p7.d, xzr, x3

    dup z0.b, #8
    dup z1.b, #8
    dup z2.h, #7
    dup z3.h, #7
    dup z4.s, #6
    dup z5.s, #6
    dup z6.d, #5
    dup z7.d, #5

    add z0.b, p0/m, z0.b, z0.b
    add z1.b, p4/m, z1.b, z1.b
    add z2.h, p1/m, z2.h, z2.h
    add z3.h, p5/m, z3.h, z3.h
    add z4.s, p2/m, z4.s, z4.s
    add z5.s, p6/m, z5.s, z5.s
    add z6.d, p3/m, z6.d, z6.d
    add z7.d, p7/m, z7.d, z7.d
  )");
  CHECK_NEON(0, uint8_t, fillNeon<uint8_t>({16}, VL / 8));
  CHECK_NEON(1, uint8_t, fillNeonCombined<uint8_t>({16}, {8}, VL / 8));
  CHECK_NEON(2, uint16_t, fillNeon<uint16_t>({14}, VL / 8));
  CHECK_NEON(3, uint16_t, fillNeonCombined<uint16_t>({14}, {7}, VL / 8));
  CHECK_NEON(4, uint32_t, fillNeon<uint32_t>({12}, VL / 8));
  CHECK_NEON(5, uint32_t, fillNeonCombined<uint32_t>({12}, {6}, VL / 8));
  CHECK_NEON(6, uint64_t, fillNeon<uint64_t>({10}, VL / 8));
  CHECK_NEON(7, uint64_t, fillNeonCombined<uint64_t>({10}, {5}, VL / 8));
}

TEST_P(InstSve, fcadd) {
  // double
  initialHeapData_.resize(VL / 4);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  std::vector<double> dsrcA = {1.0,     -42.76, -0.125, 0.0,    40.26, -684.72,
                               -0.15,   107.86, -34.71, -0.917, 0.0,   80.72,
                               -125.67, -0.01,  701.90, 7.0};
  fillHeap<double>(dheap, dsrcA, VL / 32);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ptrue p0.d

    mov x1, #0
    ld1d {z0.d}, p0/z, [x0, x1, lsl #3]
    ld1d {z1.d}, p0/z, [x0, x1, lsl #3]
    ld1d {z3.d}, p0/z, [x0, x1, lsl #3]

    fcadd z0.d, p0/m, z0.d, z1.d, #90
    fcadd z1.d, p0/m, z1.d, z3.d, #270
  )");

  std::vector<double> dresults1 = {
      43.76,   -41.76,  -0.125, -0.125, 724.98,  -644.46, -108.01, 107.71,
      -33.793, -35.627, -80.72, 80.72,  -125.66, -125.68, 694.90,  708.90};
  CHECK_NEON(0, double, fillNeon<double>(dresults1, VL / 8));

  std::vector<double> dresults2 = {
      -41.76,  -43.76, -0.125, 0.125, -644.46, -724.98, 107.71, 108.01,
      -35.627, 33.793, 80.72,  80.72, -125.68, 125.66,  708.90, -694.90};
  CHECK_NEON(1, double, fillNeon<double>(dresults2, VL / 8));

  // VL=512-bit check only (used to verify functionality - values used directly
  // from A64FX).
  if (VL == 512) {
    initialHeapData_.resize(256);
    double* heap = reinterpret_cast<double*>(initialHeapData_.data());
    heap[0] = -0.0064000000000001833;
    heap[1] = -1.0064;
    heap[2] = -0.0064000000000001833;
    heap[3] = -0.0064000000000001833;
    heap[4] = -0.0063999999999997392;
    heap[5] = 0.99360000000000004;
    heap[6] = -0.0064000000000010715;
    heap[7] = -2.0064000000000002;

    heap[8] = 0.0064000000000001833;
    heap[9] = -0.99360000000000004;
    heap[10] = 0.0064000000000001833;
    heap[11] = 2.0064000000000002;
    heap[12] = 0.0064000000000001833;
    heap[13] = 0.0064000000000000723;
    heap[14] = 0.0064000000000001833;
    heap[15] = -1.9935999999999994;

    heap[16] = -0.0064000000000001833;
    heap[17] = -1.0064;
    heap[18] = -0.0064000000000001833;
    heap[19] = -0.0064000000000001833;
    heap[20] = -0.0063999999999997392;
    heap[21] = 0.99360000000000004;
    heap[22] = -0.0064000000000010715;
    heap[23] = -2.0064000000000002;

    RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ptrue p0.d

    mov x1, #0
    mov x2, #8
    mov x3, #16
    ld1d {z0.d}, p0/z, [x0, x1, lsl #3]
    ld1d {z1.d}, p0/z, [x0, x2, lsl #3]
    ld1d {z3.d}, p0/z, [x0, x3, lsl #3]

    fcadd z0.d, p0/m, z0.d, z1.d, #270
    fcadd z3.d, p0/m, z3.d, z1.d, #90
  )");
    CHECK_NEON(0, double,
               {-1.0000000000000002, -1.0128000000000001, 2,
                -0.012800000000000367, 3.3306690738754696e-16,
                0.98719999999999986, -2.0000000000000004, -2.0128000000000004});
    CHECK_NEON(
        3, double,
        {0.98719999999999986, -0.99999999999999978, -2.0128000000000004, 0,
         -0.012799999999999812, 1.0000000000000002, 1.9871999999999983, -2});
  }
}

TEST_P(InstSve, fcmla) {
  // double
  initialHeapData_.resize(VL / 4);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  std::vector<double> dsrcA = {1.0,     -42.76, -0.125, 0.0,    40.26, -684.72,
                               -0.15,   107.86, -34.71, -0.917, 0.0,   80.72,
                               -125.67, -0.01,  701.90, 7.0};
  fillHeap<double>(dheap, dsrcA, VL / 32);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ptrue p0.d

    mov x1, #0
    ld1d {z0.d}, p0/z, [x0, x1, lsl #3]
    ld1d {z1.d}, p0/z, [x0, x1, lsl #3]

    ld1d {z2.d}, p0/z, [x0, x1, lsl #3]
    ld1d {z3.d}, p0/z, [x0, x1, lsl #3]
    ld1d {z4.d}, p0/z, [x0, x1, lsl #3]
    ld1d {z5.d}, p0/z, [x0, x1, lsl #3]

    fcmla z2.d, p0/m, z0.d, z1.d, #0
    fcmla z3.d, p0/m, z0.d, z1.d, #90
    fcmla z4.d, p0/m, z0.d, z1.d, #180
    fcmla z5.d, p0/m, z0.d, z1.d, #270
  )");

  std::vector<double> dresults1 = {2.0,
                                   -85.52,
                                   -0.109375,
                                   0.0,
                                   1661.1275999999998,
                                   -28251.5472,
                                   -0.1275,
                                   91.681,
                                   1170.0741,
                                   30.91207,
                                   0.0,
                                   80.72,
                                   15667.278900000001,
                                   1.2467000000000001,
                                   493365.51,
                                   4920.3};
  CHECK_NEON(2, double, fillNeon<double>(dresults1, VL / 8));

  std::vector<double> dresults2 = {-1827.4175999999998,
                                   -85.52,
                                   -0.125,
                                   0.0,
                                   -468801.2184,
                                   -28251.5472,
                                   -11633.9296,
                                   91.681,
                                   -35.550889,
                                   30.91207,
                                   -6515.7184,
                                   80.72,
                                   -125.6701,
                                   1.2467000000000001,
                                   652.9,
                                   4920.3};
  CHECK_NEON(3, double, fillNeon<double>(dresults2, VL / 8));

  std::vector<double> dresults3 = {0.0,
                                   0.0,
                                   -0.140625,
                                   0.0,
                                   -1580.6075999999998,
                                   26882.1072,
                                   -0.1725,
                                   124.039,
                                   -1239.4941000000001,
                                   -32.74607,
                                   0.0,
                                   80.72,
                                   -15918.618900000001,
                                   -1.2667000000000002,
                                   -491961.70999999996,
                                   -4906.3};
  CHECK_NEON(4, double, fillNeon<double>(dresults3, VL / 8));

  std::vector<double> dresults4 = {1829.4175999999998,
                                   0.0,
                                   -0.125,
                                   0.0,
                                   468881.73840000003,
                                   26882.1072,
                                   11633.6296,
                                   124.039,
                                   -33.869111000000004,
                                   -32.74607,
                                   6515.7184,
                                   80.72,
                                   -125.6699,
                                   -1.2667000000000002,
                                   750.9,
                                   -4906.3};
  CHECK_NEON(5, double, fillNeon<double>(dresults4, VL / 8));

  // VL=512-bit check only (used to verify functionality - values used directly
  // from A64FX).
  if (VL == 512) {
    initialHeapData_.resize(1024);
    double* heap = reinterpret_cast<double*>(initialHeapData_.data());
    // z0
    heap[0] = 0.0;
    heap[1] = 0.0;
    heap[2] = 0.0;
    heap[3] = 0.0;
    heap[4] = 0.0;
    heap[5] = 0.0;
    heap[6] = 0.0;
    heap[7] = 0.0;
    // z4
    heap[8] = 1.0;
    heap[9] = 0.0;
    heap[10] = 0.97003125319454409;
    heap[11] = 0.2429801799032639;
    heap[12] = 0.88192126434835505;
    heap[13] = 0.47139673682599764;
    heap[14] = 0.74095112535495899;
    heap[15] = 0.67155895484701855;
    // z6
    heap[16] = 16.103999999999999;
    heap[17] = 6.1040000000000001;
    heap[18] = -0.038574972749605967;
    heap[19] = 0.728081577463774;
    heap[20] = -0.021850966799187334;
    heap[21] = 0.83747809154537889;
    heap[22] = -0.015978276881058861;
    heap[23] = 1.1360872715821027;

    // z5
    heap[24] = 16.0976;
    heap[25] = 6.0975999999999999;
    heap[26] = -0.30696587505245193;
    heap[27] = 0.67380905904559341;
    heap[28] = -0.60471146423958411;
    heap[29] = 0.59197309973817958;
    heap[30] = -1.0511481307439354;
    heap[31] = 0.43199690405464586;
    // z7
    heap[32] = 1.0;
    heap[33] = 0.0;
    heap[34] = 0.99879545620517241;
    heap[35] = 0.049067674327418015;
    heap[36] = 0.99518472667219693;
    heap[37] = 0.098017140329560604;
    heap[38] = 0.98917650996478101;
    heap[39] = 0.14673047445536175;
    // z16
    heap[40] = 16.0976;
    heap[41] = 6.0975999999999999;
    heap[42] = -0.30733607481429615;
    heap[43] = 0.67462167039252097;
    heap[44] = -0.6076374044260926;
    heap[45] = 0.59483740442609212;
    heap[46] = -1.0626497092832914;
    heap[47] = 0.43672377953053781;

    // z2
    heap[48] = 1.0;
    heap[49] = 0.0;
    heap[50] = 0.98798500353771368;
    heap[51] = 0.14655373117284443;
    heap[52] = 0.95233240645725858;
    heap[53] = 0.28888687719060901;
    heap[54] = 0.89420497401737709;
    heap[55] = 0.42292745513703228;
    // z7
    heap[56] = 1.0;
    heap[57] = 0.0;
    heap[58] = 0.99879545620517241;
    heap[59] = 0.049067674327418015;
    heap[60] = 0.99518472667219693;
    heap[61] = 0.098017140329560604;
    heap[62] = 0.98917650996478101;
    heap[63] = 0.14673047445536175;
    // z3
    heap[64] = 1.0;
    heap[65] = 0.0;
    heap[66] = 0.98917650996478101;
    heap[67] = 0.14673047445536175;
    heap[68] = 0.95694033573220882;
    heap[69] = 0.29028467725446233;
    heap[70] = 0.90398929312344334;
    heap[71] = 0.42755509343028208;
    RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ptrue p0.d

    mov x1, #0
    mov x2, #8
    mov x3, #16
    mov x4, #24
    mov x5, #32
    mov x6, #40
    mov x7, #48
    mov x8, #56
    mov x9, #64

    ld1d {z0.d}, p0/z, [x0, x1, lsl #3]
    ld1d {z4.d}, p0/z, [x0, x2, lsl #3]
    ld1d {z6.d}, p0/z, [x0, x3, lsl #3]
    fcmla z0.d, p0/m, z4.d, z6.d, #0

    ld1d {z5.d}, p0/z, [x0, x4, lsl #3]
    ld1d {z7.d}, p0/z, [x0, x5, lsl #3]
    ld1d {z16.d}, p0/z, [x0, x6, lsl #3]
    fcmla z5.d, p0/m, z7.d, z16.d, #270

    ld1d {z2.d}, p0/z, [x0, x7, lsl #3]
    ld1d {z7.d}, p0/z, [x0, x8, lsl #3]
    ld1d {z3.d}, p0/z, [x0, x9, lsl #3]
    fcmla z2.d, p0/m, z7.d, z3.d, #90
  )");
    CHECK_NEON(0, double,
               {16.103999999999999, 6.1040000000000001, -0.037418929158245663,
                0.70626188501504517, -0.019270832266773223, 0.73858973735974798,
                -0.011839122236253687, 0.84178514238020385});
    CHECK_NEON(5, double,
               {16.0976, 6.0975999999999999, -0.27386375863541296,
                0.68888932547364823, -0.54640720289668021, 0.65153198047730188,
                -0.98706744336748087, 0.58792000007763545});
    CHECK_NEON(
        2, double,
        {1, 0, 0.98078528040323043, 0.19509032201612825, 0.92387953251128674,
         0.38268343236508978, 0.83146961230254524, 0.55557023301960218});
  }
}

TEST_P(InstSve, fadd) {
  // double
  initialHeapData_.resize(VL / 4);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  std::vector<double> dsrcA = {1.0,   -42.76,  -0.125, 0.0,
                               40.26, -684.72, -0.15,  107.86};
  std::vector<double> dsrcB = {-34.71,  -0.917, 0.0,    80.72,
                               -125.67, -0.01,  701.90, 7.0};
  fillHeapCombined<double>(dheap, dsrcA, dsrcB, VL / 32);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #0
    mov x3, #0
    mov x4, #8
    mov x5, #2
    addvl x3, x3, #1
    sdiv x3, x3, x4
    sdiv x2, x3, x5

    whilelo p0.d, xzr, x2
    ptrue p1.d

    ld1d {z0.d}, p0/z, [x0, x1, lsl #3]
    ld1d {z1.d}, p0/z, [x0, x3, lsl #3]
    ld1d {z3.d}, p1/z, [x0, x1, lsl #3]
    ld1d {z4.d}, p1/z, [x0, x3, lsl #3]

    fadd z2.d, z1.d, z0.d
    fadd z4.d, p0/m, z4.d, z3.d

    # FADD with constant
    ld1d {z5.d}, p1/z, [x0, x1, lsl #3]
    fadd z5.d, p1/m, z5.d, 0.5
  )");

  std::vector<double> dresults = {-33.71, -43.677, -0.125, 80.72,
                                  -85.41, -684.73, 701.75, 114.86};
  CHECK_NEON(2, double, fillNeon<double>(dresults, VL / 16));

  std::rotate(dsrcB.begin(), dsrcB.begin() + ((VL / 128) % 8), dsrcB.end());
  CHECK_NEON(4, double, fillNeonCombined<double>(dresults, dsrcB, VL / 8));

  std::vector<double> dresults_5 = {1.5,   -42.26,  0.375, 0.5,
                                    40.76, -684.22, 0.35,  108.36};
  CHECK_NEON(5, double, fillNeon<double>(dresults_5, VL / 8));

  // float
  initialHeapData_.resize(VL / 8);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  std::vector<float> fsrcA = {1.0f,   -42.76f,  -0.125f, 0.0f,
                              40.26f, -684.72f, -0.15f,  107.86f};
  std::vector<float> fsrcB = {-34.71f,  -0.917f, 0.0f,    80.72f,
                              -125.67f, -0.01f,  701.90f, 7.0f};
  fillHeapCombined<float>(fheap, fsrcA, fsrcB, VL / 32);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #0
    mov x3, #8
    addvl x2, x2, #1
    sdiv x2, x2, x3

    whilelo p0.s, xzr, x2
    ptrue p1.s

    ld1w {z0.s}, p0/z, [x0, x1, lsl #2]
    ld1w {z1.s}, p0/z, [x0, x2, lsl #2]
    ld1w {z3.s}, p0/z, [x0, x2, lsl #2]
    ld1w {z4.s}, p1/z, [x0, x1, lsl #2]
    ld1w {z5.s}, p0/z, [x0, x1, lsl #2]
    
    fadd z2.s, z1.s, z0.s

    fadd z4.s, p1/m, z4.s, z3.s
    fadd z5.s, p0/m, z5.s, z3.s

    # FADD with constant
    fadd z3.s, p1/m, z3.s, 0.5
  )");

  std::vector<float> fresults = {-33.71f, -43.677f, -0.125f, 80.72f,
                                 -85.41f, -684.73f, 701.75f, 114.86f};
  CHECK_NEON(2, float, fillNeon<float>(fresults, VL / 16));

  std::vector<float> fsrc_3 = {-34.21f,  -0.417f, 0.5f,    81.22f,
                               -125.17f, 0.49f,   702.40f, 7.5f};
  CHECK_NEON(3, float, fillNeonCombined<float>(fsrc_3, {0.5}, VL / 8));

  CHECK_NEON(4, float, fillNeonCombined<float>(fresults, fsrcB, VL / 8));
  CHECK_NEON(5, float, fillNeonCombined<float>(fresults, {0}, VL / 8));
}

TEST_P(InstSve, fadda) {
  // double
  initialHeapData_.resize(VL / 8);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  std::vector<double> dsrc = {1.0,    -42.76, -0.125, 0.0,
                              -34.71, -0.917, 0.0,    80.72};
  fillHeap<double>(dheap, dsrc, VL / 64);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    fmov d1, 2.75
    fmov d3, 2.75

    mov x1, #0
    mov x2, #0
    mov x3, #16
    addvl x2, x2, #1
    sdiv x2, x2, x3
    whilelo p1.d, xzr, x2
    ptrue p0.d

    ld1d {z0.d}, p0/z, [x0, x1, lsl #3]
    ld1d {z2.d}, p1/z, [x0, x2, lsl #3]

    fadda d1, p1, d1, z0.d
    fadda d3, p1, d3, z2.d
  )");
  double resultA = 2.75;
  double resultB = 2.75;
  for (int i = 0; i < VL / 128; i++) {
    resultA += dsrc[i % 8];
    resultB += dsrc[(i + VL / 128) % 8];
  }
  CHECK_NEON(1, double, {resultA, 0});
  CHECK_NEON(3, double, {resultB, 0});
}

TEST_P(InstSve, fcmge) {
  // double
  initialHeapData_.resize(VL / 16);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  std::vector<double> dsrc = {1.0, -42.76, -0.125, 1.0};
  fillHeap<double>(dheap, dsrc, VL / 128);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #0
    mov x3, #16
    addvl x2, x2, #1
    sdiv x2, x2, x3

    whilelo p0.d, xzr, x2
    ptrue p1.d
    
    ld1d {z0.d}, p0/z, [x0, x1, lsl #3]
    ld1d {z1.d}, p1/z, [x0, x1, lsl #3]
    dup z2.d, #0

    fcmge p2.d, p0/z, z0.d, #0.0
    fcmge p3.d, p0/z, z1.d, z2.d
  )");

  CHECK_PREDICATE(2, uint64_t, fillPred(VL / 16, {1, 0, 0, 1}, 8));
  CHECK_PREDICATE(3, uint64_t, fillPred(VL / 16, {1, 0, 0, 1}, 8));

  // float
  initialHeapData_.resize(VL / 16);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  std::vector<float> fsrc = {1.0,   -42.76,  -0.125, 0.0,
                             40.26, -684.72, -0.15,  107.86};
  fillHeap<float>(fheap, fsrc, VL / 64);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #0
    mov x3, #8
    addvl x2, x2, #1
    sdiv x2, x2, x3

    whilelo p0.s, xzr, x2
    ptrue p1.s

    ld1w {z0.s}, p0/z, [x0, x1, lsl #2]
    ld1w {z1.s}, p1/z, [x0, x1, lsl #2]
    dup z2.s, #0

    fcmge p2.s, p0/z, z0.s, #0.0
    fcmge p3.s, p0/z, z1.s, z2.s

  )");

  CHECK_PREDICATE(2, uint64_t, fillPred(VL / 16, {1, 0, 0, 1}, 4));
  CHECK_PREDICATE(3, uint64_t, fillPred(VL / 16, {1, 0, 0, 1}, 4));
}

TEST_P(InstSve, fcmgt) {
  // double
  initialHeapData_.resize(VL / 8);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  std::vector<double> dsrcA = {1.0, -42.76, -0.125, 0.0};
  std::vector<double> dsrcB = {-34.71, -0.917, 0.0, 80.72};
  fillHeapCombined<double>(dheap, dsrcA, dsrcB, VL / 64);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #0
    mov x3, #16
    addvl x2, x2, #1
    sdiv x2, x2, x3
    whilelo p0.d, xzr, x2
    ptrue p1.d

    ld1d {z0.d}, p1/z, [x0, x1, lsl #3]
    ld1d {z1.d}, p0/z, [x0, x2, lsl #3]
    ld1d {z2.d}, p1/z, [x0, x1, lsl #3]

    fcmgt p2.d, p0/z, z0.d, z1.d
    fcmgt p3.d, p0/z, z2.d, #0.0
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(VL / 16, {1, 0, 0, 0}, 8));
  CHECK_PREDICATE(3, uint64_t, fillPred(VL / 16, {1, 0, 0, 0}, 8));

  // float
  initialHeapData_.resize(VL / 8);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  std::vector<float> fsrcA = {1.0f, -42.76f, -0.125f, 0.0f};
  std::vector<float> fsrcB = {-34.71f, -0.917f, 0.0f, 80.72f};
  fillHeapCombined<float>(fheap, fsrcA, fsrcB, VL / 32);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #0
    mov x3, #8
    addvl x2, x2, #1
    sdiv x2, x2, x3
    whilelo p0.s, xzr, x2
    ptrue p1.s

    ld1w {z0.s}, p1/z, [x0, x1, lsl #2]
    ld1w {z1.s}, p0/z, [x0, x2, lsl #2]
    ld1w {z2.s}, p1/z, [x0, x1, lsl #2]


    fcmgt p2.s, p0/z, z0.s, z1.s
    fcmgt p3.s, p0/z, z2.s, #0.0
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(VL / 16, {1, 0, 0, 0, 1, 0, 0, 0}, 4));
  CHECK_PREDICATE(3, uint64_t, fillPred(VL / 16, {1, 0, 0, 0, 1, 0, 0, 0}, 4));
}

TEST_P(InstSve, fcmle) {
  // float
  initialHeapData_.resize(VL / 8);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  std::vector<float> fsrcA = {1.0f,    -42.76f, -0.125f, 0.0f,
                              -34.71f, -0.917f, 0.0f,    80.72f};
  fillHeap<float>(fheap, fsrcA, VL / 32);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #0
    mov x3, #8
    addvl x2, x2, #1
    sdiv x2, x2, x3

    whilelo p1.s, xzr, x2
    ptrue p0.s

    ld1w {z0.s}, p0/z, [x0, x1, lsl #2]
    ld1w {z1.s}, p0/z, [x0, x1, lsl #2]

    fcmle p2.s, p0/z, z0.s, #0.0
    fcmle p3.s, p1/z, z1.s, #0.0
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(VL / 8, {0, 1, 1, 1, 1, 1, 1, 0}, 4));
  CHECK_PREDICATE(3, uint64_t, fillPred(VL / 16, {0, 1, 1, 1, 1, 1, 1, 0}, 4));

  // double
  initialHeapData_.resize(VL / 8);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  std::vector<double> dsrcA = {1.0,    -42.76, -0.125, 0.0,
                               -34.71, -0.917, 0.0,    80.72};
  fillHeap<double>(dheap, dsrcA, VL / 64);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #0
    mov x3, #16
    addvl x2, x2, #1
    sdiv x2, x2, x3
    whilelo p1.d, xzr, x2
    ptrue p0.d

    ld1d {z0.d}, p0/z, [x0, x1, lsl #3]
    ld1d {z1.d}, p0/z, [x0, x1, lsl #3]

    fcmle p2.d, p0/z, z0.d, #0.0
    fcmle p3.d, p1/z, z1.d, #0.0
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(VL / 8, {0, 1, 1, 1, 1, 1, 1, 0}, 8));
  CHECK_PREDICATE(3, uint64_t, fillPred(VL / 16, {0, 1, 1, 1, 1, 1, 1, 0}, 8));
}

TEST_P(InstSve, fcmlt) {
  // float
  initialHeapData_.resize(VL / 16);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  std::vector<float> fsrc = {1.0,   -42.76,  -0.125, 0.0,
                             40.26, -684.72, -0.15,  107.86};
  fillHeap<float>(fheap, fsrc, VL / 64);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #0
    mov x3, #8
    addvl x2, x2, #1
    sdiv x2, x2, x3
    whilelo p0.s, xzr, x2

    ld1w {z0.s}, p0/z, [x0, x1, lsl #2]

    fcmlt p1.s, p0/z, z0.s, #0.0
  )");

  CHECK_PREDICATE(1, uint64_t, fillPred(VL / 16, {0, 1, 1, 0}, 4));
}

TEST_P(InstSve, fcvtzs) {
  // double
  initialHeapData_.resize(VL / 4);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  std::vector<double> dsrcA = {1.0, -1.0, 4.5, -4.5, 3.2, -3.2, 7.9, -7.9};
  std::vector<double> dsrcB = {1000000000000000000000000000.66,
                               -114458013083425, -10698505, 0};
  fillHeapCombined<double>(dheap, dsrcA, dsrcB, VL / 32);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #0
    mov x3, #0
    mov x4, #8
    mov x5, #2
    addvl x3, x3, #1
    sdiv x3, x3, x4
    sdiv x2, x3, x5

    ptrue p0.d
    whilelo p1.d, xzr, x2

    ld1d {z0.d}, p0/z, [x0, x1, lsl #3]
    ld1d {z3.d}, p1/z, [x0, x3, lsl #3]

    # Double to Int32
    dup z1.s, #1
    dup z2.s, #1
    dup z4.s, #1
    fcvtzs z1.s, p0/m, z0.d
    fcvtzs z2.s, p1/m, z0.d
    fcvtzs z4.s, p1/m, z3.d

    # Double to Int64
    dup z5.d, #1
    dup z6.d, #1
    dup z7.d, #1
    fcvtzs z5.d, p0/m, z0.d
    fcvtzs z6.d, p1/m, z0.d
    fcvtzs z7.d, p1/m, z3.d
  )");
  std::vector<int64_t> results64A = {1, -1, 4, -4, 3, -3, 7, -7};
  std::vector<int64_t> results64B = {INT32_MAX, INT32_MIN, -10698505, 0};
  std::vector<int64_t> results64C = {INT64_MAX, -114458013083425, -10698505, 0};

  CHECK_NEON(1, int64_t, fillNeon<int64_t>(results64A, VL / 8));
  CHECK_NEON(2, int64_t,
             fillNeonCombined<int64_t>(results64A, {4294967297}, VL / 8));
  CHECK_NEON(4, int64_t,
             fillNeonCombined<int64_t>(results64B, {4294967297}, VL / 8));

  CHECK_NEON(5, int64_t, fillNeon<int64_t>(results64A, VL / 8));
  CHECK_NEON(6, int64_t, fillNeonCombined<int64_t>(results64A, {1}, VL / 8));
  CHECK_NEON(7, int64_t, fillNeonCombined<int64_t>(results64C, {1}, VL / 8));

  // Single
  initialHeapData_.resize(VL / 2);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  std::vector<float> fsrcA = {1.0f,   -42.76f,  -0.125f, 0.0f,
                              40.26f, -684.72f, -1.15f,  107.86f};
  std::vector<float> fsrcB = {-118548568215563221587412.3368451f,
                              118548568215563221587412.3368451f,
                              0.0f,
                              80.72f,
                              -125.67f,
                              -0.01f,
                              701.90f,
                              7.0f};
  fillHeapCombined<float>(fheap, fsrcA, fsrcB, VL / 32);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #0
    mov x3, #0
    mov x4, #4
    mov x5, #2
    addvl x3, x3, #1
    sdiv x3, x3, x4
    sdiv x2, x3, x5

    ptrue p0.s
    whilelo p1.s, xzr, x2

    ld1w {z0.s}, p0/z, [x0, x1, lsl #2]
    ld1w {z3.s}, p1/z, [x0, x2, lsl #2]

    # Single to Int64
    dup z1.d, #1
    dup z2.d, #1
    dup z4.d, #1
    fcvtzs z1.d, p0/m, z0.s
    fcvtzs z2.d, p1/m, z0.s
    fcvtzs z4.d, p1/m, z3.s

    # Single to Int32
    dup z5.s, #10
    dup z6.s, #10
    dup z7.s, #10
    fcvtzs z5.s, p0/m, z0.s
    fcvtzs z6.s, p1/m, z0.s
    fcvtzs z7.s, p1/m, z3.s
  )");
  std::vector<int64_t> results32A = {1, 0, 40, -1};
  std::vector<int64_t> results32B = {INT64_MIN, 0, -125, 701};
  CHECK_NEON(1, int64_t,
             fillNeonCombined<int64_t>(results32A, results32B, VL / 8));
  CHECK_NEON(2, int64_t, fillNeonCombined<int64_t>(results32A, {1}, VL / 8));
  CHECK_NEON(4, int64_t, fillNeonCombined<int64_t>(results32B, {1}, VL / 8));

  std::vector<int32_t> results32C = {1, -42, 0, 0, 40, -684, -1, 107};
  std::vector<int32_t> results32D = {INT32_MIN, INT32_MAX, 0,   80,
                                     -125,      0,         701, 7};
  CHECK_NEON(5, int32_t,
             fillNeonCombined<int32_t>(results32C, results32D, VL / 8));
  CHECK_NEON(6, int32_t, fillNeonCombined<int32_t>(results32C, {10}, VL / 8));
  CHECK_NEON(7, int32_t, fillNeonCombined<int32_t>(results32D, {10}, VL / 8));
}

TEST_P(InstSve, fcvt) {
  // double to single
  initialHeapData_.resize(VL / 4);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  std::vector<double> dsrcA = {2.0,
                               -2.0,
                               4.5,
                               -4.5,
                               3.2,
                               -3.2,
                               std::numeric_limits<double>::max(),
                               std::numeric_limits<double>::lowest()};
  fillHeap<double>(dheap, dsrcA, VL / 32);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    fdup z0.s, #1.0
    fdup z1.s, #1.0
    fdup z2.s, #1.0
    fdup z3.s, #1.0

    mov x1, #0
    mov x2, #0
    mov x3, #0
    mov x4, #8
    mov x5, #2
    addvl x3, x3, #1
    sdiv x3, x3, x4
    sdiv x2, x3, x5

    ptrue p0.d
    whilelo p1.d, xzr, x3

    ld1d {z4.d}, p0/z, [x0, x1, lsl #3]
    ld1d {z5.d}, p1/z, [x0, x2, lsl #3]

    fcvt z0.s, p0/m, z4.d
    fcvt z1.s, p1/m, z4.d 
  )");
  std::vector<float> results64A = {2.0f,
                                   1.0f,
                                   -2.0f,
                                   1.0f,
                                   4.5f,
                                   1.0f,
                                   -4.5f,
                                   1.0f,
                                   3.2f,
                                   1.0f,
                                   -3.2f,
                                   1.0f,
                                   std::numeric_limits<float>::max(),
                                   1.0f,
                                   std::numeric_limits<float>::lowest(),
                                   1.0f};
  CHECK_NEON(0, float, fillNeon<float>(results64A, VL / 8));
  CHECK_NEON(1, float, fillNeon<float>(results64A, VL / 8));

  // single to double
  initialHeapData_.resize(VL / 2);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  std::vector<float> fsrcA = {2.0f,
                              -42.76f,
                              -0.125f,
                              0.0f,
                              40.26f,
                              -684.72f,
                              std::numeric_limits<float>::lowest(),
                              107.86f};
  std::vector<float> fsrcB = {std::numeric_limits<float>::max(),
                              -0.15f,
                              0.0f,
                              80.72f,
                              -125.67f,
                              -0.01f,
                              701.90f,
                              7.0f};
  fillHeapCombined<float>(fheap, fsrcA, fsrcB, VL / 32);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    fdup z0.d, #1.0
    fdup z1.d, #1.0

    mov x1, #0
    mov x3, #0
    mov x4, #8
    mov x5, #2
    addvl x3, x3, #1
    sdiv x3, x3, x4

    ptrue p0.s
    whilelo p1.s, xzr, x3

    ld1w {z4.s}, p0/z, [x0, x1, lsl #2]
    ld1w {z5.s}, p1/z, [x0, x3, lsl #2]

    fcvt z0.d, p0/m, z4.s
    fcvt z1.d, p1/m, z5.s  
  )");
  std::vector<double> results32A = {
      2.0, -0.125, 40.26,
      static_cast<double>(std::numeric_limits<float>::lowest())};
  std::vector<double> results32B = {
      static_cast<double>(std::numeric_limits<float>::max()), 0.0, -125.67,
      701.90};
  std::vector<double> results32C = {
      static_cast<double>(std::numeric_limits<float>::max()), 0.0, -125.67,
      701.90};
  CHECK_NEON(0, double,
             fillNeonCombined<double>(results32A, results32B, VL / 8));
  CHECK_NEON(1, double, fillNeonCombined<double>(results32C, {1.0}, VL / 8));
}

TEST_P(InstSve, fdivr) {
  // double
  initialHeapData_.resize(VL / 4);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  std::vector<double> dsrcA = {1.0, -42.76, -0.125, 1.0};
  std::vector<double> dsrcB = {-34.71, -0.917, 1.0, 80.72};
  fillHeapCombined<double>(dheap, dsrcA, dsrcB, VL / 32);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #0
    mov x3, #0
    mov x4, #8
    mov x5, #2
    addvl x3, x3, #1
    sdiv x3, x3, x4
    sdiv x2, x3, x5

    ptrue p1.d
    whilelo p0.d, xzr, x2

    ld1d {z0.d}, p1/z, [x0, x3, lsl #3]
    ld1d {z1.d}, p1/z, [x0, x1, lsl #3]
    ld1d {z2.d}, p0/z, [x0, x1, lsl #3]

    fdivr z1.d, p1/m, z1.d, z0.d
    fdivr z2.d, p0/m, z2.d, z0.d
  )");
  std::vector<double> dresultsA = {-34.71, 0.02144527595884003837, -8.0, 80.72};
  CHECK_NEON(1, double, fillNeon<double>(dresultsA, VL / 8));
  CHECK_NEON(2, double, fillNeonCombined<double>(dresultsA, {0}, VL / 8));

  // float
  initialHeapData_.resize(VL / 4);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  std::vector<float> fsrcA = {1.0f,   -42.76f,  -0.125f, 1.0f,
                              40.26f, -684.72f, -0.15f,  107.86f};
  std::vector<float> fsrcB = {-34.71f,  -0.917f, 1.0f,    80.72f,
                              -125.67f, -0.01f,  701.90f, 7.0f};
  fillHeapCombined<float>(fheap, fsrcA, fsrcB, VL / 32);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #0
    mov x3, #0
    mov x4, #4
    mov x5, #2
    addvl x3, x3, #1
    sdiv x3, x3, x4
    sdiv x2, x3, x5

    whilelo p0.s, xzr, x2
    ptrue p1.s

    ld1w {z0.s}, p1/z, [x0, x2, lsl #2]
    ld1w {z1.s}, p1/z, [x0, x1, lsl #2]

    fdivr z1.s, p0/m, z1.s, z0.s
  )");
  std::vector<float> fresultsA = {-34.71f,
                                  0.02144527595884003837f,
                                  -8.0f,
                                  80.72f,
                                  -3.1214605067064087329f,
                                  0.0000146045098726486738f,
                                  -4679.333333333333030168f,
                                  0.06489894307435564724f};
  CHECK_NEON(1, float, fillNeonCombined<float>(fresultsA, fsrcB, VL / 8));
}

TEST_P(InstSve, fdiv) {
  // double
  initialHeapData_.resize(VL / 4);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  std::vector<double> dsrcA = {1.0,   -42.76,  -0.125, 1.0,
                               40.26, -684.72, -0.15,  107.86};
  std::vector<double> dsrcB = {-34.71,  -0.917, 1.0,    80.72,
                               -125.67, -0.01,  701.90, 7.0};
  fillHeapCombined<double>(dheap, dsrcA, dsrcB, VL / 32);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #0
    mov x3, #0
    mov x4, #8
    mov x5, #2
    addvl x3, x3, #1
    sdiv x3, x3, x4
    sdiv x2, x3, x5

    whilelo p0.d, xzr, x2
    ptrue p1.d

    ld1d {z0.d}, p1/z, [x0, x1, lsl #3]
    ld1d {z1.d}, p1/z, [x0, x3, lsl #3]
    ld1d {z2.d}, p1/z, [x0, x3, lsl #3]
    
    fdiv z1.d, p1/m, z1.d, z0.d
    fdiv z2.d, p0/m, z2.d, z0.d
  )");

  std::vector<double> dresults = {-34.71,
                                  0.02144527595884003837,
                                  -8,
                                  80.72,
                                  -3.1214605067064087329,
                                  0.0000146045098726486738,
                                  -4679.333333333333030168,
                                  0.06489894307435564724};
  CHECK_NEON(1, double, fillNeon<double>(dresults, VL / 8));
  std::rotate(dsrcB.begin(), dsrcB.begin() + ((VL / 128) % 8), dsrcB.end());
  CHECK_NEON(2, double, fillNeonCombined<double>(dresults, dsrcB, VL / 8));
}

TEST_P(InstSve, fnmls) {
  // float
  initialHeapData_.resize(VL / 4);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  std::vector<float> fsrcA = {1.0f,   -42.76f,  -0.125f, 0.0f,
                              40.26f, -684.72f, -0.15f,  107.86f};
  std::vector<float> fsrcB = {-34.71f,  -0.917f, 0.0f,    80.72f,
                              -125.67f, -0.01f,  701.90f, 7.0f};
  fillHeapCombined<float>(fheap, fsrcA, fsrcB, VL / 32);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #0
    mov x3, #8
    addvl x2, x2, #1
    sdiv x2, x2, x3

    whilelo p0.s, xzr, x2
    ptrue p1.s

    ld1w {z0.s}, p0/z, [x0, x1, lsl #2]
    ld1w {z1.s}, p0/z, [x0, x2, lsl #2]
    ld1w {z2.s}, p1/z, [x0, x1, lsl #2]

    fnmls z2.s, p0/m, z1.s, z0.s
  )");
  std::vector<float> fresultsA = {-35.71f,     81.97092f, 0.125f,    0.0f,
                                  -5099.7342f, 691.5672f, -105.135f, 647.16f};
  CHECK_NEON(2, float, fillNeonCombined(fresultsA, fsrcB, VL / 8));

  // double
  initialHeapData_.resize(VL / 4);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  std::vector<double> dsrcA = {1.0, -42.76, -0.125, 0.0};
  std::vector<double> dsrcB = {-34.71, -0.917, 0.0, 80.72};
  fillHeapCombined<double>(dheap, dsrcA, dsrcB, VL / 64);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #0
    mov x3, #16
    addvl x2, x2, #1
    sdiv x2, x2, x3

    whilelo p0.d, xzr, x2
    ptrue p1.d

    ld1d {z0.d}, p0/z, [x0, x1, lsl #3]
    ld1d {z1.d}, p0/z, [x0, x2, lsl #3]
    ld1d {z2.d}, p1/z, [x0, x1, lsl #3]

    fnmls z2.d, p0/m, z1.d, z0.d
  )");
  std::vector<double> dresultsA = {-35.71, 81.97092, 0.125, 0.0};
  CHECK_NEON(2, double, fillNeonCombined(dresultsA, dsrcB, VL / 8));
}

TEST_P(InstSve, fnmsb) {
  // float
  initialHeapData_.resize(VL / 4);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  std::vector<float> fsrcA = {1.0f,   -42.76f,  -0.125f, 0.0f,
                              40.26f, -684.72f, -0.15f,  107.86f};
  std::vector<float> fsrcB = {-34.71f,  -0.917f, 0.0f,    80.72f,
                              -125.67f, -0.01f,  701.90f, 7.0f};
  fillHeapCombined<float>(fheap, fsrcA, fsrcB, VL / 32);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #0
    mov x3, #8
    addvl x2, x2, #1
    sdiv x2, x2, x3

    whilelo p0.s, xzr, x2
    ptrue p1.s

    ld1w {z0.s}, p0/z, [x0, x1, lsl #2]
    ld1w {z1.s}, p0/z, [x0, x2, lsl #2]
    ld1w {z2.s}, p1/z, [x0, x1, lsl #2]

    fnmsb z2.s, p0/m, z1.s, z0.s
  )");
  std::vector<float> fresultsA = {-35.71f,     81.97092f, 0.125f,    0.0f,
                                  -5099.7342f, 691.5672f, -105.135f, 647.16f};
  CHECK_NEON(2, float, fillNeonCombined(fresultsA, fsrcB, VL / 8));

  // double
  initialHeapData_.resize(VL / 4);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  std::vector<double> dsrcA = {1.0, -42.76, -0.125, 0.0};
  std::vector<double> dsrcB = {-34.71, -0.917, 0.0, 80.72};
  fillHeapCombined<double>(dheap, dsrcA, dsrcB, VL / 64);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #0
    mov x3, #16
    addvl x2, x2, #1
    sdiv x2, x2, x3

    whilelo p0.d, xzr, x2
    ptrue p1.d

    ld1d {z0.d}, p0/z, [x0, x1, lsl #3]
    ld1d {z1.d}, p0/z, [x0, x2, lsl #3]
    ld1d {z2.d}, p1/z, [x0, x1, lsl #3]

    fnmsb z2.d, p0/m, z1.d, z0.d
  )");
  std::vector<double> dresultsA = {-35.71, 81.97092, 0.125, 0.0};
  CHECK_NEON(2, double, fillNeonCombined(dresultsA, dsrcB, VL / 8));
}

TEST_P(InstSve, fmad) {
  initialHeapData_.resize(VL / 8);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  std::vector<float> fsrcA = {1.0f,   -42.76f,  -0.125f, 0.0f,
                              40.26f, -684.72f, -0.15f,  107.86f};
  std::vector<float> fsrcB = {-34.71f,  -0.917f, 0.0f,    80.72f,
                              -125.67f, -0.01f,  701.90f, 7.0f};
  fillHeapCombined<float>(fheap, fsrcA, fsrcB, VL / 32);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #0
    mov x3, #8
    addvl x2, x2, #1
    sdiv x2, x2, x3

    whilelo p0.s, xzr, x2
    ptrue p1.s

    ld1w {z0.s}, p0/z, [x0, x1, lsl #2]
    ld1w {z1.s}, p0/z, [x0, x2, lsl #2]
    ld1w {z2.s}, p1/z, [x0, x1, lsl #2]

    fmad z2.s, p0/m, z1.s, z0.s
  )");

  std::vector<float> fresults = {
      -33.71f,     -3.54907989502f, -0.125f,       0.0f,
      -5019.2142f, -677.872741699f, -105.4350113f, 862.88f};
  CHECK_NEON(2, float, fillNeonCombined<float>(fresults, fsrcB, VL / 8));

  // double
  initialHeapData_.resize(VL / 4);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  std::vector<double> dsrcA = {1.0, -42.76, -0.125, 0.0};
  std::vector<double> dsrcB = {-34.71, -0.917, 0.0, 80.72};
  fillHeapCombined<double>(dheap, dsrcA, dsrcB, VL / 64);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #0
    mov x3, #16
    addvl x2, x2, #1
    sdiv x2, x2, x3

    whilelo p0.d, xzr, x2
    ptrue p1.d

    ld1d {z0.d}, p0/z, [x0, x1, lsl #3]
    ld1d {z1.d}, p0/z, [x0, x2, lsl #3]
    ld1d {z2.d}, p1/z, [x0, x1, lsl #3]

    fmad z2.d, p0/m, z1.d, z0.d
  )");
  std::vector<double> dresults = {-33.71, -3.54907989502, -0.125, 0.0};
  CHECK_NEON(2, double, fillNeonCombined<double>(dresults, dsrcB, VL / 8));
}

TEST_P(InstSve, fmla) {
  // double
  initialHeapData_.resize(VL / 8);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  std::vector<double> dsrcA = {1.0, -42.76, -0.125, 0.0};
  std::vector<double> dsrcB = {-34.71, -0.917, 0.0, 80.72};
  fillHeapCombined<double>(dheap, dsrcA, dsrcB, VL / 64);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    
    mov x1, #0
    mov x2, #0
    mov x3, #16
    addvl x2, x2, #1
    sdiv x2, x2, x3

    whilelo p0.d, xzr, x2
    ptrue p1.d

    ld1d {z0.d}, p0/z, [x0, x1, lsl #3]
    ld1d {z1.d}, p0/z, [x0, x2, lsl #3]
    ld1d {z2.d}, p1/z, [x0, x1, lsl #3]

    fmla z2.d, p0/m, z1.d, z0.d
  )");
  std::vector<double> dresults = {-33.71, -3.5490799999999964, -0.125, 0.0};
  CHECK_NEON(2, double, fillNeonCombined<double>(dresults, dsrcB, VL / 8));

  // float
  initialHeapData_.resize(VL / 8);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  std::vector<float> fsrcA = {1.0f,   -42.76f,  -0.125f, 0.0f,
                              40.26f, -684.72f, -0.15f,  107.86f};
  std::vector<float> fsrcB = {-34.71f,  -0.917f, 0.0f,    80.72f,
                              -125.67f, -0.01f,  701.90f, 7.0f};
  fillHeapCombined<float>(fheap, fsrcA, fsrcB, VL / 32);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #0
    mov x3, #8
    addvl x2, x2, #1
    sdiv x2, x2, x3

    whilelo p0.s, xzr, x2
    ptrue p1.s

    ld1w {z0.s}, p0/z, [x0, x1, lsl #2]
    ld1w {z1.s}, p0/z, [x0, x2, lsl #2]
    ld1w {z2.s}, p1/z, [x0, x1, lsl #2]

    fmla z2.s, p0/m, z1.s, z0.s
  )");
  std::vector<float> fresults = {
      -33.71f,     -3.54907989502f, -0.125f,       0.0f,
      -5019.2142f, -677.872741699f, -105.4350113f, 862.88f};
  CHECK_NEON(2, float, fillNeonCombined<float>(fresults, fsrcB, VL / 8));
}

TEST_P(InstSve, fmls) {
  // float
  initialHeapData_.resize(VL / 8);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  std::vector<float> fsrcA = {1.0f,   -42.76f,  -0.125f, 0.0f,
                              40.26f, -684.72f, -0.15f,  107.86f};
  std::vector<float> fsrcB = {-34.71f,  -0.917f, 0.0f,    80.72f,
                              -125.67f, -0.01f,  701.90f, 7.0f};
  fillHeapCombined<float>(fheap, fsrcA, fsrcB, VL / 32);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #0
    mov x3, #8
    addvl x2, x2, #1
    sdiv x2, x2, x3

    whilelo p0.s, xzr, x2
    ptrue p1.s

    ld1w {z0.s}, p0/z, [x0, x1, lsl #2]
    ld1w {z1.s}, p0/z, [x0, x2, lsl #2]
    ld1w {z2.s}, p1/z, [x0, x1, lsl #2]

    fmls z2.s, p0/m, z1.s, z0.s
  )");
  std::vector<float> fresults = {35.71f,
                                 -81.97092f,
                                 -0.125f,
                                 0.0f,
                                 5099.7342f,
                                 -691.5672000000001f,
                                 105.13499999999999f,
                                 -647.16f};
  CHECK_NEON(2, float, fillNeonCombined<float>(fresults, fsrcB, VL / 8));

  // double
  initialHeapData_.resize(VL / 8);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  std::vector<double> dsrcA = {1.0, -42.76, -0.125, 0.0};
  std::vector<double> dsrcB = {-34.71, -0.917, 0.0, 80.72};
  fillHeapCombined<double>(dheap, dsrcA, dsrcB, VL / 64);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #0
    mov x3, #16
    addvl x2, x2, #1
    sdiv x2, x2, x3

    whilelo p0.d, xzr, x2
    ptrue p1.d

    ld1d {z0.d}, p0/z, [x0, x1, lsl #3]
    ld1d {z1.d}, p0/z, [x0, x2, lsl #3]
    ld1d {z2.d}, p1/z, [x0, x1, lsl #3]

    fmls z2.d, p0/m, z1.d, z0.d
  )");
  std::vector<double> dresults = {35.71, -81.97092, -0.125, 0.0};
  CHECK_NEON(2, double, fillNeonCombined<double>(dresults, dsrcB, VL / 8));
}

TEST_P(InstSve, fmsb) {
  // float
  initialHeapData_.resize(VL / 8);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  std::vector<float> fsrcA = {1.0f,   -42.76f,  -0.125f, 0.0f,
                              40.26f, -684.72f, -0.15f,  107.86f};
  std::vector<float> fsrcB = {-34.71f,  -0.917f, 0.0f,    80.72f,
                              -125.67f, -0.01f,  701.90f, 7.0f};
  fillHeapCombined<float>(fheap, fsrcA, fsrcB, VL / 32);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #0
    mov x3, #8
    addvl x2, x2, #1
    sdiv x2, x2, x3

    whilelo p0.s, xzr, x2
    ptrue p1.s

    ld1w {z0.s}, p0/z, [x0, x1, lsl #2]
    ld1w {z1.s}, p0/z, [x0, x2, lsl #2]
    ld1w {z2.s}, p1/z, [x0, x1, lsl #2]

    fmsb z2.s, p0/m, z1.s, z0.s
  )");
  std::vector<float> fresults = {
      35.71f,         -81.970916748f,  -0.125f,        0.0f,
      5099.73388672f, -691.567199707f, 105.135009766f, -647.16003418f};
  CHECK_NEON(2, float, fillNeonCombined<float>(fresults, fsrcB, VL / 8));

  // Double
  initialHeapData_.resize(VL / 4);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  std::vector<double> dsrcA = {1.0, -42.76, -0.125, 0.0};
  std::vector<double> dsrcB = {-34.71, -0.917, 0.0, 80.72};
  fillHeapCombined<double>(dheap, dsrcA, dsrcB, VL / 64);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #0
    mov x3, #16
    addvl x2, x2, #1
    sdiv x2, x2, x3

    whilelo p0.d, xzr, x3
    ptrue p1.d

    ld1d {z0.d}, p1/z, [x0, x1, lsl #3]
    ld1d {z1.d}, p1/z, [x0, x2, lsl #3]
    ld1d {z2.d}, p1/z, [x0, x1, lsl #3]

    fmsb z2.d, p0/m, z1.d, z0.d
  )");
  std::vector<double> dresults = {35.71, -81.970916748, -0.125, 0.0};
  CHECK_NEON(2, double, fillNeonCombined<double>(dresults, dsrcB, VL / 8));
}

TEST_P(InstSve, fmul) {
  // float
  initialHeapData_.resize(VL / 8);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  std::vector<float> fsrcA = {1.0f,   -42.76f,  -0.125f, 0.0f,
                              40.26f, -684.72f, -0.15f,  107.86f};
  std::vector<float> fsrcB = {-34.71f,  -0.917f, 0.0f,    80.72f,
                              -125.67f, -0.01f,  701.90f, 7.0f};
  fillHeapCombined<float>(fheap, fsrcA, fsrcB, VL / 32);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #0
    mov x3, #8
    addvl x2, x2, #1
    sdiv x2, x2, x3

    whilelo p0.s, xzr, x2
    ptrue p1.s

    ld1w {z0.s}, p0/z, [x0, x1, lsl #2]
    ld1w {z1.s}, p0/z, [x0, x2, lsl #2]
    ld1w {z3.s}, p1/z, [x0, x1, lsl #2]
    ld1w {z4.s}, p0/z, [x0, x2, lsl #2]

    fmul z2.s, z1.s, z0.s
    fmul z0.s, p0/m, z0.s, #0.5
    fmul z3.s, p0/m, z3.s, z4.s
  )");
  std::vector<float> fresultsA = {0.5f,   -21.38f,  -0.0625f, 0.0f,
                                  20.13f, -342.36f, -0.075f,  53.93f};
  std::vector<float> fresultsB = {
      -34.71f,     39.2109184265f,  0.0f,   0.0f, -5059.4742f,
      6.84719944f, -105.285011292f, 755.02f};
  CHECK_NEON(0, float, fillNeon<float>(fresultsA, VL / 16));
  CHECK_NEON(2, float, fillNeon<float>(fresultsB, VL / 16));
  CHECK_NEON(3, float, fillNeonCombined<float>(fresultsB, fsrcB, VL / 8));

  // double
  initialHeapData_.resize(VL / 8);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  std::vector<double> dsrcA = {1.0, -42.76, -0.125, 0.0};
  std::vector<double> dsrcB = {-34.71, -0.917, 0.0, 80.72};
  fillHeapCombined<double>(dheap, dsrcA, dsrcB, VL / 64);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #0
    mov x3, #16
    addvl x2, x2, #1
    sdiv x2, x2, x3

    whilelo p0.d, xzr, x2
    ptrue p1.d

    ld1d {z0.d}, p0/z, [x0, x1, lsl #3]
    ld1d {z1.d}, p0/z, [x0, x2, lsl #3]
    ld1d {z3.d}, p1/z, [x0, x1, lsl #3]
    ld1d {z4.d}, p0/z, [x0, x2, lsl #3]

    fmul z2.d, z1.d, z0.d
    fmul z0.d, p0/m, z0.d, #0.5
    fmul z3.d, p0/m, z3.d, z4.d
  )");
  std::vector<double> dresultsA = {0.5, -21.38, -0.0625, 0.0};
  std::vector<double> dresultsB = {-34.71, 39.21092, 0.0, 0.0};
  CHECK_NEON(0, double, fillNeon<double>(dresultsA, VL / 16));
  CHECK_NEON(2, double, fillNeon<double>(dresultsB, VL / 16));
  CHECK_NEON(3, double, fillNeonCombined<double>(dresultsB, dsrcB, VL / 8));
}

TEST_P(InstSve, fneg) {
  // double
  initialHeapData_.resize(VL / 8);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  std::vector<double> dsrc = {1.0,    -42.76, -0.125, 0.0,
                              -34.71, -0.917, 0.0,    80.72};
  fillHeap<double>(dheap, dsrc, VL / 64);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #0
    mov x3, #16
    addvl x2, x2, #1
    sdiv x2, x2, x3

    whilelo p0.d, xzr, x2
    ptrue p1.d

    ld1d {z0.d}, p1/z, [x0, x1, lsl #3]
    ld1d {z1.d}, p0/z, [x0, x2, lsl #3]

    fneg z2.d, p1/m, z0.d
    fneg z3.d, p0/m, z1.d
  )");
  std::vector<double> dresults = {-1.0,  42.76, 0.125, -0.0,
                                  34.71, 0.917, -0.0,  -80.72};
  CHECK_NEON(2, double, fillNeon<double>(dresults, VL / 8));
  std::rotate(dresults.begin(), dresults.begin() + ((VL / 128) % 8),
              dresults.end());
  CHECK_NEON(3, double, fillNeon<double>(dresults, VL / 16));

  // float
  initialHeapData_.resize(VL / 8);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  std::vector<float> fsrc = {
      1.0f,    -42.76f, -0.125f, 0.0f,   40.26f,   -684.72f, -0.15f,  107.86f,
      -34.71f, -0.917f, 0.0f,    80.72f, -125.67f, -0.01f,   701.90f, 7.0f};
  fillHeap<float>(fheap, fsrc, VL / 32);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #0
    mov x3, #8
    addvl x2, x2, #1
    sdiv x2, x2, x3

    whilelo p0.s, xzr, x2
    ptrue p1.s

    ld1w {z0.s}, p1/z, [x0, x1, lsl #2]
    ld1w {z1.s}, p0/z, [x0, x2, lsl #2]

    fneg z2.s, p1/m, z0.s
    fneg z3.s, p0/m, z1.s
  )");
  std::vector<float> fresults = {
      -1.0f,  42.76f, 0.125f, -0.0f,   -40.26f, 684.72f, 0.15f,    -107.86f,
      34.71f, 0.917f, -0.0f,  -80.72f, 125.67f, 0.01f,   -701.90f, -7.0f};
  CHECK_NEON(2, float, fillNeon<float>(fresults, VL / 8));
  std::rotate(fresults.begin(), fresults.begin() + ((VL / 64) % 16),
              fresults.end());
  CHECK_NEON(3, float, fillNeon<float>(fresults, VL / 16));
}

TEST_P(InstSve, frintn) {
  // 32-bit
  initialHeapData_.resize(VL / 8);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  std::vector<float> fsrcA = {1.0f,  -42.5f,   -0.125f, 0.0f,
                              40.5f, -684.72f, -0.15f,  107.86f};
  std::vector<float> fsrcB = {-34.5f,  -0.917f, 0.0f,    80.72f,
                              -125.5f, -0.01f,  701.90f, 7.5f};
  fillHeapCombined<float>(fheap, fsrcA, fsrcB, VL / 32);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #0
    mov x3, #8
    addvl x2, x2, #1
    sdiv x2, x2, x3

    ptrue p0.s
    whilelo p1.s, xzr, x2

    dup z0.s, #15
    dup z1.s, #13
    ld1w {z2.s}, p0/z, [x0, x1, lsl #2]

    frintn z0.s, p0/m, z2.s
    frintn z1.s, p1/m, z2.s
  )");
  std::vector<int32_t> results32A = {1, -42, 0, 0, 40, -685, 0, 108};
  std::vector<int32_t> results32B = {-34, -1, 0, 81, -126, 0, 702, 8};
  CHECK_NEON(0, int32_t,
             fillNeonCombined<int32_t>(results32A, results32B, VL / 8));
  CHECK_NEON(1, int32_t, fillNeonCombined<int32_t>(results32A, {13}, VL / 8));

  // 64-bit
  initialHeapData_.resize(VL / 8);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  std::vector<double> dsrcA = {1.0, -42.5, -0.125, 0.0};
  std::vector<double> dsrcB = {40.5, -684.72, -3.5, 107.5};
  fillHeapCombined<double>(dheap, dsrcA, dsrcB, VL / 64);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #0
    mov x3, #16
    addvl x2, x2, #1
    sdiv x2, x2, x3

    ptrue p0.d
    whilelo p1.d, xzr, x2

    dup z0.d, #15
    dup z1.d, #13
    ld1d {z2.d}, p0/z, [x0, x1, lsl #3]

    frintn z0.d, p0/m, z2.d
    frintn z1.d, p1/m, z2.d
  )");
  std::vector<int64_t> results64A = {1, -42, 0, 0};
  std::vector<int64_t> results64B = {40, -685, -4, 108};
  CHECK_NEON(0, int64_t,
             fillNeonCombined<int64_t>(results64A, results64B, VL / 8));
  CHECK_NEON(1, int64_t, fillNeonCombined<int64_t>(results64A, {13}, VL / 8));
}

TEST_P(InstSve, fsqrt) {
  // float
  initialHeapData_.resize(VL / 8);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  std::vector<float> fsrc = {1.0f,    42.76f,  0.125f,  0.0f,   40.26f, 684.72f,
                             0.15f,   107.86f, 34.71f,  0.917f, 0.0f,   80.72f,
                             125.67f, 0.01f,   701.90f, 7.0f};
  fillHeap<float>(fheap, fsrc, VL / 32);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #0
    mov x3, #8
    addvl x2, x2, #1
    sdiv x2, x2, x3

    whilelo p0.s, xzr, x2
    ptrue p1.s

    ld1w {z0.s}, p1/z, [x0, x1, lsl #2]
    ld1w {z1.s}, p0/z, [x0, x2, lsl #2]

    fsqrt z2.s, p1/m, z0.s
    fsqrt z3.s, p0/m, z1.s
  )");
  std::vector<float> fresults = {1.f,
                                 6.53911304473876953125f,
                                 0.3535533845424652099609375f,
                                 0.f,
                                 6.34507656097412109375f,
                                 26.1671543121337890625f,
                                 0.3872983455657958984375f,
                                 10.38556671142578125f,
                                 5.891519069671630859375f,
                                 0.95760118961334228515625f,
                                 0.f,
                                 8.98443126678466796875f,
                                 11.21026325225830078125f,
                                 0.1f,
                                 26.493396759033203125f,
                                 2.6457512378692626953125f};
  CHECK_NEON(2, float, fillNeon<float>(fresults, VL / 8));
  std::rotate(fresults.begin(), fresults.begin() + ((VL / 64) % 16),
              fresults.end());
  CHECK_NEON(3, float, fillNeon<float>(fresults, VL / 16));

  // Double
  initialHeapData_.resize(VL / 8);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  std::vector<double> dsrc = {1.0,   42.76,  0.125, 0.0,
                              40.26, 684.72, 0.15,  107.86};
  fillHeap<double>(dheap, dsrc, VL / 64);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #0
    mov x3, #16
    addvl x2, x2, #1
    sdiv x2, x2, x3

    whilelo p0.d, xzr, x2
    ptrue p1.d

    ld1d {z0.d}, p1/z, [x0, x1, lsl #3]

    fdup z2.d, #0.5
    fdup z3.d, #0.5

    fsqrt z2.d, p1/m, z0.d
    fsqrt z3.d, p0/m, z0.d
  )");
  std::vector<double> dresults = {1.0,
                                  6.53911304473876953125,
                                  0.3535533845424652099609375,
                                  0.0,
                                  6.34507656097412109375,
                                  26.1671543121337890625,
                                  0.3872983455657958984375,
                                  10.38556671142578125};
  CHECK_NEON(2, double, fillNeon<double>(dresults, VL / 8));
  CHECK_NEON(3, double, fillNeonCombined<double>(dresults, {0.5}, VL / 8));
}

TEST_P(InstSve, fsub) {
  // float
  initialHeapData_.resize(VL / 8);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  std::vector<float> fsrcA = {1.0f,   -42.76f,  -0.125f, 0.0f,
                              40.26f, -684.72f, -0.15f,  107.86f};
  std::vector<float> fsrcB = {-34.71f,  -0.917f, 0.0f,    80.72f,
                              -125.67f, -0.01f,  701.90f, 7.0f};
  fillHeapCombined<float>(fheap, fsrcA, fsrcB, VL / 32);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #0
    mov x3, #8
    addvl x2, x2, #1
    sdiv x2, x2, x3
    whilelo p0.s, xzr, x2

    ld1w {z0.s}, p0/z, [x0, x1, lsl #2]
    ld1w {z1.s}, p0/z, [x0, x2, lsl #2]

    fsub z2.s, z1.s, z0.s

    # PREDICATED VECTOR
    ptrue p1.s
    ld1w {z4.s}, p1/z, [x0, x1, lsl #2]
    
    fsub z4.s, p0/m, z4.s, z1.s
  )");
  std::vector<float> fresultsA = {-35.71f,        41.843f,  0.125f,
                                  80.72f,         -165.93f, 684.709960938f,
                                  702.050048828f, -100.86f};
  CHECK_NEON(2, float, fillNeon<float>(fresultsA, VL / 16));
  std::vector<float> fresultsB = {35.71f,          -41.843f, -0.125f,
                                  -80.72f,         165.93f,  -684.709960938f,
                                  -702.050048828f, 100.86f};
  CHECK_NEON(4, float, fillNeonCombined<float>(fresultsB, fsrcB, VL / 8));

  // double
  initialHeapData_.resize(VL / 8);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  std::vector<double> dsrcA = {1.0, -42.76, -0.125, 0.0};
  std::vector<double> dsrcB = {-34.71, -0.917, 0.0, 80.72};
  fillHeapCombined<double>(dheap, dsrcA, dsrcB, VL / 64);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #0
    mov x3, #16
    addvl x2, x2, #1
    sdiv x2, x2, x3
    whilelo p0.d, xzr, x2

    ld1d {z0.d}, p0/z, [x0, x1, lsl #3]
    ld1d {z1.d}, p0/z, [x0, x2, lsl #3]

    fsub z2.d, z1.d, z0.d

    # PREDICATED VECTOR
    ptrue p1.d
    ld1d {z3.d}, p1/z, [x0, x1, lsl #3]
    
    fsub z3.d, p0/m, z3.d, z1.d
  )");

  std::vector<double> dresultsA = {-35.71, 41.842999999999996, 0.125, 80.72};
  CHECK_NEON(2, double, fillNeon<double>(dresultsA, VL / 16));
  std::vector<double> dresultsB = {35.71, -41.842999999999996, -0.125, -80.72};
  CHECK_NEON(3, double, fillNeonCombined<double>(dresultsB, dsrcB, VL / 8));
}

TEST_P(InstSve, fsub_imm) {
  // float
  RUN_AARCH64(R"(
    mov x1, #0
    mov x2, #0
    mov x3, #8
    addvl x2, x2, #1
    sdiv x2, x2, x3
    whilelo p0.s, xzr, x2
    ptrue p1.s

    fdup z0.s, #1.25
    fdup z1.s, #-0.75

    fsub z0.s, p1/m, z0.s, #0.5
    fsub z1.s, p0/m, z1.s, #1.0
  )");
  CHECK_NEON(0, float, fillNeon<float>({0.75f}, VL / 8));
  CHECK_NEON(1, float, fillNeonCombined<float>({-1.75f}, {-0.75f}, VL / 8));

  // double
  RUN_AARCH64(R"(
    mov x1, #0
    mov x2, #0
    mov x3, #16
    addvl x2, x2, #1
    sdiv x2, x2, x3
    whilelo p0.d, xzr, x2
    ptrue p1.d

    fdup z0.d, #1.25
    fdup z1.d, #-0.75

    fsub z0.d, p1/m, z0.d, #0.5
    fsub z1.d, p0/m, z1.d, #1.0
  )");
  CHECK_NEON(0, double, fillNeon<double>({0.75}, VL / 8));
  CHECK_NEON(1, double, fillNeonCombined<double>({-1.75}, {-0.75}, VL / 8));
}

TEST_P(InstSve, incp) {
  // Scalar
  RUN_AARCH64(R"(
    # 8-bit
    mov x0, #0
    addvl x0, x0, #1
    mov x1, #2
    udiv x1, x0, x1
    ptrue p0.b
    whilelo p1.b, xzr, x1

    mov x2, #66
    mov x3, #402
    incp x2, p0.b
    incp x3, p1.b

    # 16-bit
    mov x4, #4
    udiv x4, x0, x4
    ptrue p0.h
    whilelo p1.h, xzr, x4

    mov x5, #70
    mov x6, #109
    incp x5, p0.h
    incp x6, p1.h

    # 32-bit
    mov x7, #8
    udiv x7, x0, x7
    ptrue p0.s
    whilelo p1.s, xzr, x7

    mov x8, #41
    mov x9, #527
    incp x8, p0.s
    incp x9, p1.s

    # 64-bit
    mov x10, #16
    udiv x10, x0, x10
    ptrue p0.d
    whilelo p1.d, xzr, x10

    mov x11, #50
    mov x12, #375
    incp x11, p0.d
    incp x12, p1.d
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(2), 66 + (VL / 8));
  EXPECT_EQ(getGeneralRegister<uint64_t>(3), 402 + (VL / 16));
  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 70 + (VL / 16));
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 109 + (VL / 32));
  EXPECT_EQ(getGeneralRegister<uint64_t>(8), 41 + (VL / 32));
  EXPECT_EQ(getGeneralRegister<uint64_t>(9), 527 + (VL / 64));
  EXPECT_EQ(getGeneralRegister<uint64_t>(11), 50 + (VL / 64));
  EXPECT_EQ(getGeneralRegister<uint64_t>(12), 375 + (VL / 128));
}

TEST_P(InstSve, fsubr) {
  // float
  initialHeapData_.resize(VL / 8);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  std::vector<float> fsrcA = {1.0f,   -42.76f,  -0.125f, 0.0f,
                              40.26f, -684.72f, -0.15f,  107.86f};
  std::vector<float> fsrcB = {-34.71f,  -0.917f, 0.0f,    80.72f,
                              -125.67f, -0.01f,  701.90f, 7.0f};
  fillHeapCombined<float>(fheap, fsrcA, fsrcB, VL / 32);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #0
    mov x3, #8
    addvl x2, x2, #1
    sdiv x2, x2, x3
    whilelo p0.s, xzr, x2
    ptrue p1.s

    ld1w {z1.s}, p0/z, [x0, x2, lsl #2]
    ld1w {z4.s}, p1/z, [x0, x1, lsl #2]
    
    fsubr z4.s, p0/m, z4.s, z1.s
  )");
  std::vector<float> fresultsB = {-35.71f,        41.843f,  0.125f,
                                  80.72f,         -165.93f, 684.709960938f,
                                  702.050048828f, -100.86f};
  CHECK_NEON(4, float, fillNeonCombined<float>(fresultsB, fsrcB, VL / 8));

  // double
  initialHeapData_.resize(VL / 8);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  std::vector<double> dsrcA = {1.0, -42.76, -0.125, 0.0};
  std::vector<double> dsrcB = {-34.71, -0.917, 0.0, 80.72};
  fillHeapCombined<double>(dheap, dsrcA, dsrcB, VL / 64);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #0
    mov x3, #16
    addvl x2, x2, #1
    sdiv x2, x2, x3
    whilelo p0.d, xzr, x2
    ptrue p1.d

    ld1d {z1.d}, p0/z, [x0, x2, lsl #3]
    ld1d {z3.d}, p1/z, [x0, x1, lsl #3]
    
    fsubr z3.d, p0/m, z3.d, z1.d
  )");
  std::vector<double> dresultsB = {-35.71, 41.842999999999996, 0.125, 80.72};
  CHECK_NEON(3, double, fillNeonCombined<double>(dresultsB, dsrcB, VL / 8));
}

TEST_P(InstSve, index) {
  // Immediate, Immediate
  RUN_AARCH64(R"(
    # 8-bit
    index z0.b, #-16, #-16
    index z1.b, #15, #7

    # 16-bit
    index z2.h, #-8, #-3
    index z3.h, #3, #14

    # 32-bit
    index z4.s, #-6, #0
    index z5.s, #12, #14

    # 64-bit
    index z6.d, #-5, #-9
    index z7.d, #10, #10
  )");
  CHECK_NEON(0, uint8_t, fillNeonBaseAndOffset<uint8_t>(-16, -16, VL / 8));
  CHECK_NEON(1, uint8_t, fillNeonBaseAndOffset<uint8_t>(15, 7, VL / 8));
  CHECK_NEON(2, uint16_t, fillNeonBaseAndOffset<uint16_t>(-8, -3, VL / 8));
  CHECK_NEON(3, uint16_t, fillNeonBaseAndOffset<uint16_t>(3, 14, VL / 8));
  CHECK_NEON(4, uint32_t, fillNeonBaseAndOffset<uint32_t>(-6, 0, VL / 8));
  CHECK_NEON(5, uint32_t, fillNeonBaseAndOffset<uint32_t>(12, 14, VL / 8));
  CHECK_NEON(6, uint64_t, fillNeonBaseAndOffset<uint64_t>(-5, -9, VL / 8));
  CHECK_NEON(7, uint64_t, fillNeonBaseAndOffset<uint64_t>(10, 10, VL / 8));

  // Scalar, Immediate
  RUN_AARCH64(R"(
    # 8-bit
    mov w0, #-16
    mov w1, #15
    index z0.b, w0, #-16
    index z1.b, w1, #7

    # 16-bit
    mov w0, #-8
    mov w1, #3
    index z2.h, w0, #-3
    index z3.h, w1, #14

    # 32-bit
    mov w0, #-6
    mov w1, #12
    index z4.s, w0, #0
    index z5.s, w1, #14

    # 64-bit
    mov x0, #-5
    mov x1, #10
    index z6.d, x0, #-9
    index z7.d, x1, #10
  )");
  CHECK_NEON(0, uint8_t, fillNeonBaseAndOffset<uint8_t>(-16, -16, VL / 8));
  CHECK_NEON(1, uint8_t, fillNeonBaseAndOffset<uint8_t>(15, 7, VL / 8));
  CHECK_NEON(2, uint16_t, fillNeonBaseAndOffset<uint16_t>(-8, -3, VL / 8));
  CHECK_NEON(3, uint16_t, fillNeonBaseAndOffset<uint16_t>(3, 14, VL / 8));
  CHECK_NEON(4, uint32_t, fillNeonBaseAndOffset<uint32_t>(-6, 0, VL / 8));
  CHECK_NEON(5, uint32_t, fillNeonBaseAndOffset<uint32_t>(12, 14, VL / 8));
  CHECK_NEON(6, uint64_t, fillNeonBaseAndOffset<uint64_t>(-5, -9, VL / 8));
  CHECK_NEON(7, uint64_t, fillNeonBaseAndOffset<uint64_t>(10, 10, VL / 8));

  // Immediate, Scalar
  RUN_AARCH64(R"(
    # 8-bit
    mov w0, #-16
    mov w1, #7
    index z0.b, #-16, w0
    index z1.b, #15, w1

    # 16-bit
    mov w0, #-3
    mov w1, #14
    index z2.h, #-8, w0
    index z3.h, #3, w1

    # 32-bit
    mov w0, #0
    mov w1, #14
    index z4.s, #-6, w0
    index z5.s, #12, w1

    # 64-bit
    mov x0, #-9
    mov x1, #10
    index z6.d, #-5, x0
    index z7.d, #10, x1
  )");
  CHECK_NEON(0, uint8_t, fillNeonBaseAndOffset<uint8_t>(-16, -16, VL / 8));
  CHECK_NEON(1, uint8_t, fillNeonBaseAndOffset<uint8_t>(15, 7, VL / 8));
  CHECK_NEON(2, uint16_t, fillNeonBaseAndOffset<uint16_t>(-8, -3, VL / 8));
  CHECK_NEON(3, uint16_t, fillNeonBaseAndOffset<uint16_t>(3, 14, VL / 8));
  CHECK_NEON(4, uint32_t, fillNeonBaseAndOffset<uint32_t>(-6, 0, VL / 8));
  CHECK_NEON(5, uint32_t, fillNeonBaseAndOffset<uint32_t>(12, 14, VL / 8));
  CHECK_NEON(6, uint64_t, fillNeonBaseAndOffset<uint64_t>(-5, -9, VL / 8));
  CHECK_NEON(7, uint64_t, fillNeonBaseAndOffset<uint64_t>(10, 10, VL / 8));

  // Scalar, Scalar
  RUN_AARCH64(R"(
    # 8-bit
    mov w0, #-16
    mov w1, #7
    mov w2, #15
    index z0.b, w0, w0
    index z1.b, w2, w1

    # 16-bit
    mov w0, #-3
    mov w1, #-8
    mov w2, #14
    mov w3, #3
    index z2.h, w1, w0
    index z3.h, w3, w2

    # 32-bit
    mov w0, #0
    mov w1, #-6
    mov w2, #14
    mov w3, #12
    index z4.s, w1, w0
    index z5.s, w3, w2

    # 64-bit
    mov x0, #-9
    mov x1, #-5
    mov x2, #10
    index z6.d, x1, x0
    index z7.d, x2, x2
  )");
  CHECK_NEON(0, uint8_t, fillNeonBaseAndOffset<uint8_t>(-16, -16, VL / 8));
  CHECK_NEON(1, uint8_t, fillNeonBaseAndOffset<uint8_t>(15, 7, VL / 8));
  CHECK_NEON(2, uint16_t, fillNeonBaseAndOffset<uint16_t>(-8, -3, VL / 8));
  CHECK_NEON(3, uint16_t, fillNeonBaseAndOffset<uint16_t>(3, 14, VL / 8));
  CHECK_NEON(4, uint32_t, fillNeonBaseAndOffset<uint32_t>(-6, 0, VL / 8));
  CHECK_NEON(5, uint32_t, fillNeonBaseAndOffset<uint32_t>(12, 14, VL / 8));
  CHECK_NEON(6, uint64_t, fillNeonBaseAndOffset<uint64_t>(-5, -9, VL / 8));
  CHECK_NEON(7, uint64_t, fillNeonBaseAndOffset<uint64_t>(10, 10, VL / 8));
}

TEST_P(InstSve, ld1rd) {
  initialHeapData_.resize(16);
  uint64_t* heap64 = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  fillHeap<uint64_t>(heap64, {0xDEADBEEF, 0x12345678}, 2);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # Load and broadcast values from heap
    ptrue p0.d
    ld1rd {z0.d}, p0/z, [x0]
    ld1rd {z1.d}, p0/z, [x0, #8]

    # Test for inactive lanes
    mov x1, #0
    addvl x1, x1, #1
    mov x2, #16
    udiv x1, x1, x2
    whilelo p1.d, xzr, x1
    ld1rd {z2.d}, p1/z, [x0]
    ld1rd {z3.d}, p1/z, [x0, #8]
  )");
  CHECK_NEON(0, uint64_t, fillNeon<uint64_t>({0xDEADBEEF}, VL / 8));
  CHECK_NEON(1, uint64_t, fillNeon<uint64_t>({0x12345678}, VL / 8));
  CHECK_NEON(2, uint64_t, fillNeon<uint64_t>({0xDEADBEEF}, VL / 16));
  CHECK_NEON(3, uint64_t, fillNeon<uint64_t>({0x12345678}, VL / 16));
}

TEST_P(InstSve, ld1rqd) {
  initialHeapData_.resize(32);
  uint64_t* heap64 = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  fillHeap<uint64_t>(heap64, {0xDEADBEEF, 0x12345678, 0x98765432, 0xABCDEF01},
                     4);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # Load and broadcast values from heap
    ptrue p0.d
    ld1rqd {z0.d}, p0/z, [x0]
    ld1rqd {z1.d}, p0/z, [x0, #16]

    # Test for inactive lanes
    ptrue p1.d, vl1
    ld1rqd {z2.d}, p1/z, [x0]
    add x0, x0, #32
    ld1rqd {z3.d}, p1/z, [x0, #-16]
  )");
  CHECK_NEON(0, uint64_t, fillNeon<uint64_t>({0xDEADBEEF, 0x12345678}, VL / 8));
  CHECK_NEON(1, uint64_t, fillNeon<uint64_t>({0x98765432, 0xABCDEF01}, VL / 8));
  CHECK_NEON(2, uint64_t, fillNeon<uint64_t>({0xDEADBEEF, 0}, VL / 8));
  CHECK_NEON(3, uint64_t, fillNeon<uint64_t>({0x98765432, 0}, VL / 8));
}

TEST_P(InstSve, ld1rw) {
  initialHeapData_.resize(8);
  uint32_t* heap32 = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  fillHeap<uint32_t>(heap32, {0xDEADBEEF, 0x12345678}, 2);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # Load and broadcast values from heap
    ptrue p0.s
    ld1rw {z0.s}, p0/z, [x0]
    ld1rw {z1.s}, p0/z, [x0, #4]

    # Test for inactive lanes
    mov x1, #0
    mov x2, #8
    addvl x1, x1, #1
    udiv x1, x1, x2
    whilelo p1.s, xzr, x1
    ld1rw {z2.s}, p1/z, [x0]
    ld1rw {z3.s}, p1/z, [x0, #4]
  )");
  CHECK_NEON(0, uint64_t, fillNeon<uint64_t>({0xDEADBEEFDEADBEEF}, VL / 8));
  CHECK_NEON(1, uint64_t, fillNeon<uint64_t>({0x1234567812345678}, VL / 8));
  CHECK_NEON(2, uint64_t, fillNeon<uint64_t>({0xDEADBEEFDEADBEEF}, VL / 16));
  CHECK_NEON(3, uint64_t, fillNeon<uint64_t>({0x1234567812345678}, VL / 16));
}

TEST_P(InstSve, ld1b) {
  initialHeapData_.resize(VL / 8);
  uint8_t* heap8 = reinterpret_cast<uint8_t*>(initialHeapData_.data());
  fillHeap<uint8_t>(heap8,
                    {0xEF, 0xBE, 0xAD, 0xDE, 0x78, 0x56, 0x34, 0x12, 0x32, 0x54,
                     0x76, 0x98, 0x01, 0xEF, 0xCD, 0xAB},
                    VL / 8);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    ptrue p0.b
    # Load and broadcast values from heap
    ld1b {z0.b}, p0/z, [x0, x1]

    # Test for inactive lanes
    mov x1, #0
    mov x3, #2
    addvl x1, x1, #1
    udiv x1, x1, x3
    mov x2, #0
    whilelo p1.b, xzr, x1
    ld1b {z1.b}, p1/z, [x0, x2]
  )");
  CHECK_NEON(0, uint8_t,
             fillNeon<uint8_t>({0xEF, 0xBE, 0xAD, 0xDE, 0x78, 0x56, 0x34, 0x12,
                                0x32, 0x54, 0x76, 0x98, 0x01, 0xEF, 0xCD, 0xAB},
                               VL / 8));
  CHECK_NEON(1, uint8_t,
             fillNeon<uint8_t>({0xEF, 0xBE, 0xAD, 0xDE, 0x78, 0x56, 0x34, 0x12,
                                0x32, 0x54, 0x76, 0x98, 0x01, 0xEF, 0xCD, 0xAB},
                               VL / 16));
}

TEST_P(InstSve, ld1sw_gather) {
  RUN_AARCH64(R"(
    mov x0, #0xFF
    index z1.d, x0, #12
    mov x1, #0xFFFF
    index z1.d, x1, #8
    dup z3.d, #8
    dup z4.d, -4

    ptrue p0.d
    mov x2, #0
    mov x3, #16
    addvl x2, x2, #1
    udiv x2, x2, x3
    whilelo p1.d, xzr, x2

    # Put data into memory so we have something to load
    st1w {z3.d}, p0, [z1.d]
    st1w {z4.d}, p1, [z2.d, #80]

    ld1sw {z5.d}, p0/z, [z1.d]
    ld1sw {z6.d}, p1/z, [z2.d, #80]
  )");
  CHECK_NEON(5, int64_t, fillNeon<int64_t>({8}, VL / 8));
  CHECK_NEON(6, int64_t, fillNeonCombined<int64_t>({-4}, {0}, VL / 8));
}

TEST_P(InstSve, ld1d_gather) {
  // Vector plus immediate
  RUN_AARCH64(R"(
    mov x0, #800
    index z1.d, x0, #8
    dup z2.d, #8
    dup z3.d, #4

    ptrue p0.d
    mov x1, #0
    mov x2, #16
    addvl x1, x1, #1
    udiv x1, x1, x2
    whilelo p1.d, xzr, x1

    # Put data into memory so we have something to load
    st1d {z2.d}, p0, [z1.d]
    st1d {z3.d}, p1, [z1.d, #240]

    ld1d {z4.d}, p0/z, [z1.d]
    ld1d {z5.d}, p1/z, [z1.d, #240]
  )");
  CHECK_NEON(4, uint64_t, fillNeon<uint64_t>({8}, VL / 8));
  CHECK_NEON(5, uint64_t, fillNeonCombined<uint64_t>({4}, {0}, VL / 8));

  // Scalar plus vector
  // 64-bit
  RUN_AARCH64(R"(
    mov x0, #800
    index z1.d, x0, #8
    dup z2.d, #8

    ptrue p0.d
    mov x1, #0
    mov x2, #16
    addvl x1, x1, #1
    udiv x1, x1, x2
    whilelo p1.d, xzr, x1

    # Put data into memory so we have something to load
    st1d {z2.d}, p0, [z1.d]  

    index z4.d, #0, #1
    mov x4, #0
    ld1d {z5.d}, p1/z, [x4, z1.d]
    ld1d {z6.d}, p0/z, [x0, z4.d, lsl #3]
  )");
  CHECK_NEON(5, uint64_t, fillNeonCombined<uint64_t>({8}, {0}, VL / 8));
  CHECK_NEON(6, uint64_t, fillNeon<uint64_t>({8}, VL / 8));
}

TEST_P(InstSve, ld1d) {
  initialHeapData_.resize(VL / 4);
  uint64_t* heap64 = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  std::vector<uint64_t> src = {0xDEADBEEF, 0x12345678, 0x98765432, 0xABCDEF01};
  fillHeap<uint64_t>(heap64, src, VL / 32);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #1
    ptrue p0.d
    # Load and broadcast values from heap
    ld1d {z0.d}, p0/z, [x0, x1, lsl #3]
    ld1d {z2.d}, p0/z, [x0]

    # Test for inactive lanes
    mov x1, #0
    mov x3, #16
    addvl x1, x1, #1
    udiv x1, x1, x3
    mov x2, #0
    whilelo p1.d, xzr, x1
    ld1d {z1.d}, p1/z, [x0, x2, lsl #3]
    ld1d {z3.d}, p1/z, [x0, #1, mul vl]
  )");
  CHECK_NEON(0, uint64_t,
             fillNeon<uint64_t>(
                 {0x12345678, 0x98765432, 0xABCDEF01, 0xDEADBEEF}, VL / 8));
  CHECK_NEON(1, uint64_t,
             fillNeon<uint64_t>(
                 {0xDEADBEEF, 0x12345678, 0x98765432, 0xABCDEF01}, VL / 16));
  CHECK_NEON(2, uint64_t,
             fillNeon<uint64_t>(
                 {0xDEADBEEF, 0x12345678, 0x98765432, 0xABCDEF01}, VL / 8));
  uint16_t base = VL / 64;
  CHECK_NEON(3, uint64_t,
             fillNeon<uint64_t>({src[(base) % 4], src[(base + 1) % 4],
                                 src[(base + 2) % 4], src[(base + 3) % 4]},
                                VL / 16));
}

TEST_P(InstSve, ld1h) {
  initialHeapData_.resize(VL / 4);
  uint16_t* heap16 = reinterpret_cast<uint16_t*>(initialHeapData_.data());
  fillHeap<uint16_t>(
      heap16, {0xBEEF, 0xDEAD, 0x5678, 0x1234, 0x5432, 0x9876, 0xEF01, 0xABCD},
      VL / 16);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #32
    ptrue p0.h
    # Load and broadcast values from heap
    ld1h {z0.h}, p0/z, [x0, x1, lsl #1]

    # Test for inactive lanes
    mov x1, #0
    mov x3, #4
    addvl x1, x1, #1
    udiv x1, x1, x3
    mov x2, #0
    whilelo p1.h, xzr, x1
    ld1h {z1.h}, p1/z, [x0, x2, lsl #1]
  )");
  CHECK_NEON(0, uint16_t,
             fillNeon<uint16_t>({0xBEEF, 0xDEAD, 0x5678, 0x1234, 0x5432, 0x9876,
                                 0xEF01, 0xABCD},
                                VL / 8));
  CHECK_NEON(1, uint16_t,
             fillNeonCombined<uint16_t>({0xBEEF, 0xDEAD, 0x5678, 0x1234, 0x5432,
                                         0x9876, 0xEF01, 0xABCD},
                                        {0}, VL / 8));
}

TEST_P(InstSve, ld1w) {
  initialHeapData_.resize(VL / 4);
  uint32_t* heap32 = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  std::vector<uint32_t> src = {0xDEADBEEF, 0x12345678, 0x98765432, 0xABCDEF01};
  fillHeap<uint32_t>(heap32, src, VL / 16);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #1
    ptrue p0.s
    # Load and broadcast values from heap
    ld1w {z0.s}, p0/z, [x0, x1, lsl #2]
    ld1w {z2.s}, p0/z, [x0]

    # Test for inactive lanes
    mov x1, #0
    mov x3, #8
    addvl x1, x1, #1
    udiv x1, x1, x3
    mov x2, #0
    whilelo p1.s, xzr, x1
    ld1w {z1.s}, p1/z, [x0, x2, lsl #2]
    ld1w {z3.s}, p1/z, [x0, #1, mul vl]
  )");
  CHECK_NEON(
      0, uint64_t,
      fillNeon<uint64_t>({0x9876543212345678, 0xDEADBEEFABCDEF01}, VL / 8));
  CHECK_NEON(1, uint64_t,
             fillNeonCombined<uint64_t>(
                 {0x12345678DEADBEEF, 0xABCDEF0198765432}, {0}, VL / 8));
  CHECK_NEON(
      2, uint64_t,
      fillNeon<uint64_t>({0x12345678DEADBEEF, 0xABCDEF0198765432}, VL / 8));
  CHECK_NEON(3, uint64_t,
             fillNeonCombined<uint64_t>(
                 {0x12345678DEADBEEF, 0xABCDEF0198765432}, {0}, VL / 8));
}

TEST_P(InstSve, ld2d) {
  initialHeapData_.resize(VL);
  uint64_t* heap64 = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  std::vector<uint64_t> src = {0xDEADBEEF, 0x12345678, 0x98765432, 0xABCDEF01};
  fillHeap<uint64_t>(heap64, src, VL / 8);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ptrue p0.d
    # Load and broadcast values from heap
    ld2d {z0.d, z1.d}, p0/z, [x0, #2, mul vl]
    ld2d {z2.d, z3.d}, p0/z, [x0]

    # Test for inactive lanes
    mov x1, #0
    mov x3, #16
    addvl x1, x1, #1
    udiv x1, x1, x3
    mov x2, #0
    whilelo p1.d, xzr, x1
    ld2d {z4.d, z5.d}, p1/z, [x0]
    ld2d {z6.d, z7.d}, p1/z, [x0, #4, mul vl]

    # Scalar plus Scalar
    mov x10, #2
    mov x11, #4
    ld2d {z8.d, z9.d}, p0/z, [x0, x10, lsl #3]
    ld2d {z10.d, z11.d}, p1/z, [x0, x11, lsl #3]
  )");
  int elements = VL / 64;  // DIV 64 as loading double words.

  int index = 2 * elements;
  CHECK_NEON(0, uint64_t,
             fillNeon<uint64_t>({src[index % 4], src[(index + 2) % 4],
                                 src[(index + 4) % 4], src[(index + 6) % 4]},
                                VL / 8));
  CHECK_NEON(1, uint64_t,
             fillNeon<uint64_t>({src[(index + 1) % 4], src[(index + 3) % 4],
                                 src[(index + 5) % 4], src[(index + 7) % 4]},
                                VL / 8));

  CHECK_NEON(2, uint64_t,
             fillNeon<uint64_t>(
                 {0xDEADBEEF, 0x98765432, 0xDEADBEEF, 0x98765432}, VL / 8));
  CHECK_NEON(3, uint64_t,
             fillNeon<uint64_t>(
                 {0x12345678, 0xABCDEF01, 0x12345678, 0xABCDEF01}, VL / 8));

  CHECK_NEON(4, uint64_t,
             fillNeon<uint64_t>(
                 {0xDEADBEEF, 0x98765432, 0xDEADBEEF, 0x98765432}, VL / 16));
  CHECK_NEON(5, uint64_t,
             fillNeon<uint64_t>(
                 {0x12345678, 0xABCDEF01, 0x12345678, 0xABCDEF01}, VL / 16));

  index = 4 * elements;
  CHECK_NEON(6, uint64_t,
             fillNeon<uint64_t>({src[index % 4], src[(index + 2) % 4],
                                 src[(index + 4) % 4], src[(index + 6) % 4]},
                                VL / 16));
  CHECK_NEON(7, uint64_t,
             fillNeon<uint64_t>({src[(index + 1) % 4], src[(index + 3) % 4],
                                 src[(index + 5) % 4], src[(index + 7) % 4]},
                                VL / 16));

  index = 2;
  CHECK_NEON(8, uint64_t,
             fillNeon<uint64_t>({src[index % 4], src[(index + 2) % 4],
                                 src[(index + 4) % 4], src[(index + 6) % 4]},
                                VL / 8));
  CHECK_NEON(9, uint64_t,
             fillNeon<uint64_t>({src[(index + 1) % 4], src[(index + 3) % 4],
                                 src[(index + 5) % 4], src[(index + 7) % 4]},
                                VL / 8));
  index = 4;
  CHECK_NEON(10, uint64_t,
             fillNeon<uint64_t>({src[index % 4], src[(index + 2) % 4],
                                 src[(index + 4) % 4], src[(index + 6) % 4]},
                                VL / 16));
  CHECK_NEON(11, uint64_t,
             fillNeon<uint64_t>({src[(index + 1) % 4], src[(index + 3) % 4],
                                 src[(index + 5) % 4], src[(index + 7) % 4]},
                                VL / 16));
}

TEST_P(InstSve, ld3d) {
  initialHeapData_.resize(3 * (VL / 2));
  uint64_t* heap64 = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  std::vector<uint64_t> src = {0xDEADBEEF, 0x12345678, 0x98765432, 0xABCDEF01};
  fillHeap<uint64_t>(heap64, src, 3 * (VL / 16));

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ptrue p0.d
    # Load and broadcast values from heap
    ld3d {z0.d, z1.d, z2.d}, p0/z, [x0, #3, mul vl]
    ld3d {z3.d, z4.d, z5.d}, p0/z, [x0]

    # Test for inactive lanes
    mov x1, #0
    mov x3, #16
    addvl x1, x1, #1
    udiv x1, x1, x3
    whilelo p1.d, xzr, x1
    ld3d {z6.d, z7.d, z8.d}, p1/z, [x0]
    ld3d {z9.d, z10.d, z11.d}, p1/z, [x0, #6, mul vl]
  )");
  int elements = VL / 64;  // DIV 64 as loading double words.

  int index = 3 * elements;
  CHECK_NEON(0, uint64_t,
             fillNeon<uint64_t>({src[index % 4], src[(index + 3) % 4],
                                 src[(index + 6) % 4], src[(index + 9) % 4]},
                                VL / 8));
  CHECK_NEON(1, uint64_t,
             fillNeon<uint64_t>({src[(index + 1) % 4], src[(index + 4) % 4],
                                 src[(index + 7) % 4], src[(index + 10) % 4]},
                                VL / 8));
  CHECK_NEON(2, uint64_t,
             fillNeon<uint64_t>({src[(index + 2) % 4], src[(index + 5) % 4],
                                 src[(index + 8) % 4], src[(index + 11) % 4]},
                                VL / 8));

  CHECK_NEON(3, uint64_t,
             fillNeon<uint64_t>(
                 {0xDEADBEEF, 0xABCDEF01, 0x98765432, 0x12345678}, VL / 8));
  CHECK_NEON(4, uint64_t,
             fillNeon<uint64_t>(
                 {0x12345678, 0xDEADBEEF, 0xABCDEF01, 0x98765432}, VL / 8));
  CHECK_NEON(5, uint64_t,
             fillNeon<uint64_t>(
                 {0x98765432, 0x12345678, 0xDEADBEEF, 0xABCDEF01}, VL / 8));

  CHECK_NEON(6, uint64_t,
             fillNeon<uint64_t>(
                 {0xDEADBEEF, 0xABCDEF01, 0x98765432, 0x12345678}, VL / 16));
  CHECK_NEON(7, uint64_t,
             fillNeon<uint64_t>(
                 {0x12345678, 0xDEADBEEF, 0xABCDEF01, 0x98765432}, VL / 16));
  CHECK_NEON(8, uint64_t,
             fillNeon<uint64_t>(
                 {0x98765432, 0x12345678, 0xDEADBEEF, 0xABCDEF01}, VL / 16));

  index = 6 * elements;
  CHECK_NEON(9, uint64_t,
             fillNeon<uint64_t>({src[index % 4], src[(index + 3) % 4],
                                 src[(index + 6) % 4], src[(index + 9) % 4]},
                                VL / 16));
  CHECK_NEON(10, uint64_t,
             fillNeon<uint64_t>({src[(index + 1) % 4], src[(index + 4) % 4],
                                 src[(index + 7) % 4], src[(index + 10) % 4]},
                                VL / 16));
  CHECK_NEON(11, uint64_t,
             fillNeon<uint64_t>({src[(index + 2) % 4], src[(index + 5) % 4],
                                 src[(index + 8) % 4], src[(index + 11) % 4]},
                                VL / 16));
}

TEST_P(InstSve, ld4d) {
  initialHeapData_.resize(128 * (VL / 2));
  uint64_t* heap64 = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  std::vector<uint64_t> src = {0xDEADBEEF, 0x12345678, 0x98765432, 0xABCDEF01};
  fillHeap<uint64_t>(heap64, src, 128 * (VL / 16));

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ptrue p0.d
    # Load and broadcast values from heap
    ld4d {z0.d, z1.d, z2.d, z3.d}, p0/z, [x0, #4, mul vl]
    ld4d {z4.d, z5.d, z6.d, z7.d}, p0/z, [x0]

    # Test for inactive lanes
    mov x1, #0
    mov x3, #16
    addvl x1, x1, #1
    udiv x1, x1, x3
    whilelo p1.d, xzr, x1
    ld4d {z8.d, z9.d, z10.d, z11.d}, p1/z, [x0]
    ld4d {z12.d, z13.d, z14.d, z15.d}, p1/z, [x0, #8, mul vl]
  )");
  int elements = VL / 64;  // DIV 64 as loading double words.

  int index = 4 * elements;
  CHECK_NEON(0, uint64_t,
             fillNeon<uint64_t>({src[index % 4], src[(index + 4) % 4],
                                 src[(index + 8) % 4], src[(index + 12) % 4]},
                                VL / 8));
  CHECK_NEON(1, uint64_t,
             fillNeon<uint64_t>({src[(index + 1) % 4], src[(index + 5) % 4],
                                 src[(index + 9) % 4], src[(index + 13) % 4]},
                                VL / 8));
  CHECK_NEON(2, uint64_t,
             fillNeon<uint64_t>({src[(index + 2) % 4], src[(index + 6) % 4],
                                 src[(index + 10) % 4], src[(index + 14) % 4]},
                                VL / 8));
  CHECK_NEON(3, uint64_t,
             fillNeon<uint64_t>({src[(index + 3) % 4], src[(index + 7) % 4],
                                 src[(index + 11) % 4], src[(index + 15) % 4]},
                                VL / 8));  //

  CHECK_NEON(4, uint64_t, fillNeon<uint64_t>({0xDEADBEEF}, VL / 8));  //
  CHECK_NEON(5, uint64_t, fillNeon<uint64_t>({0x12345678}, VL / 8));  //
  CHECK_NEON(6, uint64_t, fillNeon<uint64_t>({0x98765432}, VL / 8));
  CHECK_NEON(7, uint64_t, fillNeon<uint64_t>({0xABCDEF01}, VL / 8));

  CHECK_NEON(8, uint64_t, fillNeon<uint64_t>({0xDEADBEEF}, VL / 16));
  CHECK_NEON(9, uint64_t, fillNeon<uint64_t>({0x12345678}, VL / 16));
  CHECK_NEON(10, uint64_t, fillNeon<uint64_t>({0x98765432}, VL / 16));
  CHECK_NEON(11, uint64_t, fillNeon<uint64_t>({0xABCDEF01}, VL / 16));

  index = 8 * elements;
  CHECK_NEON(12, uint64_t,
             fillNeon<uint64_t>({src[index % 4], src[(index + 4) % 4],
                                 src[(index + 8) % 4], src[(index + 12) % 4]},
                                VL / 16));
  CHECK_NEON(13, uint64_t,
             fillNeon<uint64_t>({src[(index + 1) % 4], src[(index + 5) % 4],
                                 src[(index + 9) % 4], src[(index + 13) % 4]},
                                VL / 16));  //
  CHECK_NEON(14, uint64_t,
             fillNeon<uint64_t>({src[(index + 2) % 4], src[(index + 6) % 4],
                                 src[(index + 10) % 4], src[(index + 14) % 4]},
                                VL / 16));  //
  CHECK_NEON(15, uint64_t,
             fillNeon<uint64_t>({src[(index + 3) % 4], src[(index + 7) % 4],
                                 src[(index + 11) % 4], src[(index + 15) % 4]},
                                VL / 16));  //
}

TEST_P(InstSve, ldr_predicate) {
  initialHeapData_.resize(VL / 64);
  uint8_t* heap8 = reinterpret_cast<uint8_t*>(initialHeapData_.data());
  // B arrangement
  fillHeap<uint8_t>(heap8, {0xFF}, VL / 64);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    ldr p0, [x0, #0, mul vl]
  )");
  CHECK_PREDICATE(0, uint64_t, fillPred((VL / 8), {1}, 1));
  // H arrangement
  fillHeap<uint8_t>(heap8, {0x55}, VL / 64);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    ldr p0, [x0, #0, mul vl]
  )");
  CHECK_PREDICATE(0, uint64_t, fillPred((VL / 8), {1}, 2));
  // S arrangement
  fillHeap<uint8_t>(heap8, {0x11}, VL / 64);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    ldr p0, [x0, #0, mul vl]
  )");
  CHECK_PREDICATE(0, uint64_t, fillPred((VL / 8), {1}, 4));
  // D arrangement
  fillHeap<uint8_t>(heap8, {0x01}, VL / 64);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    ldr p0, [x0, #0, mul vl]
  )");
  CHECK_PREDICATE(0, uint64_t, fillPred((VL / 8), {1}, 8));
}

TEST_P(InstSve, ldr_vector) {
  initialHeapData_.resize(VL / 4);
  uint64_t* heap64 = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  std::vector<uint64_t> src = {0xFFFFFFFFFFFFFFFF, 0x0,
                               0xDEADBEEFDEADBEEF, 0x1234567812345678,
                               0xFFFFFFFFFFFFFFFF, 0x98765432ABCDEF01,
                               0xDEADBEEFDEADBEEF, 0x1234567812345678};
  fillHeap<uint64_t>(heap64, src, VL / 32);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr z0, [x0, #0, mul vl]
    ldr z1, [x0, #1, mul vl]
  )");

  CHECK_NEON(0, uint64_t, fillNeon<uint64_t>(src, VL / 8));
  std::rotate(src.begin(), src.begin() + ((VL / 64) % 8), src.end());
  CHECK_NEON(1, uint64_t, fillNeon<uint64_t>(src, VL / 8));
}

TEST_P(InstSve, lsl) {
  // 32-bit arrangement
  RUN_AARCH64(R"(
    dup z0.s, #7
    dup z1.s, #-7
    dup z2.s, #1

    lsl z0.s, z0.s, #0
    lsl z1.s, z1.s, #2
    lsl z2.s, z2.s, #31
  )");

  CHECK_NEON(0, uint32_t, fillNeon<uint32_t>({7}, VL / 8));
  CHECK_NEON(1, int32_t, fillNeon<int32_t>({-28}, VL / 8));
  CHECK_NEON(2, uint32_t, fillNeon<uint32_t>({2147483648}, VL / 8));
}

TEST_P(InstSve, mla) {
  // 8-bit
  RUN_AARCH64(R"(
    ptrue p0.b
    mov x0, #0
    addvl x1, x0, #1
    mov x2, #2
    udiv x3, x1, x2
    whilelo p1.b, xzr, x3

    dup z0.b, #2
    dup z1.b, #3 
    dup z2.b, #5
    dup z3.b, #4

    mla z2.b, p0/m, z0.b, z1.b
    mla z3.b, p1/m, z0.b, z1.b
  )");
  CHECK_NEON(2, uint8_t, fillNeon<uint8_t>({11}, VL / 8));
  CHECK_NEON(3, uint8_t, fillNeonCombined<uint8_t>({10}, {4}, VL / 8));

  // 16-bit
  RUN_AARCH64(R"(
    ptrue p0.h
    mov x0, #0
    addvl x1, x0, #1
    mov x2, #4
    udiv x3, x1, x2
    whilelo p1.h, xzr, x3

    dup z0.h, #2
    dup z1.h, #3 
    dup z2.h, #5
    dup z3.h, #4

    mla z2.h, p0/m, z0.h, z1.h
    mla z3.h, p1/m, z0.h, z1.h
  )");
  CHECK_NEON(2, uint16_t, fillNeon<uint16_t>({11}, VL / 8));
  CHECK_NEON(3, uint16_t, fillNeonCombined<uint16_t>({10}, {4}, VL / 8));

  // 32-bit
  RUN_AARCH64(R"(
    ptrue p0.s
    mov x0, #0
    addvl x1, x0, #1
    mov x2, #8
    udiv x3, x1, x2
    whilelo p1.s, xzr, x3

    dup z0.s, #2
    dup z1.s, #3 
    dup z2.s, #5
    dup z3.s, #4

    mla z2.s, p0/m, z0.s, z1.s
    mla z3.s, p1/m, z0.s, z1.s
  )");
  CHECK_NEON(2, uint32_t, fillNeon<uint32_t>({11}, VL / 8));
  CHECK_NEON(3, uint32_t, fillNeonCombined<uint32_t>({10}, {4}, VL / 8));

  // 64-bit
  RUN_AARCH64(R"(
    ptrue p0.d
    mov x0, #0
    addvl x1, x0, #1
    mov x2, #16
    udiv x3, x1, x2
    whilelo p1.d, xzr, x3

    dup z0.d, #2
    dup z1.d, #3 
    dup z2.d, #5
    dup z3.d, #4

    mla z2.d, p0/m, z0.d, z1.d
    mla z3.d, p1/m, z0.d, z1.d
  )");
  CHECK_NEON(2, uint64_t, fillNeon<uint64_t>({11}, VL / 8));
  CHECK_NEON(3, uint64_t, fillNeonCombined<uint64_t>({10}, {4}, VL / 8));
}

TEST_P(InstSve, movprfx) {
  // Non-predicated
  RUN_AARCH64(R"(
    fdup z0.s, #7
    fdup z1.s, #-7
    fdup z2.d, #14
    dup z7.s, #0
    dup z8.s, #0
    fdup z9.s, #7
    fdup z10.s, #14

    ptrue p0.s

    movprfx z3, z0
    fmla z3.s, p0/m, z7.s, z8.s
    movprfx z4, z1
    fmla z4.s, p0/m, z7.s, z8.s
    movprfx z5, z2
    fmla z5.s, p0/m, z7.s, z8.s

    # Ensure implementation without hint use gives correct output
    movprfx z6, z1
    fmla z6.s, p0/m, z9.s, z10.s
  )");

  CHECK_NEON(3, float, fillNeon<float>({7}, VL / 8));
  CHECK_NEON(4, float, fillNeon<float>({-7}, VL / 8));
  CHECK_NEON(5, double, fillNeon<double>({14}, VL / 8));
  CHECK_NEON(6, float, fillNeon<float>({91}, VL / 8));

  // Predicated
  RUN_AARCH64(R"(
    mov x0, #0
    addvl x1, x0, #1
    mov x2, #8
    udiv x3, x1, x2
    mov x4, #16
    udiv x5, x1, x4
    whilelo p0.s, xzr, x3
    whilelo p1.d, xzr, x3
    whilelo p3.d, xzr, x5

    dup z0.s, #9
    dup z1.d, #5

    dup z2.s, #0
    dup z3.d, #0

    dup z6.d, #3

    movprfx z4.s, p0/z, z0.s
    fmla z4.s, p0/m, z2.s, z2.s
    movprfx z5.d, p1/z, z1.d
    fmla z5.d, p1/m, z3.d, z3.d
    movprfx z6.d, p3/m, z1.d
    fmla z6.d, p3/m, z3.d, z3.d
  )");
  CHECK_NEON(4, uint32_t, fillNeonCombined<uint32_t>({9u}, {0}, VL / 8));
  CHECK_NEON(5, uint64_t, fillNeon<uint64_t>({5u}, VL / 8));
  CHECK_NEON(6, uint64_t, fillNeonCombined<uint64_t>({5u}, {3u}, VL / 8));
}

TEST_P(InstSve, mul) {
  // Vectors
  // 8-bit
  RUN_AARCH64(R"(
    ptrue p0.b
    mov x0, #0
    addvl x1, x0, #1
    mov x2, #2
    udiv x3, x1, x2
    whilelo p1.b, xzr, x3

    mov z0.b, #2
    mov z1.b, #3
    mov z2.b, #2

    mul z0.b, p0/m, z0.b, z2.b
    mul z1.b, p1/m, z1.b, z2.b
  )");
  CHECK_NEON(0, uint8_t, fillNeon<uint8_t>({4}, VL / 8));
  CHECK_NEON(1, uint8_t, fillNeonCombined<uint8_t>({6}, {3}, VL / 8));

  // 16-bit
  RUN_AARCH64(R"(
    ptrue p0.h
    mov x0, #0
    addvl x1, x0, #1
    mov x2, #4
    udiv x3, x1, x2
    whilelo p1.h, xzr, x3

    mov z0.h, #2
    mov z1.h, #3
    mov z2.h, #2

    mul z0.h, p0/m, z0.h, z2.h
    mul z1.h, p1/m, z1.h, z2.h
  )");
  CHECK_NEON(0, uint16_t, fillNeon<uint16_t>({4}, VL / 8));
  CHECK_NEON(1, uint16_t, fillNeonCombined<uint16_t>({6}, {3}, VL / 8));

  // 32-bit
  RUN_AARCH64(R"(
    ptrue p0.s
    mov x0, #0
    addvl x1, x0, #1
    mov x2, #8
    udiv x3, x1, x2
    whilelo p1.s, xzr, x3

    mov z0.s, #2
    mov z1.s, #3
    mov z2.s, #2

    mul z0.s, p0/m, z0.s, z2.s
    mul z1.s, p1/m, z1.s, z2.s
  )");
  CHECK_NEON(0, uint32_t, fillNeon<uint32_t>({4}, VL / 8));
  CHECK_NEON(1, uint32_t, fillNeonCombined<uint32_t>({6}, {3}, VL / 8));

  // 64-bit
  RUN_AARCH64(R"(
    ptrue p0.d
    mov x0, #0
    addvl x1, x0, #1
    mov x2, #16
    udiv x3, x1, x2
    whilelo p1.d, xzr, x3

    mov z0.d, #2
    mov z1.d, #3
    mov z2.d, #2

    mul z0.d, p0/m, z0.d, z2.d
    mul z1.d, p1/m, z1.d, z2.d
  )");
  CHECK_NEON(0, uint64_t, fillNeon<uint64_t>({4}, VL / 8));
  CHECK_NEON(1, uint64_t, fillNeonCombined<uint64_t>({6}, {3}, VL / 8));
}

TEST_P(InstSve, orr) {
  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #8
    addvl x0, x0, #1
    udiv x0, x0, x1

    # Test varying permutations of active and inactive lanes
    ptrue p0.s
    ptrue p1.s
    ptrue p2.s
    orr p3.b, p0/z, p1.b, p2.b

    whilelo p1.s, xzr, x0
    orr p4.b, p0/z, p1.b, p2.b

    whilelo p2.s, xzr, x0
    orr p5.b, p0/z, p1.b, p2.b

    whilelo p0.s, xzr, x0
    ptrue p1.s
    ptrue p2.s
    orr p6.b, p0/z, p1.b, p2.b

    # Check mov alias
    mov p7.b, p0.b
    mov p8.b, p1.b

    mov z0.s, #127
    mov z1.d, z0.d
  )");
  CHECK_PREDICATE(3, uint64_t, fillPred(VL / 8, {1}, 4));
  CHECK_PREDICATE(4, uint64_t, fillPred(VL / 8, {1}, 4));
  CHECK_PREDICATE(5, uint64_t, fillPred(VL / 16, {1}, 4));
  CHECK_PREDICATE(6, uint64_t, fillPred(VL / 16, {1}, 4));
  CHECK_PREDICATE(7, uint64_t, fillPred(VL / 16, {1}, 4));
  CHECK_PREDICATE(8, uint64_t, fillPred(VL / 8, {1}, 4));

  CHECK_NEON(1, uint64_t, fillNeon<uint64_t>({0x7F0000007F}, VL / 8));
}

TEST_P(InstSve, ptest) {
  RUN_AARCH64(R"(
    ptrue p0.s
    ptest p0, p0.b
  )");
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    ptrue p0.s
    mov x0, #0
    mov x1, #8
    addvl x0, x0, #1
    udiv x0, x0, x1
    whilelo p1.s, xzr, x0
    ptest p1, p0.b
  )");
  EXPECT_EQ(getNZCV(), 0b1010);
}

TEST_P(InstSve, pfalse) {
  RUN_AARCH64(R"(
    pfalse p0.b
  )");
  CHECK_PREDICATE(0, uint64_t, fillPred(VL / 8, {0}, 1));
}

TEST_P(InstSve, ptrue) {
  RUN_AARCH64(R"(
    ptrue p0.s
    ptrue p1.d
    ptrue p2.b
    ptrue p3.h
  )");
  CHECK_PREDICATE(0, uint64_t, fillPred(VL / 8, {1}, 4));
  CHECK_PREDICATE(1, uint64_t, fillPred(VL / 8, {1}, 8));
  CHECK_PREDICATE(2, uint64_t, fillPred(VL / 8, {1}, 1));
  CHECK_PREDICATE(3, uint64_t, fillPred(VL / 8, {1}, 2));
}

TEST_P(InstSve, punpk) {
  RUN_AARCH64(R"(
    ptrue p0.b
    mov x0, #0
    mov x1, #8
    addvl x0, x0, #1
    udiv x0, x0, x1
    whilelo p1.s, xzr, x0
    punpkhi p2.h, p0.b
    punpkhi p3.h, p1.b
    punpklo p4.h, p0.b
    punpklo p5.h, p1.b
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(VL / 8, {1}, 2));
  CHECK_PREDICATE(3, uint64_t, fillPred(VL / 8, {0}, 2));
  CHECK_PREDICATE(4, uint64_t, fillPred(VL / 8, {1}, 2));
  CHECK_PREDICATE(5, uint64_t, fillPred(VL / 8, {1}, 8));
}

TEST_P(InstSve, rdvl) {
  RUN_AARCH64(R"(
    rdvl x0, #-32
    rdvl x1, #-3
    rdvl x2, #0
    rdvl x3, #3
    rdvl x4, #31
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(0), (VL / 8) * -32);
  EXPECT_EQ(getGeneralRegister<int64_t>(1), (VL / 8) * -3);
  EXPECT_EQ(getGeneralRegister<int64_t>(2), 0);
  EXPECT_EQ(getGeneralRegister<int64_t>(3), (VL / 8) * 3);
  EXPECT_EQ(getGeneralRegister<int64_t>(4), (VL / 8) * 31);
}

TEST_P(InstSve, rev) {
  // Predicate
  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #2
    mov x2, #4
    mov x3, #8
    mov x4, #16
    addvl x5, x0, #1
    udiv x6, x5, x1
    udiv x7, x5, x2
    udiv x8, x5, x3
    udiv x9, x5, x4

    whilelo p0.b, xzr, x6
    whilelo p1.h, xzr, x7
    whilelo p2.s, xzr, x8
    whilelo p3.d, xzr, x9

    rev p4.b, p0.b
    rev p5.h, p1.h
    rev p6.s, p2.s
    rev p7.d, p3.d
  )");

  CHECK_PREDICATE(0, uint8_t,
                  fillPredFromTwoSources<uint8_t>({0xFFu}, {0}, VL / 64));
  CHECK_PREDICATE(1, uint8_t,
                  fillPredFromTwoSources<uint8_t>({0x55u}, {0}, VL / 64));
  CHECK_PREDICATE(2, uint8_t,
                  fillPredFromTwoSources<uint8_t>({0x11u}, {0}, VL / 64));
  CHECK_PREDICATE(3, uint8_t,
                  fillPredFromTwoSources<uint8_t>({0x1u}, {0}, VL / 64));

  CHECK_PREDICATE(4, uint8_t,
                  fillPredFromTwoSources<uint8_t>({0}, {0xFFu}, VL / 64));
  CHECK_PREDICATE(5, uint8_t,
                  fillPredFromTwoSources<uint8_t>({0}, {0x55u}, VL / 64));
  CHECK_PREDICATE(6, uint8_t,
                  fillPredFromTwoSources<uint8_t>({0}, {0x11u}, VL / 64));
  CHECK_PREDICATE(7, uint8_t,
                  fillPredFromTwoSources<uint8_t>({0}, {0x1u}, VL / 64));

  // Vector
  RUN_AARCH64(R"(
    index z0.b, #0, #1
    index z1.h, #0, #2
    index z2.s, #0, #4
    index z3.d, #0, #8

    rev z4.b, z0.b
    rev z5.h, z1.h
    rev z6.s, z2.s
    rev z7.d, z3.d
  )");
  CHECK_NEON(4, uint8_t,
             fillNeonBaseAndOffset<uint8_t>((VL / 8 - 1), -1, VL / 8));
  CHECK_NEON(5, uint16_t,
             fillNeonBaseAndOffset<uint16_t>((VL / 8 - 2), -2, VL / 8));
  CHECK_NEON(6, uint32_t,
             fillNeonBaseAndOffset<uint32_t>((VL / 8 - 4), -4, VL / 8));
  CHECK_NEON(7, uint64_t,
             fillNeonBaseAndOffset<uint64_t>((VL / 8 - 8), -8, VL / 8));
}

TEST_P(InstSve, scvtf) {
  RUN_AARCH64(R"(
    dup z0.s, #-6
    dup z1.s, #12
    dup z2.d, #-5
    dup z3.d, #10

    ptrue p0.s
    ptrue p1.d
    mov x1, #0
    mov x2, #8
    mov x3, #16
    addvl x4, x1, #1
    udiv x5, x4, x2
    udiv x6, x4, x3
    
    whilelo p2.s, xzr, x5
    whilelo p3.d, xzr, x6

    # int64 -> double
    scvtf z5.d, p1/m, z2.d
    scvtf z6.d, p3/m, z3.d

    # int64 -> float
    scvtf z7.s, p1/m, z2.d
    scvtf z8.s, p3/m, z3.d

    # int32 -> double
    scvtf z9.d, p0/m, z0.s
    scvtf z10.d, p2/m, z1.s

    # int32 -> float
    scvtf z11.s, p0/m, z0.s
    scvtf z12.s, p2/m, z1.s
  )");

  CHECK_NEON(5, double, fillNeon<double>({-5.0}, VL / 8));
  CHECK_NEON(6, double, fillNeon<double>({0xa}, VL / 16));
  CHECK_NEON(7, float, fillNeon<float>({-5.0f, 0}, VL / 8));
  CHECK_NEON(8, float, fillNeon<float>({0xa, 0}, VL / 16));
  CHECK_NEON(9, double, fillNeon<double>({-6.0}, VL / 8));
  CHECK_NEON(10, double, fillNeon<double>({0xc}, VL / 16));
  CHECK_NEON(11, float, fillNeon<float>({-6.0f}, VL / 8));
  CHECK_NEON(12, float, fillNeon<float>({0xc}, VL / 16));

  // Boundary tests
  // Double
  initialHeapData_.resize(16);
  int64_t* dheap = reinterpret_cast<int64_t*>(initialHeapData_.data());
  dheap[0] = INT64_MAX;
  dheap[1] = INT64_MIN;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ptrue p0.d
    
    mov x1, #0
    addvl x2, x1, #1
    mov x3, #16
    udiv x4, x2, x3
    whilelo p1.d, xzr, x4

    ldr x5, [x0]
    ldr x6, [x0, #8]

    dup z0.d, x5
    dup z1.d, x6

    # int64 -> double
    scvtf z2.d, p0/m, z0.d
    scvtf z3.d, p1/m, z1.d

    # int64 -> single
    scvtf z4.s, p0/m, z0.d
    scvtf z5.s, p1/m, z1.d
  )");
  CHECK_NEON(2, double,
             fillNeon<double>({static_cast<double>(INT64_MAX)}, VL / 8));
  CHECK_NEON(3, double,
             fillNeonCombined<double>({static_cast<double>(INT64_MIN)},
                                      {static_cast<double>(0)}, VL / 8));
  CHECK_NEON(4, float,
             fillNeon<float>({static_cast<float>(INT64_MAX), 0}, VL / 8));
  CHECK_NEON(5, float,
             fillNeonCombined<float>({static_cast<float>(INT64_MIN), 0},
                                     {static_cast<float>(0)}, VL / 8));

  // Single
  initialHeapData_.resize(8);
  int32_t* fheap = reinterpret_cast<int32_t*>(initialHeapData_.data());
  fheap[0] = INT32_MAX;
  fheap[1] = INT32_MIN;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ptrue p0.s
    
    mov x1, #0
    addvl x2, x1, #1
    mov x3, #8
    udiv x4, x2, x3
    whilelo p1.s, xzr, x4

    ldr w5, [x0]
    ldr w6, [x0, #4]

    dup z0.s, w5
    dup z1.s, w6

    # int32 -> double
    scvtf z2.d, p0/m, z0.s
    scvtf z3.d, p1/m, z1.s

    # int32 -> single
    scvtf z4.s, p0/m, z0.s
    scvtf z5.s, p1/m, z1.s
  )");
  CHECK_NEON(2, double,
             fillNeon<double>({static_cast<double>(INT32_MAX)}, VL / 8));
  CHECK_NEON(3, double,
             fillNeonCombined<double>({static_cast<double>(INT32_MIN)},
                                      {static_cast<double>(0)}, VL / 8));
  CHECK_NEON(4, float,
             fillNeon<float>({static_cast<float>(INT32_MAX)}, VL / 8));
  CHECK_NEON(5, float,
             fillNeonCombined<float>({static_cast<float>(INT32_MIN)},
                                     {static_cast<float>(0)}, VL / 8));
}

TEST_P(InstSve, sel) {
  // 64-bit
  initialHeapData_.resize(VL / 4);
  uint64_t* heap64 = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  std::vector<uint64_t> srcA64 = {0xDEADBEEF, 0x12345678, 0x98765432,
                                  0xABCDEF01};
  std::vector<uint64_t> srcB64 = {0xABCDEF01, 0x98765432, 0x12345678,
                                  0xDEADBEEF};
  fillHeapCombined<uint64_t>(heap64, srcA64, srcB64, VL / 32);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #0
    mov x3, #0
    mov x4, #8
    mov x5, #2
    addvl x2, x2, #1
    udiv x2, x2, x4
    udiv x3, x2, x5
    whilelo p1.d, xzr, x3
    ptrue p0.d

    ld1d {z0.d}, p0/z, [x0, x1, lsl #3]
    ld1d {z1.d}, p0/z, [x0, x2, lsl #3]

    sel z2.d, p1, z0.d, z1.d
  )");
  std::rotate(srcB64.begin(), srcB64.begin() + ((VL / 128) % 4), srcB64.end());
  CHECK_NEON(2, uint64_t, fillNeonCombined<uint64_t>(srcA64, srcB64, VL / 8));

  // 32-bit
  initialHeapData_.resize(VL / 4);
  uint32_t* heap32 = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  std::vector<uint32_t> srcA32 = {0xDEADBEEF, 0x12345678, 0x98765432,
                                  0xABCDEF01};
  std::vector<uint32_t> srcB32 = {0xABCDEF01, 0x98765432, 0x12345678,
                                  0xDEADBEEF};
  fillHeapCombined<uint32_t>(heap32, srcA32, srcB32, VL / 16);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #0
    mov x3, #0
    mov x4, #4
    mov x5, #2
    addvl x2, x2, #1
    udiv x2, x2, x4
    udiv x3, x2, x5
    whilelo p1.s, xzr, x3
    ptrue p0.s

    ld1w {z0.s}, p0/z, [x0, x1, lsl #2]
    ld1w {z1.s}, p0/z, [x0, x2, lsl #2]

    sel z2.s, p1, z0.s, z1.s
  )");
  std::rotate(srcB32.begin(), srcB32.begin() + ((VL / 64) % 4), srcB32.end());
  CHECK_NEON(2, uint32_t, fillNeonCombined<uint32_t>(srcA32, srcB32, VL / 8));
}

TEST_P(InstSve, smax) {
  // 32-bit
  initialHeapData_.resize(VL / 4);
  int32_t* heap32 = reinterpret_cast<int32_t*>(initialHeapData_.data());
  std::vector<int32_t> srcA32 = {1,  2,   3,   4,   5,  6,  7,   8,
                                 -9, -10, -11, -12, 13, 14, -15, -1};
  std::vector<int32_t> srcB32 = {16, 15, 14, 13, -12, -11, -10, -9,
                                 8,  7,  6,  5,  4,   3,   -2,  -1};
  fillHeapCombined<int32_t>(heap32, srcA32, srcB32, VL / 16);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #0
    mov x3, #0
    mov x4, #4
    mov x5, #2
    addvl x2, x2, #1
    udiv x2, x2, x4
    udiv x3, x2, x5
    whilelo p1.s, xzr, x3
    ptrue p0.s

    ld1w {z0.s}, p0/z, [x0, x1, lsl #2]
    ld1w {z1.s}, p0/z, [x0, x2, lsl #2]
    ld1w {z2.s}, p0/z, [x0, x2, lsl #2]
    ld1w {z3.s}, p0/z, [x0, x1, lsl #2]
    ld1w {z4.s}, p0/z, [x0, x1, lsl #2]
    ld1w {z5.s}, p0/z, [x0, x1, lsl #2]

    smax z1.s, p0/m, z1.s, z0.s
    smax z2.s, p1/m, z2.s, z0.s

    smax z3.s, z3.s, #0
    smax z4.s, z4.s, #-128
    smax z5.s, z5.s, #127
  )");
  std::vector<int32_t> results32 = {16, 15, 14, 13, 5,  6,  7,  8,
                                    8,  7,  6,  5,  13, 14, -2, -1};
  CHECK_NEON(1, int32_t, fillNeon<int32_t>(results32, VL / 8));
  std::rotate(srcB32.begin(), srcB32.begin() + ((VL / 64) % 16), srcB32.end());
  CHECK_NEON(2, int32_t, fillNeonCombined<int32_t>(results32, srcB32, VL / 8));

  CHECK_NEON(3, int32_t,
             fillNeon<int32_t>(
                 {1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 13, 14, 0, 0}, VL / 8));
  CHECK_NEON(4, int32_t,
             fillNeon<int32_t>(
                 {1, 2, 3, 4, 5, 6, 7, 8, -9, -10, -11, -12, 13, 14, -15, -1},
                 VL / 8));
  CHECK_NEON(5, int32_t,
             fillNeon<int32_t>({127, 127, 127, 127, 127, 127, 127, 127, 127,
                                127, 127, 127, 127, 127, 127, 127},
                               VL / 8));
}

TEST_P(InstSve, smin) {
  // 32-bit
  initialHeapData_.resize(VL / 4);
  int32_t* heap32 = reinterpret_cast<int32_t*>(initialHeapData_.data());
  std::vector<int32_t> srcA32 = {1,  2,   3,   4,   5,  6,  7,   8,
                                 -9, -10, -11, -12, 13, 14, -15, -1};
  std::vector<int32_t> srcB32 = {16, 15, 14, 13, -12, -11, -10, -9,
                                 8,  7,  6,  5,  4,   3,   -2,  -1};
  fillHeapCombined<int32_t>(heap32, srcA32, srcB32, VL / 16);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #0
    mov x3, #0
    mov x4, #4
    mov x5, #2
    addvl x2, x2, #1
    udiv x2, x2, x4
    udiv x3, x2, x5
    whilelo p1.s, xzr, x3
    ptrue p0.s

    ld1w {z0.s}, p0/z, [x0, x1, lsl #2]
    ld1w {z1.s}, p0/z, [x0, x2, lsl #2]
    ld1w {z2.s}, p0/z, [x0, x2, lsl #2]

    smin z1.s, p0/m, z1.s, z0.s
    smin z2.s, p1/m, z2.s, z0.s

    sminv s3, p1, z1.s
    sminv s4, p0, z2.s
  )");

  std::vector<int32_t> results32 = {1,  2,   3,   4,   -12, -11, -10, -9,
                                    -9, -10, -11, -12, 4,   3,   -15, -1};
  std::array<int32_t, 64> arrA = fillNeon<int32_t>(results32, VL / 8);
  std::rotate(srcB32.begin(), srcB32.begin() + ((VL / 64) % 16), srcB32.end());
  std::array<int32_t, 64> arrB =
      fillNeonCombined<int32_t>(results32, srcB32, VL / 8);

  CHECK_NEON(1, int32_t, arrA);
  CHECK_NEON(2, int32_t, arrB);
  // Find miniumum element. Modify search end point to only consider the
  // elements within the current VL and predication.
  int32_t minElemA = arrA[std::distance(
      arrA.begin(),
      std::min_element(arrA.begin(), arrA.end() - (64 - VL / 64)))];
  int32_t minElemB = arrB[std::distance(
      arrB.begin(),
      std::min_element(arrB.begin(), arrB.end() - (64 - VL / 32)))];
  CHECK_NEON(3, int32_t, {minElemA, 0, 0, 0});
  CHECK_NEON(4, int32_t, {minElemB, 0, 0, 0});
}

TEST_P(InstSve, smulh) {
  // Vectors
  // 8-bit
  RUN_AARCH64(R"(
    ptrue p0.b
    mov x0, #0
    addvl x1, x0, #1
    mov x2, #2
    udiv x3, x1, x2
    whilelo p1.b, xzr, x3

    dup z0.b, #127
    dup z1.b, #77
    dup z2.b, #-16
    dup z3.b, #45

    smulh z0.b, p0/m, z0.b, z1.b
    smulh z2.b, p1/m, z2.b, z3.b
  )");
  CHECK_NEON(0, int8_t, fillNeon<int8_t>({38}, VL / 8));
  CHECK_NEON(2, int8_t, fillNeonCombined<int8_t>({-3}, {-16}, VL / 8));

  // 16-bit
  RUN_AARCH64(R"(
    ptrue p0.h
    mov x0, #0
    addvl x1, x0, #1
    mov x2, #4
    udiv x3, x1, x2
    whilelo p1.h, xzr, x3

    movz w0, #5120
    movz w1, #63744

    dup z0.h, w0
    dup z1.h, #77
    dup z2.h, w1
    dup z3.h, #45

    smulh z0.h, p0/m, z0.h, z1.h
    smulh z2.h, p1/m, z2.h, z3.h
  )");
  CHECK_NEON(0, int16_t, fillNeon<int16_t>({6}, VL / 8));
  CHECK_NEON(2, int16_t, fillNeonCombined<int16_t>({-2}, {-1792}, VL / 8));

  // 32-bit
  initialHeapData_.resize(12);
  int32_t* heapi32 = reinterpret_cast<int32_t*>(initialHeapData_.data());
  heapi32[0] = 0x7EADBEEF;
  heapi32[1] = -1076902265;
  RUN_AARCH64(R"(
    ptrue p0.s
    mov x0, #0
    addvl x1, x0, #1
    mov x2, #8
    udiv x3, x1, x2
    whilelo p1.s, xzr, x3

    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    add x1, x0, #4

    ldar w3, [x0]
    ldar w4, [x1]

    dup z0.s, w3
    dup z1.s, #122
    dup z2.s, w4
    dup z3.s, #45

    smulh z0.s, p0/m, z0.s, z1.s
    smulh z2.s, p1/m, z2.s, z3.s
  )");
  CHECK_NEON(0, int32_t, fillNeon<int32_t>({60}, VL / 8));
  CHECK_NEON(2, int32_t,
             fillNeonCombined<int32_t>({-12}, {-1076902265}, VL / 8));
}

TEST_P(InstSve, st1b) {
  initialHeapData_.resize(VL / 8);
  uint8_t* heap8 = reinterpret_cast<uint8_t*>(initialHeapData_.data());
  std::vector<uint8_t> src = {0xEF, 0xBE, 0xAD, 0xDE, 0x78, 0x56, 0x34, 0x12,
                              0x32, 0x54, 0x76, 0x98, 0x01, 0xEF, 0xCD, 0xAB};
  fillHeap<uint8_t>(heap8, src, VL / 8);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    sub sp, sp, #4095
    mov x1, #0
    ptrue p0.b

    ld1b {z0.b}, p0/z, [x0, x1]
    st1b {z0.b}, p0, [sp, x1]

    mov x2, #0
    mov x4, #2
    addvl x2, x2, #1
    udiv x2, x2, x4
    mov x3, #0
    whilelo p1.b, xzr, x2

    ld1b {z1.b}, p1/z, [x0, x3]
    st1b {z1.b}, p1, [x2, x3]
  )");

  for (int i = 0; i < (VL / 8); i++) {
    EXPECT_EQ(getMemoryValue<uint8_t>(process_->getStackPointer() - 4095 + i),
              src[i % 16]);
  }
  for (int i = 0; i < (VL / 16); i++) {
    EXPECT_EQ(getMemoryValue<uint8_t>((VL / 16) + i), src[i % 16]);
  }
}

TEST_P(InstSve, st1b_scatter) {
  initialHeapData_.resize(VL / 4);
  uint8_t* heap8 = reinterpret_cast<uint8_t*>(initialHeapData_.data());
  std::vector<uint8_t> src = {0xEF, 0xBE, 0xAD, 0xDE, 0x78, 0x56, 0x34, 0x12,
                              0x32, 0x54, 0x76, 0x98, 0x01, 0xEF, 0xCD, 0xAB};
  fillHeap<uint8_t>(heap8, src, VL / 8);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #1
    ptrue p0.d

    addvl x3, x0, #1
    mov x4, #16
    udiv x5, x3, x4
    whilelo p1.d, xzr, x5

    index z0.d, #0, #-3
    index z1.d, #0, #1

    ld1d {z4.d}, p0/z, [x0, x1, lsl #3]
    ld1d {z5.d}, p1/z, [x0, x2, lsl #3]

    st1b {z4.d}, p0, [sp, z0.d]
    st1b {z5.d}, p1, [x1, z1.d]
  )");

  for (uint64_t i = 0; i < VL / 64; i++) {
    EXPECT_EQ(getMemoryValue<uint8_t>(process_->getStackPointer() - (3 * i)),
              src[(8 * i) % 16]);
  }

  for (uint64_t i = 0; i < VL / 128; i++) {
    EXPECT_EQ(getMemoryValue<uint8_t>(i), src[(8 * (i + 1)) % 16]);
  }
}

TEST_P(InstSve, st1d_scatter) {
  // Vector plus imm
  RUN_AARCH64(R"(
    mov x0, #24
    mov x1, #800
    index z1.d, x1, x0
    index z2.d, #8, #-4

    ptrue p0.d

    st1d {z2.d}, p0, [z1.d]
  )");
  for (uint64_t i = 0; i < VL / 64; i++) {
    EXPECT_EQ(getMemoryValue<uint64_t>(800 + (24 * i)),
              static_cast<uint64_t>(8 - (4 * i)));
  }

  RUN_AARCH64(R"(
    mov x0, #24
    mov x1, #800
    index z1.d, x1, x0
    index z3.d, #8, #-5

    mov x1, #0
    addvl x2, x1, #1
    mov x3, #16
    udiv x4, x2, x3
    whilelo p1.d, xzr, x4

    st1d {z3.d}, p1, [z1.d, #240]
  )");
  for (uint64_t i = 0; i < VL / 128; i++) {
    EXPECT_EQ(getMemoryValue<uint64_t>(2720 + (24 * i)),
              static_cast<uint64_t>(8 - (5 * i)));
  }

  // Scalar plus Vector
  // 64-bit
  RUN_AARCH64(R"(
    mov x0, #24
    mov x1, #800
    mov x2, #240
    index z1.d, xzr, x0
    index z2.d, #8, #-4

    mov x3, #0
    addvl x4, x3, #1
    mov x5, #16
    udiv x6, x4, x5
    whilelo p1.d, xzr, x6

    st1d {z2.d}, p1, [x1, z1.d]
  )");
  for (uint64_t i = 0; i < VL / 128; i++) {
    EXPECT_EQ(getMemoryValue<uint64_t>(800 + (24 * i)),
              static_cast<uint64_t>(8 - (4 * i)));
  }

  RUN_AARCH64(R"(
    mov x0, #24
    mov x1, #800
    mov x2, #240
    index z3.d, #8, #-5
    index z4.d, #0, #1

    ptrue p0.d

    st1d {z3.d}, p0, [x2, z4.d, lsl #3]
  )");
  for (uint64_t i = 0; i < VL / 64; i++) {
    EXPECT_EQ(getMemoryValue<uint64_t>(240 + (i << 3)),
              static_cast<uint64_t>(8 - (5 * i)));
  }
}

TEST_P(InstSve, st1d) {
  initialHeapData_.resize(VL / 4);
  uint64_t* heap64 = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  std::vector<uint64_t> src = {0xDEADBEEF, 0x12345678, 0x98765432, 0xABCDEF01};
  fillHeap<uint64_t>(heap64, src, VL / 32);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    sub sp, sp, #4095
    mov x1, #0
    mov x4, #256
    madd x4, x4, x4, x4
    ptrue p0.d
    ld1d {z0.d}, p0/z, [x0, x1, lsl #3]
    ld1d {z2.d}, p0/z, [x0, x1, lsl #3]
    st1d {z0.d}, p0, [sp, x1, lsl #3]
    st1d {z2.d}, p0, [x4]

    mov x2, #0
    mov x5, #16
    addvl x2, x2, #1
    udiv x2, x2, x5
    mov x3, #2
    whilelo p1.d, xzr, x2
    ld1d {z1.d}, p1/z, [x0, x3, lsl #3]
    ld1d {z3.d}, p1/z, [x0, x3, lsl #3]
    st1d {z3.d}, p1, [x2, #4, mul vl]
    st1d {z1.d}, p1, [x2, x3, lsl #3]
  )");

  for (int i = 0; i < (VL / 64); i++) {
    EXPECT_EQ(
        getMemoryValue<uint64_t>(process_->getStackPointer() - 4095 + (i * 8)),
        src[i % 4]);
  }
  for (int i = 0; i < (VL / 64); i++) {
    EXPECT_EQ(getMemoryValue<uint64_t>(65792 + (i * 8)), src[i % 4]);
  }
  std::rotate(src.begin(), src.begin() + 2, src.end());
  for (int i = 0; i < (VL / 128); i++) {
    EXPECT_EQ(getMemoryValue<uint64_t>((VL / 128) + 16 + (i * 8)), src[i % 4]);
  }
  for (int i = 0; i < (VL / 128); i++) {
    EXPECT_EQ(getMemoryValue<uint64_t>((VL / 128) + (VL / 2) + (i * 8)),
              src[i % 4]);
  }
}

TEST_P(InstSve, st2d) {
  // 32-bit
  RUN_AARCH64(R"(
    ptrue p0.d
    mov x0, #0
    addvl x1, x0, #1
    mov x2, #16
    udiv x3, x1, x2
    whilelo p1.d, xzr, x3

    sub sp, sp, #4095
    mov x6, #300

    dup z0.d, #3
    dup z1.d, #4
    dup z2.d, #5
    dup z3.d, #6

    st2d {z0.d, z1.d}, p0, [sp]
    st2d {z2.d, z3.d}, p1, [x6, #4, mul vl]
  )");

  for (int i = 0; i < (VL / 64); i++) {
    EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 4095 +
                                       (2 * i * 8)),
              3);
    EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 4095 +
                                       (2 * i * 8) + 8),
              4);
  }

  int index = 4 * (VL / 64) * 8;
  for (int i = 0; i < (VL / 128); i++) {
    EXPECT_EQ(getMemoryValue<uint64_t>(300 + index + (2 * i * 8)), 5);
    EXPECT_EQ(getMemoryValue<uint64_t>(300 + index + (2 * i * 8) + 8), 6);
  }
}

TEST_P(InstSve, st1w_scatter) {
  // 32-bit
  RUN_AARCH64(R"(
    index z1.s, #0, #12
    index z2.s, #8, #-4

    ptrue p0.s

    st1w {z2.s}, p0, [z1.s]
  )");
  for (uint32_t i = 0; i < VL / 32; i++) {
    EXPECT_EQ(getMemoryValue<uint32_t>(0 + (12 * i)),
              static_cast<uint32_t>(8 - (4 * i)));
  }

  RUN_AARCH64(R"(
    index z1.s, #0, #12
    index z2.s, #8, #-4

    mov x1, #0
    addvl x2, x1, #1
    mov x3, #8
    udiv x4, x2, x3
    whilelo p1.s, xzr, x4

    st1w {z2.s}, p1, [z1.s, #80]
  )");
  for (uint32_t i = 0; i < VL / 64; i++) {
    EXPECT_EQ(getMemoryValue<uint32_t>(320 + (12 * i)),
              static_cast<uint32_t>(8 - (4 * i)));
  }

  // 64-bit
  RUN_AARCH64(R"(
    index z1.d, #0, #12
    index z2.d, #8, #-4

    ptrue p0.d

    st1w {z2.d}, p0, [z1.d]
  )");
  for (uint64_t i = 0; i < VL / 64; i++) {
    EXPECT_EQ(getMemoryValue<uint64_t>(0 + (12 * i)),
              static_cast<uint64_t>(8 - (4 * i)));
  }

  RUN_AARCH64(R"(
    index z1.d, #0, #12
    index z2.d, #8, #-4

    mov x1, #0
    addvl x2, x1, #1
    mov x3, #16
    udiv x4, x2, x3
    whilelo p1.d, xzr, x4

    st1w {z2.d}, p1, [z1.d, #80]
  )");
  for (uint64_t i = 0; i < VL / 128; i++) {
    EXPECT_EQ(getMemoryValue<uint64_t>(320 + (12 * i)),
              static_cast<uint64_t>(8 - (4 * i)));
  }
}

TEST_P(InstSve, st1w) {
  // 32-bit
  initialHeapData_.resize(VL / 4);
  uint32_t* heap32 = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  std::vector<uint32_t> src = {0xDEADBEEF, 0x12345678, 0x98765432, 0xABCDEF01};
  fillHeap<uint32_t>(heap32, src, VL / 16);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    sub sp, sp, #4095
    mov x1, #0
    mov x4, #0
    addvl x4, x4, #1
    ptrue p0.s

    ld1w {z0.s}, p0/z, [x0, x1, lsl #2]
    ld1w {z2.s}, p0/z, [x0, x1, lsl #2]
    st1w {z0.s}, p0, [sp, x1, lsl #2]
    st1w {z2.s}, p0, [x4]
  )");

  for (int i = 0; i < (VL / 32); i++) {
    EXPECT_EQ(
        getMemoryValue<uint32_t>(process_->getStackPointer() - 4095 + (i * 4)),
        src[i % 4]);
  }
  for (int i = 0; i < (VL / 32); i++) {
    EXPECT_EQ(getMemoryValue<uint32_t>((VL / 8) + (i * 4)), src[i % 4]);
  }

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x2, #0
    mov x4, #8
    addvl x2, x2, #1
    udiv x2, x2, x4
    mov x3, #4
    whilelo p1.s, xzr, x2

    ld1w {z3.s}, p1/z, [x0, x3, lsl #2]
    st1w {z3.s}, p1, [x2, #4, mul vl]
    ld1w {z1.s}, p1/z, [x0, x3, lsl #2]
    st1w {z1.s}, p1, [x2, x3, lsl #2]
  )");

  for (int i = 0; i < (VL / 64); i++) {
    EXPECT_EQ(getMemoryValue<uint32_t>((VL / 64) + (VL / 2) + (i * 4)),
              src[i % 4]);
  }
  for (int i = 0; i < (VL / 64); i++) {
    EXPECT_EQ(getMemoryValue<uint32_t>((VL / 64) + 16 + (i * 4)), src[i % 4]);
  }

  // 64-bit
  // initialHeapData_.resize(64);
  // uint64_t* heap64 = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  // heap64[0] = 0xDEADBEEFDEADBEEF;
  // heap64[1] = 0x1234567812345678;
  // heap64[2] = 0x9876543298765432;
  // heap64[3] = 0xABCDEF01ABCDEF01;
  // heap64[4] = 0xDEADBEEFDEADBEEF;
  // heap64[5] = 0x1234567812345678;
  // heap64[6] = 0x9876543298765432;
  // heap64[7] = 0xABCDEF01ABCDEF01;

  // RUN_AARCH64(R"(
  //   # Get heap address
  //   mov x0, 0
  //   mov x8, 214
  //   svc #0

  //   mov x1, #0
  //   mov x4, #64
  //   mov x5, #3
  //   ptrue p0.d
  //   ld1w {z0.d}, p0/z, [x0, x1, lsl #3]
  //   ld1w {z2.d}, p0/z, [x0, x1, lsl #3]
  //   st1w {z0.d}, p0, [sp, x1, lsl #2]
  //   st1w {z2.d}, p0, [x4, x5, lsl #2]
  // )");
  // CHECK_NEON(0, uint64_t,
  //            {0xDEADBEEFDEADBEEFu, 0x1234567812345678u,
  //            0x9876543298765432u,
  //             0xABCDEF01ABCDEF01u, 0xDEADBEEFDEADBEEFu,
  //             0x1234567812345678u, 0x9876543298765432u,
  //             0xABCDEF01ABCDEF01u});
  // CHECK_NEON(2, uint64_t,
  //            {0xDEADBEEFDEADBEEFu, 0x1234567812345678u,
  //            0x9876543298765432u,
  //             0xABCDEF01ABCDEF01u, 0xDEADBEEFDEADBEEFu,
  //             0x1234567812345678u, 0x9876543298765432u,
  //             0xABCDEF01ABCDEF01u});

  // EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer()),
  // 0xDEADBEEF);
  // EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer()
  // + 4),
  //           0x12345678);
  // EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() + 8),
  //           0x98765432);
  // EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() + 12),
  //           0xABCDEF01);
  // EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() + 16),
  //           0xDEADBEEF);
  // EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() + 20),
  //           0x12345678);
  // EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() + 24),
  //           0x98765432);
  // EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() + 28),
  //           0xABCDEF01);

  // EXPECT_EQ(getMemoryValue<uint32_t>(64 + (3 * 4)), 0xDEADBEEF);
  // EXPECT_EQ(getMemoryValue<uint32_t>(64 + (3 * 4) + 4), 0x12345678);
  // EXPECT_EQ(getMemoryValue<uint32_t>(64 + (3 * 4) + 8), 0x98765432);
  // EXPECT_EQ(getMemoryValue<uint32_t>(64 + (3 * 4) + 12), 0xABCDEF01);
  // EXPECT_EQ(getMemoryValue<uint32_t>(64 + (3 * 4) + 16), 0xDEADBEEF);
  // EXPECT_EQ(getMemoryValue<uint32_t>(64 + (3 * 4) + 20), 0x12345678);
  // EXPECT_EQ(getMemoryValue<uint32_t>(64 + (3 * 4) + 24), 0x98765432);
  // EXPECT_EQ(getMemoryValue<uint32_t>(64 + (3 * 4) + 28), 0xABCDEF01);
}

TEST_P(InstSve, str_predicate) {
  initialHeapData_.resize(VL / 64);
  uint8_t* heap8 = reinterpret_cast<uint8_t*>(initialHeapData_.data());

  fillHeap<uint8_t>(heap8, {0xFF}, VL / 64);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    sub sp, sp, #4095

    ldr p0, [x0, #0, mul vl]
    str p0, [sp, #0, mul vl]
  )");
  for (int i = 0; i < (VL / 64); i++) {
    EXPECT_EQ(getMemoryValue<uint8_t>(process_->getStackPointer() - 4095 + i),
              0xFF);
  }

  fillHeap<uint8_t>(heap8, {0xDE}, VL / 64);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    sub sp, sp, #4095

    ldr p0, [x0, #0, mul vl]
    str p0, [sp, #1, mul vl]
  )");
  for (int i = 0; i < (VL / 64); i++) {
    EXPECT_EQ(getMemoryValue<uint8_t>(process_->getStackPointer() -
                                      (4095 - (VL / 64)) + i),
              0xDE);
  }

  fillHeap<uint8_t>(heap8, {0x12}, VL / 64);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    sub sp, sp, #4095

    ldr p0, [x0, #0, mul vl]
    str p0, [sp, #2, mul vl]
  )");
  for (int i = 0; i < (VL / 64); i++) {
    EXPECT_EQ(getMemoryValue<uint8_t>(process_->getStackPointer() -
                                      (4095 - (VL / 64) * 2) + i),
              0x12);
  }

  fillHeap<uint8_t>(heap8, {0x98}, VL / 64);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214

    svc #0

    sub sp, sp, #4095
    ldr p0, [x0, #0, mul vl]
    str p0, [sp, #3, mul vl]
  )");
  for (int i = 0; i < (VL / 64); i++) {
    EXPECT_EQ(getMemoryValue<uint8_t>(process_->getStackPointer() -
                                      (4095 - (VL / 64) * 3) + i),
              0x98);
  }
}

TEST_P(InstSve, str_vector) {
  initialHeapData_.resize(VL / 4);
  uint64_t* heap64 = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  std::vector<uint64_t> src = {0xFFFFFFFFFFFFFFFF, 0x0,
                               0xDEADBEEFDEADBEEF, 0x1234567812345678,
                               0xFFFFFFFFFFFFFFFF, 0x98765432ABCDEF01,
                               0xDEADBEEFDEADBEEF, 0x1234567812345678};
  fillHeap<uint64_t>(heap64, src, VL / 32);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    sub sp, sp, #4095
    mov x1, #0
    addvl x1, x1, #1
    ldr z0, [x0, #0, mul vl]
    ldr z1, [x0, #0, mul vl]
    str z0, [sp, #0, mul vl]
    str z1, [x1, #4, mul vl]
  )");
  for (int i = 0; i < (VL / 64); i++) {
    EXPECT_EQ(
        getMemoryValue<uint64_t>(process_->getStackPointer() - 4095 + (i * 8)),
        src[i % 8]);
  }
  for (int i = 0; i < (VL / 64); i++) {
    EXPECT_EQ(getMemoryValue<uint64_t>((VL / 8) + (VL / 2) + (i * 8)),
              src[i % 8]);
  }
}

TEST_P(InstSve, sub) {
  // SUB (Vectors, unpredicated)
  RUN_AARCH64(R"(
    # Initialise vectors
    # 8-bit
    dup z0.b, #-16
    dup z1.b, #15
    # 16-bit
    dup z2.h, #-8
    dup z3.h, #3
    # 32-bit
    dup z4.s, #-6
    dup z5.s, #12
    # 64-bit
    dup z6.d, #-5
    dup z7.d, #10

    # Calculate Sub
    # 8-bit
    sub z8.b, z0.b, z1.b
    sub z9.b, z1.b, z0.b
    # 16-bit
    sub z10.h, z2.h, z3.h
    sub z11.h, z3.h, z2.h
    # 32-bit
    sub z12.s, z4.s, z5.s
    sub z13.s, z5.s, z4.s
    # 64-bit
    sub z14.d, z6.d, z7.d
    sub z15.d, z7.d, z6.d
  )");
  CHECK_NEON(8, uint8_t, fillNeon<uint8_t>({0xE1}, VL / 8));
  CHECK_NEON(9, uint8_t, fillNeon<uint8_t>({0x1F}, VL / 8));
  CHECK_NEON(10, uint16_t, fillNeon<uint16_t>({0xFFF5}, VL / 8));
  CHECK_NEON(11, uint16_t, fillNeon<uint16_t>({0xB}, VL / 8));
  CHECK_NEON(12, uint32_t, fillNeon<uint32_t>({0xFFFFFFEE}, VL / 8));
  CHECK_NEON(13, uint32_t, fillNeon<uint32_t>({0x12}, VL / 8));
  CHECK_NEON(14, uint64_t, fillNeon<uint64_t>({0xFFFFFFFFFFFFFFF1}, VL / 8));
  CHECK_NEON(15, uint64_t, fillNeon<uint64_t>({0xF}, VL / 8));
}

TEST_P(InstSve, sxtw) {
  initialHeapData_.resize(VL / 4);
  uint64_t* heap64 = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  fillHeap<uint64_t>(
      heap64,
      {0xFFFFFFFFFFFFFFFF, 0x0, 0xDEADBEEFDEADBEEF, 0x1234567812345678,
       0xFFFFFFFFFFFFFFFF, 0x98765432ABCDEF01, 0xDEADBEEFDEADBEEF,
       0x1234567812345678},
      VL / 64);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    
    ptrue p0.d
    mov x2, #0
    addvl x1, x2, #1
    mov x3, #16
    udiv x4, x1, x3
    whilelo p1.d, xzr, x4

    dup z2.d, #0xF

    ld1d {z0.d}, p0/z, [x0, x2, lsl #3]

    sxtw z1.d, p0/m, z0.d
    sxtw z2.d, p1/m, z0.d
  )");
  CHECK_NEON(1, int64_t,
             fillNeon<int64_t>({-1, 0, -559038737, 305419896, -1, -1412567295,
                                -559038737, 305419896},
                               VL / 8));
  CHECK_NEON(2, int64_t,
             fillNeonCombined<int64_t>({-1, 0, -559038737, 305419896, -1,
                                        -1412567295, -559038737, 305419896},
                                       {0xF}, VL / 8));
}

TEST_P(InstSve, trn1) {
  // 8-bit
  RUN_AARCH64(R"(
    index z0.b, #0, #1
    index z1.b, #10, #1

    trn1 z2.b, z0.b, z1.b
  )");
  std::vector<uint8_t> result8;
  int i1 = 0;
  int i2 = 10;
  for (int i = 0; i < VL / 16; i++) {
    result8.push_back(i1);
    result8.push_back(i2);
    i1 += 2;
    i2 += 2;
  }
  CHECK_NEON(2, uint8_t, fillNeon<uint8_t>(result8, VL / 8));

  // 16-bit
  RUN_AARCH64(R"(
    index z0.h, #0, #1
    index z1.h, #10, #1

    trn1 z2.h, z0.h, z1.h
  )");
  std::vector<uint16_t> result16;
  i1 = 0;
  i2 = 10;
  for (int i = 0; i < VL / 32; i++) {
    result16.push_back(i1);
    result16.push_back(i2);
    i1 += 2;
    i2 += 2;
  }
  CHECK_NEON(2, uint16_t, fillNeon<uint16_t>(result16, VL / 8));

  // 32-bit
  RUN_AARCH64(R"(
    index z0.s, #0, #1
    index z1.s, #10, #1

    trn1 z2.s, z0.s, z1.s
  )");
  std::vector<uint32_t> result32;
  i1 = 0;
  i2 = 10;
  for (int i = 0; i < VL / 64; i++) {
    result32.push_back(i1);
    result32.push_back(i2);
    i1 += 2;
    i2 += 2;
  }
  CHECK_NEON(2, uint32_t, fillNeon<uint32_t>(result32, VL / 8));

  // 64-bit
  RUN_AARCH64(R"(
    index z0.d, #0, #1
    index z1.d, #10, #1

    trn1 z2.d, z0.d, z1.d
  )");
  std::vector<uint64_t> result64;
  i1 = 0;
  i2 = 10;
  for (int i = 0; i < VL / 128; i++) {
    result64.push_back(i1);
    result64.push_back(i2);
    i1 += 2;
    i2 += 2;
  }
  CHECK_NEON(2, uint64_t, fillNeon<uint64_t>(result64, VL / 8));
}

TEST_P(InstSve, trn2) {
  // 8-bit
  RUN_AARCH64(R"(
    index z0.b, #0, #1
    index z1.b, #10, #1

    trn2 z2.b, z0.b, z1.b
  )");
  std::vector<uint8_t> result8;
  int i1 = 1;
  int i2 = 11;
  for (int i = 0; i < VL / 16; i++) {
    result8.push_back(i1);
    result8.push_back(i2);
    i1 += 2;
    i2 += 2;
  }
  CHECK_NEON(2, uint8_t, fillNeon<uint8_t>(result8, VL / 8));

  // 16-bit
  RUN_AARCH64(R"(
    index z0.h, #0, #1
    index z1.h, #10, #1

    trn2 z2.h, z0.h, z1.h
  )");
  std::vector<uint16_t> result16;
  i1 = 1;
  i2 = 11;
  for (int i = 0; i < VL / 32; i++) {
    result16.push_back(i1);
    result16.push_back(i2);
    i1 += 2;
    i2 += 2;
  }
  CHECK_NEON(2, uint16_t, fillNeon<uint16_t>(result16, VL / 8));

  // 32-bit
  RUN_AARCH64(R"(
    index z0.s, #0, #1
    index z1.s, #10, #1

    trn2 z2.s, z0.s, z1.s
  )");
  std::vector<uint32_t> result32;
  i1 = 1;
  i2 = 11;
  for (int i = 0; i < VL / 64; i++) {
    result32.push_back(i1);
    result32.push_back(i2);
    i1 += 2;
    i2 += 2;
  }
  CHECK_NEON(2, uint32_t, fillNeon<uint32_t>(result32, VL / 8));

  // 64-bit
  RUN_AARCH64(R"(
    index z0.d, #0, #1
    index z1.d, #10, #1

    trn2 z2.d, z0.d, z1.d
  )");
  std::vector<uint64_t> result64;
  i1 = 1;
  i2 = 11;
  for (int i = 0; i < VL / 128; i++) {
    result64.push_back(i1);
    result64.push_back(i2);
    i1 += 2;
    i2 += 2;
  }
  CHECK_NEON(2, uint64_t, fillNeon<uint64_t>(result64, VL / 8));
}

TEST_P(InstSve, uaddv) {
  // 8-bit
  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #2
    addvl x0, x0, #1
    sdiv x0, x0, x1

    ptrue p0.b
    whilelo p1.b, xzr, x0

    dup z0.b, #3
    dup z1.b, #9

    uaddv d2, p0, z0.b
    uaddv d3, p1, z1.b
  )");
  CHECK_NEON(2, uint64_t, {(3 * (VL / 8)), 0});
  CHECK_NEON(3, uint64_t, {(9 * (VL / 16)), 0});

  // 16-bit
  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #4
    addvl x0, x0, #1
    sdiv x0, x0, x1

    ptrue p0.h
    whilelo p1.h, xzr, x0

    dup z0.h, #3
    dup z1.h, #9

    uaddv d2, p0, z0.h
    uaddv d3, p1, z1.h
  )");
  CHECK_NEON(2, uint64_t, {(3 * (VL / 16)), 0});
  CHECK_NEON(3, uint64_t, {(9 * (VL / 32)), 0});

  // 32-bit
  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #8
    addvl x0, x0, #1
    sdiv x0, x0, x1

    ptrue p0.s
    whilelo p1.s, xzr, x0

    dup z0.s, #3
    dup z1.s, #9

    uaddv d2, p0, z0.s
    uaddv d3, p1, z1.s
  )");
  CHECK_NEON(2, uint64_t, {(3 * (VL / 32)), 0});
  CHECK_NEON(3, uint64_t, {(9 * (VL / 64)), 0});

  // 64-bit
  RUN_AARCH64(R"(
    mov x0, #0
    mov x1, #16
    addvl x0, x0, #1
    sdiv x0, x0, x1

    ptrue p0.d
    whilelo p1.d, xzr, x0

    dup z0.d, #3
    dup z1.d, #9

    uaddv d2, p0, z0.d
    uaddv d3, p1, z1.d
  )");
  CHECK_NEON(2, uint64_t, {(3 * (VL / 64)), 0});
  CHECK_NEON(3, uint64_t, {(9 * (VL / 128)), 0});
}

TEST_P(InstSve, uqdec) {
  // d arrangement
  RUN_AARCH64(R"(
    mov x0, #1024
    mov x1, #1024
    mov x2, #1

    uqdecd x0, all, mul #7
    uqdecd x1
    uqdecd x2, all, mul #7

    mov w3, #1024
    mov w4, #1024
    mov w5, #1

    uqdecd w3, all, mul #7
    uqdecd w4
    uqdecd w5, all, mul #7
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 1024 - (7 * (VL / 64)));
  EXPECT_EQ(getGeneralRegister<uint64_t>(1), 1024 - ((VL / 64)));
  EXPECT_EQ(getGeneralRegister<uint64_t>(2), 0);
  EXPECT_EQ(getGeneralRegister<uint32_t>(3), 1024 - (7 * (VL / 64)));
  EXPECT_EQ(getGeneralRegister<uint32_t>(4), 1024 - ((VL / 64)));
  EXPECT_EQ(getGeneralRegister<uint32_t>(5), 0);
  // h arrangement
  RUN_AARCH64(R"(
    mov x0, #1024
    mov x1, #1024
    mov x2, #1

    uqdech x0, all, mul #7
    uqdech x1
    uqdech x2, all, mul #7
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 1024 - (7 * (VL / 16)));
  EXPECT_EQ(getGeneralRegister<uint64_t>(1), 1024 - ((VL / 16)));
  EXPECT_EQ(getGeneralRegister<uint64_t>(2), 0);

  // w arrangement
  RUN_AARCH64(R"(
    mov x0, #1024
    mov x1, #1024
    mov x2, #1

    uqdecw x0, all, mul #7
    uqdecw x1
    uqdecw x2, all, mul #7
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 1024 - (7 * (VL / 32)));
  EXPECT_EQ(getGeneralRegister<uint64_t>(1), 1024 - ((VL / 32)));
  EXPECT_EQ(getGeneralRegister<uint64_t>(2), 0);
}

TEST_P(InstSve, uunpklo) {
  initialHeapData_.resize(VL / 4);
  uint32_t* heap32 = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  fillHeap<uint32_t>(heap32, {0xFFFFFFFF}, VL / 32);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    dup z0.b, #0
    dup z1.h, #0
    dup z2.s, #0

    mov x1, #0
    addvl x2, x1, #1
    mov x3, #2
    udiv x4, x2, x3
    mov x5, #4
    udiv x6, x2, x5
    mov x7, #8
    udiv x8, x2, x7

    whilelo p0.b, xzr, x4
    whilelo p1.h, xzr, x6
    whilelo p2.s, xzr, x8

    # Fill only first half of vector with -1
    ld1b {z0.b}, p0/z, [x0, x1]
    ld1h {z1.h}, p1/z, [x0, x1, lsl #1]
    ld1w {z2.s}, p2/z, [x0, x1, lsl #2]

    uunpklo z3.h, z0.b
    uunpklo z4.s, z1.h
    uunpklo z5.d, z2.s 
  )");
  CHECK_NEON(0, uint8_t, fillNeonCombined<uint8_t>({0xFFu}, {0}, VL / 8))
  CHECK_NEON(1, uint16_t, fillNeonCombined<uint16_t>({0xFFFFu}, {0}, VL / 8))
  CHECK_NEON(2, uint32_t,
             fillNeonCombined<uint32_t>({0xFFFFFFFFu}, {0}, VL / 8))
  CHECK_NEON(3, uint16_t, fillNeon<uint16_t>({0x00FFu}, VL / 8));
  CHECK_NEON(4, uint32_t, fillNeon<uint32_t>({0x0000FFFFu}, VL / 8));
  CHECK_NEON(5, uint64_t, fillNeon<uint64_t>({0x00000000FFFFFFFFu}, VL / 8));
}

TEST_P(InstSve, uunpkhi) {
  // 8-bit
  initialHeapData_.resize(VL / 4);
  uint8_t* heap8 = reinterpret_cast<uint8_t*>(initialHeapData_.data());
  fillHeapCombined<uint8_t>(heap8, {0}, {0xFF}, VL / 8);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0 
    addvl x2, x1, #1

    whilelo p0.b, xzr, x2

    # Fill whole vector with -1
    ld1b {z0.b}, p0/z, [x0, x1]

    uunpkhi z1.h, z0.b
  )");
  CHECK_NEON(0, uint8_t, fillNeonCombined<uint8_t>({0}, {0xFFu}, VL / 8));
  CHECK_NEON(1, uint16_t, fillNeon<uint16_t>({0x00FF}, VL / 8));

  // 16-bit
  uint16_t* heap16 = reinterpret_cast<uint16_t*>(initialHeapData_.data());
  fillHeapCombined<uint16_t>(heap16, {0}, {0xFFFF}, VL / 16);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    addvl x2, x1, #1
    mov x3, #2
    udiv x4, x2, x3

    whilelo p0.h, xzr, x4

    ld1h {z0.h}, p0/z, [x0, x1, lsl #1]

    uunpkhi z1.s, z0.h
  )");
  CHECK_NEON(0, uint16_t, fillNeonCombined<uint16_t>({0}, {0xFFFFu}, VL / 8))
  CHECK_NEON(1, uint32_t, fillNeon<uint32_t>({0x0000FFFFu}, VL / 8))

  // 32-bit
  uint32_t* heap32 = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  fillHeapCombined<uint32_t>(heap32, {0}, {0xFFFFFFFF}, VL / 32);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    addvl x2, x1, #1
    mov x3, #4
    udiv x4, x2, x3

    whilelo p0.s, xzr, x4

    ld1w {z0.s}, p0/z, [x0, x1, lsl #2]

    uunpkhi z1.d, z0.s
  )");
  CHECK_NEON(0, uint32_t,
             fillNeonCombined<uint32_t>({0}, {0xFFFFFFFFu}, VL / 8))
  CHECK_NEON(1, uint64_t, fillNeon<uint64_t>({0x00000000FFFFFFFFu}, VL / 8))
}

TEST_P(InstSve, uzp1) {
  RUN_AARCH64(R"(
    dup z0.s, #1
    dup z1.s, #2

    uzp1 z2.s, z1.s, z0.s

    mov x0, #0
    mov x1, #8
    addvl x0, x0, #1
    udiv x0, x0, x1
    whilelo p0.s, xzr, x0

    fmul z1.s, p0/m, z1.s, #2

    uzp1 z4.s, z1.s, z0.s
  )");
  std::vector<uint32_t> results32A(VL / 128, 4);
  std::vector<uint32_t> results32B(VL / 128, 2);
  results32A.insert(results32A.end(), results32B.begin(), results32B.end());

  CHECK_NEON(2, uint32_t, fillNeonCombined<uint32_t>({2}, {1}, VL / 8));
  CHECK_NEON(4, uint32_t, fillNeonCombined<uint32_t>(results32A, {1}, VL / 8));
}

TEST_P(InstSve, whilelo) {
  // 8-bit arrangement, 64-bit source operands
  RUN_AARCH64(R"(
    mov x0, #0
    addvl x0, x0, #1

    whilelo p0.b, xzr, x0
  )");
  CHECK_PREDICATE(0, uint64_t, fillPred(VL / 8, {1}, 1));
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #0
    addvl x0, x0, #1
    mov x1, #2
    udiv x2, x0, x1

    whilelo p1.b, x2, x0
  )");
  CHECK_PREDICATE(1, uint64_t, fillPred(VL / 16, {1}, 1));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov x0, #0
    addvl x0, x0, #1
    mov x1, #2
    udiv x2, x0, x1
    mov x3, #4
    udiv x4, x0, x3
    add x5, x4, x2

    whilelo p2.b, x5, x0
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(VL / 32, {1}, 1));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov x0, #0
    addvl x0, x0, #1
    mov x1, #4
    udiv x2, x0, x1

    whilelo p3.b, x2, x0
  )");
  CHECK_PREDICATE(3, uint64_t, fillPred((VL / 32) * 3, {1}, 1));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    whilelo p4.b, xzr, xzr
  )");
  CHECK_PREDICATE(4, uint64_t, fillPred((VL / 8), {0}, 1));
  EXPECT_EQ(getNZCV(), 0b0110);

  // 16-bit arrangement, 64-bit source operands
  RUN_AARCH64(R"(
    mov x0, #0
    addvl x0, x0, #1
    mov x1, #2
    udiv x2, x0, x1

    whilelo p0.h, xzr, x2
  )");
  CHECK_PREDICATE(0, uint64_t, fillPred(VL / 8, {1}, 2));
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #0
    addvl x0, x0, #1
    mov x1, #2
    udiv x2, x0, x1

    udiv x3, x2, x1

    whilelo p1.h, x3, x2
  )");
  CHECK_PREDICATE(1, uint64_t, fillPred(VL / 16, {1}, 2));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov x0, #0
    addvl x0, x0, #1
    mov x1, #2
    udiv x2, x0, x1

    udiv x3, x2, x1
    mov x4, #4
    udiv x5, x2, x4
    add x6, x5, x3

    whilelo p2.h, x6, x2
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(VL / 32, {1}, 2));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov x0, #0
    addvl x0, x0, #1
    mov x1, #2
    udiv x2, x0, x1

    mov x3, #4
    udiv x4, x2, x3

    whilelo p3.h, x4, x2
  )");
  CHECK_PREDICATE(3, uint64_t, fillPred((VL / 32) * 3, {1}, 2));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    whilelo p4.h, xzr, xzr
  )");
  CHECK_PREDICATE(4, uint64_t, fillPred((VL / 8), {0}, 2));
  EXPECT_EQ(getNZCV(), 0b0110);

  // 32-bit arrangement, 64-bit source operands
  RUN_AARCH64(R"(
    mov x0, #0
    addvl x0, x0, #1
    mov x1, #4
    udiv x2, x0, x1

    whilelo p0.s, xzr, x2
  )");
  CHECK_PREDICATE(0, uint64_t, fillPred(VL / 8, {1}, 4));
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #0
    addvl x0, x0, #1
    mov x1, #4
    udiv x2, x0, x1

    mov x3, #2
    udiv x4, x2, x3

    whilelo p1.s, x4, x2
  )");
  CHECK_PREDICATE(1, uint64_t, fillPred(VL / 16, {1}, 4));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov x0, #0
    addvl x0, x0, #1
    mov x1, #4
    udiv x2, x0, x1

    mov x3, #2
    udiv x4, x2, x3
    udiv x5, x2, x1
    add x6, x5, x4

    whilelo p2.s, x6, x2
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(VL / 32, {1}, 4));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov x0, #0
    addvl x0, x0, #1
    mov x1, #4
    udiv x2, x0, x1

    udiv x3, x2, x1

    whilelo p3.s, x3, x2
  )");
  CHECK_PREDICATE(3, uint64_t, fillPred((VL / 32) * 3, {1}, 4));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    whilelo p4.s, xzr, xzr
  )");
  CHECK_PREDICATE(4, uint64_t, fillPred((VL / 8), {0}, 4));
  EXPECT_EQ(getNZCV(), 0b0110);

  // 64-bit arrangement, 64-bit source operands
  RUN_AARCH64(R"(
    mov x0, #0
    addvl x0, x0, #1
    mov x1, #8
    udiv x2, x0, x1

    whilelo p0.d, xzr, x2
  )");
  CHECK_PREDICATE(0, uint64_t, fillPred(VL / 8, {1}, 8));
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #0
    addvl x0, x0, #1
    mov x1, #8
    udiv x2, x0, x1

    mov x3, #2
    udiv x4, x2, x3

    whilelo p1.d, x4, x2
  )");
  CHECK_PREDICATE(1, uint64_t, fillPred(VL / 16, {1}, 8));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov x0, #0
    addvl x0, x0, #1
    mov x1, #8
    udiv x2, x0, x1

    mov x3, #2
    udiv x4, x2, x3
    mov x5, #4
    udiv x6, x2, x5
    add x7, x6, x4

    whilelo p2.d, x7, x2
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(VL / 32, {1}, 8));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov x0, #0
    addvl x0, x0, #1
    mov x1, #8
    udiv x2, x0, x1

    mov x3, #4
    udiv x4, x2, x3

    whilelo p3.d, x4, x2
  )");
  CHECK_PREDICATE(3, uint64_t, fillPred((VL / 32) * 3, {1}, 8));
  if (VL == 128) {
    EXPECT_EQ(getNZCV(), 0b1000);
  } else {
    EXPECT_EQ(getNZCV(), 0b1010);
  }

  RUN_AARCH64(R"(
    whilelo p4.d, xzr, xzr
  )");
  CHECK_PREDICATE(4, uint64_t, fillPred((VL / 8), {0}, 8));
  EXPECT_EQ(getNZCV(), 0b0110);

  // --------------------------------------------------------------------

  // 8-bit arrangement, 32-bit source operands
  RUN_AARCH64(R"(
    mov w0, #0
    addvl x0, x0, #1

    whilelo p0.b, wzr, w0
  )");
  CHECK_PREDICATE(0, uint64_t, fillPred(VL / 8, {1}, 1));
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov w0, #0
    addvl x0, x0, #1
    mov w1, #2
    udiv w2, w0, w1

    whilelo p1.b, w2, w0
  )");
  CHECK_PREDICATE(1, uint64_t, fillPred(VL / 16, {1}, 1));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov w0, #0
    addvl x0, x0, #1
    mov w1, #2
    udiv w2, w0, w1
    mov w3, #4
    udiv w4, w0, w3
    add w5, w4, w2

    whilelo p2.b, w5, w0
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(VL / 32, {1}, 1));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov w0, #0
    addvl x0, x0, #1
    mov w1, #4
    udiv w2, w0, w1

    whilelo p3.b, w2, w0
  )");
  CHECK_PREDICATE(3, uint64_t, fillPred((VL / 32) * 3, {1}, 1));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    whilelo p4.b, wzr, wzr
  )");
  CHECK_PREDICATE(4, uint64_t, fillPred((VL / 8), {0}, 1));
  EXPECT_EQ(getNZCV(), 0b0110);

  // 16-bit arrangement, 32-bit source operands
  RUN_AARCH64(R"(
    mov w0, #0
    addvl x0, x0, #1
    mov w1, #2
    udiv w2, w0, w1

    whilelo p0.h, wzr, w2
  )");
  CHECK_PREDICATE(0, uint64_t, fillPred(VL / 8, {1}, 2));
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov w0, #0
    addvl x0, x0, #1
    mov w1, #2
    udiv w2, w0, w1

    udiv w3, w2, w1

    whilelo p1.h, w3, w2
  )");
  CHECK_PREDICATE(1, uint64_t, fillPred(VL / 16, {1}, 2));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov w0, #0
    addvl x0, x0, #1
    mov w1, #2
    udiv w2, w0, w1

    udiv w3, w2, w1
    mov w4, #4
    udiv w5, w2, w4
    add w6, w5, w3

    whilelo p2.h, w6, w2
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(VL / 32, {1}, 2));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov w0, #0
    addvl x0, x0, #1
    mov w1, #2
    udiv w2, w0, w1

    mov w3, #4
    udiv w4, w2, w3

    whilelo p3.h, w4, w2
  )");
  CHECK_PREDICATE(3, uint64_t, fillPred((VL / 32) * 3, {1}, 2));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    whilelo p4.h, wzr, wzr
  )");
  CHECK_PREDICATE(4, uint64_t, fillPred((VL / 8), {0}, 2));
  EXPECT_EQ(getNZCV(), 0b0110);

  // 32-bit arrangement, 32-bit source operands
  RUN_AARCH64(R"(
    mov w0, #0
    addvl x0, x0, #1
    mov w1, #4
    udiv w2, w0, w1

    whilelo p0.s, wzr, w2
  )");
  CHECK_PREDICATE(0, uint64_t, fillPred(VL / 8, {1}, 4));
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov w0, #0
    addvl x0, x0, #1
    mov w1, #4
    udiv w2, w0, w1

    mov w3, #2
    udiv w4, w2, w3

    whilelo p1.s, w4, w2
  )");
  CHECK_PREDICATE(1, uint64_t, fillPred(VL / 16, {1}, 4));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov w0, #0
    addvl x0, x0, #1
    mov w1, #4
    udiv w2, w0, w1

    mov w3, #2
    udiv w4, w2, w3
    udiv w5, w2, w1
    add w6, w5, w4

    whilelo p2.s, w6, w2
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(VL / 32, {1}, 4));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov w0, #0
    addvl x0, x0, #1
    mov w1, #4
    udiv w2, w0, w1

    udiv w3, w2, w1

    whilelo p3.s, w3, w2
  )");
  CHECK_PREDICATE(3, uint64_t, fillPred((VL / 32) * 3, {1}, 4));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    whilelo p4.s, wzr, wzr
  )");
  CHECK_PREDICATE(4, uint64_t, fillPred((VL / 8), {0}, 4));
  EXPECT_EQ(getNZCV(), 0b0110);

  // 64-bit arrangement, 32-bit source operands
  RUN_AARCH64(R"(
    mov w0, #0
    addvl x0, x0, #1
    mov w1, #8
    udiv w2, w0, w1

    whilelo p0.d, wzr, w2
  )");
  CHECK_PREDICATE(0, uint64_t, fillPred(VL / 8, {1}, 8));
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov w0, #0
    addvl x0, x0, #1
    mov w1, #8
    udiv w2, w0, w1

    mov w3, #2
    udiv w4, w2, w3

    whilelo p1.d, w4, w2
  )");
  CHECK_PREDICATE(1, uint64_t, fillPred(VL / 16, {1}, 8));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov w0, #0
    addvl x0, x0, #1
    mov w1, #8
    udiv w2, w0, w1

    mov w3, #2
    udiv w4, w2, w3
    mov w5, #4
    udiv w6, w2, w5
    add w7, w6, w4

    whilelo p2.d, w7, w2
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(VL / 32, {1}, 8));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov w0, #0
    addvl x0, x0, #1
    mov w1, #8
    udiv w2, w0, w1

    mov w3, #4
    udiv w4, w2, w3

    whilelo p3.d, w4, w2
  )");
  CHECK_PREDICATE(3, uint64_t, fillPred((VL / 32) * 3, {1}, 8));
  if (VL == 128) {
    EXPECT_EQ(getNZCV(), 0b1000);
  } else {
    EXPECT_EQ(getNZCV(), 0b1010);
  }

  RUN_AARCH64(R"(
    whilelo p4.d, wzr, wzr
  )");
  CHECK_PREDICATE(4, uint64_t, fillPred((VL / 8), {0}, 8));
  EXPECT_EQ(getNZCV(), 0b0110);
}

TEST_P(InstSve, whilelt) {
  // 8-bit arrangement, 64-bit source operands
  RUN_AARCH64(R"(
    mov x0, #0
    addvl x0, x0, #1

    whilelt p0.b, xzr, x0
  )");
  CHECK_PREDICATE(0, uint64_t, fillPred(VL / 8, {1}, 1));
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #0
    addvl x0, x0, #1
    mov x1, #-2
    sdiv x2, x0, x1
    mov x3, #0

    whilelt p1.b, x2, x3
  )");
  CHECK_PREDICATE(1, uint64_t, fillPred(VL / 16, {1}, 1));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov x0, #0
    addvl x0, x0, #1
    mov x1, #2
    udiv x2, x0, x1
    mov x3, #4
    udiv x4, x0, x3
    add x5, x4, x2

    whilelt p2.b, x5, x0
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(VL / 32, {1}, 1));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov x0, #0
    addvl x0, x0, #1
    mov x1, #4
    udiv x2, x0, x1

    whilelt p3.b, x2, x0
  )");
  CHECK_PREDICATE(3, uint64_t, fillPred((VL / 32) * 3, {1}, 1));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    whilelt p4.b, xzr, xzr
  )");
  CHECK_PREDICATE(4, uint64_t, fillPred((VL / 8), {0}, 1));
  EXPECT_EQ(getNZCV(), 0b0110);

  // 16-bit arrangement, 64-bit source operands
  RUN_AARCH64(R"(
    mov x0, #0
    addvl x0, x0, #1
    mov x1, #2
    udiv x2, x0, x1

    whilelt p0.h, xzr, x2
  )");
  CHECK_PREDICATE(0, uint64_t, fillPred(VL / 8, {1}, 2));
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #0
    addvl x0, x0, #1
    mov x1, #-2
    mov x2, #2
    sdiv x3, x0, x1

    sdiv x4, x3, x2

    whilelt p1.h, x3, x4
  )");
  CHECK_PREDICATE(1, uint64_t, fillPred(VL / 16, {1}, 2));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov x0, #0
    addvl x0, x0, #1
    mov x1, #2
    udiv x2, x0, x1

    udiv x3, x2, x1
    mov x4, #4
    udiv x5, x2, x4
    add x6, x5, x3

    whilelt p2.h, x6, x2
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(VL / 32, {1}, 2));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov x0, #0
    addvl x0, x0, #1
    mov x1, #2
    udiv x2, x0, x1

    mov x3, #4
    udiv x4, x2, x3

    whilelt p3.h, x4, x2
  )");
  CHECK_PREDICATE(3, uint64_t, fillPred((VL / 32) * 3, {1}, 2));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    whilelt p4.h, xzr, xzr
  )");
  CHECK_PREDICATE(4, uint64_t, fillPred((VL / 8), {0}, 2));
  EXPECT_EQ(getNZCV(), 0b0110);

  // 32-bit arrangement, 64-bit source operands
  RUN_AARCH64(R"(
    mov x0, #0
    addvl x0, x0, #1
    mov x1, #4
    udiv x2, x0, x1

    whilelt p0.s, xzr, x2
  )");
  CHECK_PREDICATE(0, uint64_t, fillPred(VL / 8, {1}, 4));
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #0
    addvl x0, x0, #1
    mov x1, #-4
    sdiv x2, x0, x1

    mov x3, #2
    sdiv x4, x2, x3

    whilelt p1.s, x2, x4
  )");
  CHECK_PREDICATE(1, uint64_t, fillPred(VL / 16, {1}, 4));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov x0, #0
    addvl x0, x0, #1
    mov x1, #4
    udiv x2, x0, x1

    mov x3, #2
    udiv x4, x2, x3
    udiv x5, x2, x1
    add x6, x5, x4

    whilelt p2.s, x6, x2
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(VL / 32, {1}, 4));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov x0, #0
    addvl x0, x0, #1
    mov x1, #4
    udiv x2, x0, x1

    udiv x3, x2, x1

    whilelt p3.s, x3, x2
  )");
  CHECK_PREDICATE(3, uint64_t, fillPred((VL / 32) * 3, {1}, 4));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    whilelt p4.s, xzr, xzr
  )");
  CHECK_PREDICATE(4, uint64_t, fillPred((VL / 8), {0}, 4));
  EXPECT_EQ(getNZCV(), 0b0110);

  // 64-bit arrangement, 64-bit source operands
  RUN_AARCH64(R"(
    mov x0, #0
    addvl x0, x0, #1
    mov x1, #8
    udiv x2, x0, x1

    whilelt p0.d, xzr, x2
  )");
  CHECK_PREDICATE(0, uint64_t, fillPred(VL / 8, {1}, 8));
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #0
    addvl x0, x0, #1
    mov x1, #-8
    sdiv x2, x0, x1

    mov x3, #2
    sdiv x4, x2, x3

    whilelt p1.d, x2, x4
  )");
  CHECK_PREDICATE(1, uint64_t, fillPred(VL / 16, {1}, 8));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov x0, #0
    addvl x0, x0, #1
    mov x1, #8
    udiv x2, x0, x1

    mov x3, #2
    udiv x4, x2, x3
    mov x5, #4
    udiv x6, x2, x5
    add x7, x6, x4

    whilelt p2.d, x7, x2
  )");
  CHECK_PREDICATE(2, uint64_t, fillPred(VL / 32, {1}, 8));
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov x0, #0
    addvl x0, x0, #1
    mov x1, #8
    udiv x2, x0, x1

    mov x3, #4
    udiv x4, x2, x3

    whilelt p3.d, x4, x2
  )");
  CHECK_PREDICATE(3, uint64_t, fillPred((VL / 32) * 3, {1}, 8));
  if (VL == 128) {
    EXPECT_EQ(getNZCV(), 0b1000);
  } else {
    EXPECT_EQ(getNZCV(), 0b1010);
  }

  RUN_AARCH64(R"(
    whilelt p4.d, xzr, xzr
  )");
  CHECK_PREDICATE(4, uint64_t, fillPred((VL / 8), {0}, 8));
  EXPECT_EQ(getNZCV(), 0b0110);
}

TEST_P(InstSve, zip_pred) {
  RUN_AARCH64(R"(
    ptrue p0.b
    ptrue p1.h
    ptrue p2.s
    ptrue p3.d

    whilelo p4.b, xzr, xzr
    whilelo p5.h, xzr, xzr
    whilelo p6.s, xzr, xzr
    whilelo p7.d, xzr, xzr

    # Interleave (or Zip) true with false
    zip1 p8.b, p0.b, p4.b
    zip1 p9.h, p1.h, p5.h
    zip1 p10.s, p2.s, p6.s
    zip1 p11.d, p3.d, p7.d

    zip2 p12.b, p0.b, p4.b
    zip2 p13.h, p1.h, p5.h
    zip2 p14.s, p2.s, p6.s
    zip2 p15.d, p3.d, p7.d
  )");
  CHECK_PREDICATE(8, uint64_t, fillPred(VL / 8, {1}, 2));
  CHECK_PREDICATE(9, uint64_t, fillPred(VL / 8, {1}, 4));
  CHECK_PREDICATE(10, uint64_t, fillPred(VL / 8, {1}, 8));
  CHECK_PREDICATE(11, uint64_t, fillPred(VL / 8, {1}, 16));
  CHECK_PREDICATE(12, uint64_t, fillPred(VL / 8, {1}, 2));
  CHECK_PREDICATE(13, uint64_t, fillPred(VL / 8, {1}, 4));
  CHECK_PREDICATE(14, uint64_t, fillPred(VL / 8, {1}, 8));
  CHECK_PREDICATE(15, uint64_t, fillPred(VL / 8, {1}, 16));
}

TEST_P(InstSve, zip) {
  // d arrangement
  RUN_AARCH64(R"(
    # 64-bit  
    fdup z0.d, #0.5
    fdup z1.d, #-0.5
    fdup z2.d, #0.75
    fdup z3.d, #-0.75

    zip1 z4.d, z0.d, z1.d
    zip2 z5.d, z2.d, z3.d

    #32-bit
    fdup z6.s, #0.5
    fdup z7.s, #-0.75
    fdup z8.s, #-0.5
    fdup z9.s, #0.75
    zip1 z10.s, z6.s, z7.s
    zip2 z11.s, z8.s, z9.s
  )");

  CHECK_NEON(4, double, fillNeon<double>({0.5, -0.5}, VL / 8));
  CHECK_NEON(5, double, fillNeon<double>({0.75, -0.75}, VL / 8));
  CHECK_NEON(10, float, fillNeon<float>({0.5, -0.75}, VL / 8));
  CHECK_NEON(11, float, fillNeon<float>({-0.5, 0.75}, VL / 8));
}

INSTANTIATE_TEST_SUITE_P(AArch64, InstSve,
                         ::testing::ValuesIn(genCoreTypeVLPairs(EMULATION)),
                         paramToString);

}  // namespace