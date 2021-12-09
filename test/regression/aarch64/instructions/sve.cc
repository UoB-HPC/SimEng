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
  EXPECT_EQ(getGeneralRegister<int64_t>(3), 298);
  EXPECT_EQ(getGeneralRegister<int64_t>(4), 1992);
  EXPECT_EQ(getGeneralRegister<int64_t>(5), -1024);
}

TEST_P(InstSve, and) {
  // VL = 512-bits
  // Predicates, Predicated
  RUN_AARCH64(R"(
    mov x0, #8

    ptrue p0.s
    ptrue p1.s
    whilelo p2.s, xzr, x0

    and p3.b, p0/z, p1.b, p0.b
    and p4.b, p2/z, p1.b, p0.b

  )");
  CHECK_PREDICATE(3, uint32_t, {0x11111111, 0x11111111, 0, 0, 0, 0, 0, 0});
  CHECK_PREDICATE(4, uint32_t, {0x11111111, 0, 0, 0, 0, 0, 0, 0});

  // Vectors, Predicated
  RUN_AARCH64(R"(
    # 8-bit
    mov x0, #32
    index z0.b, #8, #2
    dup z1.b, #15
    dup z2.b, #3
    ptrue p0.b
    whilelo p1.b, xzr, x0

    and z0.b, p0/m, z0.b, z1.b
    and z1.b, p1/m, z1.b, z2.b 

    # 16-bit
    mov x0, #16
    index z3.h, #8, #2
    dup z4.h, #15
    dup z5.h, #3
    ptrue p0.h
    whilelo p1.h, xzr, x0

    and z3.h, p0/m, z3.h, z4.h
    and z4.h, p1/m, z4.h, z5.h 

    # 32-bit
    mov x0, #8
    index z6.s, #8, #2
    dup z7.s, #15
    dup z8.s, #3
    ptrue p0.s
    whilelo p1.s, xzr, x0

    and z6.s, p0/m, z6.s, z7.s
    and z7.s, p1/m, z7.s, z8.s 

    # 64-bit
    mov x0, #4
    index z9.d, #8, #2
    dup z10.d, #15
    dup z11.d, #3
    ptrue p0.d
    whilelo p1.d, xzr, x0

    and z9.d, p0/m, z9.d, z10.d
    and z10.d, p1/m, z10.d, z11.d 
  )");
  CHECK_NEON(0, uint8_t,
             {8, 10, 12, 14, 0, 2, 4, 6, 8, 10, 12, 14, 0, 2, 4, 6,
              8, 10, 12, 14, 0, 2, 4, 6, 8, 10, 12, 14, 0, 2, 4, 6,
              8, 10, 12, 14, 0, 2, 4, 6, 8, 10, 12, 14, 0, 2, 4, 6,
              8, 10, 12, 14, 0, 2, 4, 6, 8, 10, 12, 14, 0, 2, 4, 6});
  CHECK_NEON(1, uint8_t,
             {3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,
              3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,
              15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
              15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15});

  CHECK_NEON(3, uint16_t,
             {8, 10, 12, 14, 0, 2, 4, 6, 8, 10, 12, 14, 0, 2, 4, 6,
              8, 10, 12, 14, 0, 2, 4, 6, 8, 10, 12, 14, 0, 2, 4, 6});
  CHECK_NEON(4, uint16_t,
             {3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,
              15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15});

  CHECK_NEON(6, uint32_t,
             {8, 10, 12, 14, 0, 2, 4, 6, 8, 10, 12, 14, 0, 2, 4, 6});
  CHECK_NEON(7, uint32_t,
             {3, 3, 3, 3, 3, 3, 3, 3, 15, 15, 15, 15, 15, 15, 15, 15});

  CHECK_NEON(9, uint64_t, {8, 10, 12, 14, 0, 2, 4, 6});
  CHECK_NEON(10, uint64_t, {3, 3, 3, 3, 15, 15, 15, 15});
}

TEST_P(InstSve, cmpne_imm) {
  // VL = 512-bits
  // 32-bit
  RUN_AARCH64(R"(
    ptrue p0.s
    dup z0.s, #-3

    cmpne p2.s, p0/z, z0.s, #0
  )");
  CHECK_PREDICATE(2, uint32_t, {286331153, 286331153, 0, 0, 0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    ptrue p0.s
    dup z0.s, #0

    cmpne p2.s, p0/z, z0.s, #0
  )");
  CHECK_PREDICATE(2, uint32_t, {0, 0, 0, 0, 0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b0110);

  RUN_AARCH64(R"(
    ptrue p0.s
    dup z0.s, #3

    cmpne p2.s, p0/z, z0.s, #0
  )");
  CHECK_PREDICATE(2, uint32_t, {286331153, 286331153, 0, 0, 0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #8
    whilelo p0.s, xzr, x0
    dup z0.s, #-3
   
    cmpne p2.s, p0/z, z0.s, #0
  )");
  CHECK_PREDICATE(2, uint32_t, {286331153, 0, 0, 0, 0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov x0, #8
    whilelo p0.s, xzr, x0
    dup z0.s, #0

    cmpne p2.s, p0/z, z0.s, #0
  )");
  CHECK_PREDICATE(2, uint32_t, {0, 0, 0, 0, 0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b0110);

  RUN_AARCH64(R"(
    mov x0, #8
    whilelo p0.s, xzr, x0
    dup z0.s, #3

    cmpne p2.s, p0/z, z0.s, #0
  )");
  CHECK_PREDICATE(2, uint32_t, {286331153, 0, 0, 0, 0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1010);
}

TEST_P(InstSve, cmpeq_imm) {
  // VL = 512-bits
  // 8-bit
  RUN_AARCH64(R"(
    mov x0, #64
    whilelo p0.b, xzr, x0
    dup z0.b, #-5

    cmpeq p1.b, p0/z, z0.b, #-5
  )");
  CHECK_PREDICATE(1, uint64_t, {0xFFFFFFFFFFFFFFFFu, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #32
    whilelo p0.b, xzr, x0
    dup z0.b, #4

    cmpeq p1.b, p0/z, z0.b, #4
  )");
  CHECK_PREDICATE(1, uint64_t, {0x00000000FFFFFFFFu, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov x0, #64
    whilelo p0.b, xzr, x0
    dup z0.b, #-5

    cmpeq p1.b, p0/z, z0.b, #4
  )");
  CHECK_PREDICATE(1, uint64_t, {0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b0110);

  // 16-bit
  RUN_AARCH64(R"(
    mov x0, #32
    whilelo p0.h, xzr, x0
    dup z0.h, #-5

    cmpeq p1.h, p0/z, z0.h, #-5
  )");
  CHECK_PREDICATE(1, uint64_t, {0x5555555555555555u, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #16
    whilelo p0.h, xzr, x0
    dup z0.h, #4

    cmpeq p1.h, p0/z, z0.h, #4
  )");
  CHECK_PREDICATE(1, uint64_t, {0x0000000055555555u, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov x0, #32
    whilelo p0.h, xzr, x0
    dup z0.h, #-5

    cmpeq p1.h, p0/z, z0.h, #4
  )");
  CHECK_PREDICATE(1, uint64_t, {0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b0110);

  // 32-bit
  RUN_AARCH64(R"(
    mov x0, #16
    whilelo p0.s, xzr, x0
    dup z0.s, #-5

    cmpeq p1.s, p0/z, z0.s, #-5
  )");
  CHECK_PREDICATE(1, uint64_t, {0x1111111111111111u, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #8
    whilelo p0.s, xzr, x0
    dup z0.s, #4

    cmpeq p1.s, p0/z, z0.s, #4
  )");
  CHECK_PREDICATE(1, uint64_t, {0x0000000011111111u, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov x0, #16
    whilelo p0.s, xzr, x0
    dup z0.s, #-5

    cmpeq p1.s, p0/z, z0.s, #4
  )");
  CHECK_PREDICATE(1, uint64_t, {0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b0110);

  // 64-bit
  RUN_AARCH64(R"(
    mov x0, #8
    whilelo p0.d, xzr, x0
    dup z0.d, #-5

    cmpeq p1.d, p0/z, z0.d, #-5
  )");
  CHECK_PREDICATE(1, uint64_t, {0x101010101010101u, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #4
    whilelo p0.d, xzr, x0
    dup z0.d, #4

    cmpeq p1.d, p0/z, z0.d, #4
  )");
  CHECK_PREDICATE(1, uint64_t, {0x000000001010101u, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov x0, #8
    whilelo p0.d, xzr, x0
    dup z0.d, #-5

    cmpeq p1.d, p0/z, z0.d, #4
  )");
  CHECK_PREDICATE(1, uint64_t, {0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b0110);
}

TEST_P(InstSve, cmpeq_vec) {
  // VL = 512-bits
  // 8-bit
  RUN_AARCH64(R"(
    mov x0, #64
    whilelo p0.b, xzr, x0
    dup z0.b, #-5

    cmpeq p1.b, p0/z, z0.b, z0.b
  )");
  CHECK_PREDICATE(1, uint64_t, {0xFFFFFFFFFFFFFFFFu, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #32
    whilelo p0.b, xzr, x0
    dup z0.b, #4

    cmpeq p1.b, p0/z, z0.b, z0.b
  )");
  CHECK_PREDICATE(1, uint64_t, {0x00000000FFFFFFFFu, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov x0, #64
    whilelo p0.b, xzr, x0
    dup z0.b, #-5
    dup z2.b, #4

    cmpeq p1.b, p0/z, z0.b, z2.b
  )");
  CHECK_PREDICATE(1, uint64_t, {0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b0110);

  // 16-bit
  RUN_AARCH64(R"(
    mov x0, #32
    whilelo p0.h, xzr, x0
    dup z0.h, #-5

    cmpeq p1.h, p0/z, z0.h, z0.h
  )");
  CHECK_PREDICATE(1, uint64_t, {0x5555555555555555u, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #16
    whilelo p0.h, xzr, x0
    dup z0.h, #4

    cmpeq p1.h, p0/z, z0.h, z0.h
  )");
  CHECK_PREDICATE(1, uint64_t, {0x0000000055555555u, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov x0, #32
    whilelo p0.h, xzr, x0
    dup z0.h, #-5
    dup z2.h, #4

    cmpeq p1.h, p0/z, z0.h, z2.h
  )");
  CHECK_PREDICATE(1, uint64_t, {0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b0110);

  // 32-bit
  RUN_AARCH64(R"(
    mov x0, #16
    whilelo p0.s, xzr, x0
    dup z0.s, #-5

    cmpeq p1.s, p0/z, z0.s, z0.s
  )");
  CHECK_PREDICATE(1, uint64_t, {0x1111111111111111u, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #8
    whilelo p0.s, xzr, x0
    dup z0.s, #4

    cmpeq p1.s, p0/z, z0.s, z0.s
  )");
  CHECK_PREDICATE(1, uint64_t, {0x0000000011111111u, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov x0, #16
    whilelo p0.s, xzr, x0
    dup z0.s, #-5
    dup z2.s, #4

    cmpeq p1.s, p0/z, z0.s, z2.s
  )");
  CHECK_PREDICATE(1, uint64_t, {0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b0110);

  // 64-bit
  RUN_AARCH64(R"(
    mov x0, #8
    whilelo p0.d, xzr, x0
    dup z0.d, #-5

    cmpeq p1.d, p0/z, z0.d, z0.d
  )");
  CHECK_PREDICATE(1, uint64_t, {0x101010101010101u, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #4
    whilelo p0.d, xzr, x0
    dup z0.d, #4

    cmpeq p1.d, p0/z, z0.d, z0.d
  )");
  CHECK_PREDICATE(1, uint64_t, {0x000000001010101u, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov x0, #8
    whilelo p0.d, xzr, x0
    dup z0.d, #-5
    dup z2.d, #4

    cmpeq p1.d, p0/z, z0.d, z2.d
  )");
  CHECK_PREDICATE(1, uint64_t, {0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b0110);
}

TEST_P(InstSve, cmpgt_vec) {
  // VL = 512-bits
  // 8-bit
  RUN_AARCH64(R"(
    mov x0, #64
    whilelo p0.b, xzr, x0
    dup z0.b, #5
    dup z1.b, #-4

    cmpgt p1.b, p0/z, z0.b, z1.b
  )");
  CHECK_PREDICATE(1, uint64_t, {0xFFFFFFFFFFFFFFFFu, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #32
    whilelo p0.b, xzr, x0
    dup z0.b, #5
    dup z1.b, #-4

    cmpgt p1.b, p0/z, z0.b, z1.b
  )");
  CHECK_PREDICATE(1, uint64_t, {0x00000000FFFFFFFFu, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov x0, #64
    whilelo p0.b, xzr, x0
    dup z0.b, #5
    dup z1.b, #-4

    cmpgt p1.b, p0/z, z1.b, z0.b
  )");
  CHECK_PREDICATE(1, uint64_t, {0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b0110);

  // 16-bit
  RUN_AARCH64(R"(
    mov x0, #32
    whilelo p0.h, xzr, x0
    dup z0.h, #5
    dup z1.h, #-4

    cmpgt p1.h, p0/z, z0.h, z1.h
  )");
  CHECK_PREDICATE(1, uint64_t, {0x5555555555555555u, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #16
    whilelo p0.h, xzr, x0
    dup z0.h, #5
    dup z1.h, #-4

    cmpgt p1.h, p0/z, z0.h, z1.h
  )");
  CHECK_PREDICATE(1, uint64_t, {0x0000000055555555u, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov x0, #32
    whilelo p0.h, xzr, x0
    dup z0.h, #5
    dup z1.h, #-4

    cmpgt p1.h, p0/z, z1.h, z0.h
  )");
  CHECK_PREDICATE(1, uint64_t, {0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b0110);

  // 32-bit
  RUN_AARCH64(R"(
    mov x0, #16
    whilelo p0.s, xzr, x0
    dup z0.s, #5
    dup z1.s, #-4

    cmpgt p1.s, p0/z, z0.s, z1.s
  )");
  CHECK_PREDICATE(1, uint64_t, {0x1111111111111111u, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #8
    whilelo p0.s, xzr, x0
    dup z0.s, #5
    dup z1.s, #-4

    cmpgt p1.s, p0/z, z0.s, z1.s
  )");
  CHECK_PREDICATE(1, uint64_t, {0x0000000011111111u, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov x0, #16
    whilelo p0.s, xzr, x0
    dup z0.s, #5
    dup z1.s, #-4

    cmpgt p1.s, p0/z, z1.s, z0.s
  )");
  CHECK_PREDICATE(1, uint64_t, {0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b0110);

  // 64-bit
  RUN_AARCH64(R"(
    mov x0, #8
    whilelo p0.d, xzr, x0
    dup z0.d, #5
    dup z1.d, #-4

    cmpgt p1.d, p0/z, z0.d, z1.d
  )");
  CHECK_PREDICATE(1, uint64_t, {0x101010101010101u, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #4
    whilelo p0.d, xzr, x0
    dup z0.d, #5
    dup z1.d, #-4

    cmpgt p1.d, p0/z, z0.d, z1.d
  )");
  CHECK_PREDICATE(1, uint64_t, {0x000000001010101u, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov x0, #8
    whilelo p0.d, xzr, x0
    dup z0.d, #5
    dup z1.d, #-4

    cmpgt p1.d, p0/z, z1.d, z0.d
  )");
  CHECK_PREDICATE(1, uint64_t, {0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b0110);
}

TEST_P(InstSve, cmphi_vec) {
  // VL = 512-bits
  // 8-bit
  RUN_AARCH64(R"(
    mov x0, #64
    whilelo p0.b, xzr, x0
    dup z0.b, #-5
    dup z1.b, #4

    cmphi p1.b, p0/z, z0.b, z1.b
  )");
  CHECK_PREDICATE(1, uint64_t, {0xFFFFFFFFFFFFFFFFu, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #32
    whilelo p0.b, xzr, x0
    dup z0.b, #-5
    dup z1.b, #4

    cmphi p1.b, p0/z, z0.b, z1.b
  )");
  CHECK_PREDICATE(1, uint64_t, {0x00000000FFFFFFFFu, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov x0, #64
    whilelo p0.b, xzr, x0
    dup z0.b, #-5
    dup z1.b, #4

    cmphi p1.b, p0/z, z1.b, z0.b
  )");
  CHECK_PREDICATE(1, uint64_t, {0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b0110);

  // 16-bit
  RUN_AARCH64(R"(
    mov x0, #32
    whilelo p0.h, xzr, x0
    dup z0.h, #-5
    dup z1.h, #4

    cmphi p1.h, p0/z, z0.h, z1.h
  )");
  CHECK_PREDICATE(1, uint64_t, {0x5555555555555555u, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #16
    whilelo p0.h, xzr, x0
    dup z0.h, #-5
    dup z1.h, #4

    cmphi p1.h, p0/z, z0.h, z1.h
  )");
  CHECK_PREDICATE(1, uint64_t, {0x0000000055555555u, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov x0, #32
    whilelo p0.h, xzr, x0
    dup z0.h, #-5
    dup z1.h, #4

    cmphi p1.h, p0/z, z1.h, z0.h
  )");
  CHECK_PREDICATE(1, uint64_t, {0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b0110);

  // 32-bit
  RUN_AARCH64(R"(
    mov x0, #16
    whilelo p0.s, xzr, x0
    dup z0.s, #-5
    dup z1.s, #4

    cmphi p1.s, p0/z, z0.s, z1.s
  )");
  CHECK_PREDICATE(1, uint64_t, {0x1111111111111111u, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #8
    whilelo p0.s, xzr, x0
    dup z0.s, #-5
    dup z1.s, #4

    cmphi p1.s, p0/z, z0.s, z1.s
  )");
  CHECK_PREDICATE(1, uint64_t, {0x0000000011111111u, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov x0, #16
    whilelo p0.s, xzr, x0
    dup z0.s, #-5
    dup z1.s, #4

    cmphi p1.s, p0/z, z1.s, z0.s
  )");
  CHECK_PREDICATE(1, uint64_t, {0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b0110);

  // 64-bit
  RUN_AARCH64(R"(
    mov x0, #8
    whilelo p0.d, xzr, x0
    dup z0.d, #-5
    dup z1.d, #4

    cmphi p1.d, p0/z, z0.d, z1.d
  )");
  CHECK_PREDICATE(1, uint64_t, {0x101010101010101u, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #4
    whilelo p0.d, xzr, x0
    dup z0.d, #-5
    dup z1.d, #4

    cmphi p1.d, p0/z, z0.d, z1.d
  )");
  CHECK_PREDICATE(1, uint64_t, {0x000000001010101u, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov x0, #8
    whilelo p0.d, xzr, x0
    dup z0.d, #-5
    dup z1.d, #4

    cmphi p1.d, p0/z, z1.d, z0.d
  )");
  CHECK_PREDICATE(1, uint64_t, {0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b0110);
}

TEST_P(InstSve, cnt) {
  // VL = 512-bits
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
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 64);
  EXPECT_EQ(getGeneralRegister<uint64_t>(1), 32);
  EXPECT_EQ(getGeneralRegister<uint64_t>(2), 16);
  EXPECT_EQ(getGeneralRegister<uint64_t>(3), 8);
  EXPECT_EQ(getGeneralRegister<uint64_t>(4), 192);
  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 96);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 48);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 24);
}

TEST_P(InstSve, cntp) {
  // VL = 512-bits
  RUN_AARCH64(R"(
    # 8-bit
    mov x0, #32
    ptrue p0.b
    whilelo p1.b, xzr, x0
    cntp x0, p0, p0.b
    cntp x1, p1, p0.b

    # 16-bit
    mov x2, #16
    ptrue p0.h
    whilelo p2.h, xzr, x2
    cntp x2, p0, p0.h
    cntp x3, p2, p0.h

    # 32-bit
    mov x4, #8
    ptrue p0.s
    whilelo p3.s, xzr, x4
    cntp x4, p0, p0.s
    cntp x5, p3, p0.s

    # 64-bit
    mov x6, #4
    ptrue p0.d
    whilelo p4.d, xzr, x6
    cntp x6, p0, p0.d
    cntp x7, p4, p0.d
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 64);
  EXPECT_EQ(getGeneralRegister<uint64_t>(1), 32);
  EXPECT_EQ(getGeneralRegister<uint64_t>(2), 32);
  EXPECT_EQ(getGeneralRegister<uint64_t>(3), 16);
  EXPECT_EQ(getGeneralRegister<uint64_t>(4), 16);
  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 8);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 8);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 4);
}

TEST_P(InstSve, dec) {
  // VL = 512-bits
  // pattern = all
  RUN_AARCH64(R"(
    mov x0, #128
    mov x1, #128
    decb x0
    decd x1
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 64);
  EXPECT_EQ(getGeneralRegister<uint64_t>(1), 120);
}

TEST_P(InstSve, dupm) {
  // VL = 512-bit
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

  CHECK_NEON(0, uint64_t, {0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1});
  CHECK_NEON(1, uint64_t, {0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3});
  CHECK_NEON(2, uint64_t, {0x7, 0x7, 0x7, 0x7, 0x7, 0x7, 0x7, 0x7});
  CHECK_NEON(3, uint64_t, {0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf, 0xf});
  CHECK_NEON(4, uint64_t, {0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f, 0x1f});
  CHECK_NEON(5, uint64_t, {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff});
  CHECK_NEON(6, uint64_t,
             {0x1ff, 0x1ff, 0x1ff, 0x1ff, 0x1ff, 0x1ff, 0x1ff, 0x1ff});
  CHECK_NEON(7, uint64_t,
             {0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff});
  CHECK_NEON(
      8, uint64_t,
      {0x1ffff, 0x1ffff, 0x1ffff, 0x1ffff, 0x1ffff, 0x1ffff, 0x1ffff, 0x1ffff});
  CHECK_NEON(9, uint64_t,
             {0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
              0xffffffff, 0xffffffff, 0xffffffff});
  CHECK_NEON(10, uint64_t,
             {0x1ffffffff, 0x1ffffffff, 0x1ffffffff, 0x1ffffffff, 0x1ffffffff,
              0x1ffffffff, 0x1ffffffff, 0x1ffffffff});
  CHECK_NEON(11, uint64_t,
             {0xefffffffffffffff, 0xefffffffffffffff, 0xefffffffffffffff,
              0xefffffffffffffff, 0xefffffffffffffff, 0xefffffffffffffff,
              0xefffffffffffffff, 0xefffffffffffffff});
}

TEST_P(InstSve, dups) {
  // VL = 512-bit
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

  CHECK_NEON(0, int8_t,
             {7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
              7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
              7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7});
  CHECK_NEON(1, int8_t,
             {-7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7,
              -7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7,
              -7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7,
              -7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7});
  // CHECK_NEON(2, float, {0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f});
  // CHECK_NEON(3, float, {-0.5f, -0.5f, -0.5f, -0.5f, -0.5f, -0.5f, -0.5f,
  // -0.5f}); CHECK_NEON(6, float, {14.5f, 14.5f, 14.5f, 14.5f, 14.5f,
  // 14.5f, 14.5f, 14.5f, 14.5f, 14.5f, 14.5f, 14.5f, 14.5f, 14.5f,
  // 14.5f, 14.5f});
  // CHECK_NEON(7, float, {-14.5f, -14.5f, -14.5f, -14.5f, -14.5f, -14.5f,
  // -14.5f, -14.5f, -14.5f, -14.5f, -14.5f, -14.5f, -14.5f, -14.5f, -14.5f,
  // -14.5f});
  CHECK_NEON(8, int8_t,
             {3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
              3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
              3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3});
  CHECK_NEON(9, int8_t,
             {-3, -3, -3, -3, -3, -3, -3, -3, -3, -3, -3, -3, -3, -3, -3, -3,
              -3, -3, -3, -3, -3, -3, -3, -3, -3, -3, -3, -3, -3, -3, -3, -3,
              -3, -3, -3, -3, -3, -3, -3, -3, -3, -3, -3, -3, -3, -3, -3, -3,
              -3, -3, -3, -3, -3, -3, -3, -3, -3, -3, -3, -3, -3, -3, -3, -3});

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

  CHECK_NEON(0, int16_t, {7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
                          7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7});
  CHECK_NEON(1, int16_t,
             {-7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7,
              -7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7});
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
  CHECK_NEON(8, int16_t, {3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
                          3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3});
  CHECK_NEON(9, int16_t,
             {-3, -3, -3, -3, -3, -3, -3, -3, -3, -3, -3, -3, -3, -3, -3, -3,
              -3, -3, -3, -3, -3, -3, -3, -3, -3, -3, -3, -3, -3, -3, -3, -3});

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

  CHECK_NEON(0, int32_t, {7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7});
  CHECK_NEON(1, int32_t,
             {-7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7});
  CHECK_NEON(2, float,
             {0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f,
              0.5f, 0.5f, 0.5f, 0.5f, 0.5f});
  CHECK_NEON(3, float,
             {-0.5f, -0.5f, -0.5f, -0.5f, -0.5f, -0.5f, -0.5f, -0.5f, -0.5f,
              -0.5f, -0.5f, -0.5f, -0.5f, -0.5f, -0.5f, -0.5f});
  CHECK_NEON(6, float,
             {14.5f, 14.5f, 14.5f, 14.5f, 14.5f, 14.5f, 14.5f, 14.5f, 14.5f,
              14.5f, 14.5f, 14.5f, 14.5f, 14.5f, 14.5f, 14.5f});
  CHECK_NEON(7, float,
             {-14.5f, -14.5f, -14.5f, -14.5f, -14.5f, -14.5f, -14.5f, -14.5f,
              -14.5f, -14.5f, -14.5f, -14.5f, -14.5f, -14.5f, -14.5f, -14.5f});
  CHECK_NEON(8, int32_t, {3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3});
  CHECK_NEON(9, int32_t,
             {-3, -3, -3, -3, -3, -3, -3, -3, -3, -3, -3, -3, -3, -3, -3, -3});
  CHECK_NEON(10, int32_t, {9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9});
  CHECK_NEON(11, int32_t,
             {-9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9});

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

  CHECK_NEON(0, int64_t, {7, 7, 7, 7, 7, 7, 7, 7});
  CHECK_NEON(1, int64_t, {-7, -7, -7, -7, -7, -7, -7, -7});
  CHECK_NEON(2, double, {0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5});
  CHECK_NEON(3, double, {-0.5, -0.5, -0.5, -0.5, -0.5, -0.5, -0.5, -0.5});
  CHECK_NEON(6, double, {14.5, 14.5, 14.5, 14.5, 14.5, 14.5, 14.5, 14.5});
  CHECK_NEON(7, double,
             {-14.5, -14.5, -14.5, -14.5, -14.5, -14.5, -14.5, -14.5});
  CHECK_NEON(8, int64_t, {3, 3, 3, 3, 3, 3, 3, 3});
  CHECK_NEON(9, int64_t, {-3, -3, -3, -3, -3, -3, -3, -3});
}

TEST_P(InstSve, eor) {
  // VL = 512-bits
  // Predicate, Predicated
  RUN_AARCH64(R"(
    mov x0, #48
    mov x1, #32
    ptrue p0.b
    whilelo p1.b, xzr, x0
    whilelo p2.b, xzr, x1
    rev p3.b, p1.b

    eor p4.b, p0/z, p0.b, p1.b
    eor p5.b, p1/z, p0.b, p2.b
    eor p6.b, p0/z, p2.b, p3.b
    eor p7.b, p1/z, p3.b, p0.b

    # Test alias of not
    not p8.b, p0/z, p6.b
  )");
  CHECK_PREDICATE(4, uint64_t, {0xFFFF000000000000u, 0, 0, 0});
  CHECK_PREDICATE(5, uint64_t, {0x0000FFFF00000000u, 0, 0, 0});
  CHECK_PREDICATE(6, uint64_t, {0xFFFFFFFF0000FFFFu, 0, 0, 0});
  CHECK_PREDICATE(7, uint64_t, {0x000000000000FFFFu, 0, 0, 0});
  CHECK_PREDICATE(8, uint64_t, {0x00000000FFFF0000u, 0, 0, 0});

  // Vectors, Predicated
  RUN_AARCH64(R"(
    # 8-bit
    mov x0, #32
    index z0.b, #8, #2
    dup z1.b, #15
    dup z2.b, #3
    ptrue p0.b
    whilelo p1.b, xzr, x0

    eor z0.b, p0/m, z0.b, z1.b
    eor z1.b, p1/m, z1.b, z2.b 

    # 16-bit
    mov x0, #16
    index z3.h, #8, #2
    dup z4.h, #15
    dup z5.h, #3
    ptrue p0.h
    whilelo p1.h, xzr, x0

    eor z3.h, p0/m, z3.h, z4.h
    eor z4.h, p1/m, z4.h, z5.h 

    # 32-bit
    mov x0, #8
    index z6.s, #8, #2
    dup z7.s, #15
    dup z8.s, #3
    ptrue p0.s
    whilelo p1.s, xzr, x0

    eor z6.s, p0/m, z6.s, z7.s
    eor z7.s, p1/m, z7.s, z8.s 

    # 64-bit
    mov x0, #4
    index z9.d, #8, #2
    dup z10.d, #15
    dup z11.d, #3
    ptrue p0.d
    whilelo p1.d, xzr, x0

    eor z9.d, p0/m, z9.d, z10.d
    eor z10.d, p1/m, z10.d, z11.d 
  )");
  CHECK_NEON(0, uint8_t,
             {7,   5,   3,   1,   31,  29,  27,  25,  23,  21,  19,  17, 47,
              45,  43,  41,  39,  37,  35,  33,  63,  61,  59,  57,  55, 53,
              51,  49,  79,  77,  75,  73,  71,  69,  67,  65,  95,  93, 91,
              89,  87,  85,  83,  81,  111, 109, 107, 105, 103, 101, 99, 97,
              127, 125, 123, 121, 119, 117, 115, 113, 143, 141, 139, 137});
  CHECK_NEON(1, uint8_t,
             {12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
              12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
              15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
              15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15});

  CHECK_NEON(3, uint16_t,
             {7,  5,  3,  1,  31, 29, 27, 25, 23, 21, 19, 17, 47, 45, 43, 41,
              39, 37, 35, 33, 63, 61, 59, 57, 55, 53, 51, 49, 79, 77, 75, 73});
  CHECK_NEON(4, uint16_t,
             {12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12,
              15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15});

  CHECK_NEON(6, uint32_t,
             {7, 5, 3, 1, 31, 29, 27, 25, 23, 21, 19, 17, 47, 45, 43, 41});
  CHECK_NEON(7, uint32_t,
             {12, 12, 12, 12, 12, 12, 12, 12, 15, 15, 15, 15, 15, 15, 15, 15});

  CHECK_NEON(9, uint64_t, {7, 5, 3, 1, 31, 29, 27, 25});
  CHECK_NEON(10, uint64_t, {12, 12, 12, 12, 15, 15, 15, 15});
}

TEST_P(InstSve, inc) {
  // VL = 512-bits
  // pattern = all
  RUN_AARCH64(R"(
    mov x0, #64
    mov x1, #196
    mov x2, #96
    mov x3, #128
    mov x4, #64
    mov x5, #196
    mov x6, #96
    mov x7, #128
    incb x0
    incd x1
    inch x2
    incw x3
    incb x4, all, mul #3
    incd x5, all, mul #3
    inch x6, all, mul #3
    incw x7, all, mul #3
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 128);
  EXPECT_EQ(getGeneralRegister<uint64_t>(1), 204);
  EXPECT_EQ(getGeneralRegister<uint64_t>(2), 128);
  EXPECT_EQ(getGeneralRegister<uint64_t>(3), 144);
  EXPECT_EQ(getGeneralRegister<uint64_t>(4), 256);
  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 220);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 192);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 176);

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
             {31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31});
  CHECK_NEON(1, int32_t,
             {85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85, 85});
  CHECK_NEON(2, int16_t,
             {57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57,
              57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57, 57});
  CHECK_NEON(3, int16_t,
             {83, 83, 83, 83, 83, 83, 83, 83, 83, 83, 83, 83, 83, 83, 83, 83,
              83, 83, 83, 83, 83, 83, 83, 83, 83, 83, 83, 83, 83, 83, 83, 83});
  CHECK_NEON(4, int64_t, {11, 11, 11, 11, 11, 11, 11, 11});
  CHECK_NEON(5, int64_t, {124, 124, 124, 124, 124, 124, 124, 124});
}

TEST_P(InstSve, fabs) {
  // VL = 512-bits
  // float
  initialHeapData_.resize(64);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  fheap[0] = 1.0;
  fheap[1] = -42.76;
  fheap[2] = -0.125;
  fheap[3] = 0.0;
  fheap[4] = 40.26;
  fheap[5] = -684.72;
  fheap[6] = -0.15;
  fheap[7] = 107.86;

  fheap[8] = -34.71f;
  fheap[9] = -0.917f;
  fheap[10] = 0.0f;
  fheap[11] = 80.72f;
  fheap[12] = -125.67f;
  fheap[13] = -0.01f;
  fheap[14] = 701.90f;
  fheap[15] = 7.0f;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #8
    whilelo p0.s, xzr, x2
    ptrue p1.s

    ld1w {z0.s}, p1/z, [x0, x1, lsl #2]
    ld1w {z1.s}, p1/z, [x0, x2, lsl #2]

    fdup z3.s, #3.0

    fabs z2.s, p1/m, z0.s
    fabs z3.s, p0/m, z1.s
  )");

  CHECK_NEON(2, float,
             {1.0f, 42.76f, 0.125f, 0.0f, 40.26f, 684.72f, 0.15f, 107.86f,
              34.71f, 0.917f, 0.0f, 80.72f, 125.67f, 0.01f, 701.90f, 7.0f});
  CHECK_NEON(3, float,
             {34.71f, 0.917f, 0.0f, 80.72f, 125.67f, 0.01f, 701.90f, 7.0f, 3.0f,
              3.0f, 3.0f, 3.0f, 3.0f, 3.0f, 3.0f, 3.0f});

  // double
  initialHeapData_.resize(128);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  dheap[0] = 1.0;
  dheap[1] = -42.76;
  dheap[2] = -0.125;
  dheap[3] = 0.0;
  dheap[4] = 40.26;
  dheap[5] = -684.72;
  dheap[6] = -0.15;
  dheap[7] = 107.86;

  dheap[8] = -34.71f;
  dheap[9] = -0.917f;
  dheap[10] = 0.0f;
  dheap[11] = 80.72f;
  dheap[12] = -125.67f;
  dheap[13] = -0.01f;
  dheap[14] = 701.90f;
  dheap[15] = 7.0f;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #4
    mov x3, #8
    whilelo p0.d, xzr, x2
    ptrue p1.d

    ld1d {z0.d}, p1/z, [x0, x1, lsl #3]
    ld1d {z1.d}, p1/z, [x0, x3, lsl #3]

    fdup z3.d, #3.0

    fabs z2.d, p1/m, z0.d
    fabs z3.d, p0/m, z1.d
  )");

  CHECK_NEON(2, double, {1.0, 42.76, 0.125, 0.0, 40.26, 684.72, 0.15, 107.86});
  CHECK_NEON(3, double, {34.71, 0.917, 0.0, 80.72, 3.0, 3.0, 3.0, 3.0});
}

TEST_P(InstSve, add) {
  // VL = 512-bits
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
  CHECK_NEON(
      0, uint8_t,
      {
          16u, 16u, 16u, 16u, 16u, 16u, 16u, 16u, 16u, 16u, 16u, 16u, 16u,
          16u, 16u, 16u, 16u, 16u, 16u, 16u, 16u, 16u, 16u, 16u, 16u, 16u,
          16u, 16u, 16u, 16u, 16u, 16u, 16u, 16u, 16u, 16u, 16u, 16u, 16u,
          16u, 16u, 16u, 16u, 16u, 16u, 16u, 16u, 16u, 16u, 16u, 16u, 16u,
          16u, 16u, 16u, 16u, 16u, 16u, 16u, 16u, 16u, 16u, 16u, 16u,
      });
  CHECK_NEON(1, uint16_t,
             {14u, 14u, 14u, 14u, 14u, 14u, 14u, 14u, 14u, 14u, 14u,
              14u, 14u, 14u, 14u, 14u, 14u, 14u, 14u, 14u, 14u, 14u,
              14u, 14u, 14u, 14u, 14u, 14u, 14u, 14u, 14u, 14u});
  CHECK_NEON(2, uint32_t,
             {12u, 12u, 12u, 12u, 12u, 12u, 12u, 12u, 12u, 12u, 12u, 12u, 12u,
              12u, 12u, 12u});
  CHECK_NEON(3, uint64_t, {10u, 10u, 10u, 10u, 10u, 10u, 10u, 10u});
}

TEST_P(InstSve, fadd) {
  // VL = 512-bits
  // double
  initialHeapData_.resize(128);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  dheap[0] = 1.0;
  dheap[1] = -42.76;
  dheap[2] = -0.125;
  dheap[3] = 0.0;
  dheap[4] = 40.26;
  dheap[5] = -684.72;
  dheap[6] = -0.15;
  dheap[7] = 107.86;

  dheap[8] = -34.71;
  dheap[9] = -0.917;
  dheap[10] = 0.0;
  dheap[11] = 80.72;
  dheap[12] = -125.67;
  dheap[13] = -0.01;
  dheap[14] = 701.90;
  dheap[15] = 7.0;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #4
    mov x3, #8
    whilelo p0.d, xzr, x2
    ptrue p1.d

    ld1d {z0.d}, p0/z, [x0, x1, lsl #3]
    ld1d {z1.d}, p0/z, [x0, x3, lsl #3]
    ld1d {z3.d}, p1/z, [x0, x1, lsl #3]
    ld1d {z4.d}, p1/z, [x0, x3, lsl #3]

    fadd z2.d, z1.d, z0.d
    fadd z4.d, p0/m, z4.d, z3.d

    # FADD with constant
    ld1d {z5.d}, p1/z, [x0, x3, lsl #3]
    fadd z5.d, p0/m, z5.d, z3.d
    fadd z5.d, p0/m, z5.d, 0.5
  )");

  CHECK_NEON(2, double, {-33.71, -43.677, -0.125, 80.72, 0, 0, 0, 0});
  CHECK_NEON(4, double,
             {-33.71, -43.677, -0.125, 80.72, -125.67, -0.01, 701.90, 7.0});
  CHECK_NEON(5, double,
             {-33.21, -43.177, 0.375, 81.22, -125.67, -0.01, 701.90, 7.0});

  // float
  initialHeapData_.resize(68);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  fheap[0] = 1.0;
  fheap[1] = -42.76;
  fheap[2] = -0.125;
  fheap[3] = 0.0;
  fheap[4] = 40.26;
  fheap[5] = -684.72;
  fheap[6] = -0.15;
  fheap[7] = 107.86;

  fheap[8] = -34.71f;
  fheap[9] = -0.917f;
  fheap[10] = 0.0f;
  fheap[11] = 80.72f;
  fheap[12] = -125.67f;
  fheap[13] = -0.01f;
  fheap[14] = 701.90f;
  fheap[15] = 7.0f;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #8
    whilelo p0.s, xzr, x2
    ptrue p1.s

    ld1w {z0.s}, p0/z, [x0, x1, lsl #2]
    ld1w {z1.s}, p0/z, [x0, x2, lsl #2]
    ld1w {z4.s}, p1/z, [x0, x1, lsl #2]
    ld1w {z5.s}, p1/z, [x0, x1, lsl #2]

    fadd z2.s, z1.s, z0.s

    # FADD with constant
    ld1w {z3.s}, p0/z, [x0, x2, lsl #2]
    fadd z3.s, z1.s, z0.s
    fadd z3.s, p1/m, z3.s, 0.5

    fadd z4.s, p1/m, z4.s, z3.s
    fadd z5.s, p0/m, z5.s, z4.s
  )");

  CHECK_NEON(2, float,
             {-33.71f, -43.677f, -0.125f, 80.72f, -85.41f, -684.73f, 701.75f,
              114.86f, 0, 0, 0, 0, 0, 0, 0, 0});
  CHECK_NEON(3, float,
             {-33.21f, -43.177f, 0.375f, 81.22f, -84.91f, -684.23f, 702.25f,
              115.36f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f});
  CHECK_NEON(
      4, float,
      {-32.21f, -85.937f, 0.25f, 81.22f, -44.65f, -1368.95f, 702.1f, 223.22f,
       -34.21f, -0.417f, 0.5f, 81.22f, -125.17f, 0.49f, 702.4f, 7.5f});
  CHECK_NEON(
      5, float,
      {-31.21f, -128.697f, 0.125f, 81.22f, -4.39f, -2053.67f, 701.95f, 331.08f,
       -34.71f, -0.917f, 0.0f, 80.72f, -125.67f, -0.01f, 701.90f, 7.0f});
}

TEST_P(InstSve, fadda) {
  // VL = 512-bits
  // double
  initialHeapData_.resize(64);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  dheap[0] = 1.0;
  dheap[1] = -42.76;
  dheap[2] = -0.125;
  dheap[3] = 0.0;

  dheap[4] = -34.71;
  dheap[5] = -0.917;
  dheap[6] = 0.0;
  dheap[7] = 80.72;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    fmov d1, 2.75
    fmov d3, 2.75

    mov x1, #0
    mov x2, #4
    whilelo p1.d, xzr, x2
    ptrue p0.d

    ld1d {z0.d}, p0/z, [x0, x1, lsl #3]
    ld1d {z2.d}, p1/z, [x0, x2, lsl #3]

    fadda d1, p1, d1, z0.d
    fadda d3, p1, d3, z2.d
  )");

  CHECK_NEON(1, double, {-39.135, 0});
  CHECK_NEON(3, double, {47.8429999999999964, 0});
}

TEST_P(InstSve, fcmge) {
  // VL = 512-bits
  // Zero
  // double
  initialHeapData_.resize(128);
  double* dheap_z = reinterpret_cast<double*>(initialHeapData_.data());
  dheap_z[0] = 1.0;
  dheap_z[1] = -42.76;
  dheap_z[2] = -0.125;
  dheap_z[3] = 1.0;
  dheap_z[4] = 40.26;
  dheap_z[5] = -684.72;
  dheap_z[6] = -0.15;
  dheap_z[7] = 107.86;

  dheap_z[8] = -34.71;
  dheap_z[9] = -0.917;
  dheap_z[10] = 1.0;
  dheap_z[11] = 80.72;
  dheap_z[12] = -125.67;
  dheap_z[13] = -0.01;
  dheap_z[14] = 701.90;
  dheap_z[15] = 7.0;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #4
    whilelo p0.d, xzr, x2

    ld1d {z0.d}, p0/z, [x0, x1, lsl #3]

    fcmge p1.d, p0/z, z0.d, #0.0
  )");

  CHECK_PREDICATE(1, uint32_t, {0x01000001, 0, 0, 0, 0, 0});

  // float
  initialHeapData_.resize(68);
  float* fheap_z = reinterpret_cast<float*>(initialHeapData_.data());
  fheap_z[0] = 1.0;
  fheap_z[1] = -42.76;
  fheap_z[2] = -0.125;
  fheap_z[3] = 0.0;
  fheap_z[4] = 40.26;
  fheap_z[5] = -684.72;
  fheap_z[6] = -0.15;
  fheap_z[7] = 107.86;

  fheap_z[8] = -34.71f;
  fheap_z[9] = -0.917f;
  fheap_z[10] = 0.0f;
  fheap_z[11] = 80.72f;
  fheap_z[12] = -125.67f;
  fheap_z[13] = -0.01f;
  fheap_z[14] = 701.90f;
  fheap_z[15] = 7.0f;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #8
    whilelo p0.s, xzr, x2

    ld1w {z0.s}, p0/z, [x0, x1, lsl #2]

    fcmge p1.s, p0/z, z0.s, #0.0
  )");

  CHECK_PREDICATE(1, uint32_t, {0x10011001, 0, 0, 0, 0, 0, 0, 0});

  // Vector
  // double
  initialHeapData_.resize(128);
  double* dheap_v = reinterpret_cast<double*>(initialHeapData_.data());
  dheap_v[0] = 1.0;
  dheap_v[1] = -42.76;
  dheap_v[2] = -0.125;
  dheap_v[3] = 1.0;
  dheap_v[4] = 40.26;
  dheap_v[5] = -684.72;
  dheap_v[6] = -0.15;
  dheap_v[7] = 107.86;

  dheap_v[8] = -34.71;
  dheap_v[9] = -0.917;
  dheap_v[10] = 80.72;
  dheap_v[11] = 1.0;
  dheap_v[12] = -125.67;
  dheap_v[13] = -0.01;
  dheap_v[14] = 701.90;
  dheap_v[15] = 7.0;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #4
    mov x3, #8
    whilelo p0.d, xzr, x2
    ptrue p1.d

    ld1d {z0.d}, p1/z, [x0, x1, lsl #3]
    ld1d {z1.d}, p1/z, [x0, x3, lsl #3]

    fcmge p1.d, p0/z, z0.d, z1.d
  )");

  CHECK_PREDICATE(1, uint64_t, {0x0000000001000001u, 0, 0, 0});

  // float
  initialHeapData_.resize(68);
  float* fheap_v = reinterpret_cast<float*>(initialHeapData_.data());
  fheap_v[0] = 1.0;
  fheap_v[1] = -42.76;
  fheap_v[2] = -0.125;
  fheap_v[3] = 0.0;
  fheap_v[4] = 40.26;
  fheap_v[5] = -684.72;
  fheap_v[6] = -0.15;
  fheap_v[7] = 107.86;

  fheap_v[8] = -34.71f;
  fheap_v[9] = -0.917f;
  fheap_v[10] = 80.72f;
  fheap_v[11] = 0.0f;
  fheap_v[12] = -125.67f;
  fheap_v[13] = -0.01f;
  fheap_v[14] = 701.90f;
  fheap_v[15] = 7.0f;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #8
    whilelo p0.s, xzr, x2

    ld1w {z0.s}, p0/z, [x0, x1, lsl #2]
    ld1w {z1.s}, p0/z, [x0, x2, lsl #2]

    fcmge p1.s, p0/z, z0.s, z1.s
  )");

  CHECK_PREDICATE(1, uint64_t, {0x0000000010011001u, 0, 0, 0});
}

TEST_P(InstSve, fcmgt) {
  // VL = 512-bits
  // Vector
  // double
  initialHeapData_.resize(128);
  double* dheap_v = reinterpret_cast<double*>(initialHeapData_.data());
  dheap_v[0] = 1.0;
  dheap_v[1] = -42.76;
  dheap_v[2] = -0.125;
  dheap_v[3] = 1.0;
  dheap_v[4] = 40.26;
  dheap_v[5] = -684.72;
  dheap_v[6] = -0.15;
  dheap_v[7] = 107.86;

  dheap_v[8] = -34.71;
  dheap_v[9] = -0.917;
  dheap_v[10] = 1.0;
  dheap_v[11] = 80.72;
  dheap_v[12] = -125.67;
  dheap_v[13] = -0.01;
  dheap_v[14] = 701.90;
  dheap_v[15] = 7.0;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #4
    mov x3, #8
    whilelo p0.d, xzr, x2
    ptrue p1.d
    
    ld1d {z0.d}, p1/z, [x0, x1, lsl #3]
    ld1d {z1.d}, p0/z, [x0, x3, lsl #3]

    fcmgt p2.d, p0/z, z0.d, z1.d
  )");
  CHECK_PREDICATE(2, uint32_t, {1, 0, 0, 0, 0, 0, 0});

  // float
  initialHeapData_.resize(68);
  float* fheap_v = reinterpret_cast<float*>(initialHeapData_.data());
  fheap_v[0] = 1.0;
  fheap_v[1] = -42.76;
  fheap_v[2] = -0.125;
  fheap_v[3] = 0.0;
  fheap_v[4] = 40.26;
  fheap_v[5] = -684.72;
  fheap_v[6] = -0.15;
  fheap_v[7] = 107.86;

  fheap_v[8] = -34.71f;
  fheap_v[9] = -0.917f;
  fheap_v[10] = 0.0f;
  fheap_v[11] = 80.72f;
  fheap_v[12] = -125.67f;
  fheap_v[13] = -0.01f;
  fheap_v[14] = 701.90f;
  fheap_v[15] = 7.0f;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #8
    whilelo p0.s, xzr, x2
    ptrue p1.s

    ld1w {z0.s}, p1/z, [x0, x1, lsl #2]
    ld1w {z1.s}, p0/z, [x0, x2, lsl #2]

    fcmgt p2.s, p0/z, z0.s, z1.s
  )");
  CHECK_PREDICATE(2, uint32_t, {0x10010001, 0, 0, 0, 0, 0, 0, 0});

  // Zero
  // double
  initialHeapData_.resize(128);
  double* dheap_z = reinterpret_cast<double*>(initialHeapData_.data());
  dheap_z[0] = 1.0;
  dheap_z[1] = -42.76;
  dheap_z[2] = -0.125;
  dheap_z[3] = 1.0;
  dheap_z[4] = 40.26;
  dheap_z[5] = -684.72;
  dheap_z[6] = -0.15;
  dheap_z[7] = 107.86;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #4
    whilelo p0.d, xzr, x2
    ptrue p1.d
    
    ld1d {z0.d}, p1/z, [x0, x1, lsl #3]

    fcmgt p2.d, p0/z, z0.d, #0.0
  )");
  CHECK_PREDICATE(2, uint64_t, {0x000000001000001u, 0, 0, 0});

  // float
  initialHeapData_.resize(68);
  float* fheap_z = reinterpret_cast<float*>(initialHeapData_.data());
  fheap_z[0] = 1.0;
  fheap_z[1] = -42.76;
  fheap_z[2] = -0.125;
  fheap_z[3] = 0.0;
  fheap_z[4] = 40.26;
  fheap_z[5] = -684.72;
  fheap_z[6] = -0.15;
  fheap_z[7] = 107.86;

  fheap_z[8] = -34.71f;
  fheap_z[9] = -0.917f;
  fheap_z[10] = 0.0f;
  fheap_z[11] = 80.72f;
  fheap_z[12] = -125.67f;
  fheap_z[13] = -0.01f;
  fheap_z[14] = 701.90f;
  fheap_z[15] = 7.0f;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #8
    whilelo p0.s, xzr, x2
    ptrue p1.s

    ld1w {z0.s}, p1/z, [x0, x1, lsl #2]

    fcmgt p2.s, p0/z, z0.s, #0.0
  )");
  CHECK_PREDICATE(2, uint64_t, {0x0000000010010001u, 0, 0, 0});
}

TEST_P(InstSve, fcmle) {
  // VL = 512-bits
  // float
  initialHeapData_.resize(68);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  fheap[0] = 1.0;
  fheap[1] = -42.76;
  fheap[2] = -0.125;
  fheap[3] = 0.0;
  fheap[4] = 40.26;
  fheap[5] = -684.72;
  fheap[6] = -0.15;
  fheap[7] = 107.86;

  fheap[8] = -34.71f;
  fheap[9] = -0.917f;
  fheap[10] = 0.0f;
  fheap[11] = 80.72f;
  fheap[12] = -125.67f;
  fheap[13] = -0.01f;
  fheap[14] = 701.90f;
  fheap[15] = 7.0f;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #8
    ptrue p0.s
    whilelo p1.s, xzr, x2

    ld1w {z0.s}, p0/z, [x0, x1, lsl #2]
    ld1w {z1.s}, p0/z, [x0, x1, lsl #2]

    fcmle p2.s, p0/z, z0.s, #0.0
    fcmle p3.s, p1/z, z1.s, #0.0
  )");
  CHECK_PREDICATE(2, uint64_t, {0x0011011101101110u, 0, 0, 0});
  CHECK_PREDICATE(3, uint64_t, {0x0000000001101110u, 0, 0, 0});

  // double
  initialHeapData_.resize(68);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  dheap[0] = 1.0;
  dheap[1] = -42.76;
  dheap[2] = -0.125;
  dheap[3] = 0.0;
  dheap[4] = 40.26;
  dheap[5] = -684.72;
  dheap[6] = -0.15;
  dheap[7] = 107.86;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #4
    ptrue p0.d
    whilelo p1.d, xzr, x2

    ld1d {z0.d}, p0/z, [x0, x1, lsl #3]
    ld1d {z1.d}, p0/z, [x0, x1, lsl #3]

    fcmle p2.d, p0/z, z0.d, #0.0
    fcmle p3.d, p1/z, z1.d, #0.0
  )");
  CHECK_PREDICATE(2, uint64_t, {0x0001010001010100u, 0, 0, 0});
  CHECK_PREDICATE(3, uint64_t, {0x0000000001010100u, 0, 0, 0});
}

TEST_P(InstSve, fcmlt) {
  // VL = 512-bits
  // float
  initialHeapData_.resize(68);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  fheap[0] = 1.0;
  fheap[1] = -42.76;
  fheap[2] = -0.125;
  fheap[3] = 0.0;
  fheap[4] = 40.26;
  fheap[5] = -684.72;
  fheap[6] = -0.15;
  fheap[7] = 107.86;

  fheap[8] = -34.71f;
  fheap[9] = -0.917f;
  fheap[10] = 0.0f;
  fheap[11] = 80.72f;
  fheap[12] = -125.67f;
  fheap[13] = -0.01f;
  fheap[14] = 701.90f;
  fheap[15] = 7.0f;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #8
    whilelo p0.s, xzr, x2

    ld1w {z0.s}, p0/z, [x0, x1, lsl #2]

    fcmlt p1.s, p0/z, z0.s, #0.0
  )");

  CHECK_PREDICATE(1, uint32_t, {0x01100110, 0, 0, 0, 0, 0, 0, 0});
}

TEST_P(InstSve, fcvtzs) {
  // VL = 512-bits
  // double
  initialHeapData_.resize(96);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  dheap[0] = 1.0;
  dheap[1] = -1.0;
  dheap[2] = 4.5;
  dheap[3] = -4.5;
  dheap[4] = 3.2;
  dheap[5] = -3.2;
  dheap[6] = 7.9;
  dheap[7] = -7.9;

  dheap[8] = 1000000000000000000000000000.66;
  dheap[9] = -114458013083425;
  dheap[10] = -10698505.18;
  dheap[11] = 0;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ptrue p0.d

    mov x1, #0
    mov x2, #4
    mov x3, #8
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

  CHECK_NEON(1, int64_t, {1, -1, 4, -4, 3, -3, 7, -7});
  CHECK_NEON(2, int64_t,
             {1, -1, 4, -4, 4294967297, 4294967297, 4294967297, 4294967297});
  CHECK_NEON(4, int64_t,
             {2147483647, -2147483648, -10698505, 0, 4294967297, 4294967297,
              4294967297, 4294967297});

  CHECK_NEON(5, int64_t, {1, -1, 4, -4, 3, -3, 7, -7});
  CHECK_NEON(6, int64_t, {1, -1, 4, -4, 1, 1, 1, 1});
  CHECK_NEON(7, int64_t,
             {INT64_MAX, -114458013083425, -10698505, 0, 1, 1, 1, 1});

  // Single
  initialHeapData_.resize(128);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  fheap[0] = 1.0f;
  fheap[1] = -42.76f;
  fheap[2] = -0.125f;
  fheap[3] = 0.0f;
  fheap[4] = 40.26f;
  fheap[5] = -684.72f;
  fheap[6] = -1.15f;
  fheap[7] = 107.86f;

  fheap[8] = -118548568215563221587412.3368451;
  fheap[9] = 118548568215563221587412.3368451;
  fheap[10] = 0.0f;
  fheap[11] = 80.72f;
  fheap[12] = -125.67f;
  fheap[13] = -0.01f;
  fheap[14] = 701.90f;
  fheap[15] = 7.0f;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ptrue p0.s

    mov x1, #0
    mov x2, #8
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
  CHECK_NEON(1, int64_t, {1, 0, 40, -1, INT64_MIN, 0, -125, 701});
  CHECK_NEON(2, int64_t, {1, 0, 40, -1, 1, 1, 1, 1});
  CHECK_NEON(4, int64_t, {INT64_MIN, 0, -125, 701, 1, 1, 1, 1});

  CHECK_NEON(5, int32_t,
             {1, -42, 0, 0, 40, -684, -1, 107, INT32_MIN, INT32_MAX, 0, 80,
              -125, 0, 701, 7});
  CHECK_NEON(6, int32_t,
             {1, -42, 0, 0, 40, -684, -1, 107, 10, 10, 10, 10, 10, 10, 10, 10});
  CHECK_NEON(7, int32_t,
             {INT32_MIN, INT32_MAX, 0, 80, -125, 0, 701, 7, 10, 10, 10, 10, 10,
              10, 10, 10});
}

TEST_P(InstSve, fcvt) {
  // VL = 512
  // double to single
  initialHeapData_.resize(96);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  dheap[0] = 2.0;
  dheap[1] = -2.0;
  dheap[2] = 4.5;
  dheap[3] = -4.5;
  dheap[4] = 3.2;
  dheap[5] = -3.2;
  dheap[6] = 7.9;
  dheap[7] = -7.9;
  dheap[8] = std::numeric_limits<double>::max();
  dheap[9] = std::numeric_limits<double>::lowest();
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    fdup z0.s, #1.0
    fdup z1.s, #1.0
    fdup z2.s, #1.0
    fdup z3.s, #1.0

    ptrue p0.d

    mov x1, #0
    mov x2, #4
    mov x3, #8
    whilelo p1.d, xzr, x3

    ld1d {z4.d}, p0/z, [x0, x1, lsl #3]
    ld1d {z5.d}, p1/z, [x0, x2, lsl #3]

    fcvt z0.s, p0/m, z4.d
    fcvt z1.s, p1/m, z4.d

    fcvt z2.s, p0/m, z5.d
    fcvt z3.s, p1/m, z5.d    
  )");
  CHECK_NEON(0, float,
             {2.0f, 1.0f, -2.0f, 1.0f, 4.5f, 1.0f, -4.5f, 1.0f, 3.2f, 1.0f,
              -3.2f, 1.0f, 7.9f, 1.0f, -7.9f, 1.0f});
  CHECK_NEON(1, float,
             {2.0f, 1.0f, -2.0f, 1.0f, 4.5f, 1.0f, -4.5f, 1.0f, 3.2f, 1.0f,
              -3.2f, 1.0f, 7.9f, 1.0f, -7.9f, 1.0f});
  CHECK_NEON(
      2, float,
      {3.2f, 1.0f, -3.2f, 1.0f, 7.9f, 1.0f, -7.9f, 1.0f,
       std::numeric_limits<float>::max(), 1.0f,
       std::numeric_limits<float>::lowest(), 1.0f, 0.0f, 1.0f, 0.0f, 1.0f});
  CHECK_NEON(
      3, float,
      {3.2f, 1.0f, -3.2f, 1.0f, 7.9f, 1.0f, -7.9f, 1.0f,
       std::numeric_limits<float>::max(), 1.0f,
       std::numeric_limits<float>::lowest(), 1.0f, 0.0f, 1.0f, 0.0f, 1.0f});

  // single to double
  initialHeapData_.resize(68);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  fheap[0] = 2.0f;
  fheap[1] = -42.76f;
  fheap[2] = -0.125f;
  fheap[3] = 0.0f;
  fheap[4] = 40.26f;
  fheap[5] = -684.72f;
  fheap[6] = std::numeric_limits<float>::lowest();
  fheap[7] = 107.86f;

  fheap[8] = std::numeric_limits<float>::max();
  fheap[9] = -0.15f;
  fheap[10] = 0.0f;
  fheap[11] = 80.72f;
  fheap[12] = -125.67f;
  fheap[13] = -0.01f;
  fheap[14] = 701.90f;
  fheap[15] = 7.0f;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    fdup z0.d, #1.0
    fdup z1.d, #1.0

    ptrue p0.s

    mov x1, #0
    mov x2, #4
    mov x3, #8
    whilelo p1.s, xzr, x3

    ld1w {z4.s}, p0/z, [x0, x1, lsl #2]
    ld1w {z5.s}, p1/z, [x0, x2, lsl #2]

    fcvt z0.d, p0/m, z4.s
    fcvt z1.d, p1/m, z4.s  
  )");
  CHECK_NEON(0, double,
             {2.0, -0.125, 40.26,
              static_cast<double>(std::numeric_limits<float>::lowest()),
              static_cast<double>(std::numeric_limits<float>::max()), 0.0,
              -125.67, 701.90});
  CHECK_NEON(1, double,
             {2.0, -0.125, 40.26,
              static_cast<double>(std::numeric_limits<float>::lowest()), 1.0,
              1.0, 1.0, 1.0});
}

TEST_P(InstSve, fdivr) {
  // VL = 512-bits
  // double
  initialHeapData_.resize(128);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  dheap[0] = 1.0;
  dheap[1] = -42.76;
  dheap[2] = -0.125;
  dheap[3] = 1.0;
  dheap[4] = 40.26;
  dheap[5] = -684.72;
  dheap[6] = -0.15;
  dheap[7] = 107.86;

  dheap[8] = -34.71;
  dheap[9] = -0.917;
  dheap[10] = 1.0;
  dheap[11] = 80.72;
  dheap[12] = -125.67;
  dheap[13] = -0.01;
  dheap[14] = 701.90;
  dheap[15] = 7.0;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #4
    whilelo p0.d, xzr, x2
    ptrue p1.d

    mov x3, #8
    ld1d {z0.d}, p1/z, [x0, x3, lsl #3]
    ld1d {z1.d}, p1/z, [x0, x1, lsl #3]
    ld1d {z2.d}, p1/z, [x0, x1, lsl #3]

    fdivr z1.d, p1/m, z1.d, z0.d
    fdivr z2.d, p0/m, z2.d, z0.d
  )");

  CHECK_NEON(1, double,
             {-34.71, 0.02144527595884003837, -8.0, 80.72,
              -3.1214605067064087329, 0.0000146045098726486738,
              -4679.333333333333030168, 0.06489894307435564724});
  CHECK_NEON(2, double,
             {-34.71, 0.02144527595884003837, -8.0, 80.72, 40.26, -684.72,
              -0.15, 107.86});

  // float
  initialHeapData_.resize(128);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  fheap[0] = 1.0f;
  fheap[1] = -42.76f;
  fheap[2] = -0.125f;
  fheap[3] = 1.0f;
  fheap[4] = 40.26f;
  fheap[5] = -684.72f;
  fheap[6] = -0.15f;
  fheap[7] = 107.86f;

  fheap[8] = -34.71f;
  fheap[9] = -0.917f;
  fheap[10] = 1.0f;
  fheap[11] = 80.72f;
  fheap[12] = -125.67f;
  fheap[13] = -0.01f;
  fheap[14] = 701.90f;
  fheap[15] = 7.0f;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #8
    whilelo p0.s, xzr, x2
    ptrue p1.s

    ld1w {z0.s}, p1/z, [x0, x2, lsl #2]
    ld1w {z1.s}, p1/z, [x0, x1, lsl #2]

    fdivr z1.s, p0/m, z1.s, z0.s
  )");

  CHECK_NEON(1, float,
             {-34.71f, 0.02144527595884003837f, -8.0f, 80.72f,
              -3.1214605067064087329f, 0.0000146045098726486738f,
              -4679.333333333333030168f, 0.06489894307435564724f, -34.71f,
              -0.917f, 1.0f, 80.72f, -125.67f, -0.01f, 701.90f, 7.0f});
}

TEST_P(InstSve, fdiv) {
  // VL = 512-bits
  // double
  initialHeapData_.resize(128);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  dheap[0] = 1.0;
  dheap[1] = -42.76;
  dheap[2] = -0.125;
  dheap[3] = 1.0;
  dheap[4] = 40.26;
  dheap[5] = -684.72;
  dheap[6] = -0.15;
  dheap[7] = 107.86;

  dheap[8] = -34.71;
  dheap[9] = -0.917;
  dheap[10] = 1.0;
  dheap[11] = 80.72;
  dheap[12] = -125.67;
  dheap[13] = -0.01;
  dheap[14] = 701.90;
  dheap[15] = 7.0;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #4
    whilelo p0.d, xzr, x2
    ptrue p1.d

    mov x3, #8
    ld1d {z0.d}, p1/z, [x0, x1, lsl #3]
    ld1d {z1.d}, p1/z, [x0, x3, lsl #3]
    ld1d {z2.d}, p1/z, [x0, x3, lsl #3]

    fdiv z1.d, p1/m, z1.d, z0.d
    fdiv z2.d, p0/m, z2.d, z0.d
  )");

  CHECK_NEON(1, double,
             {-34.71, 0.02144527595884003837, -8, 80.72, -3.1214605067064087329,
              0.0000146045098726486738, -4679.333333333333030168,
              0.06489894307435564724});
  CHECK_NEON(
      2, double,
      {-34.71, 0.02144527595884003837, -8, 80.72, -125.67, -0.01, 701.90, 7.0});
}

TEST_P(InstSve, fnmls) {
  // VL = 512-bits
  // float
  initialHeapData_.resize(68);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  fheap[0] = 1.0f;
  fheap[1] = -42.76f;
  fheap[2] = -0.125f;
  fheap[3] = 0.0f;
  fheap[4] = 40.26f;
  fheap[5] = -684.72f;
  fheap[6] = -0.15f;
  fheap[7] = 107.86f;

  fheap[8] = -34.71f;
  fheap[9] = -0.917f;
  fheap[10] = 0.0f;
  fheap[11] = 80.72f;
  fheap[12] = -125.67f;
  fheap[13] = -0.01f;
  fheap[14] = 701.90f;
  fheap[15] = 7.0f;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #8
    whilelo p0.s, xzr, x2
    ptrue p1.s

    ld1w {z0.s}, p0/z, [x0, x1, lsl #2]
    ld1w {z1.s}, p0/z, [x0, x2, lsl #2]
    ld1w {z2.s}, p1/z, [x0, x1, lsl #2]

    fnmls z2.s, p0/m, z1.s, z0.s
  )");
  CHECK_NEON(2, float,
             {-35.71f, 81.97092f, 0.125f, 0.0f, -5099.7342f, 691.5672f,
              -105.135f, 647.16f, -34.71f, -0.917f, 0.0f, 80.72f, -125.67f,
              -0.01f, 701.90f, 7.0f});

  // double
  initialHeapData_.resize(136);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  dheap[0] = 1.0;
  dheap[1] = -42.76;
  dheap[2] = -0.125;
  dheap[3] = 0.0;
  dheap[4] = 40.26;
  dheap[5] = -684.72;
  dheap[6] = -0.15;
  dheap[7] = 107.86;

  dheap[8] = -34.71;
  dheap[9] = -0.917;
  dheap[10] = 0.0;
  dheap[11] = 80.72;
  dheap[12] = -125.67;
  dheap[13] = -0.01;
  dheap[14] = 701.90;
  dheap[15] = 7.0;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #8
    whilelo p0.d, xzr, x2
    ptrue p1.d

    ld1d {z0.d}, p0/z, [x0, x1, lsl #3]
    ld1d {z1.d}, p0/z, [x0, x2, lsl #3]
    ld1d {z2.d}, p1/z, [x0, x1, lsl #3]

    fnmls z2.d, p0/m, z1.d, z0.d
  )");
  CHECK_NEON(
      2, double,
      {-35.71, 81.97092, 0.125, 0.0, -5099.7342, 691.5672, -105.135, 647.16});
}

TEST_P(InstSve, fnmsb) {
  // VL = 512-bits
  // float
  initialHeapData_.resize(68);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  fheap[0] = 1.0f;
  fheap[1] = -42.76f;
  fheap[2] = -0.125f;
  fheap[3] = 0.0f;
  fheap[4] = 40.26f;
  fheap[5] = -684.72f;
  fheap[6] = -0.15f;
  fheap[7] = 107.86f;

  fheap[8] = -34.71f;
  fheap[9] = -0.917f;
  fheap[10] = 0.0f;
  fheap[11] = 80.72f;
  fheap[12] = -125.67f;
  fheap[13] = -0.01f;
  fheap[14] = 701.90f;
  fheap[15] = 7.0f;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #8
    whilelo p0.s, xzr, x2
    ptrue p1.s

    ld1w {z0.s}, p0/z, [x0, x1, lsl #2]
    ld1w {z1.s}, p0/z, [x0, x2, lsl #2]
    ld1w {z2.s}, p1/z, [x0, x1, lsl #2]

    fnmsb z2.s, p0/m, z1.s, z0.s
  )");
  CHECK_NEON(2, float,
             {-35.71f, 81.97092f, 0.125f, 0.0f, -5099.7342f, 691.5672f,
              -105.135f, 647.16f, -34.71f, -0.917f, 0.0f, 80.72f, -125.67f,
              -0.01f, 701.90f, 7.0f});

  // double
  initialHeapData_.resize(136);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  dheap[0] = 1.0;
  dheap[1] = -42.76;
  dheap[2] = -0.125;
  dheap[3] = 0.0;
  dheap[4] = 40.26;
  dheap[5] = -684.72;
  dheap[6] = -0.15;
  dheap[7] = 107.86;

  dheap[8] = -34.71;
  dheap[9] = -0.917;
  dheap[10] = 0.0;
  dheap[11] = 80.72;
  dheap[12] = -125.67;
  dheap[13] = -0.01;
  dheap[14] = 701.90;
  dheap[15] = 7.0;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #8
    whilelo p0.d, xzr, x2
    ptrue p1.d

    ld1d {z0.d}, p0/z, [x0, x1, lsl #3]
    ld1d {z1.d}, p0/z, [x0, x2, lsl #3]
    ld1d {z2.d}, p1/z, [x0, x1, lsl #3]

    fnmsb z2.d, p0/m, z1.d, z0.d
  )");
  CHECK_NEON(
      2, double,
      {-35.71, 81.97092, 0.125, 0.0, -5099.7342, 691.5672, -105.135, 647.16});
}

TEST_P(InstSve, fmad) {
  // VL = 512-bits
  // float
  initialHeapData_.resize(68);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  fheap[0] = 1.0;
  fheap[1] = -42.76;
  fheap[2] = -0.125;
  fheap[3] = 0.0;
  fheap[4] = 40.26;
  fheap[5] = -684.72;
  fheap[6] = -0.15;
  fheap[7] = 107.86;

  fheap[8] = -34.71f;
  fheap[9] = -0.917f;
  fheap[10] = 0.0f;
  fheap[11] = 80.72f;
  fheap[12] = -125.67f;
  fheap[13] = -0.01f;
  fheap[14] = 701.90f;
  fheap[15] = 7.0f;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #8
    whilelo p0.s, xzr, x2
    ptrue p1.s

    ld1w {z0.s}, p0/z, [x0, x1, lsl #2]
    ld1w {z1.s}, p0/z, [x0, x2, lsl #2]
    ld1w {z2.s}, p1/z, [x0, x1, lsl #2]

    fmad z2.s, p0/m, z1.s, z0.s
  )");

  CHECK_NEON(2, float,
             {-33.71f, -3.54907989502f, -0.125f, 0.0f, -5019.2142f,
              -677.872741699f, -105.4350113f, 862.88f, -34.71f, -0.917f, 0.0f,
              80.72f, -125.67f, -0.01f, 701.90f, 7.0f});

  // double
  initialHeapData_.resize(136);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  dheap[0] = 1.0;
  dheap[1] = -42.76;
  dheap[2] = -0.125;
  dheap[3] = 0.0;
  dheap[4] = 40.26;
  dheap[5] = -684.72;
  dheap[6] = -0.15;
  dheap[7] = 107.86;

  dheap[8] = -34.71;
  dheap[9] = -0.917;
  dheap[10] = 0.0;
  dheap[11] = 80.72;
  dheap[12] = -125.67;
  dheap[13] = -0.01;
  dheap[14] = 701.90;
  dheap[15] = 7.0;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #8
    whilelo p0.d, xzr, x2
    ptrue p1.d

    ld1d {z0.d}, p0/z, [x0, x1, lsl #3]
    ld1d {z1.d}, p0/z, [x0, x2, lsl #3]
    ld1d {z2.d}, p1/z, [x0, x1, lsl #3]

    fmad z2.d, p0/m, z1.d, z0.d
  )");

  CHECK_NEON(2, double,
             {-33.71, -3.54907989502, -0.125, 0.0, -5019.2142, -677.872741699,
              -105.4350113, 862.88});
}

TEST_P(InstSve, fmla) {
  // VL = 512-bits
  // double
  initialHeapData_.resize(64);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  dheap[0] = 1.0;
  dheap[1] = -42.76;
  dheap[2] = -0.125;
  dheap[3] = 0.0;

  dheap[4] = -34.71;
  dheap[5] = -0.917;
  dheap[6] = 0.0;
  dheap[7] = 80.72;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #4
    whilelo p0.d, xzr, x2
    ptrue p1.d

    ld1d {z0.d}, p0/z, [x0, x1, lsl #3]
    ld1d {z1.d}, p0/z, [x0, x2, lsl #3]
    ld1d {z2.d}, p1/z, [x0, x1, lsl #3]

    fmla z2.d, p0/m, z1.d, z0.d
  )");

  CHECK_NEON(
      2, double,
      {-33.71, -3.5490799999999964, -0.125, 0.0, -34.71, -0.917, 0.0, 80.72});

  // float
  initialHeapData_.resize(68);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  fheap[0] = 1.0;
  fheap[1] = -42.76;
  fheap[2] = -0.125;
  fheap[3] = 0.0;
  fheap[4] = 40.26;
  fheap[5] = -684.72;
  fheap[6] = -0.15;
  fheap[7] = 107.86;

  fheap[8] = -34.71f;
  fheap[9] = -0.917f;
  fheap[10] = 0.0f;
  fheap[11] = 80.72f;
  fheap[12] = -125.67f;
  fheap[13] = -0.01f;
  fheap[14] = 701.90f;
  fheap[15] = 7.0f;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #8
    whilelo p0.s, xzr, x2
    ptrue p1.s

    ld1w {z0.s}, p0/z, [x0, x1, lsl #2]
    ld1w {z1.s}, p0/z, [x0, x2, lsl #2]
    ld1w {z2.s}, p1/z, [x0, x1, lsl #2]

    fmla z2.s, p0/m, z1.s, z0.s
  )");

  CHECK_NEON(2, float,
             {-33.71f, -3.54907989502f, -0.125f, 0.0f, -5019.2142f,
              -677.872741699f, -105.4350113f, 862.88f, -34.71f, -0.917f, 0.0f,
              80.72f, -125.67f, -0.01f, 701.90f, 7.0f});
}

TEST_P(InstSve, fmls) {
  // VL = 512-bits
  // float
  initialHeapData_.resize(68);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  fheap[0] = 1.0f;
  fheap[1] = -42.76f;
  fheap[2] = -0.125f;
  fheap[3] = 0.0f;
  fheap[4] = 40.26f;
  fheap[5] = -684.72f;
  fheap[6] = -0.15f;
  fheap[7] = 107.86f;

  fheap[8] = -34.71f;
  fheap[9] = -0.917f;
  fheap[10] = 0.0f;
  fheap[11] = 80.72f;
  fheap[12] = -125.67f;
  fheap[13] = -0.01f;
  fheap[14] = 701.90f;
  fheap[15] = 7.0f;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #8
    whilelo p0.s, xzr, x2
    ptrue p1.s

    ld1w {z0.s}, p0/z, [x0, x1, lsl #2]
    ld1w {z1.s}, p0/z, [x0, x2, lsl #2]
    ld1w {z2.s}, p1/z, [x0, x1, lsl #2]

    fmls z2.s, p0/m, z1.s, z0.s
  )");

  CHECK_NEON(2, float,
             {35.71f, -81.97092f, -0.125f, 0.0f, 5099.7342f,
              -691.5672000000001f, 105.13499999999999f, -647.16f, -34.71f,
              -0.917f, 0.0f, 80.72f, -125.67f, -0.01f, 701.90f, 7.0f});

  // double
  initialHeapData_.resize(136);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  dheap[0] = 1.0;
  dheap[1] = -42.76;
  dheap[2] = -0.125;
  dheap[3] = 0.0;
  dheap[4] = 40.26;
  dheap[5] = -684.72;
  dheap[6] = -0.15;
  dheap[7] = 107.86;

  dheap[8] = -34.71;
  dheap[9] = -0.917;
  dheap[10] = 0.0;
  dheap[11] = 80.72;
  dheap[12] = -125.67;
  dheap[13] = -0.01;
  dheap[14] = 701.90;
  dheap[15] = 7.0;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #8
    whilelo p0.d, xzr, x2
    ptrue p1.d

    ld1d {z0.d}, p0/z, [x0, x1, lsl #3]
    ld1d {z1.d}, p0/z, [x0, x2, lsl #3]
    ld1d {z2.d}, p1/z, [x0, x1, lsl #3]

    fmls z2.d, p0/m, z1.d, z0.d
  )");

  CHECK_NEON(2, double,
             {35.71f, -81.97092f, -0.125f, 0.0f, 5099.7342f,
              -691.5672000000001f, 105.13499999999999f, -647.16f});
}

TEST_P(InstSve, fmsb) {
  // VL = 512-bits
  // float
  initialHeapData_.resize(68);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  fheap[0] = 1.0;
  fheap[1] = -42.76;
  fheap[2] = -0.125;
  fheap[3] = 0.0;
  fheap[4] = 40.26;
  fheap[5] = -684.72;
  fheap[6] = -0.15;
  fheap[7] = 107.86;

  fheap[8] = -34.71f;
  fheap[9] = -0.917f;
  fheap[10] = 0.0f;
  fheap[11] = 80.72f;
  fheap[12] = -125.67f;
  fheap[13] = -0.01f;
  fheap[14] = 701.90f;
  fheap[15] = 7.0f;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #8
    whilelo p0.s, xzr, x2
    ptrue p1.s

    ld1w {z0.s}, p0/z, [x0, x1, lsl #2]
    ld1w {z1.s}, p0/z, [x0, x2, lsl #2]
    ld1w {z2.s}, p1/z, [x0, x1, lsl #2]

    fmsb z2.s, p0/m, z1.s, z0.s
  )");

  CHECK_NEON(2, float,
             {35.71f, -81.970916748f, -0.125f, 0.0f, 5099.73388672f,
              -691.567199707f, 105.135009766f, -647.16003418f, -34.71f, -0.917f,
              0.0f, 80.72f, -125.67f, -0.01f, 701.90f, 7.0f});

  // Double
  initialHeapData_.resize(136);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  dheap[0] = 1.0;
  dheap[1] = -42.76;
  dheap[2] = -0.125;
  dheap[3] = 0.0;
  dheap[4] = 40.26;
  dheap[5] = -684.72;
  dheap[6] = -0.15;
  dheap[7] = 107.86;

  dheap[8] = -34.71;
  dheap[9] = -0.917;
  dheap[10] = 0.0;
  dheap[11] = 80.72;
  dheap[12] = -125.67;
  dheap[13] = -0.01;
  dheap[14] = 701.90;
  dheap[15] = 7.0;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #8
    mov x3, #4
    whilelo p0.d, xzr, x3
    ptrue p1.d

    ld1d {z0.d}, p1/z, [x0, x1, lsl #3]
    ld1d {z1.d}, p1/z, [x0, x2, lsl #3]
    ld1d {z2.d}, p1/z, [x0, x1, lsl #3]
    ld1d {z3.d}, p1/z, [x0, x1, lsl #3]

    fmsb z2.d, p0/m, z1.d, z0.d
    fmsb z3.d, p1/m, z1.d, z0.d
  )");

  CHECK_NEON(
      2, double,
      {35.71, -81.970916748, -0.125, 0.0, 40.26, -684.72, -0.15, 107.86});
  CHECK_NEON(3, double,
             {35.71, -81.970916748, -0.125, 0.0, 5099.73388672, -691.567199707,
              105.135009766, -647.16003418});
}

TEST_P(InstSve, fmul) {
  // VL = 512-bits
  // float
  initialHeapData_.resize(68);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  fheap[0] = 1.0f;
  fheap[1] = -42.76f;
  fheap[2] = -0.125f;
  fheap[3] = 0.0f;
  fheap[4] = 40.26f;
  fheap[5] = -684.72f;
  fheap[6] = -0.15f;
  fheap[7] = 107.86f;

  fheap[8] = -34.71f;
  fheap[9] = -0.917f;
  fheap[10] = 0.0f;
  fheap[11] = 80.72f;
  fheap[12] = -125.67f;
  fheap[13] = -0.01f;
  fheap[14] = 701.90f;
  fheap[15] = 7.0f;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #8
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

  CHECK_NEON(2, float,
             {-34.71f, 39.2109184265f, 0.0f, 0.0f, -5059.4742f, 6.84719944f,
              -105.285011292f, 755.02f, 0, 0, 0, 0, 0, 0, 0, 0});
  CHECK_NEON(0, float,
             {0.5f, -21.38f, -0.0625f, 0, 20.13f, -342.36f, -0.075f, 53.93f, 0,
              0, 0, 0, 0, 0, 0, 0});
  CHECK_NEON(3, float,
             {-34.71f, 39.21092f, -0.0f, 0.0f, -5059.4742f, 6.847200000000001f,
              -105.285f, 755.02f, -34.71f, -0.917f, 0.0f, 80.72f, -125.67f,
              -0.01f, 701.9f, 7.0f});

  // double
  initialHeapData_.resize(64);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  dheap[0] = 1.0;
  dheap[1] = -42.76;
  dheap[2] = -0.125;
  dheap[3] = 0.0;

  dheap[4] = -34.71;
  dheap[5] = -0.917;
  dheap[6] = 0.0;
  dheap[7] = 80.72;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #4
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

  CHECK_NEON(2, double, {-34.71, 39.21092, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0});
  CHECK_NEON(0, double, {0.5, -21.38, -0.0625, 0.0, 0.0, 0.0, 0.0, 0.0});
  CHECK_NEON(3, double,
             {-34.71, 39.21092, 0.0, 0.0, -34.71, -0.917, 0.0, 80.72});
}

TEST_P(InstSve, fneg) {
  // VL = 512-bits
  // double
  initialHeapData_.resize(64);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  dheap[0] = 1.0;
  dheap[1] = -42.76;
  dheap[2] = -0.125;
  dheap[3] = 0.0;

  dheap[4] = -34.71;
  dheap[5] = -0.917;
  dheap[6] = 0.0;
  dheap[7] = 80.72;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #4
    whilelo p0.d, xzr, x2
    ptrue p1.d
    
    ld1d {z0.d}, p1/z, [x0, x1, lsl #3]
    ld1d {z1.d}, p0/z, [x0, x2, lsl #3]

    fneg z2.d, p1/m, z0.d
    fneg z3.d, p0/m, z1.d
  )");

  CHECK_NEON(2, double, {-1.0, 42.76, 0.125, -0.0, 34.71, 0.917, -0.0, -80.72});
  CHECK_NEON(3, double, {34.71, 0.917, 0.0, -80.72, 0, 0, 0, 0});

  // float
  initialHeapData_.resize(64);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  fheap[0] = 1.0;
  fheap[1] = -42.76;
  fheap[2] = -0.125;
  fheap[3] = 0.0;
  fheap[4] = 40.26;
  fheap[5] = -684.72;
  fheap[6] = -0.15;
  fheap[7] = 107.86;

  fheap[8] = -34.71f;
  fheap[9] = -0.917f;
  fheap[10] = 0.0f;
  fheap[11] = 80.72f;
  fheap[12] = -125.67f;
  fheap[13] = -0.01f;
  fheap[14] = 701.90f;
  fheap[15] = 7.0f;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #8
    whilelo p0.s, xzr, x2
    ptrue p1.s
    
    ld1w {z0.s}, p1/z, [x0, x1, lsl #2]
    ld1w {z1.s}, p0/z, [x0, x2, lsl #2]

    fneg z2.s, p1/m, z0.s
    fneg z3.s, p0/m, z1.s
  )");

  CHECK_NEON(2, float,
             {-1.0f, 42.76f, 0.125f, -0.0f, -40.26f, 684.72f, 0.15f, -107.86f,
              34.71f, 0.917f, -0.0f, -80.72f, 125.67f, 0.01f, -701.90f, -7.0f});
  CHECK_NEON(3, float,
             {34.71f, 0.917f, -0.0f, -80.72f, 125.67f, 0.01f, -701.90f, -7.0f,
              0, 0, 0, 0, 0, 0, 0, 0});
}

TEST_P(InstSve, frintn) {
  // VL = 512-bits
  // 32-bit
  initialHeapData_.resize(64);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  fheap[0] = 1.0f;
  fheap[1] = -42.5f;
  fheap[2] = -0.125f;
  fheap[3] = 0.0f;
  fheap[4] = 40.5f;
  fheap[5] = -684.72f;
  fheap[6] = -0.15f;
  fheap[7] = 107.86f;

  fheap[8] = -34.5f;
  fheap[9] = -0.917f;
  fheap[10] = 0.0f;
  fheap[11] = 80.72f;
  fheap[12] = -125.5f;
  fheap[13] = -0.01f;
  fheap[14] = 701.90f;
  fheap[15] = 7.5f;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #8
    ptrue p0.s
    whilelo p1.s, xzr, x2

    dup z0.s, #15
    dup z1.s, #13
    ld1w {z2.s}, p0/z, [x0, x1, lsl #2]

    frintn z0.s, p0/m, z2.s
    frintn z1.s, p1/m, z2.s
  )");
  CHECK_NEON(0, int32_t,
             {1, -42, 0, 0, 40, -685, 0, 108, -34, -1, 0, 81, -126, 0, 702, 8});
  CHECK_NEON(1, int32_t,
             {1, -42, 0, 0, 40, -685, 0, 108, 13, 13, 13, 13, 13, 13, 13, 13});

  // 64-bit
  initialHeapData_.resize(64);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  dheap[0] = 1.0f;
  dheap[1] = -42.5f;
  dheap[2] = -0.125f;
  dheap[3] = 0.0f;
  dheap[4] = 40.5f;
  dheap[5] = -684.72f;
  dheap[6] = -3.5f;
  dheap[7] = 107.5f;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #4
    ptrue p0.d
    whilelo p1.d, xzr, x2

    dup z0.d, #15
    dup z1.d, #13
    ld1d {z2.d}, p0/z, [x0, x1, lsl #3]

    frintn z0.d, p0/m, z2.d
    frintn z1.d, p1/m, z2.d
  )");
  CHECK_NEON(0, int64_t, {1, -42, 0, 0, 40, -685, -4, 108});
  CHECK_NEON(1, int64_t, {1, -42, 0, 0, 13, 13, 13, 13});
}

TEST_P(InstSve, fsqrt) {
  // VL = 512-bits
  // Float
  initialHeapData_.resize(68);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  fheap[0] = 1.0;
  fheap[1] = 42.76;
  fheap[2] = 0.125;
  fheap[3] = 0.0;
  fheap[4] = 40.26;
  fheap[5] = 684.72;
  fheap[6] = 0.15;
  fheap[7] = 107.86;

  fheap[8] = 34.71f;
  fheap[9] = 0.917f;
  fheap[10] = 0.0f;
  fheap[11] = 80.72f;
  fheap[12] = 125.67f;
  fheap[13] = 0.01f;
  fheap[14] = 701.90f;
  fheap[15] = 7.0f;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #8
    whilelo p0.s, xzr, x2
    ptrue p1.s

    ld1w {z0.s}, p1/z, [x0, x1, lsl #2]
    ld1w {z1.s}, p0/z, [x0, x2, lsl #2]

    fdup z2.s, #0.5
    fdup z3.s, #0.5

    fsqrt z2.s, p1/m, z0.s
    fsqrt z3.s, p0/m, z1.s
  )");

  CHECK_NEON(2, float,
             {1, 6.53911304473876953125f, 0.3535533845424652099609375f, 0,
              6.34507656097412109375f, 26.1671543121337890625f,
              0.3872983455657958984375f, 10.38556671142578125f,
              5.891519069671630859375f, 0.95760118961334228515625f, 0,
              8.98443126678466796875f, 11.21026325225830078125f, 0.1f,
              26.493396759033203125f, 2.6457512378692626953125f});
  CHECK_NEON(3, float,
             {5.891519069671630859375f, 0.95760118961334228515625f, 0,
              8.98443126678466796875f, 11.21026325225830078125f, 0.1f,
              26.493396759033203125f, 2.6457512378692626953125f, 0.5f, 0.5f,
              0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f});

  // Double
  initialHeapData_.resize(68);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  dheap[0] = 1.0;
  dheap[1] = 42.76;
  dheap[2] = 0.125;
  dheap[3] = 0.0;
  dheap[4] = 40.26;
  dheap[5] = 684.72;
  dheap[6] = 0.15;
  dheap[7] = 107.86;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #4
    whilelo p0.d, xzr, x2
    ptrue p1.d

    ld1d {z0.d}, p1/z, [x0, x1, lsl #3]

    fdup z2.d, #0.5
    fdup z3.d, #0.5

    fsqrt z2.d, p1/m, z0.d
    fsqrt z3.d, p0/m, z0.d
  )");

  CHECK_NEON(2, double,
             {1, 6.53911304473876953125f, 0.3535533845424652099609375f, 0,
              6.34507656097412109375f, 26.1671543121337890625f,
              0.3872983455657958984375f, 10.38556671142578125f});
  CHECK_NEON(3, double,
             {1, 6.53911304473876953125f, 0.3535533845424652099609375f, 0, 0.5,
              0.5, 0.5, 0.5});
}

TEST_P(InstSve, fsub) {
  // VL = 512-bits
  // float
  initialHeapData_.resize(128);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  fheap[0] = 1.0;
  fheap[1] = -42.76;
  fheap[2] = -0.125;
  fheap[3] = 0.0;
  fheap[4] = 40.26;
  fheap[5] = -684.72;
  fheap[6] = -0.15;
  fheap[7] = 107.86;

  fheap[8] = -34.71f;
  fheap[9] = -0.917f;
  fheap[10] = 0.0f;
  fheap[11] = 80.72f;
  fheap[12] = -125.67f;
  fheap[13] = -0.01f;
  fheap[14] = 701.90f;
  fheap[15] = 7.0f;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #8
    whilelo p0.s, xzr, x2

    ld1w {z0.s}, p0/z, [x0, x1, lsl #2]
    ld1w {z1.s}, p0/z, [x0, x2, lsl #2]

    fsub z2.s, z1.s, z0.s

    # PREDICATED VECTOR
    ptrue p1.s
    ld1w {z4.s}, p1/z, [x0, x1, lsl #2]
    
    fsub z4.s, p0/m, z4.s, z1.s
  )");
  CHECK_NEON(2, float,
             {-35.71f, 41.843f, 0.125f, 80.72f, -165.93f, 684.709960938f,
              702.050048828f, -100.86f, 0, 0, 0, 0, 0, 0, 0, 0});
  CHECK_NEON(4, float,
             {35.71f, -41.843f, -0.125f, -80.72f, 165.93f, -684.71f,
              -702.050048828f, 100.86f, -34.71f, -0.917f, 0.0f, 80.72f,
              -125.67f, -0.01f, 701.90f, 7.0f});

  // double
  initialHeapData_.resize(64);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  dheap[0] = 1.0;
  dheap[1] = -42.76;
  dheap[2] = -0.125;
  dheap[3] = 0.0;

  dheap[4] = -34.71;
  dheap[5] = -0.917;
  dheap[6] = 0.0;
  dheap[7] = 80.72;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #4
    whilelo p0.d, xzr, x2

    ld1d {z0.d}, p0/z, [x0, x1, lsl #3]
    ld1d {z1.d}, p0/z, [x0, x2, lsl #3]

    fsub z2.d, z1.d, z0.d

    # PREDICATED VECTOR
    ptrue p1.d
    ld1d {z3.d}, p1/z, [x0, x1, lsl #3]
    
    fsub z3.d, p0/m, z3.d, z1.d
  )");

  CHECK_NEON(2, double, {-35.71, 41.842999999999996, 0.125, 80.72, 0, 0, 0, 0});
  CHECK_NEON(
      3, double,
      {35.71, -41.842999999999996, -0.125, -80.72, -34.71, -0.917, 0.0, 80.72});
}

TEST_P(InstSve, incp) {
  // VL = 512-bits
  // Scalar
  RUN_AARCH64(R"(
    # 8-bit
    mov x0, #48
    mov x1, #66
    mov x2, #402
    ptrue p0.b
    whilelo p1.b, xzr, x0
    incp x1, p0.b
    incp x2, p1.b

    # 16-bit
    mov x3, #24
    mov x4, #70
    mov x5, #109
    ptrue p0.h
    whilelo p1.h, xzr, x3
    incp x4, p0.h
    incp x5, p1.h

    # 32-bit
    mov x6, #12
    mov x7, #41
    mov x8, #527
    ptrue p0.s
    whilelo p1.s, xzr, x6
    incp x7, p0.s
    incp x8, p1.s

    # 64-bit
    mov x9, #6
    mov x10, #50
    mov x11, #375
    ptrue p0.d
    whilelo p1.d, xzr, x9
    incp x10, p0.d
    incp x11, p1.d
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(1), 66 + 64);
  EXPECT_EQ(getGeneralRegister<uint64_t>(2), 402 + 48);
  EXPECT_EQ(getGeneralRegister<uint64_t>(4), 70 + 32);
  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 109 + 24);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 41 + 16);
  EXPECT_EQ(getGeneralRegister<uint64_t>(8), 527 + 12);
  EXPECT_EQ(getGeneralRegister<uint64_t>(10), 50 + 8);
  EXPECT_EQ(getGeneralRegister<uint64_t>(11), 375 + 6);
}

TEST_P(InstSve, index) {
  // VL = 512-bits
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
  CHECK_NEON(0, uint8_t,
             {0xf0, 0xe0, 0xd0, 0xc0, 0xb0, 0xa0, 0x90, 0x80, 0x70, 0x60, 0x50,
              0x40, 0x30, 0x20, 0x10, 0x0,  0xf0, 0xe0, 0xd0, 0xc0, 0xb0, 0xa0,
              0x90, 0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10, 0x0,  0xf0,
              0xe0, 0xd0, 0xc0, 0xb0, 0xa0, 0x90, 0x80, 0x70, 0x60, 0x50, 0x40,
              0x30, 0x20, 0x10, 0x0,  0xf0, 0xe0, 0xd0, 0xc0, 0xb0, 0xa0, 0x90,
              0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10, 0x0});
  CHECK_NEON(1, uint8_t,
             {0xf,  0x16, 0x1d, 0x24, 0x2b, 0x32, 0x39, 0x40, 0x47, 0x4e, 0x55,
              0x5c, 0x63, 0x6a, 0x71, 0x78, 0x7f, 0x86, 0x8d, 0x94, 0x9b, 0xa2,
              0xa9, 0xb0, 0xb7, 0xbe, 0xc5, 0xcc, 0xd3, 0xda, 0xe1, 0xe8, 0xef,
              0xf6, 0xfd, 0x4,  0xb,  0x12, 0x19, 0x20, 0x27, 0x2e, 0x35, 0x3c,
              0x43, 0x4a, 0x51, 0x58, 0x5f, 0x66, 0x6d, 0x74, 0x7b, 0x82, 0x89,
              0x90, 0x97, 0x9e, 0xa5, 0xac, 0xb3, 0xba, 0xc1, 0xc8});
  CHECK_NEON(2, uint16_t,
             {0xfff8, 0xfff5, 0xfff2, 0xffef, 0xffec, 0xffe9, 0xffe6, 0xffe3,
              0xffe0, 0xffdd, 0xffda, 0xffd7, 0xffd4, 0xffd1, 0xffce, 0xffcb,
              0xffc8, 0xffc5, 0xffc2, 0xffbf, 0xffbc, 0xffb9, 0xffb6, 0xffb3,
              0xffb0, 0xffad, 0xffaa, 0xffa7, 0xffa4, 0xffa1, 0xff9e, 0xff9b});
  CHECK_NEON(3, uint16_t,
             {0x3,   0x11,  0x1f,  0x2d,  0x3b,  0x49,  0x57,  0x65,
              0x73,  0x81,  0x8f,  0x9d,  0xab,  0xb9,  0xc7,  0xd5,
              0xe3,  0xf1,  0xff,  0x10d, 0x11b, 0x129, 0x137, 0x145,
              0x153, 0x161, 0x16f, 0x17d, 0x18b, 0x199, 0x1a7, 0x1b5});
  CHECK_NEON(
      4, uint32_t,
      {0xfffffffa, 0xfffffffa, 0xfffffffa, 0xfffffffa, 0xfffffffa, 0xfffffffa,
       0xfffffffa, 0xfffffffa, 0xfffffffa, 0xfffffffa, 0xfffffffa, 0xfffffffa,
       0xfffffffa, 0xfffffffa, 0xfffffffa, 0xfffffffa});
  CHECK_NEON(5, uint32_t,
             {0xc, 0x1a, 0x28, 0x36, 0x44, 0x52, 0x60, 0x6e, 0x7c, 0x8a, 0x98,
              0xa6, 0xb4, 0xc2, 0xd0, 0xde});
  CHECK_NEON(6, uint64_t,
             {0xfffffffffffffffb, 0xfffffffffffffff2, 0xffffffffffffffe9,
              0xffffffffffffffe0, 0xffffffffffffffd7, 0xffffffffffffffce,
              0xffffffffffffffc5, 0xffffffffffffffbc});
  CHECK_NEON(7, uint64_t, {0xa, 0x14, 0x1e, 0x28, 0x32, 0x3c, 0x46, 0x50});

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
  CHECK_NEON(0, uint8_t,
             {0xf0, 0xe0, 0xd0, 0xc0, 0xb0, 0xa0, 0x90, 0x80, 0x70, 0x60, 0x50,
              0x40, 0x30, 0x20, 0x10, 0x0,  0xf0, 0xe0, 0xd0, 0xc0, 0xb0, 0xa0,
              0x90, 0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10, 0x0,  0xf0,
              0xe0, 0xd0, 0xc0, 0xb0, 0xa0, 0x90, 0x80, 0x70, 0x60, 0x50, 0x40,
              0x30, 0x20, 0x10, 0x0,  0xf0, 0xe0, 0xd0, 0xc0, 0xb0, 0xa0, 0x90,
              0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10, 0x0});
  CHECK_NEON(1, uint8_t,
             {0xf,  0x16, 0x1d, 0x24, 0x2b, 0x32, 0x39, 0x40, 0x47, 0x4e, 0x55,
              0x5c, 0x63, 0x6a, 0x71, 0x78, 0x7f, 0x86, 0x8d, 0x94, 0x9b, 0xa2,
              0xa9, 0xb0, 0xb7, 0xbe, 0xc5, 0xcc, 0xd3, 0xda, 0xe1, 0xe8, 0xef,
              0xf6, 0xfd, 0x4,  0xb,  0x12, 0x19, 0x20, 0x27, 0x2e, 0x35, 0x3c,
              0x43, 0x4a, 0x51, 0x58, 0x5f, 0x66, 0x6d, 0x74, 0x7b, 0x82, 0x89,
              0x90, 0x97, 0x9e, 0xa5, 0xac, 0xb3, 0xba, 0xc1, 0xc8});
  CHECK_NEON(2, uint16_t,
             {0xfff8, 0xfff5, 0xfff2, 0xffef, 0xffec, 0xffe9, 0xffe6, 0xffe3,
              0xffe0, 0xffdd, 0xffda, 0xffd7, 0xffd4, 0xffd1, 0xffce, 0xffcb,
              0xffc8, 0xffc5, 0xffc2, 0xffbf, 0xffbc, 0xffb9, 0xffb6, 0xffb3,
              0xffb0, 0xffad, 0xffaa, 0xffa7, 0xffa4, 0xffa1, 0xff9e, 0xff9b});
  CHECK_NEON(3, uint16_t,
             {0x3,   0x11,  0x1f,  0x2d,  0x3b,  0x49,  0x57,  0x65,
              0x73,  0x81,  0x8f,  0x9d,  0xab,  0xb9,  0xc7,  0xd5,
              0xe3,  0xf1,  0xff,  0x10d, 0x11b, 0x129, 0x137, 0x145,
              0x153, 0x161, 0x16f, 0x17d, 0x18b, 0x199, 0x1a7, 0x1b5});
  CHECK_NEON(
      4, uint32_t,
      {0xfffffffa, 0xfffffffa, 0xfffffffa, 0xfffffffa, 0xfffffffa, 0xfffffffa,
       0xfffffffa, 0xfffffffa, 0xfffffffa, 0xfffffffa, 0xfffffffa, 0xfffffffa,
       0xfffffffa, 0xfffffffa, 0xfffffffa, 0xfffffffa});
  CHECK_NEON(5, uint32_t,
             {0xc, 0x1a, 0x28, 0x36, 0x44, 0x52, 0x60, 0x6e, 0x7c, 0x8a, 0x98,
              0xa6, 0xb4, 0xc2, 0xd0, 0xde});
  CHECK_NEON(6, uint64_t,
             {0xfffffffffffffffb, 0xfffffffffffffff2, 0xffffffffffffffe9,
              0xffffffffffffffe0, 0xffffffffffffffd7, 0xffffffffffffffce,
              0xffffffffffffffc5, 0xffffffffffffffbc});
  CHECK_NEON(7, uint64_t, {0xa, 0x14, 0x1e, 0x28, 0x32, 0x3c, 0x46, 0x50});

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
  CHECK_NEON(0, uint8_t,
             {0xf0, 0xe0, 0xd0, 0xc0, 0xb0, 0xa0, 0x90, 0x80, 0x70, 0x60, 0x50,
              0x40, 0x30, 0x20, 0x10, 0x0,  0xf0, 0xe0, 0xd0, 0xc0, 0xb0, 0xa0,
              0x90, 0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10, 0x0,  0xf0,
              0xe0, 0xd0, 0xc0, 0xb0, 0xa0, 0x90, 0x80, 0x70, 0x60, 0x50, 0x40,
              0x30, 0x20, 0x10, 0x0,  0xf0, 0xe0, 0xd0, 0xc0, 0xb0, 0xa0, 0x90,
              0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10, 0x0});
  CHECK_NEON(1, uint8_t,
             {0xf,  0x16, 0x1d, 0x24, 0x2b, 0x32, 0x39, 0x40, 0x47, 0x4e, 0x55,
              0x5c, 0x63, 0x6a, 0x71, 0x78, 0x7f, 0x86, 0x8d, 0x94, 0x9b, 0xa2,
              0xa9, 0xb0, 0xb7, 0xbe, 0xc5, 0xcc, 0xd3, 0xda, 0xe1, 0xe8, 0xef,
              0xf6, 0xfd, 0x4,  0xb,  0x12, 0x19, 0x20, 0x27, 0x2e, 0x35, 0x3c,
              0x43, 0x4a, 0x51, 0x58, 0x5f, 0x66, 0x6d, 0x74, 0x7b, 0x82, 0x89,
              0x90, 0x97, 0x9e, 0xa5, 0xac, 0xb3, 0xba, 0xc1, 0xc8});
  CHECK_NEON(2, uint16_t,
             {0xfff8, 0xfff5, 0xfff2, 0xffef, 0xffec, 0xffe9, 0xffe6, 0xffe3,
              0xffe0, 0xffdd, 0xffda, 0xffd7, 0xffd4, 0xffd1, 0xffce, 0xffcb,
              0xffc8, 0xffc5, 0xffc2, 0xffbf, 0xffbc, 0xffb9, 0xffb6, 0xffb3,
              0xffb0, 0xffad, 0xffaa, 0xffa7, 0xffa4, 0xffa1, 0xff9e, 0xff9b});
  CHECK_NEON(3, uint16_t,
             {0x3,   0x11,  0x1f,  0x2d,  0x3b,  0x49,  0x57,  0x65,
              0x73,  0x81,  0x8f,  0x9d,  0xab,  0xb9,  0xc7,  0xd5,
              0xe3,  0xf1,  0xff,  0x10d, 0x11b, 0x129, 0x137, 0x145,
              0x153, 0x161, 0x16f, 0x17d, 0x18b, 0x199, 0x1a7, 0x1b5});
  CHECK_NEON(
      4, uint32_t,
      {0xfffffffa, 0xfffffffa, 0xfffffffa, 0xfffffffa, 0xfffffffa, 0xfffffffa,
       0xfffffffa, 0xfffffffa, 0xfffffffa, 0xfffffffa, 0xfffffffa, 0xfffffffa,
       0xfffffffa, 0xfffffffa, 0xfffffffa, 0xfffffffa});
  CHECK_NEON(5, uint32_t,
             {0xc, 0x1a, 0x28, 0x36, 0x44, 0x52, 0x60, 0x6e, 0x7c, 0x8a, 0x98,
              0xa6, 0xb4, 0xc2, 0xd0, 0xde});
  CHECK_NEON(6, uint64_t,
             {0xfffffffffffffffb, 0xfffffffffffffff2, 0xffffffffffffffe9,
              0xffffffffffffffe0, 0xffffffffffffffd7, 0xffffffffffffffce,
              0xffffffffffffffc5, 0xffffffffffffffbc});
  CHECK_NEON(7, uint64_t, {0xa, 0x14, 0x1e, 0x28, 0x32, 0x3c, 0x46, 0x50});

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
  CHECK_NEON(0, uint8_t,
             {0xf0, 0xe0, 0xd0, 0xc0, 0xb0, 0xa0, 0x90, 0x80, 0x70, 0x60, 0x50,
              0x40, 0x30, 0x20, 0x10, 0x0,  0xf0, 0xe0, 0xd0, 0xc0, 0xb0, 0xa0,
              0x90, 0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10, 0x0,  0xf0,
              0xe0, 0xd0, 0xc0, 0xb0, 0xa0, 0x90, 0x80, 0x70, 0x60, 0x50, 0x40,
              0x30, 0x20, 0x10, 0x0,  0xf0, 0xe0, 0xd0, 0xc0, 0xb0, 0xa0, 0x90,
              0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10, 0x0});
  CHECK_NEON(1, uint8_t,
             {0xf,  0x16, 0x1d, 0x24, 0x2b, 0x32, 0x39, 0x40, 0x47, 0x4e, 0x55,
              0x5c, 0x63, 0x6a, 0x71, 0x78, 0x7f, 0x86, 0x8d, 0x94, 0x9b, 0xa2,
              0xa9, 0xb0, 0xb7, 0xbe, 0xc5, 0xcc, 0xd3, 0xda, 0xe1, 0xe8, 0xef,
              0xf6, 0xfd, 0x4,  0xb,  0x12, 0x19, 0x20, 0x27, 0x2e, 0x35, 0x3c,
              0x43, 0x4a, 0x51, 0x58, 0x5f, 0x66, 0x6d, 0x74, 0x7b, 0x82, 0x89,
              0x90, 0x97, 0x9e, 0xa5, 0xac, 0xb3, 0xba, 0xc1, 0xc8});
  CHECK_NEON(2, uint16_t,
             {0xfff8, 0xfff5, 0xfff2, 0xffef, 0xffec, 0xffe9, 0xffe6, 0xffe3,
              0xffe0, 0xffdd, 0xffda, 0xffd7, 0xffd4, 0xffd1, 0xffce, 0xffcb,
              0xffc8, 0xffc5, 0xffc2, 0xffbf, 0xffbc, 0xffb9, 0xffb6, 0xffb3,
              0xffb0, 0xffad, 0xffaa, 0xffa7, 0xffa4, 0xffa1, 0xff9e, 0xff9b});
  CHECK_NEON(3, uint16_t,
             {0x3,   0x11,  0x1f,  0x2d,  0x3b,  0x49,  0x57,  0x65,
              0x73,  0x81,  0x8f,  0x9d,  0xab,  0xb9,  0xc7,  0xd5,
              0xe3,  0xf1,  0xff,  0x10d, 0x11b, 0x129, 0x137, 0x145,
              0x153, 0x161, 0x16f, 0x17d, 0x18b, 0x199, 0x1a7, 0x1b5});
  CHECK_NEON(
      4, uint32_t,
      {0xfffffffa, 0xfffffffa, 0xfffffffa, 0xfffffffa, 0xfffffffa, 0xfffffffa,
       0xfffffffa, 0xfffffffa, 0xfffffffa, 0xfffffffa, 0xfffffffa, 0xfffffffa,
       0xfffffffa, 0xfffffffa, 0xfffffffa, 0xfffffffa});
  CHECK_NEON(5, uint32_t,
             {0xc, 0x1a, 0x28, 0x36, 0x44, 0x52, 0x60, 0x6e, 0x7c, 0x8a, 0x98,
              0xa6, 0xb4, 0xc2, 0xd0, 0xde});
  CHECK_NEON(6, uint64_t,
             {0xfffffffffffffffb, 0xfffffffffffffff2, 0xffffffffffffffe9,
              0xffffffffffffffe0, 0xffffffffffffffd7, 0xffffffffffffffce,
              0xffffffffffffffc5, 0xffffffffffffffbc});
  CHECK_NEON(7, uint64_t, {0xa, 0x14, 0x1e, 0x28, 0x32, 0x3c, 0x46, 0x50});
}

TEST_P(InstSve, ld1rd) {
  // VL = 512-bits
  // 32-bit
  initialHeapData_.resize(16);
  uint64_t* heap64 = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  heap64[0] = 0xDEADBEEF;
  heap64[1] = 0x12345678;

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
    mov x1, #4
    whilelo p1.d, xzr, x1
    ld1rd {z2.d}, p1/z, [x0]
    ld1rd {z3.d}, p1/z, [x0, #8]
  )");
  CHECK_NEON(0, uint64_t,
             {0xDEADBEEF, 0xDEADBEEF, 0xDEADBEEF, 0xDEADBEEF, 0xDEADBEEF,
              0xDEADBEEF, 0xDEADBEEF, 0xDEADBEEF});
  CHECK_NEON(1, uint64_t,
             {0x12345678, 0x12345678, 0x12345678, 0x12345678, 0x12345678,
              0x12345678, 0x12345678, 0x12345678});
  CHECK_NEON(2, uint64_t, {0xDEADBEEF, 0xDEADBEEF, 0xDEADBEEF, 0xDEADBEEF});
  CHECK_NEON(3, uint64_t, {0x12345678, 0x12345678, 0x12345678, 0x12345678});
}

TEST_P(InstSve, ld1rw) {
  // VL = 512-bits
  // 32-bit
  initialHeapData_.resize(8);
  uint32_t* heap32 = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap32[0] = 0xDEADBEEF;
  heap32[1] = 0x12345678;

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
    mov x1, #8
    whilelo p1.s, xzr, x1
    ld1rw {z2.s}, p1/z, [x0]
    ld1rw {z3.s}, p1/z, [x0, #4]
  )");
  CHECK_NEON(0, uint64_t,
             {0xDEADBEEFDEADBEEF, 0xDEADBEEFDEADBEEF, 0xDEADBEEFDEADBEEF,
              0xDEADBEEFDEADBEEF, 0xDEADBEEFDEADBEEF, 0xDEADBEEFDEADBEEF,
              0xDEADBEEFDEADBEEF, 0xDEADBEEFDEADBEEF});
  CHECK_NEON(1, uint64_t,
             {0x1234567812345678, 0x1234567812345678, 0x1234567812345678,
              0x1234567812345678, 0x1234567812345678, 0x1234567812345678,
              0x1234567812345678, 0x1234567812345678});
  CHECK_NEON(2, uint64_t,
             {0xDEADBEEFDEADBEEF, 0xDEADBEEFDEADBEEF, 0xDEADBEEFDEADBEEF,
              0xDEADBEEFDEADBEEF});
  CHECK_NEON(3, uint64_t,
             {0x1234567812345678, 0x1234567812345678, 0x1234567812345678,
              0x1234567812345678});
}

TEST_P(InstSve, ld1b) {
  // VL = 512-bits
  initialHeapData_.resize(64);
  initialHeapData_ = {
      0xEF, 0xBE, 0xAD, 0xDE, 0x78, 0x56, 0x34, 0x12, 0x32, 0x54, 0x76,
      0x98, 0x01, 0xEF, 0xCD, 0xAB, 0xEF, 0xBE, 0xAD, 0xDE, 0x78, 0x56,
      0x34, 0x12, 0x32, 0x54, 0x76, 0x98, 0x01, 0xEF, 0xCD, 0xAB, 0xEF,
      0xBE, 0xAD, 0xDE, 0x78, 0x56, 0x34, 0x12, 0x32, 0x54, 0x76, 0x98,
      0x01, 0xEF, 0xCD, 0xAB, 0xEF, 0xBE, 0xAD, 0xDE, 0x78, 0x56, 0x34,
      0x12, 0x32, 0x54, 0x76, 0x98, 0x01, 0xEF, 0xCD, 0xAB};

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
    mov x1, #32
    mov x2, #0
    whilelo p1.b, xzr, x1
    ld1b {z1.b}, p1/z, [x0, x2]
  )");
  CHECK_NEON(0, uint8_t,
             {0xEF, 0xBE, 0xAD, 0xDE, 0x78, 0x56, 0x34, 0x12, 0x32, 0x54, 0x76,
              0x98, 0x01, 0xEF, 0xCD, 0xAB, 0xEF, 0xBE, 0xAD, 0xDE, 0x78, 0x56,
              0x34, 0x12, 0x32, 0x54, 0x76, 0x98, 0x01, 0xEF, 0xCD, 0xAB, 0xEF,
              0xBE, 0xAD, 0xDE, 0x78, 0x56, 0x34, 0x12, 0x32, 0x54, 0x76, 0x98,
              0x01, 0xEF, 0xCD, 0xAB, 0xEF, 0xBE, 0xAD, 0xDE, 0x78, 0x56, 0x34,
              0x12, 0x32, 0x54, 0x76, 0x98, 0x01, 0xEF, 0xCD, 0xAB});
  CHECK_NEON(1, uint8_t,
             {0xEF, 0xBE, 0xAD, 0xDE, 0x78, 0x56, 0x34, 0x12, 0x32, 0x54, 0x76,
              0x98, 0x01, 0xEF, 0xCD, 0xAB, 0xEF, 0xBE, 0xAD, 0xDE, 0x78, 0x56,
              0x34, 0x12, 0x32, 0x54, 0x76, 0x98, 0x01, 0xEF, 0xCD, 0xAB, 0,
              0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
              0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
              0,    0,    0,    0,    0,    0,    0,    0,    0});
}

TEST_P(InstSve, ld1sw_gather) {
  // VL = 512-bits
  RUN_AARCH64(R"(
    mov x0, #0xFF
    index z1.d, x0, #12
    index z2.d, #8, #-4
    index z3.d, #8, #-4

    ptrue p0.d
    mov x1, #4
    whilelo p1.d, xzr, x1

    # Put data into memory so we have something to load
    st1w {z2.d}, p0, [z1.d]
    st1w {z3.d}, p1, [z1.d, #80]

    ld1sw {z4.d}, p0/z, [z1.d]
    ld1sw {z5.d}, p1/z, [z1.d, #80]
  )");
  CHECK_NEON(4, int64_t, {8, 4, 0, -4, -8, -12, -16, -20});
  CHECK_NEON(5, int64_t, {8, 4, 0, -4, 0, 0, 0, 0});
}

TEST_P(InstSve, ld1d_gather) {
  // VL = 512-bits
  // Vector plus immediate
  RUN_AARCH64(R"(
    mov x0, #-24
    mov x1, #800
    index z1.d, x1, x0
    index z2.d, #8, #-4
    index z3.d, #8, #-4

    ptrue p0.d
    mov x1, #4
    whilelo p1.d, xzr, x1

    # Put data into memory so we have something to load
    st1d {z2.d}, p0, [z1.d]
    st1d {z3.d}, p1, [z1.d, #240]

    ld1d {z4.d}, p0/z, [z1.d]
    ld1d {z5.d}, p1/z, [z1.d, #240]
  )");
  CHECK_NEON(4, uint64_t,
             {static_cast<uint64_t>(8), static_cast<uint64_t>(4), 0,
              static_cast<uint64_t>(-4), static_cast<uint64_t>(-8),
              static_cast<uint64_t>(-12), static_cast<uint64_t>(-16),
              static_cast<uint64_t>(-20)});
  CHECK_NEON(5, uint64_t,
             {static_cast<uint64_t>(8), static_cast<uint64_t>(4), 0,
              static_cast<uint64_t>(-4), 0, 0, 0, 0});

  // Scalar plus vector
  // 64-bit
  RUN_AARCH64(R"(
    mov x0, #-24
    mov x1, #800
    index z1.d, x1, x0
    index z2.d, #8, #-4
    index z3.d, #8, #-4
    index z4.d, x1, #8

    ptrue p0.d
    mov x2, #4
    whilelo p1.d, xzr, x2

    # Put data into memory so we have something to load
    st1d {z2.d}, p0, [z1.d]
    st1d {z3.d}, p0, [z4.d]    

    index z4.d, #0, #1
    mov x4, #0
    ld1d {z5.d}, p1/z, [x4, z1.d]
    ld1d {z6.d}, p0/z, [x1, z4.d, lsl #3]
  )");
  CHECK_NEON(5, uint64_t,
             {static_cast<uint64_t>(8), static_cast<uint64_t>(4), 0,
              static_cast<uint64_t>(-4), 0, 0, 0, 0});
  CHECK_NEON(6, uint64_t,
             {static_cast<uint64_t>(8), static_cast<uint64_t>(4), 0,
              static_cast<uint64_t>(-4), static_cast<uint64_t>(-8),
              static_cast<uint64_t>(-12), static_cast<uint64_t>(-16),
              static_cast<uint64_t>(-20)});
}

TEST_P(InstSve, ld1d) {
  // VL = 512-bits
  initialHeapData_.resize(128);
  uint64_t* heap64 = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  heap64[0] = 0xDEADBEEF;
  heap64[1] = 0x12345678;
  heap64[2] = 0x98765432;
  heap64[3] = 0xABCDEF01;
  heap64[4] = 0xDEADBEEF;
  heap64[5] = 0x12345678;
  heap64[6] = 0x98765432;
  heap64[7] = 0xABCDEF01;
  heap64[8] = 0xDEADBEEF;
  heap64[9] = 0x12345678;
  heap64[10] = 0x98765432;
  heap64[11] = 0xABCDEF01;
  heap64[12] = 0xDEADBEEF;
  heap64[13] = 0x12345678;
  heap64[14] = 0x98765432;
  heap64[15] = 0xABCDEF01;

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
    mov x1, #4
    mov x2, #0
    whilelo p1.d, xzr, x1
    ld1d {z1.d}, p1/z, [x0, x2, lsl #3]
    ld1d {z3.d}, p1/z, [x0, #1, mul vl]
  )");
  CHECK_NEON(0, uint64_t,
             {0x12345678, 0x98765432, 0xABCDEF01, 0xDEADBEEF, 0x12345678,
              0x98765432, 0xABCDEF01, 0xDEADBEEF});
  CHECK_NEON(1, uint64_t,
             {0xDEADBEEF, 0x12345678, 0x98765432, 0xABCDEF01, 0, 0, 0, 0});
  CHECK_NEON(2, uint64_t,
             {0xDEADBEEF, 0x12345678, 0x98765432, 0xABCDEF01, 0xDEADBEEF,
              0x12345678, 0x98765432, 0xABCDEF01});
  CHECK_NEON(3, uint64_t,
             {0xDEADBEEF, 0x12345678, 0x98765432, 0xABCDEF01, 0, 0, 0, 0});
}

TEST_P(InstSve, ld1h) {
  // VL = 512-bits
  initialHeapData_.resize(128);
  uint16_t* heap16 = reinterpret_cast<uint16_t*>(initialHeapData_.data());
  heap16[0] = 0xBEEF;
  heap16[1] = 0xDEAD;
  heap16[2] = 0x5678;
  heap16[3] = 0x1234;
  heap16[4] = 0x5432;
  heap16[5] = 0x9876;
  heap16[6] = 0xEF01;
  heap16[7] = 0xABCD;
  heap16[8] = 0xBEEF;
  heap16[9] = 0xDEAD;
  heap16[10] = 0x5678;
  heap16[11] = 0x1234;
  heap16[12] = 0x5432;
  heap16[13] = 0x9876;
  heap16[14] = 0xEF01;
  heap16[15] = 0xABCD;
  heap16[16] = 0xBEEF;
  heap16[17] = 0xDEAD;
  heap16[18] = 0x5678;
  heap16[19] = 0x1234;
  heap16[20] = 0x5432;
  heap16[21] = 0x9876;
  heap16[22] = 0xEF01;
  heap16[23] = 0xABCD;
  heap16[24] = 0xBEEF;
  heap16[25] = 0xDEAD;
  heap16[26] = 0x5678;
  heap16[27] = 0x1234;
  heap16[28] = 0x5432;
  heap16[29] = 0x9876;
  heap16[30] = 0xEF01;
  heap16[31] = 0xABCD;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #32
    whilelo p0.h, xzr, x2
    # Load and broadcast values from heap
    ld1h {z0.h}, p0/z, [x0, x1, lsl #1]

    # Test for inactive lanes
    mov x1, #16
    mov x2, #0
    whilelo p1.h, xzr, x1
    ld1h {z1.h}, p1/z, [x0, x2, lsl #1]
  )");
  CHECK_NEON(0, uint16_t,
             {0xBEEF, 0xDEAD, 0x5678, 0x1234, 0x5432, 0x9876, 0xEF01, 0xABCD,
              0xBEEF, 0xDEAD, 0x5678, 0x1234, 0x5432, 0x9876, 0xEF01, 0xABCD,
              0xBEEF, 0xDEAD, 0x5678, 0x1234, 0x5432, 0x9876, 0xEF01, 0xABCD,
              0xBEEF, 0xDEAD, 0x5678, 0x1234, 0x5432, 0x9876, 0xEF01, 0xABCD});
  CHECK_NEON(1, uint16_t,
             {0xBEEF, 0xDEAD, 0x5678, 0x1234, 0x5432, 0x9876, 0xEF01, 0xABCD,
              0xBEEF, 0xDEAD, 0x5678, 0x1234, 0x5432, 0x9876, 0xEF01, 0xABCD,
              0,      0,      0,      0,      0,      0,      0,      0,
              0,      0,      0,      0,      0,      0,      0,      0});
}

TEST_P(InstSve, ld1w) {
  // VL = 512-bits
  initialHeapData_.resize(128);
  uint32_t* heap32 = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap32[0] = 0xDEADBEEF;
  heap32[1] = 0x12345678;
  heap32[2] = 0x98765432;
  heap32[3] = 0xABCDEF01;
  heap32[4] = 0xDEADBEEF;
  heap32[5] = 0x12345678;
  heap32[6] = 0x98765432;
  heap32[7] = 0xABCDEF01;
  heap32[8] = 0xDEADBEEF;
  heap32[9] = 0x12345678;
  heap32[10] = 0x98765432;
  heap32[11] = 0xABCDEF01;
  heap32[12] = 0xDEADBEEF;
  heap32[13] = 0x12345678;
  heap32[14] = 0x98765432;
  heap32[15] = 0xABCDEF01;
  heap32[16] = 0xDEADBEEF;
  heap32[17] = 0xABCDEF01;
  heap32[18] = 0x98765432;
  heap32[19] = 0x12345678;
  heap32[20] = 0xDEADBEEF;
  heap32[21] = 0xABCDEF01;
  heap32[22] = 0x98765432;
  heap32[23] = 0x12345678;
  heap32[24] = 0xDEADBEEF;
  heap32[25] = 0xABCDEF01;
  heap32[26] = 0x98765432;
  heap32[27] = 0x12345678;
  heap32[28] = 0xDEADBEEF;
  heap32[29] = 0xABCDEF01;
  heap32[30] = 0x98765432;
  heap32[31] = 0x12345678;

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
    mov x1, #8
    mov x2, #0
    whilelo p1.s, xzr, x1
    ld1w {z1.s}, p1/z, [x0, x2, lsl #2]
    ld1w {z3.s}, p1/z, [x0, #1, mul vl]
  )");
  CHECK_NEON(0, uint64_t,
             {0x9876543212345678, 0xDEADBEEFABCDEF01, 0x9876543212345678,
              0xDEADBEEFABCDEF01, 0x9876543212345678, 0xDEADBEEFABCDEF01,
              0x9876543212345678, 0xDEADBEEFABCDEF01});
  CHECK_NEON(1, uint64_t,
             {0x12345678DEADBEEF, 0xABCDEF0198765432, 0x12345678DEADBEEF,
              0xABCDEF0198765432});
  CHECK_NEON(2, uint64_t,
             {0x12345678DEADBEEF, 0xABCDEF0198765432, 0x12345678DEADBEEF,
              0xABCDEF0198765432, 0x12345678DEADBEEF, 0xABCDEF0198765432,
              0x12345678DEADBEEF, 0xABCDEF0198765432});
  CHECK_NEON(3, uint64_t,
             {0xABCDEF01DEADBEEF, 0x1234567898765432, 0xABCDEF01DEADBEEF,
              0x1234567898765432, 0, 0, 0, 0});
}

TEST_P(InstSve, ldr_predicate) {
  // VL = 512-bits
  initialHeapData_.resize(32);
  uint64_t* heap64 = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  heap64[0] = 0xFFFFFFFFFFFFFFFF;
  heap64[1] = 0x0;
  heap64[2] = 0xDEADBEEFDEADBEEF;
  heap64[3] = 0x1234567812345678;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr p0, [x0, #0, mul vl]
    ldr p1, [x0, #1, mul vl]
    ldr p2, [x0, #2, mul vl]
    ldr p3, [x0, #3, mul vl]
  )");

  CHECK_PREDICATE(0, uint64_t, {0xFFFFFFFFFFFFFFFF, 0, 0, 0});
  CHECK_PREDICATE(1, uint64_t, {0, 0, 0, 0});
  CHECK_PREDICATE(2, uint64_t, {0xDEADBEEFDEADBEEF, 0, 0, 0});
  CHECK_PREDICATE(3, uint64_t, {0x1234567812345678, 0, 0, 0});
}

TEST_P(InstSve, ldr_vector) {
  // VL = 512-bits
  initialHeapData_.resize(128);
  uint64_t* heap64 = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  heap64[0] = 0xFFFFFFFFFFFFFFFF;
  heap64[1] = 0x0;
  heap64[2] = 0xDEADBEEFDEADBEEF;
  heap64[3] = 0x1234567812345678;
  heap64[4] = 0xFFFFFFFFFFFFFFFF;
  heap64[5] = 0x98765432ABCDEF01;
  heap64[6] = 0xDEADBEEFDEADBEEF;
  heap64[7] = 0x1234567812345678;

  heap64[8] = 0x1234567812345678;
  heap64[9] = 0xDEADBEEFDEADBEEF;
  heap64[10] = 0x98765432ABCDEF01;
  heap64[11] = 0xFFFFFFFFFFFFFFFF;
  heap64[12] = 0x1234567812345678;
  heap64[13] = 0xDEADBEEFDEADBEEF;
  heap64[14] = 0x0;
  heap64[15] = 0xFFFFFFFFFFFFFFFF;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr z0, [x0, #0, mul vl]
    ldr z1, [x0, #1, mul vl]
  )");

  CHECK_NEON(0, uint64_t,
             {0xFFFFFFFFFFFFFFFF, 0, 0xDEADBEEFDEADBEEF, 0x1234567812345678,
              0xFFFFFFFFFFFFFFFF, 0x98765432ABCDEF01, 0xDEADBEEFDEADBEEF,
              0x1234567812345678});
  CHECK_NEON(1, uint64_t,
             {0x1234567812345678, 0xDEADBEEFDEADBEEF, 0x98765432ABCDEF01,
              0xFFFFFFFFFFFFFFFF, 0x1234567812345678, 0xDEADBEEFDEADBEEF, 0,
              0xFFFFFFFFFFFFFFFF});
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

  CHECK_NEON(0, uint32_t, {7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7});
  CHECK_NEON(1, int32_t,
             {-28, -28, -28, -28, -28, -28, -28, -28, -28, -28, -28, -28, -28,
              -28, -28, -28});
  CHECK_NEON(
      2, uint32_t,
      {2147483648, 2147483648, 2147483648, 2147483648, 2147483648, 2147483648,
       2147483648, 2147483648, 2147483648, 2147483648, 2147483648, 2147483648,
       2147483648, 2147483648, 2147483648, 2147483648});
}

TEST_P(InstSve, mla) {
  // VL = 512-bits
  // 8-bit
  RUN_AARCH64(R"(
    mov x0, #48
    ptrue p0.b
    whilelo p1.b, xzr, x0

    dup z0.b, #2
    dup z1.b, #3 
    index z2.b, #5, #1
    index z3.b, #4, #2

    mla z2.b, p0/m, z0.b, z1.b
    mla z3.b, p1/m, z0.b, z1.b
  )");
  CHECK_NEON(2, uint8_t,
             {11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
              27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
              43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58,
              59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74});
  CHECK_NEON(3, uint8_t,
             {10,  12,  14,  16,  18,  20,  22,  24,  26,  28,  30,  32,  34,
              36,  38,  40,  42,  44,  46,  48,  50,  52,  54,  56,  58,  60,
              62,  64,  66,  68,  70,  72,  74,  76,  78,  80,  82,  84,  86,
              88,  90,  92,  94,  96,  98,  100, 102, 104, 100, 102, 104, 106,
              108, 110, 112, 114, 116, 118, 120, 122, 124, 126, 128, 130});

  // 16-bit
  RUN_AARCH64(R"(
    mov x0, #24
    ptrue p0.h
    whilelo p1.h, xzr, x0

    dup z0.h, #2
    dup z1.h, #3 
    index z2.h, #5, #1
    index z3.h, #4, #2

    mla z2.h, p0/m, z0.h, z1.h
    mla z3.h, p1/m, z0.h, z1.h
  )");
  CHECK_NEON(2, uint16_t,
             {11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
              27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42});
  CHECK_NEON(3, uint16_t,
             {10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32, 34, 36, 38, 40,
              42, 44, 46, 48, 50, 52, 54, 56, 52, 54, 56, 58, 60, 62, 64, 66});

  // 32-bit
  RUN_AARCH64(R"(
    mov x0, #12
    ptrue p0.s
    whilelo p1.s, xzr, x0

    dup z0.s, #2
    dup z1.s, #3 
    index z2.s, #5, #1
    index z3.s, #4, #2

    mla z2.s, p0/m, z0.s, z1.s
    mla z3.s, p1/m, z0.s, z1.s
  )");
  CHECK_NEON(2, uint32_t,
             {11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26});
  CHECK_NEON(3, uint32_t,
             {10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32, 28, 30, 32, 34});

  // 64-bit
  RUN_AARCH64(R"(
    mov x0, #6
    ptrue p0.d
    whilelo p1.d, xzr, x0

    dup z0.d, #2
    dup z1.d, #3 
    index z2.d, #5, #1
    index z3.d, #4, #2

    mla z2.d, p0/m, z0.d, z1.d
    mla z3.d, p1/m, z0.d, z1.d
  )");
  CHECK_NEON(2, uint64_t, {11, 12, 13, 14, 15, 16, 17, 18});
  CHECK_NEON(3, uint64_t, {10, 12, 14, 16, 18, 20, 16, 18});
}

TEST_P(InstSve, movprfx) {
  // VL = 512-bits
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

  CHECK_NEON(3, float, {7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7});
  CHECK_NEON(4, float,
             {-7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7, -7});
  CHECK_NEON(5, double, {14, 14, 14, 14, 14, 14, 14, 14});
  CHECK_NEON(6, float,
             {91, 91, 91, 91, 91, 91, 91, 91, 91, 91, 91, 91, 91, 91, 91, 91});

  // Predicated
  RUN_AARCH64(R"(
    mov x1, #8
    whilelo p0.s, xzr, x1
    whilelo p1.d, xzr, x1
    mov x2, #4
    whilelo p3.d, xzr, x2

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
  CHECK_NEON(4, uint32_t,
             {9u, 9u, 9u, 9u, 9u, 9u, 9u, 9u, 0, 0, 0, 0, 0, 0, 0, 0});
  CHECK_NEON(5, uint64_t, {5u, 5u, 5u, 5u, 5u, 5u, 5u, 5u});
  CHECK_NEON(6, uint64_t, {5u, 5u, 5u, 5u, 3u, 3u, 3u, 3u});
}

TEST_P(InstSve, mul) {
  // VL = 512-bits
  // Vectors
  // 8-bit
  RUN_AARCH64(R"(
    ptrue p0.b
    mov x0, #32
    whilelo p1.b, xzr, x0

    mov z0.b, #2
    mov z1.b, #3
    index z2.b, #1, #1

    mul z0.b, p0/m, z0.b, z2.b
    mul z1.b, p1/m, z1.b, z2.b
  )");
  CHECK_NEON(0, uint8_t,
             {2,   4,   6,   8,   10,  12,  14,  16,  18,  20,  22,  24,  26,
              28,  30,  32,  34,  36,  38,  40,  42,  44,  46,  48,  50,  52,
              54,  56,  58,  60,  62,  64,  66,  68,  70,  72,  74,  76,  78,
              80,  82,  84,  86,  88,  90,  92,  94,  96,  98,  100, 102, 104,
              106, 108, 110, 112, 114, 116, 118, 120, 122, 124, 126, 128});
  CHECK_NEON(1, uint8_t,
             {3,  6,  9,  12, 15, 18, 21, 24, 27, 30, 33, 36, 39, 42, 45, 48,
              51, 54, 57, 60, 63, 66, 69, 72, 75, 78, 81, 84, 87, 90, 93, 96,
              3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,
              3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3});

  // 16-bit
  RUN_AARCH64(R"(
    ptrue p0.h
    mov x0, #16
    whilelo p1.h, xzr, x0

    mov z0.h, #2
    mov z1.h, #3
    index z2.h, #1, #1

    mul z0.h, p0/m, z0.h, z2.h
    mul z1.h, p1/m, z1.h, z2.h
  )");
  CHECK_NEON(0, uint16_t,
             {2,  4,  6,  8,  10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32,
              34, 36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 56, 58, 60, 62, 64});
  CHECK_NEON(1, uint16_t,
             {3, 6, 9, 12, 15, 18, 21, 24, 27, 30, 33, 36, 39, 42, 45, 48,
              3, 3, 3, 3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3});

  // 32-bit
  RUN_AARCH64(R"(
    ptrue p0.s
    mov x0, #8
    whilelo p1.s, xzr, x0

    mov z0.s, #2
    mov z1.s, #3
    index z2.s, #1, #1

    mul z0.s, p0/m, z0.s, z2.s
    mul z1.s, p1/m, z1.s, z2.s
  )");
  CHECK_NEON(0, uint32_t,
             {2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32});
  CHECK_NEON(1, uint32_t,
             {3, 6, 9, 12, 15, 18, 21, 24, 3, 3, 3, 3, 3, 3, 3, 3});

  // 64-bit
  RUN_AARCH64(R"(
    ptrue p0.d
    mov x0, #4
    whilelo p1.d, xzr, x0

    mov z0.d, #2
    mov z1.d, #3
    index z2.d, #1, #1

    mul z0.d, p0/m, z0.d, z2.d
    mul z1.d, p1/m, z1.d, z2.d
  )");
  CHECK_NEON(0, uint64_t, {2, 4, 6, 8, 10, 12, 14, 16});
  CHECK_NEON(1, uint64_t, {3, 6, 9, 12, 3, 3, 3, 3});
}

TEST_P(InstSve, orr) {
  // VL = 512-bits
  RUN_AARCH64(R"(
    mov x0, #8

    # Test varying permutations of active and inactive lanes
    #ptrue p0.s
    #ptrue p1.s
    #ptrue p2.s
    #orr p3.b, p0/z, p1.b, p2.b
    #whilelo p1.s, xzr, x0
    #orr p4.b, p0/z, p1.b, p2.b
    #whilelo p2.s, xzr, x0
    #orr p5.b, p0/z, p1.b, p2.b
    whilelo p0.s, xzr, x0
    ptrue p1.s
    #ptrue p2.s
    #orr p6.b, p0/z, p1.b, p2.b

    # Check mov alias
    mov p7.b, p0.b
    mov p8.b, p1.b

    mov z0.s, #4
    mov z1.d, z0.d
  )");
  // CHECK_PREDICATE(3, uint32_t, {0x11111111, 0x11111111, 0, 0, 0, 0, 0,
  // 0}); CHECK_PREDICATE(4, uint32_t, {0x11111111, 0x11111111, 0, 0, 0, 0,
  // 0, 0}); CHECK_PREDICATE(5, uint32_t, {0x11111111, 0, 0, 0, 0, 0, 0,
  // 0}); CHECK_PREDICATE(6, uint32_t, {0x11111111, 0, 0, 0, 0, 0, 0, 0});
  CHECK_PREDICATE(7, uint32_t, {0x11111111, 0, 0, 0, 0, 0, 0, 0});
  CHECK_PREDICATE(8, uint32_t, {0x11111111, 0x11111111, 0, 0, 0, 0, 0, 0});

  CHECK_NEON(1, uint64_t,
             {0x400000004, 0x400000004, 0x400000004, 0x400000004, 0x400000004,
              0x400000004, 0x400000004, 0x400000004});
}

TEST_P(InstSve, ptest) {
  // VL = 512-bits
  RUN_AARCH64(R"(
    ptrue p0.s
    ptest p0, p0.b
  )");
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    ptrue p0.s
    mov x0, #8
    whilelo p1.s, xzr, x0
    ptest p1, p0.b
  )");
  EXPECT_EQ(getNZCV(), 0b1010);
}

TEST_P(InstSve, pfalse) {
  // VL = 512-bits
  RUN_AARCH64(R"(
    pfalse p0.b
  )");
  CHECK_PREDICATE(0, uint32_t, {0, 0, 0, 0, 0, 0, 0, 0});
}

TEST_P(InstSve, ptrue) {
  // VL = 512-bits
  // 64/32-bit arrangement
  RUN_AARCH64(R"(
    ptrue p0.s
    ptrue p1.d
    ptrue p2.b
    ptrue p3.h
  )");
  CHECK_PREDICATE(0, uint32_t, {286331153, 286331153, 0, 0, 0, 0, 0, 0});
  CHECK_PREDICATE(1, uint32_t, {0x1010101, 0x1010101, 0, 0, 0, 0, 0, 0});
  CHECK_PREDICATE(2, uint32_t, {0xFFFFFFFF, 0xFFFFFFFF, 0, 0, 0, 0, 0, 0});
  CHECK_PREDICATE(3, uint32_t, {0x55555555, 0x55555555, 0, 0, 0, 0, 0, 0});
}

TEST_P(InstSve, punpk) {
  // VL = 512-bits
  RUN_AARCH64(R"(
    ptrue p0.b
    mov x0, #8
    whilelo p1.s, xzr, x0

    punpkhi p2.h, p0.b
    punpkhi p3.h, p1.b
    punpklo p4.h, p0.b
    punpklo p5.h, p1.b
  )");
  CHECK_PREDICATE(2, uint32_t, {0x55555555, 0x55555555, 0, 0, 0, 0, 0, 0});
  CHECK_PREDICATE(3, uint32_t, {0, 0, 0, 0, 0, 0, 0, 0});
  CHECK_PREDICATE(4, uint32_t, {0x55555555, 0x55555555, 0, 0, 0, 0, 0, 0});
  CHECK_PREDICATE(5, uint32_t, {0x1010101, 0x1010101, 0, 0, 0, 0, 0, 0});
}

TEST_P(InstSve, rdvl) {
  // VL = 512-bits
  RUN_AARCH64(R"(
    rdvl x0, #-32
    rdvl x1, #-3
    rdvl x2, #0
    rdvl x3, #3
    rdvl x4, #31
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(0), -2048);
  EXPECT_EQ(getGeneralRegister<int64_t>(1), -192);
  EXPECT_EQ(getGeneralRegister<int64_t>(2), 0);
  EXPECT_EQ(getGeneralRegister<int64_t>(3), 192);
  EXPECT_EQ(getGeneralRegister<int64_t>(4), 1984);
}

TEST_P(InstSve, rev) {
  // VL = 512-bits
  // Predicate
  RUN_AARCH64(R"(
    mov x1, #32
    mov x2, #16
    mov x3, #8
    mov x4, #4

    whilelo p0.b, xzr, x1
    whilelo p1.h, xzr, x2
    whilelo p2.s, xzr, x3
    whilelo p3.d, xzr, x4

    rev p4.b, p0.b
    rev p5.h, p1.h
    rev p6.s, p2.s
    rev p7.d, p3.d
  )");
  CHECK_PREDICATE(0, uint64_t, {0x00000000FFFFFFFFu, 0, 0, 0});
  CHECK_PREDICATE(1, uint64_t, {0x0000000055555555u, 0, 0, 0});
  CHECK_PREDICATE(2, uint64_t, {0x0000000011111111u, 0, 0, 0});
  CHECK_PREDICATE(3, uint64_t, {0x000000001010101u, 0, 0, 0});

  CHECK_PREDICATE(4, uint64_t, {0xFFFFFFFF00000000u, 0, 0, 0});
  CHECK_PREDICATE(5, uint64_t, {0x5555555500000000u, 0, 0, 0});
  CHECK_PREDICATE(6, uint64_t, {0x1111111100000000u, 0, 0, 0});
  CHECK_PREDICATE(7, uint64_t, {0x101010100000000u, 0, 0, 0});

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
             {63, 62, 61, 60, 59, 58, 57, 56, 55, 54, 53, 52, 51, 50, 49, 48,
              47, 46, 45, 44, 43, 42, 41, 40, 39, 38, 37, 36, 35, 34, 33, 32,
              31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16,
              15, 14, 13, 12, 11, 10, 9,  8,  7,  6,  5,  4,  3,  2,  1,  0});
  CHECK_NEON(5, uint16_t,
             {62, 60, 58, 56, 54, 52, 50, 48, 46, 44, 42, 40, 38, 36, 34, 32,
              30, 28, 26, 24, 22, 20, 18, 16, 14, 12, 10, 8,  6,  4,  2,  0});
  CHECK_NEON(6, uint32_t,
             {60, 56, 52, 48, 44, 40, 36, 32, 28, 24, 20, 16, 12, 8, 4, 0});
  CHECK_NEON(7, uint64_t, {56, 48, 40, 32, 24, 16, 8, 0});
}

TEST_P(InstSve, scvtf) {
  // VL = 512-bits
  RUN_AARCH64(R"(
    index z0.s, #-6, #0
    index z1.s, #12, #14
    index z2.d, #-5, #-9
    index z3.d, #10, #10

    ptrue p0.s
    ptrue p1.d
    mov x1, #8
    mov x2, #4
    whilelo p2.s, xzr, x1
    whilelo p3.d, xzr, x2

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
  CHECK_NEON(5, double,
             {-5.0, -14.0, -23.0, -32.0, -41.0, -50.0, -59.0, -68.0});
  CHECK_NEON(6, double, {0xa, 0x14, 0x1e, 0x28, 0, 0, 0, 0});
  CHECK_NEON(7, float,
             {-5.0f, 0x0, -14.0f, 0x0, -23.0f, 0x0, -32.0f, 0x0, -41.0f, 0x0,
              -50.0f, 0x0, -59.0f, 0x0, -68.0f, 0x0});
  CHECK_NEON(8, float,
             {0xa, 0x0, 0x14, 0x0, 0x1e, 0x0, 0x28, 0x0, 0, 0x0, 0, 0x0, 0, 0x0,
              0, 0x0});
  CHECK_NEON(9, double, {-6.0, -6.0, -6.0, -6.0, -6.0, -6.0, -6.0, -6.0});
  CHECK_NEON(10, double, {0xc, 0x28, 0x44, 0x60, 0x0, 0x0, 0x0, 0x0});
  CHECK_NEON(11, float,
             {-6.0f, -6.0f, -6.0f, -6.0f, -6.0f, -6.0f, -6.0f, -6.0f, -6.0f,
              -6.0f, -6.0f, -6.0f, -6.0f, -6.0f, -6.0f, -6.0f});
  CHECK_NEON(12, float,
             {0xc, 0x1a, 0x28, 0x36, 0x44, 0x52, 0x60, 0x6e, 0x0, 0x0, 0x0, 0x0,
              0x0, 0x0, 0x0, 0x0});

  // Boundary tests
  // Double
  initialHeapData_.resize(32);
  int64_t* dheap = reinterpret_cast<int64_t*>(initialHeapData_.data());
  dheap[0] = INT64_MAX;
  dheap[1] = INT64_MIN;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ptrue p0.d
    
    mov x1, #8
    whilelo p1.d, xzr, x1

    ldr x2, [x0]
    ldr x3, [x0, #8]

    dup z0.d, x2
    dup z1.d, x3

    # int64 -> double
    scvtf z2.d, p0/m, z0.d
    scvtf z3.d, p1/m, z1.d

    # int64 -> single
    scvtf z4.s, p0/m, z0.d
    scvtf z5.s, p1/m, z1.d
  )");
  CHECK_NEON(2, double,
             {static_cast<double>(INT64_MAX), static_cast<double>(INT64_MAX),
              static_cast<double>(INT64_MAX), static_cast<double>(INT64_MAX),
              static_cast<double>(INT64_MAX), static_cast<double>(INT64_MAX),
              static_cast<double>(INT64_MAX), static_cast<double>(INT64_MAX)});
  CHECK_NEON(3, double,
             {static_cast<double>(INT64_MIN), static_cast<double>(INT64_MIN),
              static_cast<double>(INT64_MIN), static_cast<double>(INT64_MIN),
              static_cast<double>(INT64_MIN), static_cast<double>(INT64_MIN),
              static_cast<double>(INT64_MIN), static_cast<double>(INT64_MIN)});
  CHECK_NEON(
      4, float,
      {static_cast<float>(INT64_MAX), 0.0f, static_cast<float>(INT64_MAX), 0.0f,
       static_cast<float>(INT64_MAX), 0.0f, static_cast<float>(INT64_MAX), 0.0f,
       static_cast<float>(INT64_MAX), 0.0f, static_cast<float>(INT64_MAX), 0.0f,
       static_cast<float>(INT64_MAX), 0.0f, static_cast<float>(INT64_MAX),
       0.0f});
  CHECK_NEON(
      5, float,
      {static_cast<float>(INT64_MIN), 0.0f, static_cast<float>(INT64_MIN), 0.0f,
       static_cast<float>(INT64_MIN), 0.0f, static_cast<float>(INT64_MIN), 0.0f,
       static_cast<float>(INT64_MIN), 0.0f, static_cast<float>(INT64_MIN), 0.0f,
       static_cast<float>(INT64_MIN), 0.0f, static_cast<float>(INT64_MIN),
       0.0f});

  // Single
  initialHeapData_.resize(32);
  int32_t* fheap = reinterpret_cast<int32_t*>(initialHeapData_.data());
  fheap[0] = INT32_MAX;
  fheap[1] = INT32_MIN;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ptrue p0.s
    
    mov x1, #8
    whilelo p1.s, xzr, x1

    ldr w2, [x0]
    ldr w3, [x0, #4]

    dup z0.s, w2
    dup z1.s, w3

    # int32 -> double
    scvtf z2.d, p0/m, z0.s
    scvtf z3.d, p1/m, z1.s

    # int32 -> single
    scvtf z4.s, p0/m, z0.s
    scvtf z5.s, p1/m, z1.s
  )");
  CHECK_NEON(2, double,
             {static_cast<double>(INT32_MAX), static_cast<double>(INT32_MAX),
              static_cast<double>(INT32_MAX), static_cast<double>(INT32_MAX),
              static_cast<double>(INT32_MAX), static_cast<double>(INT32_MAX),
              static_cast<double>(INT32_MAX), static_cast<double>(INT32_MAX)});
  CHECK_NEON(3, double,
             {static_cast<double>(INT32_MIN), static_cast<double>(INT32_MIN),
              static_cast<double>(INT32_MIN), static_cast<double>(INT32_MIN),
              0.0, 0.0, 0.0, 0.0});
  CHECK_NEON(4, float,
             {static_cast<float>(INT32_MAX), static_cast<float>(INT32_MAX),
              static_cast<float>(INT32_MAX), static_cast<float>(INT32_MAX),
              static_cast<float>(INT32_MAX), static_cast<float>(INT32_MAX),
              static_cast<float>(INT32_MAX), static_cast<float>(INT32_MAX),
              static_cast<float>(INT32_MAX), static_cast<float>(INT32_MAX),
              static_cast<float>(INT32_MAX), static_cast<float>(INT32_MAX),
              static_cast<float>(INT32_MAX), static_cast<float>(INT32_MAX),
              static_cast<float>(INT32_MAX), static_cast<float>(INT32_MAX)});
  CHECK_NEON(5, float,
             {static_cast<float>(INT32_MIN), static_cast<float>(INT32_MIN),
              static_cast<float>(INT32_MIN), static_cast<float>(INT32_MIN),
              static_cast<float>(INT32_MIN), static_cast<float>(INT32_MIN),
              static_cast<float>(INT32_MIN), static_cast<float>(INT32_MIN),
              0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f});
}

TEST_P(InstSve, sel) {
  // VL = 512-bits
  // 64-bit
  initialHeapData_.resize(128);
  uint64_t* heap64 = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  heap64[0] = 0xDEADBEEF;
  heap64[1] = 0x12345678;
  heap64[2] = 0x98765432;
  heap64[3] = 0xABCDEF01;
  heap64[4] = 0xDEADBEEF;
  heap64[5] = 0x12345678;
  heap64[6] = 0x98765432;
  heap64[7] = 0xABCDEF01;
  heap64[8] = 0xABCDEF01;
  heap64[9] = 0x98765432;
  heap64[10] = 0x12345678;
  heap64[11] = 0xDEADBEEF;
  heap64[12] = 0xABCDEF01;
  heap64[13] = 0x98765432;
  heap64[14] = 0x12345678;
  heap64[15] = 0xDEADBEEF;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #8
    ptrue p0.d
    ld1d {z0.d}, p0/z, [x0, x1, lsl #3]
    ld1d {z1.d}, p0/z, [x0, x2, lsl #3]

    mov x3, #4
    whilelo p1.d, xzr, x3

    sel z2.d, p1, z0.d, z1.d
  )");
  CHECK_NEON(2, uint64_t,
             {0xDEADBEEF, 0x12345678, 0x98765432, 0xABCDEF01, 0xABCDEF01,
              0x98765432, 0x12345678, 0xDEADBEEF});

  // 32-bit
  initialHeapData_.resize(128);
  uint32_t* heap32 = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap32[0] = 0xDEADBEEF;
  heap32[1] = 0x12345678;
  heap32[2] = 0x98765432;
  heap32[3] = 0xABCDEF01;
  heap32[4] = 0xDEADBEEF;
  heap32[5] = 0x12345678;
  heap32[6] = 0x98765432;
  heap32[7] = 0xABCDEF01;
  heap32[8] = 0xDEADBEEF;
  heap32[9] = 0x12345678;
  heap32[10] = 0x98765432;
  heap32[11] = 0xABCDEF01;
  heap32[12] = 0xDEADBEEF;
  heap32[13] = 0x12345678;
  heap32[14] = 0x98765432;
  heap32[15] = 0xABCDEF01;

  heap32[16] = 0xABCDEF01;
  heap32[17] = 0x98765432;
  heap32[18] = 0x12345678;
  heap32[19] = 0xDEADBEEF;
  heap32[20] = 0xABCDEF01;
  heap32[21] = 0x98765432;
  heap32[22] = 0x12345678;
  heap32[23] = 0xDEADBEEF;
  heap32[24] = 0xABCDEF01;
  heap32[25] = 0x98765432;
  heap32[26] = 0x12345678;
  heap32[27] = 0xDEADBEEF;
  heap32[28] = 0xABCDEF01;
  heap32[29] = 0x98765432;
  heap32[30] = 0x12345678;
  heap32[31] = 0xDEADBEEF;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #16
    ptrue p0.s
    ld1w {z0.s}, p0/z, [x0, x1, lsl #2]
    ld1w {z1.s}, p0/z, [x0, x2, lsl #2]

    mov x3, #8
    whilelo p1.s, xzr, x3

    sel z2.s, p1, z0.s, z1.s
  )");
  CHECK_NEON(2, uint64_t,
             {0x12345678DEADBEEF, 0xABCDEF0198765432, 0x12345678DEADBEEF,
              0xABCDEF0198765432, 0x98765432ABCDEF01, 0xDEADBEEF12345678,
              0x98765432ABCDEF01, 0xDEADBEEF12345678});
}

TEST_P(InstSve, smax) {
  // VL = 512-bits
  // 32-bit
  initialHeapData_.resize(128);
  int32_t* heap32 = reinterpret_cast<int32_t*>(initialHeapData_.data());
  heap32[0] = 1;
  heap32[1] = 2;
  heap32[2] = 3;
  heap32[3] = 4;
  heap32[4] = 5;
  heap32[5] = 6;
  heap32[6] = 7;
  heap32[7] = 8;
  heap32[8] = -9;
  heap32[9] = -10;
  heap32[10] = -11;
  heap32[11] = -12;
  heap32[12] = 13;
  heap32[13] = 14;
  heap32[14] = -15;
  heap32[15] = -1;

  heap32[16] = 16;
  heap32[17] = 15;
  heap32[18] = 14;
  heap32[19] = 13;
  heap32[20] = -12;
  heap32[21] = -11;
  heap32[22] = -10;
  heap32[23] = -9;
  heap32[24] = 8;
  heap32[25] = 7;
  heap32[26] = 6;
  heap32[27] = 5;
  heap32[28] = 4;
  heap32[29] = 3;
  heap32[30] = -2;
  heap32[31] = -1;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #16
    ptrue p0.s
    ld1w {z0.s}, p0/z, [x0, x1, lsl #2]
    ld1w {z1.s}, p0/z, [x0, x2, lsl #2]
    ld1w {z2.s}, p0/z, [x0, x2, lsl #2]
    ld1w {z3.s}, p0/z, [x0, x1, lsl #2]
    ld1w {z4.s}, p0/z, [x0, x1, lsl #2]
    ld1w {z5.s}, p0/z, [x0, x1, lsl #2]

    mov x3, #8
    whilelo p1.s, xzr, x3

    smax z1.s, p0/m, z1.s, z0.s
    smax z2.s, p1/m, z2.s, z0.s

    smax z3.s, z3.s, #0
    smax z4.s, z4.s, #-128
    smax z5.s, z5.s, #127
  )");
  CHECK_NEON(1, int32_t,
             {16, 15, 14, 13, 5, 6, 7, 8, 8, 7, 6, 5, 13, 14, -2, -1});
  CHECK_NEON(2, int32_t,
             {16, 15, 14, 13, 5, 6, 7, 8, 8, 7, 6, 5, 4, 3, -2, -1});
  CHECK_NEON(3, int32_t, {1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 13, 14, 0, 0});
  CHECK_NEON(4, int32_t,
             {1, 2, 3, 4, 5, 6, 7, 8, -9, -10, -11, -12, 13, 14, -15, -1});
  CHECK_NEON(5, int32_t,
             {127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
              127, 127, 127});
}

TEST_P(InstSve, smin) {
  // VL = 512-bits
  // 32-bit
  initialHeapData_.resize(128);
  int32_t* heap32 = reinterpret_cast<int32_t*>(initialHeapData_.data());
  heap32[0] = 1;
  heap32[1] = 2;
  heap32[2] = 3;
  heap32[3] = 4;
  heap32[4] = 5;
  heap32[5] = 6;
  heap32[6] = 7;
  heap32[7] = 8;
  heap32[8] = -9;
  heap32[9] = -10;
  heap32[10] = -11;
  heap32[11] = -12;
  heap32[12] = 13;
  heap32[13] = 14;
  heap32[14] = -15;
  heap32[15] = -1;

  heap32[16] = 16;
  heap32[17] = 15;
  heap32[18] = 14;
  heap32[19] = 13;
  heap32[20] = -12;
  heap32[21] = -11;
  heap32[22] = -10;
  heap32[23] = -9;
  heap32[24] = 8;
  heap32[25] = 7;
  heap32[26] = 6;
  heap32[27] = 5;
  heap32[28] = 4;
  heap32[29] = 3;
  heap32[30] = -2;
  heap32[31] = -1;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #16
    ptrue p0.s
    ld1w {z0.s}, p0/z, [x0, x1, lsl #2]
    ld1w {z1.s}, p0/z, [x0, x2, lsl #2]
    ld1w {z2.s}, p0/z, [x0, x2, lsl #2]

    mov x3, #8
    whilelo p1.s, xzr, x3

    smin z1.s, p0/m, z1.s, z0.s
    smin z2.s, p1/m, z2.s, z0.s

    sminv s3, p1, z1.s
    sminv s4, p0, z2.s
  )");
  CHECK_NEON(1, int32_t,
             {1, 2, 3, 4, -12, -11, -10, -9, -9, -10, -11, -12, 4, 3, -15, -1});
  CHECK_NEON(2, int32_t,
             {1, 2, 3, 4, -12, -11, -10, -9, 8, 7, 6, 5, 4, 3, -2, -1});
  CHECK_NEON(3, int32_t, {-12, 0, 0, 0});
  CHECK_NEON(4, int32_t, {-12, 0, 0, 0});
}

TEST_P(InstSve, st1b) {
  // VL = 512-bit
  initialHeapData_.resize(64);
  initialHeapData_ = {
      0xEF, 0xBE, 0xAD, 0xDE, 0x78, 0x56, 0x34, 0x12, 0x32, 0x54, 0x76,
      0x98, 0x01, 0xEF, 0xCD, 0xAB, 0xEF, 0xBE, 0xAD, 0xDE, 0x78, 0x56,
      0x34, 0x12, 0x32, 0x54, 0x76, 0x98, 0x01, 0xEF, 0xCD, 0xAB, 0xEF,
      0xBE, 0xAD, 0xDE, 0x78, 0x56, 0x34, 0x12, 0x32, 0x54, 0x76, 0x98,
      0x01, 0xEF, 0xCD, 0xAB, 0xEF, 0xBE, 0xAD, 0xDE, 0x78, 0x56, 0x34,
      0x12, 0x32, 0x54, 0x76, 0x98, 0x01, 0xEF, 0xCD, 0xAB};

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    ptrue p0.b
    ld1b {z0.b}, p0/z, [x0, x1]
    st1b {z0.b}, p0, [sp, x1]

    mov x2, #32
    mov x3, #0
    whilelo p1.b, xzr, x2
    ld1b {z1.b}, p1/z, [x0, x3]
    st1b {z1.b}, p1, [x2, x3]
  )");
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer()),
            0x12345678DEADBEEF);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() + 8),
            0xABCDEF0198765432);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() + 16),
            0x12345678DEADBEEF);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() + 24),
            0xABCDEF0198765432);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() + 32),
            0x12345678DEADBEEF);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() + 40),
            0xABCDEF0198765432);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() + 48),
            0x12345678DEADBEEF);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() + 56),
            0xABCDEF0198765432);

  EXPECT_EQ(getMemoryValue<uint64_t>(32), 0x12345678DEADBEEF);
  EXPECT_EQ(getMemoryValue<uint64_t>(32 + 8), 0xABCDEF0198765432);
  EXPECT_EQ(getMemoryValue<uint64_t>(32 + 16), 0x12345678DEADBEEF);
  EXPECT_EQ(getMemoryValue<uint64_t>(32 + 24), 0xABCDEF0198765432);
}

TEST_P(InstSve, st1b_scatter) {
  // VL = 512-bit
  initialHeapData_.resize(128);
  uint64_t* heap64 = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  heap64[0] = 0xDEADBEEF;
  heap64[1] = 0x12345678;
  heap64[2] = 0x98765432;
  heap64[3] = 0xABCDEF01;
  heap64[4] = 0xDEADBEEF;
  heap64[5] = 0x12345678;
  heap64[6] = 0x98765432;
  heap64[7] = 0xABCDEF01;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #4
    mov x3, #107
    mov x4, #2
    mov x5, #512
    ptrue p0.d
    whilelo p1.d, xzr, x2

    index z0.d, #0, #3
    index z1.d, #0, #1
    index z2.d, #4, #10
    index z3.d, #15, #-10

    ld1d {z4.d}, p0/z, [x0, x1, lsl #3]
    ld1d {z5.d}, p0/z, [x0, x1, lsl #3]
    ld1d {z6.d}, p1/z, [x0, x4, lsl #3]
    ld1d {z7.d}, p1/z, [x0, x4, lsl #3]

    st1b {z4.d}, p0, [sp, z0.d]
    st1b {z5.d}, p0, [x5, z1.d]
    st1b {z6.d}, p1, [x3, z2.d]
    st1b {z7.d}, p1, [x3, z3.d]
  )");
  EXPECT_EQ(getMemoryValue<uint8_t>(process_->getStackPointer()), 0xEF);
  EXPECT_EQ(getMemoryValue<uint8_t>(process_->getStackPointer() + 3), 0x78);
  EXPECT_EQ(getMemoryValue<uint8_t>(process_->getStackPointer() + 6), 0x32);
  EXPECT_EQ(getMemoryValue<uint8_t>(process_->getStackPointer() + 9), 0x01);
  EXPECT_EQ(getMemoryValue<uint8_t>(process_->getStackPointer() + 12), 0xEF);
  EXPECT_EQ(getMemoryValue<uint8_t>(process_->getStackPointer() + 15), 0x78);
  EXPECT_EQ(getMemoryValue<uint8_t>(process_->getStackPointer() + 18), 0x32);
  EXPECT_EQ(getMemoryValue<uint8_t>(process_->getStackPointer() + 21), 0x01);

  EXPECT_EQ(getMemoryValue<uint8_t>(512), 0xEF);
  EXPECT_EQ(getMemoryValue<uint8_t>(512 + 1), 0x78);
  EXPECT_EQ(getMemoryValue<uint8_t>(512 + 2), 0x32);
  EXPECT_EQ(getMemoryValue<uint8_t>(512 + 3), 0x01);
  EXPECT_EQ(getMemoryValue<uint8_t>(512 + 4), 0xEF);
  EXPECT_EQ(getMemoryValue<uint8_t>(512 + 5), 0x78);
  EXPECT_EQ(getMemoryValue<uint8_t>(512 + 6), 0x32);
  EXPECT_EQ(getMemoryValue<uint8_t>(512 + 7), 0x01);

  EXPECT_EQ(getMemoryValue<uint8_t>(107 + 4), 0x32);
  EXPECT_EQ(getMemoryValue<uint8_t>(107 + 14), 0x01);
  EXPECT_EQ(getMemoryValue<uint8_t>(107 + 24), 0xEF);
  EXPECT_EQ(getMemoryValue<uint8_t>(107 + 34), 0x78);

  EXPECT_EQ(getMemoryValue<uint8_t>(107 + 15), 0x32);
  EXPECT_EQ(getMemoryValue<uint8_t>(107 + 5), 0x01);
  EXPECT_EQ(getMemoryValue<uint8_t>(107 + -5), 0xEF);
  EXPECT_EQ(getMemoryValue<uint8_t>(107 + -15), 0x78);
}

TEST_P(InstSve, st1d_scatter) {
  // VL = 512-bits
  // Vector plus imm
  RUN_AARCH64(R"(
    mov x0, #-24
    mov x1, #800
    index z1.d, x1, x0
    index z2.d, #8, #-4
    index z3.d, #8, #-5

    ptrue p0.d
    mov x1, #4
    whilelo p1.d, xzr, x1

    st1d {z2.d}, p0, [z1.d]
    st1d {z3.d}, p1, [z1.d, #240]
  )");
  EXPECT_EQ(getMemoryValue<uint64_t>(800), static_cast<uint64_t>(8));
  EXPECT_EQ(getMemoryValue<uint64_t>(800 - 24), static_cast<uint64_t>(4));
  EXPECT_EQ(getMemoryValue<uint64_t>(800 - 48), static_cast<uint64_t>(0));
  EXPECT_EQ(getMemoryValue<uint64_t>(800 - 72), static_cast<uint64_t>(-4));
  EXPECT_EQ(getMemoryValue<uint64_t>(800 - 96), static_cast<uint64_t>(-8));
  EXPECT_EQ(getMemoryValue<uint64_t>(800 - 120), static_cast<uint64_t>(-12));
  EXPECT_EQ(getMemoryValue<uint64_t>(800 - 144), static_cast<uint64_t>(-16));
  EXPECT_EQ(getMemoryValue<uint64_t>(800 - 168), static_cast<uint64_t>(-20));

  EXPECT_EQ(getMemoryValue<int64_t>(800 + (8 * 240) - 0),
            static_cast<uint64_t>(8));
  EXPECT_EQ(getMemoryValue<int64_t>(800 + (8 * 240) - 24),
            static_cast<uint64_t>(3));
  EXPECT_EQ(getMemoryValue<int64_t>(800 + (8 * 240) - 48),
            static_cast<uint64_t>(-2));
  EXPECT_EQ(getMemoryValue<int64_t>(800 + (8 * 240) - 72),
            static_cast<uint64_t>(-7));

  // Scalar plus Vector
  // 64-bit
  RUN_AARCH64(R"(
    mov x0, #-24
    mov x1, #800
    mov x2, #240
    index z1.d, xzr, x0
    index z2.d, #8, #-4
    index z3.d, #8, #-5
    index z4.d, #8, #2

    ptrue p0.d
    mov x3, #4
    whilelo p1.d, xzr, x3

    st1d {z2.d}, p1, [x1, z1.d]
    st1d {z3.d}, p0, [x2, z4.d, lsl #3]
  )");
  EXPECT_EQ(getMemoryValue<uint64_t>(800), static_cast<uint64_t>(8));
  EXPECT_EQ(getMemoryValue<uint64_t>(800 - 24), static_cast<uint64_t>(4));
  EXPECT_EQ(getMemoryValue<uint64_t>(800 - 48), static_cast<uint64_t>(0));
  EXPECT_EQ(getMemoryValue<uint64_t>(800 - 72), static_cast<uint64_t>(-4));

  EXPECT_EQ(getMemoryValue<int64_t>(240 + (8 << 3)), static_cast<uint64_t>(8));
  EXPECT_EQ(getMemoryValue<int64_t>(240 + (10 << 3)), static_cast<uint64_t>(3));
  EXPECT_EQ(getMemoryValue<int64_t>(240 + (12 << 3)),
            static_cast<uint64_t>(-2));
  EXPECT_EQ(getMemoryValue<int64_t>(240 + (14 << 3)),
            static_cast<uint64_t>(-7));
  EXPECT_EQ(getMemoryValue<int64_t>(240 + (16 << 3)),
            static_cast<uint64_t>(-12));
  EXPECT_EQ(getMemoryValue<int64_t>(240 + (18 << 3)),
            static_cast<uint64_t>(-17));
  EXPECT_EQ(getMemoryValue<int64_t>(240 + (20 << 3)),
            static_cast<uint64_t>(-22));
  EXPECT_EQ(getMemoryValue<int64_t>(240 + (22 << 3)),
            static_cast<uint64_t>(-27));
}

TEST_P(InstSve, st1d) {
  // VL = 512-bit
  initialHeapData_.resize(128);
  uint64_t* heap64 = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  heap64[0] = 0xDEADBEEF;
  heap64[1] = 0x12345678;
  heap64[2] = 0x98765432;
  heap64[3] = 0xABCDEF01;
  heap64[4] = 0xDEADBEEF;
  heap64[5] = 0x12345678;
  heap64[6] = 0x98765432;
  heap64[7] = 0xABCDEF01;
  heap64[8] = 0xDEADBEEF;
  heap64[9] = 0x12345678;
  heap64[10] = 0x98765432;
  heap64[11] = 0xABCDEF01;
  heap64[12] = 0xDEADBEEF;
  heap64[13] = 0x12345678;
  heap64[14] = 0x98765432;
  heap64[15] = 0xABCDEF01;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x4, #512
    ptrue p0.d
    ld1d {z0.d}, p0/z, [x0, x1, lsl #3]
    ld1d {z2.d}, p0/z, [x0, x1, lsl #3]
    st1d {z0.d}, p0, [sp, x1, lsl #3]
    st1d {z2.d}, p0, [x4]

    mov x2, #4
    mov x3, #8
    mov x4, #2
    whilelo p1.d, xzr, x2
    ld1d {z1.d}, p1/z, [x0, x4, lsl #3]
    ld1d {z3.d}, p1/z, [x0, x4, lsl #3]
    st1d {z1.d}, p1, [x3, x4, lsl #3]
    st1d {z3.d}, p1, [x3, #4, mul vl]
  )");
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer()), 0xDEADBEEF);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() + 8),
            0x12345678);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() + 16),
            0x98765432);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() + 24),
            0xABCDEF01);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() + 32),
            0xDEADBEEF);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() + 40),
            0x12345678);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() + 48),
            0x98765432);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() + 56),
            0xABCDEF01);

  EXPECT_EQ(getMemoryValue<uint64_t>(512), 0xDEADBEEF);
  EXPECT_EQ(getMemoryValue<uint64_t>(512 + 8), 0x12345678);
  EXPECT_EQ(getMemoryValue<uint64_t>(512 + 16), 0x98765432);
  EXPECT_EQ(getMemoryValue<uint64_t>(512 + 24), 0xABCDEF01);
  EXPECT_EQ(getMemoryValue<uint64_t>(512 + 32), 0xDEADBEEF);
  EXPECT_EQ(getMemoryValue<uint64_t>(512 + 40), 0x12345678);
  EXPECT_EQ(getMemoryValue<uint64_t>(512 + 48), 0x98765432);
  EXPECT_EQ(getMemoryValue<uint64_t>(512 + 56), 0xABCDEF01);

  EXPECT_EQ(getMemoryValue<uint64_t>(8 + 16), 0x98765432);
  EXPECT_EQ(getMemoryValue<uint64_t>(8 + 24), 0xABCDEF01);
  EXPECT_EQ(getMemoryValue<uint64_t>(8 + 32), 0xDEADBEEF);
  EXPECT_EQ(getMemoryValue<uint64_t>(8 + 40), 0x12345678);

  EXPECT_EQ(getMemoryValue<uint64_t>(264), 0x98765432);
  EXPECT_EQ(getMemoryValue<uint64_t>(264 + 8), 0xABCDEF01);
  EXPECT_EQ(getMemoryValue<uint64_t>(264 + 16), 0xDEADBEEF);
  EXPECT_EQ(getMemoryValue<uint64_t>(264 + 24), 0x12345678);
}

TEST_P(InstSve, st1w_scatter) {
  // VL = 512-bit

  // 32-bit
  RUN_AARCH64(R"(
    index z1.s, #0, #12
    index z2.s, #8, #-4
    index z3.s, #8, #-4

    ptrue p0.s
    mov x1, #8
    whilelo p1.s, xzr, x1

    st1w {z2.s}, p0, [z1.s]
    st1w {z3.s}, p1, [z1.s, #80]
  )");
  EXPECT_EQ(getMemoryValue<uint32_t>(0), static_cast<uint32_t>(8));
  EXPECT_EQ(getMemoryValue<uint32_t>(0 + 12), static_cast<uint32_t>(4));
  EXPECT_EQ(getMemoryValue<uint32_t>(0 + 24), static_cast<uint32_t>(0));
  EXPECT_EQ(getMemoryValue<uint32_t>(0 + 36), static_cast<uint32_t>(-4));
  EXPECT_EQ(getMemoryValue<uint32_t>(0 + 48), static_cast<uint32_t>(-8));
  EXPECT_EQ(getMemoryValue<uint32_t>(0 + 60), static_cast<uint32_t>(-12));
  EXPECT_EQ(getMemoryValue<uint32_t>(0 + 72), static_cast<uint32_t>(-16));
  EXPECT_EQ(getMemoryValue<uint32_t>(0 + 84), static_cast<uint32_t>(-20));
  EXPECT_EQ(getMemoryValue<uint32_t>(0 + 96), static_cast<uint32_t>(-24));
  EXPECT_EQ(getMemoryValue<uint32_t>(0 + 108), static_cast<uint32_t>(-28));
  EXPECT_EQ(getMemoryValue<uint32_t>(0 + 120), static_cast<uint32_t>(-32));
  EXPECT_EQ(getMemoryValue<uint32_t>(0 + 132), static_cast<uint32_t>(-36));
  EXPECT_EQ(getMemoryValue<uint32_t>(0 + 144), static_cast<uint32_t>(-40));
  EXPECT_EQ(getMemoryValue<uint32_t>(0 + 156), static_cast<uint32_t>(-44));
  EXPECT_EQ(getMemoryValue<uint32_t>(0 + 168), static_cast<uint32_t>(-48));
  EXPECT_EQ(getMemoryValue<uint32_t>(0 + 180), static_cast<uint32_t>(-52));

  EXPECT_EQ(getMemoryValue<uint32_t>(0 + (4 * 80) + 0),
            static_cast<uint32_t>(8));
  EXPECT_EQ(getMemoryValue<uint32_t>(0 + (4 * 80) + 12),
            static_cast<uint32_t>(4));
  EXPECT_EQ(getMemoryValue<uint32_t>(0 + (4 * 80) + 24),
            static_cast<uint32_t>(0));
  EXPECT_EQ(getMemoryValue<uint32_t>(0 + (4 * 80) + 36),
            static_cast<uint32_t>(-4));
  EXPECT_EQ(getMemoryValue<uint32_t>(0 + (4 * 80) + 48),
            static_cast<uint32_t>(-8));
  EXPECT_EQ(getMemoryValue<uint32_t>(0 + (4 * 80) + 60),
            static_cast<uint32_t>(-12));
  EXPECT_EQ(getMemoryValue<uint32_t>(0 + (4 * 80) + 72),
            static_cast<uint32_t>(-16));
  EXPECT_EQ(getMemoryValue<uint32_t>(0 + (4 * 80) + 84),
            static_cast<uint32_t>(-20));

  // 64-bit
  RUN_AARCH64(R"(
    index z1.d, #0, #12
    index z2.d, #8, #-4
    index z3.d, #8, #-4

    ptrue p0.d
    mov x1, #4
    whilelo p1.d, xzr, x1

    st1w {z2.d}, p0, [z1.d]
    st1w {z3.d}, p1, [z1.d, #80]
  )");
  EXPECT_EQ(getMemoryValue<uint32_t>(0), static_cast<uint32_t>(8));
  EXPECT_EQ(getMemoryValue<uint32_t>(0 + 12), static_cast<uint32_t>(4));
  EXPECT_EQ(getMemoryValue<uint32_t>(0 + 24), static_cast<uint32_t>(0));
  EXPECT_EQ(getMemoryValue<uint32_t>(0 + 36), static_cast<uint32_t>(-4));
  EXPECT_EQ(getMemoryValue<uint32_t>(0 + 48), static_cast<uint32_t>(-8));
  EXPECT_EQ(getMemoryValue<uint32_t>(0 + 60), static_cast<uint32_t>(-12));
  EXPECT_EQ(getMemoryValue<uint32_t>(0 + 72), static_cast<uint32_t>(-16));
  EXPECT_EQ(getMemoryValue<uint32_t>(0 + 84), static_cast<uint32_t>(-20));

  EXPECT_EQ(getMemoryValue<uint32_t>(0 + (4 * 80) + 0),
            static_cast<uint32_t>(8));
  EXPECT_EQ(getMemoryValue<uint32_t>(0 + (4 * 80) + 12),
            static_cast<uint32_t>(4));
  EXPECT_EQ(getMemoryValue<uint32_t>(0 + (4 * 80) + 24),
            static_cast<uint32_t>(0));
  EXPECT_EQ(getMemoryValue<uint32_t>(0 + (4 * 80) + 36),
            static_cast<uint32_t>(-4));
}

TEST_P(InstSve, st1w) {
  // VL = 512-bit
  // 32-bit
  initialHeapData_.resize(64);
  uint32_t* heap32 = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap32[0] = 0xDEADBEEF;
  heap32[1] = 0x12345678;
  heap32[2] = 0x98765432;
  heap32[3] = 0xABCDEF01;
  heap32[4] = 0xDEADBEEF;
  heap32[5] = 0x12345678;
  heap32[6] = 0x98765432;
  heap32[7] = 0xABCDEF01;
  heap32[8] = 0xDEADBEEF;
  heap32[9] = 0x12345678;
  heap32[10] = 0x98765432;
  heap32[11] = 0xABCDEF01;
  heap32[12] = 0xDEADBEEF;
  heap32[13] = 0x12345678;
  heap32[14] = 0x98765432;
  heap32[15] = 0xABCDEF01;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x4, #64
    ptrue p0.s
    ld1w {z0.s}, p0/z, [x0, x1, lsl #2]
    ld1w {z2.s}, p0/z, [x0, x1, lsl #2]
    st1w {z0.s}, p0, [sp, x1, lsl #2]
    st1w {z2.s}, p0, [x4]
  )");
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer()), 0xDEADBEEF);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() + 4),
            0x12345678);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() + 8),
            0x98765432);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() + 12),
            0xABCDEF01);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() + 16),
            0xDEADBEEF);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() + 20),
            0x12345678);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() + 24),
            0x98765432);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() + 28),
            0xABCDEF01);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() + 32),
            0xDEADBEEF);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() + 36),
            0x12345678);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() + 40),
            0x98765432);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() + 44),
            0xABCDEF01);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() + 48),
            0xDEADBEEF);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() + 52),
            0x12345678);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() + 56),
            0x98765432);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() + 60),
            0xABCDEF01);

  EXPECT_EQ(getMemoryValue<uint32_t>(64), 0xDEADBEEF);
  EXPECT_EQ(getMemoryValue<uint32_t>(64 + 4), 0x12345678);
  EXPECT_EQ(getMemoryValue<uint32_t>(64 + 8), 0x98765432);
  EXPECT_EQ(getMemoryValue<uint32_t>(64 + 12), 0xABCDEF01);
  EXPECT_EQ(getMemoryValue<uint32_t>(64 + 16), 0xDEADBEEF);
  EXPECT_EQ(getMemoryValue<uint32_t>(64 + 20), 0x12345678);
  EXPECT_EQ(getMemoryValue<uint32_t>(64 + 24), 0x98765432);
  EXPECT_EQ(getMemoryValue<uint32_t>(64 + 28), 0xABCDEF01);
  EXPECT_EQ(getMemoryValue<uint32_t>(64 + 32), 0xDEADBEEF);
  EXPECT_EQ(getMemoryValue<uint32_t>(64 + 36), 0x12345678);
  EXPECT_EQ(getMemoryValue<uint32_t>(64 + 40), 0x98765432);
  EXPECT_EQ(getMemoryValue<uint32_t>(64 + 44), 0xABCDEF01);
  EXPECT_EQ(getMemoryValue<uint32_t>(64 + 48), 0xDEADBEEF);
  EXPECT_EQ(getMemoryValue<uint32_t>(64 + 52), 0x12345678);
  EXPECT_EQ(getMemoryValue<uint32_t>(64 + 56), 0x98765432);
  EXPECT_EQ(getMemoryValue<uint32_t>(64 + 60), 0xABCDEF01);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x2, #8
    mov x3, #4
    whilelo p1.s, xzr, x2
    ld1w {z3.s}, p1/z, [x0, x3, lsl #2]
    st1w {z3.s}, p1, [x2, #4, mul vl]
    ld1w {z1.s}, p1/z, [x0, x3, lsl #2]
    st1w {z1.s}, p1, [x2, x3, lsl #2]
  )");

  EXPECT_EQ(getMemoryValue<uint32_t>(8 + 16), 0xDEADBEEF);
  EXPECT_EQ(getMemoryValue<uint32_t>(8 + 20), 0x12345678);
  EXPECT_EQ(getMemoryValue<uint32_t>(8 + 24), 0x98765432);
  EXPECT_EQ(getMemoryValue<uint32_t>(8 + 28), 0xABCDEF01);
  EXPECT_EQ(getMemoryValue<uint32_t>(8 + 32), 0xDEADBEEF);
  EXPECT_EQ(getMemoryValue<uint32_t>(8 + 36), 0x12345678);
  EXPECT_EQ(getMemoryValue<uint32_t>(8 + 40), 0x98765432);
  EXPECT_EQ(getMemoryValue<uint32_t>(8 + 44), 0xABCDEF01);

  EXPECT_EQ(getMemoryValue<uint32_t>(264), 0xDEADBEEF);
  EXPECT_EQ(getMemoryValue<uint32_t>(264 + 4), 0x12345678);
  EXPECT_EQ(getMemoryValue<uint32_t>(264 + 8), 0x98765432);
  EXPECT_EQ(getMemoryValue<uint32_t>(264 + 12), 0xABCDEF01);
  EXPECT_EQ(getMemoryValue<uint32_t>(264 + 16), 0xDEADBEEF);
  EXPECT_EQ(getMemoryValue<uint32_t>(264 + 20), 0x12345678);
  EXPECT_EQ(getMemoryValue<uint32_t>(264 + 24), 0x98765432);
  EXPECT_EQ(getMemoryValue<uint32_t>(264 + 28), 0xABCDEF01);

  // 64-bit
  initialHeapData_.resize(64);
  uint64_t* heap64 = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  heap64[0] = 0xDEADBEEFDEADBEEF;
  heap64[1] = 0x1234567812345678;
  heap64[2] = 0x9876543298765432;
  heap64[3] = 0xABCDEF01ABCDEF01;
  heap64[4] = 0xDEADBEEFDEADBEEF;
  heap64[5] = 0x1234567812345678;
  heap64[6] = 0x9876543298765432;
  heap64[7] = 0xABCDEF01ABCDEF01;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x4, #64
    mov x5, #3
    ptrue p0.d
    ld1d {z0.d}, p0/z, [x0, x1, lsl #3]
    ld1d {z2.d}, p0/z, [x0, x1, lsl #3]
    st1w {z0.d}, p0, [sp, x1, lsl #2]
    st1w {z2.d}, p0, [x4, x5, lsl #2]
  )");
  CHECK_NEON(0, uint64_t,
             {0xDEADBEEFDEADBEEFu, 0x1234567812345678u, 0x9876543298765432u,
              0xABCDEF01ABCDEF01u, 0xDEADBEEFDEADBEEFu, 0x1234567812345678u,
              0x9876543298765432u, 0xABCDEF01ABCDEF01u});
  CHECK_NEON(2, uint64_t,
             {0xDEADBEEFDEADBEEFu, 0x1234567812345678u, 0x9876543298765432u,
              0xABCDEF01ABCDEF01u, 0xDEADBEEFDEADBEEFu, 0x1234567812345678u,
              0x9876543298765432u, 0xABCDEF01ABCDEF01u});

  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer()), 0xDEADBEEF);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() + 4),
            0x12345678);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() + 8),
            0x98765432);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() + 12),
            0xABCDEF01);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() + 16),
            0xDEADBEEF);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() + 20),
            0x12345678);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() + 24),
            0x98765432);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() + 28),
            0xABCDEF01);

  EXPECT_EQ(getMemoryValue<uint32_t>(64 + (3 * 4)), 0xDEADBEEF);
  EXPECT_EQ(getMemoryValue<uint32_t>(64 + (3 * 4) + 4), 0x12345678);
  EXPECT_EQ(getMemoryValue<uint32_t>(64 + (3 * 4) + 8), 0x98765432);
  EXPECT_EQ(getMemoryValue<uint32_t>(64 + (3 * 4) + 12), 0xABCDEF01);
  EXPECT_EQ(getMemoryValue<uint32_t>(64 + (3 * 4) + 16), 0xDEADBEEF);
  EXPECT_EQ(getMemoryValue<uint32_t>(64 + (3 * 4) + 20), 0x12345678);
  EXPECT_EQ(getMemoryValue<uint32_t>(64 + (3 * 4) + 24), 0x98765432);
  EXPECT_EQ(getMemoryValue<uint32_t>(64 + (3 * 4) + 28), 0xABCDEF01);
}

TEST_P(InstSve, str_predicate) {
  // VL = 512-bit
  initialHeapData_.resize(32);
  uint64_t* heap64 = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  heap64[0] = 0xFFFFFFFFFFFFFFFF;
  heap64[1] = 0x0;
  heap64[2] = 0xDEADBEEFDEADBEEF;
  heap64[3] = 0x1234567812345678;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #8
    ldr p0, [x0, #0, mul vl]
    ldr p1, [x0, #1, mul vl]
    ldr p2, [x0, #2, mul vl]
    ldr p3, [x0, #3, mul vl]

    str p0, [sp, #0, mul vl]
    str p1, [sp, #1, mul vl]
    str p2, [x1, #2, mul vl]
    str p3, [x1, #3, mul vl]
  )");
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer()),
            0xFFFFFFFFFFFFFFFF);

  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() + 8), 0);

  EXPECT_EQ(getMemoryValue<uint64_t>(8 + 16), 0xDEADBEEFDEADBEEF);

  EXPECT_EQ(getMemoryValue<uint64_t>(8 + 24), 0x1234567812345678);
}

TEST_P(InstSve, str_vector) {
  // VL = 512-bit
  initialHeapData_.resize(128);
  uint64_t* heap64 = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  heap64[0] = 0xFFFFFFFFFFFFFFFF;
  heap64[1] = 0x0;
  heap64[2] = 0xDEADBEEFDEADBEEF;
  heap64[3] = 0x1234567812345678;
  heap64[4] = 0xFFFFFFFFFFFFFFFF;
  heap64[5] = 0x98765432ABCDEF01;
  heap64[6] = 0xDEADBEEFDEADBEEF;
  heap64[7] = 0x1234567812345678;

  heap64[8] = 0x1234567812345678;
  heap64[9] = 0xDEADBEEFDEADBEEF;
  heap64[10] = 0x98765432ABCDEF01;
  heap64[11] = 0xFFFFFFFFFFFFFFFF;
  heap64[12] = 0x1234567812345678;
  heap64[13] = 0xDEADBEEFDEADBEEF;
  heap64[14] = 0x0;
  heap64[15] = 0xFFFFFFFFFFFFFFFF;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    
    mov x1, #512
    ldr z0, [x0, #0, mul vl]
    ldr z1, [x0, #1, mul vl]

    str z0, [sp, #0, mul vl]
    str z1, [x1, #3, mul vl]
  )");
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer()),
            0xFFFFFFFFFFFFFFFF);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() + 8), 0x0);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() + 16),
            0xDEADBEEFDEADBEEF);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() + 24),
            0x1234567812345678);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() + 32),
            0xFFFFFFFFFFFFFFFF);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() + 40),
            0x98765432ABCDEF01);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() + 48),
            0xDEADBEEFDEADBEEF);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() + 56),
            0x1234567812345678);

  EXPECT_EQ(getMemoryValue<uint64_t>(512 + 192), 0x1234567812345678);
  EXPECT_EQ(getMemoryValue<uint64_t>(512 + 200), 0xDEADBEEFDEADBEEF);
  EXPECT_EQ(getMemoryValue<uint64_t>(512 + 208), 0x98765432ABCDEF01);
  EXPECT_EQ(getMemoryValue<uint64_t>(512 + 216), 0xFFFFFFFFFFFFFFFF);
  EXPECT_EQ(getMemoryValue<uint64_t>(512 + 224), 0x1234567812345678);
  EXPECT_EQ(getMemoryValue<uint64_t>(512 + 232), 0xDEADBEEFDEADBEEF);
  EXPECT_EQ(getMemoryValue<uint64_t>(512 + 240), 0x0);
  EXPECT_EQ(getMemoryValue<uint64_t>(512 + 248), 0xFFFFFFFFFFFFFFFF);
}

TEST_P(InstSve, sub) {
  // VL = 512-bit
  // SUB (Vectors, unpredicated)
  RUN_AARCH64(R"(
    # Initialise vectors
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
  CHECK_NEON(8, uint8_t,
             {0xe1, 0xca, 0xb3, 0x9c, 0x85, 0x6e, 0x57, 0x40, 0x29, 0x12, 0xfb,
              0xe4, 0xcd, 0xb6, 0x9f, 0x88, 0x71, 0x5a, 0x43, 0x2c, 0x15, 0xfe,
              0xe7, 0xd0, 0xb9, 0xa2, 0x8b, 0x74, 0x5d, 0x46, 0x2f, 0x18, 0x1,
              0xea, 0xd3, 0xbc, 0xa5, 0x8e, 0x77, 0x60, 0x49, 0x32, 0x1b, 0x4,
              0xed, 0xd6, 0xbf, 0xa8, 0x91, 0x7a, 0x63, 0x4c, 0x35, 0x1e, 0x7,
              0xf0, 0xd9, 0xc2, 0xab, 0x94, 0x7d, 0x66, 0x4f, 0x38});
  CHECK_NEON(9, uint8_t,
             {0x1f, 0x36, 0x4d, 0x64, 0x7b, 0x92, 0xa9, 0xc0, 0xd7, 0xee, 0x5,
              0x1c, 0x33, 0x4a, 0x61, 0x78, 0x8f, 0xa6, 0xbd, 0xd4, 0xeb, 0x2,
              0x19, 0x30, 0x47, 0x5e, 0x75, 0x8c, 0xa3, 0xba, 0xd1, 0xe8, 0xff,
              0x16, 0x2d, 0x44, 0x5b, 0x72, 0x89, 0xa0, 0xb7, 0xce, 0xe5, 0xfc,
              0x13, 0x2a, 0x41, 0x58, 0x6f, 0x86, 0x9d, 0xb4, 0xcb, 0xe2, 0xf9,
              0x10, 0x27, 0x3e, 0x55, 0x6c, 0x83, 0x9a, 0xb1, 0xc8});
  CHECK_NEON(10, uint16_t,
             {0xfff5, 0xffe4, 0xffd3, 0xffc2, 0xffb1, 0xffa0, 0xff8f, 0xff7e,
              0xff6d, 0xff5c, 0xff4b, 0xff3a, 0xff29, 0xff18, 0xff07, 0xfef6,
              0xfee5, 0xfed4, 0xfec3, 0xfeb2, 0xfea1, 0xfe90, 0xfe7f, 0xfe6e,
              0xfe5d, 0xfe4c, 0xfe3b, 0xfe2a, 0xfe19, 0xfe08, 0xfdf7, 0xfde6});
  CHECK_NEON(11, uint16_t,
             {0xb,   0x1c,  0x2d,  0x3e,  0x4f,  0x60,  0x71,  0x82,
              0x93,  0xa4,  0xb5,  0xc6,  0xd7,  0xe8,  0xf9,  0x10a,
              0x11b, 0x12c, 0x13d, 0x14e, 0x15f, 0x170, 0x181, 0x192,
              0x1a3, 0x1b4, 0x1c5, 0x1d6, 0x1e7, 0x1f8, 0x209, 0x21a});
  CHECK_NEON(
      12, uint32_t,
      {0xffffffee, 0xffffffe0, 0xffffffd2, 0xffffffc4, 0xffffffb6, 0xffffffa8,
       0xffffff9a, 0xffffff8c, 0xffffff7e, 0xffffff70, 0xffffff62, 0xffffff54,
       0xffffff46, 0xffffff38, 0xffffff2a, 0xffffff1c});
  CHECK_NEON(13, uint32_t,
             {0x12, 0x20, 0x2e, 0x3c, 0x4a, 0x58, 0x66, 0x74, 0x82, 0x90, 0x9e,
              0xac, 0xba, 0xc8, 0xd6, 0xe4});
  CHECK_NEON(14, uint64_t,
             {0xfffffffffffffff1, 0xffffffffffffffde, 0xffffffffffffffcb,
              0xffffffffffffffb8, 0xffffffffffffffa5, 0xffffffffffffff92,
              0xffffffffffffff7f, 0xffffffffffffff6c});
  CHECK_NEON(15, uint64_t, {0xf, 0x22, 0x35, 0x48, 0x5b, 0x6e, 0x81, 0x94});
}

TEST_P(InstSve, sxtw) {
  // VL = 512-bit
  initialHeapData_.resize(128);
  uint64_t* heap64 = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  heap64[0] = 0xFFFFFFFFFFFFFFFF;
  heap64[1] = 0x0;
  heap64[2] = 0xDEADBEEFDEADBEEF;
  heap64[3] = 0x1234567812345678;
  heap64[4] = 0xFFFFFFFFFFFFFFFF;
  heap64[5] = 0x98765432ABCDEF01;
  heap64[6] = 0xDEADBEEFDEADBEEF;
  heap64[7] = 0x1234567812345678;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    
    ptrue p0.d
    mov x1, #4
    mov x2, #0
    whilelo p1.d, xzr, x1

    dup z2.d, #0xF

    ld1d {z0.d}, p0/z, [x0, x2, lsl #3]

    sxtw z1.d, p0/m, z0.d
    sxtw z2.d, p1/m, z0.d
  )");
  CHECK_NEON(
      1, int64_t,
      {-1, 0, -559038737, 305419896, -1, -1412567295, -559038737, 305419896});
  CHECK_NEON(2, int64_t, {-1, 0, -559038737, 305419896, 0xF, 0xF, 0xF, 0xF});
}

TEST_P(InstSve, uqdec) {
  // VL = 512-bit
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
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 968);
  EXPECT_EQ(getGeneralRegister<uint64_t>(1), 1016);
  EXPECT_EQ(getGeneralRegister<uint64_t>(2), 0);
  EXPECT_EQ(getGeneralRegister<uint32_t>(3), 968);
  EXPECT_EQ(getGeneralRegister<uint32_t>(4), 1016);
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
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 800);
  EXPECT_EQ(getGeneralRegister<uint64_t>(1), 992);
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
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 912);
  EXPECT_EQ(getGeneralRegister<uint64_t>(1), 1008);
  EXPECT_EQ(getGeneralRegister<uint64_t>(2), 0);
}

TEST_P(InstSve, uunpklo) {
  // VL = 512-bit
  initialHeapData_.resize(128);
  uint32_t* heap32 = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap32[0] = 0xFFFFFFFF;
  heap32[1] = 0xFFFFFFFF;
  heap32[2] = 0xFFFFFFFF;
  heap32[3] = 0xFFFFFFFF;
  heap32[4] = 0xFFFFFFFF;
  heap32[5] = 0xFFFFFFFF;
  heap32[6] = 0xFFFFFFFF;
  heap32[7] = 0xFFFFFFFF;
  heap32[8] = 0xFFFFFFFF;
  heap32[9] = 0xFFFFFFFF;
  heap32[10] = 0xFFFFFFFF;
  heap32[11] = 0xFFFFFFFF;
  heap32[12] = 0xFFFFFFFF;
  heap32[13] = 0xFFFFFFFF;
  heap32[14] = 0xFFFFFFFF;
  heap32[15] = 0xFFFFFFFF;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    dup z0.b, #0
    dup z1.h, #0
    dup z2.s, #0

    mov x1, #32
    mov x2, #16
    mov x3, #8
    mov x4, #0

    whilelo p0.b, xzr, x1
    whilelo p1.h, xzr, x2
    whilelo p2.s, xzr, x3

    # Fill only first half of vector with -1
    ld1b {z0.b}, p0/z, [x0, x4]
    ld1h {z1.h}, p1/z, [x0, x4, lsl #1]
    ld1w {z2.s}, p2/z, [x0, x4, lsl #2]

    uunpklo z3.h, z0.b
    uunpklo z4.s, z1.h
    uunpklo z5.d, z2.s 
  )");
  CHECK_NEON(
      0, uint8_t,
      {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu,
       0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu,
       0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu,
       0xFFu, 0xFFu, 0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0})
  CHECK_NEON(
      1, uint16_t,
      {0xFFFFu, 0xFFFFu, 0xFFFFu, 0xFFFFu, 0xFFFFu, 0xFFFFu, 0xFFFFu, 0xFFFFu,
       0xFFFFu, 0xFFFFu, 0xFFFFu, 0xFFFFu, 0xFFFFu, 0xFFFFu, 0xFFFFu, 0xFFFFu,
       0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0})
  CHECK_NEON(2, uint32_t,
             {0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu,
              0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0, 0, 0, 0, 0, 0, 0, 0})
  CHECK_NEON(3, uint16_t,
             {0x00FF, 0x00FF, 0x00FF, 0x00FF, 0x00FF, 0x00FF, 0x00FF, 0x00FF,
              0x00FF, 0x00FF, 0x00FF, 0x00FF, 0x00FF, 0x00FF, 0x00FF, 0x00FF,
              0x00FF, 0x00FF, 0x00FF, 0x00FF, 0x00FF, 0x00FF, 0x00FF, 0x00FF,
              0x00FF, 0x00FF, 0x00FF, 0x00FF, 0x00FF, 0x00FF, 0x00FF, 0x00FF});
  CHECK_NEON(
      4, uint32_t,
      {0x0000FFFF, 0x0000FFFF, 0x0000FFFF, 0x0000FFFF, 0x0000FFFF, 0x0000FFFF,
       0x0000FFFF, 0x0000FFFF, 0x0000FFFF, 0x0000FFFF, 0x0000FFFF, 0x0000FFFF,
       0x0000FFFF, 0x0000FFFF, 0x0000FFFF, 0x0000FFFF});
  CHECK_NEON(5, uint64_t,
             {0x00000000FFFFFFFF, 0x00000000FFFFFFFF, 0x00000000FFFFFFFF,
              0x00000000FFFFFFFF, 0x00000000FFFFFFFF, 0x00000000FFFFFFFF,
              0x00000000FFFFFFFF, 0x00000000FFFFFFFF});
}

TEST_P(InstSve, uunpkhi) {
  // VL = 512-bit

  // 8-bit
  initialHeapData_.resize(128);
  initialHeapData_ = {
      0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
      0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
      0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0 
    mov x2, #64

    whilelo p0.b, xzr, x2

    # Fill whole vecotr with -1
    ld1b {z0.b}, p0/z, [x0, x1]

    uunpkhi z1.h, z0.b
  )");
  CHECK_NEON(
      0, uint8_t,
      {0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu,
       0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu,
       0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu,
       0xFFu, 0xFFu, 0xFFu, 0xFFu})
  CHECK_NEON(1, uint16_t,
             {0x00FF, 0x00FF, 0x00FF, 0x00FF, 0x00FF, 0x00FF, 0x00FF, 0x00FF,
              0x00FF, 0x00FF, 0x00FF, 0x00FF, 0x00FF, 0x00FF, 0x00FF, 0x00FF,
              0x00FF, 0x00FF, 0x00FF, 0x00FF, 0x00FF, 0x00FF, 0x00FF, 0x00FF,
              0x00FF, 0x00FF, 0x00FF, 0x00FF, 0x00FF, 0x00FF, 0x00FF, 0x00FF});

  // 16-bit
  initialHeapData_.resize(128);
  uint16_t* heap16 = reinterpret_cast<uint16_t*>(initialHeapData_.data());
  heap16[0] = 0;
  heap16[1] = 0;
  heap16[2] = 0;
  heap16[3] = 0;
  heap16[4] = 0;
  heap16[5] = 0;
  heap16[6] = 0;
  heap16[7] = 0;
  heap16[8] = 0;
  heap16[9] = 0;
  heap16[10] = 0;
  heap16[11] = 0;
  heap16[12] = 0;
  heap16[13] = 0;
  heap16[14] = 0;
  heap16[15] = 0;
  heap16[16] = 0xFFFF;
  heap16[17] = 0xFFFF;
  heap16[18] = 0xFFFF;
  heap16[19] = 0xFFFF;
  heap16[20] = 0xFFFF;
  heap16[21] = 0xFFFF;
  heap16[22] = 0xFFFF;
  heap16[23] = 0xFFFF;
  heap16[24] = 0xFFFF;
  heap16[25] = 0xFFFF;
  heap16[26] = 0xFFFF;
  heap16[27] = 0xFFFF;
  heap16[28] = 0xFFFF;
  heap16[29] = 0xFFFF;
  heap16[30] = 0xFFFF;
  heap16[31] = 0xFFFF;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #32
    
    whilelo p0.h, xzr, x2

    ld1h {z0.h}, p0/z, [x0, x1, lsl #1]

    uunpkhi z1.s, z0.h
  )");
  CHECK_NEON(
      0, uint16_t,
      {0,       0,       0,       0,       0,       0,       0,       0,
       0,       0,       0,       0,       0,       0,       0,       0,
       0xFFFFu, 0xFFFFu, 0xFFFFu, 0xFFFFu, 0xFFFFu, 0xFFFFu, 0xFFFFu, 0xFFFFu,
       0xFFFFu, 0xFFFFu, 0xFFFFu, 0xFFFFu, 0xFFFFu, 0xFFFFu, 0xFFFFu, 0xFFFFu})
  CHECK_NEON(
      1, uint32_t,
      {0x0000FFFF, 0x0000FFFF, 0x0000FFFF, 0x0000FFFF, 0x0000FFFF, 0x0000FFFF,
       0x0000FFFF, 0x0000FFFF, 0x0000FFFF, 0x0000FFFF, 0x0000FFFF, 0x0000FFFF,
       0x0000FFFF, 0x0000FFFF, 0x0000FFFF, 0x0000FFFF});

  // 32-bit
  initialHeapData_.resize(128);
  uint32_t* heap32 = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap32[0] = 0;
  heap32[1] = 0;
  heap32[2] = 0;
  heap32[3] = 0;
  heap32[4] = 0;
  heap32[5] = 0;
  heap32[6] = 0;
  heap32[7] = 0;
  heap32[8] = 0xFFFFFFFF;
  heap32[9] = 0xFFFFFFFF;
  heap32[10] = 0xFFFFFFFF;
  heap32[11] = 0xFFFFFFFF;
  heap32[12] = 0xFFFFFFFF;
  heap32[13] = 0xFFFFFFFF;
  heap32[14] = 0xFFFFFFFF;
  heap32[15] = 0xFFFFFFFF;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #16

    whilelo p0.s, xzr, x2

    ld1w {z0.s}, p0/z, [x0, x1, lsl #2]

    uunpkhi z1.d, z0.s 
  )");
  CHECK_NEON(0, uint32_t,
             {0, 0, 0, 0, 0, 0, 0, 0, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu,
              0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu})
  CHECK_NEON(1, uint64_t,
             {0x00000000FFFFFFFF, 0x00000000FFFFFFFF, 0x00000000FFFFFFFF,
              0x00000000FFFFFFFF, 0x00000000FFFFFFFF, 0x00000000FFFFFFFF,
              0x00000000FFFFFFFF, 0x00000000FFFFFFFF});
}

TEST_P(InstSve, uzp1) {
  RUN_AARCH64(R"(
    dup z0.s, #1
    dup z1.s, #2

    uzp1 z2.s, z1.s, z0.s

    mov x0, #8
    whilelo p0.s, xzr, x0

    fmul z1.s, p0/m, z1.s, #2

    uzp1 z4.s, z1.s, z0.s
  )");

  CHECK_NEON(2, uint32_t, {2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1});
  CHECK_NEON(4, uint32_t, {4, 4, 4, 4, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1});
}

TEST_P(InstSve, whilelo) {
  // VL = 512-bits
  // 8-bit arrangement, 64-bit source operands
  RUN_AARCH64(R"(
    mov x0, #64

    whilelo p0.b, xzr, x0
  )");
  CHECK_PREDICATE(0, uint8_t, {255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0,
                               0,   0,   0,   0,   0,   0,   0,   0,   0, 0, 0,
                               0,   0,   0,   0,   0,   0,   0,   0,   0, 0});
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #64
    mov x1, #32

    whilelo p1.b, x1, x0
  )");
  CHECK_PREDICATE(1, uint8_t,
                  {255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                   0,   0,   0,   0,   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov x0, #64
    mov x2, #44

    whilelo p2.b, x2, x0
  )");
  CHECK_PREDICATE(2, uint8_t,
                  {255, 255, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                   0,   0,   0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov x0, #64
    mov x3, #20

    whilelo p3.b, x3, x0
  )");
  CHECK_PREDICATE(3, uint8_t,
                  {255, 255, 255, 255, 255, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                   0,   0,   0,   0,   0,   0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    whilelo p4.b, xzr, xzr
  )");
  CHECK_PREDICATE(4, uint8_t, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b0110);

  // 16-bit arrangement, 64-bit source operands
  RUN_AARCH64(R"(
    mov x0, #32

    whilelo p0.h, xzr, x0
  )");
  CHECK_PREDICATE(
      0, uint16_t,
      {21845, 21845, 21845, 21845, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #32
    mov x1, #16

    whilelo p1.h, x1, x0
  )");
  CHECK_PREDICATE(1, uint16_t,
                  {21845, 21845, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov x0, #32
    mov x2, #27

    whilelo p2.h, x2, x0
  )");
  CHECK_PREDICATE(2, uint16_t,
                  {341, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov x0, #32
    mov x3, #10

    whilelo p3.h, x3, x0
  )");
  CHECK_PREDICATE(3, uint16_t,
                  {21845, 21845, 1365, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    whilelo p4.h, xzr, xzr
  )");
  CHECK_PREDICATE(4, uint16_t,
                  {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b0110);

  // 32-bit arrangement, 64-bit source operands
  RUN_AARCH64(R"(
    mov x0, #16

    whilelo p0.s, xzr, x0
  )");
  CHECK_PREDICATE(0, uint32_t, {286331153, 286331153, 0, 0, 0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #16
    mov x1, #8

    whilelo p1.s, x1, x0
  )");
  CHECK_PREDICATE(1, uint32_t, {286331153, 0, 0, 0, 0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov x0, #16
    mov x2, #11

    whilelo p2.s, x2, x0
  )");
  CHECK_PREDICATE(2, uint32_t, {69905, 0, 0, 0, 0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov x0, #16
    mov x3, #5

    whilelo p3.s, x3, x0
  )");
  CHECK_PREDICATE(3, uint32_t, {286331153, 273, 0, 0, 0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    whilelo p4.s, xzr, xzr
  )");
  CHECK_PREDICATE(4, uint32_t, {0, 0, 0, 0, 0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b0110);

  // 64-bit arrangement, 64-bit source operands
  RUN_AARCH64(R"(
    mov x0, #8

    whilelo p0.d, xzr, x0
  )");
  CHECK_PREDICATE(0, uint32_t, {0x1010101, 0x1010101, 0, 0, 0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov x0, #8
    mov x1, #4

    whilelo p1.d, x1, x0
  )");
  CHECK_PREDICATE(1, uint32_t, {0x1010101, 0, 0, 0, 0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov x0, #8
    mov x2, #5

    whilelo p2.d, x2, x0
  )");
  CHECK_PREDICATE(2, uint32_t, {0x10101, 0, 0, 0, 0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov x0, #8
    mov x3, #2

    whilelo p3.d, x3, x0
  )");
  CHECK_PREDICATE(3, uint32_t, {0x1010101, 0x101, 0, 0, 0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    whilelo p4.d, xzr, xzr
  )");
  CHECK_PREDICATE(4, uint32_t, {0, 0, 0, 0, 0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b0110);

  // --------------------------------------------------------------------

  // 8-bit arrangement, 32-bit source operands
  RUN_AARCH64(R"(
    mov w0, #64

    whilelo p0.b, wzr, w0
  )");
  CHECK_PREDICATE(0, uint8_t, {255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0,
                               0,   0,   0,   0,   0,   0,   0,   0,   0, 0, 0,
                               0,   0,   0,   0,   0,   0,   0,   0,   0, 0});
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov w0, #64
    mov w1, #32

    whilelo p1.b, w1, w0
  )");
  CHECK_PREDICATE(1, uint8_t,
                  {255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                   0,   0,   0,   0,   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov w0, #64
    mov w2, #44

    whilelo p2.b, w2, w0
  )");
  CHECK_PREDICATE(2, uint8_t,
                  {255, 255, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                   0,   0,   0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov w0, #64
    mov w3, #20

    whilelo p3.b, w3, w0
  )");
  CHECK_PREDICATE(3, uint8_t,
                  {255, 255, 255, 255, 255, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                   0,   0,   0,   0,   0,   0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    whilelo p4.b, wzr, wzr
  )");
  CHECK_PREDICATE(4, uint8_t, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b0110);

  // 16-bit arrangement, 32-bit source operands
  RUN_AARCH64(R"(
    mov w0, #32

    whilelo p0.h, wzr, w0
  )");
  CHECK_PREDICATE(
      0, uint16_t,
      {21845, 21845, 21845, 21845, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov w0, #32
    mov w1, #16

    whilelo p1.h, w1, w0
  )");
  CHECK_PREDICATE(1, uint16_t,
                  {21845, 21845, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov w0, #32
    mov w2, #27

    whilelo p2.h, w2, w0
  )");
  CHECK_PREDICATE(2, uint16_t,
                  {341, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov w0, #32
    mov w3, #10

    whilelo p3.h, w3, w0
  )");
  CHECK_PREDICATE(3, uint16_t,
                  {21845, 21845, 1365, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    whilelo p4.h, wzr, wzr
  )");
  CHECK_PREDICATE(4, uint16_t,
                  {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b0110);

  // 32-bit arrangement, 32-bit source operands
  RUN_AARCH64(R"(
    mov w0, #16

    whilelo p0.s, wzr, w0
  )");
  CHECK_PREDICATE(0, uint32_t, {286331153, 286331153, 0, 0, 0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov w0, #16
    mov w1, #8

    whilelo p1.s, w1, w0
  )");
  CHECK_PREDICATE(1, uint32_t, {286331153, 0, 0, 0, 0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov w0, #16
    mov w2, #11

    whilelo p2.s, w2, w0
  )");
  CHECK_PREDICATE(2, uint32_t, {69905, 0, 0, 0, 0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov w0, #16
    mov w3, #5

    whilelo p3.s, w3, w0
  )");
  CHECK_PREDICATE(3, uint32_t, {286331153, 273, 0, 0, 0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    whilelo p4.s, wzr, wzr
  )");
  CHECK_PREDICATE(4, uint32_t, {0, 0, 0, 0, 0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b0110);

  // 64-bit arrangement, 32-bit source operands
  RUN_AARCH64(R"(
    mov w0, #8

    whilelo p0.d, wzr, w0
  )");
  CHECK_PREDICATE(0, uint32_t, {0x1010101, 0x1010101, 0, 0, 0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1000);

  RUN_AARCH64(R"(
    mov w0, #8
    mov w1, #4

    whilelo p1.d, w1, w0
  )");
  CHECK_PREDICATE(1, uint32_t, {0x1010101, 0, 0, 0, 0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov w0, #8
    mov w2, #5

    whilelo p2.d, w2, w0
  )");
  CHECK_PREDICATE(2, uint32_t, {0x10101, 0, 0, 0, 0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    mov w0, #8
    mov w3, #2

    whilelo p3.d, w3, w0
  )");
  CHECK_PREDICATE(3, uint32_t, {0x1010101, 0x101, 0, 0, 0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    whilelo p4.d, wzr, wzr
  )");
  CHECK_PREDICATE(4, uint32_t, {0, 0, 0, 0, 0, 0, 0, 0});
  EXPECT_EQ(getNZCV(), 0b0110);
}

TEST_P(InstSve, zip_pred) {
  // VL = 512-bits
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
  CHECK_PREDICATE(
      8, uint8_t,
      {0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0, 0, 0, 0, 0, 0, 0, 0,
       0,    0,    0,    0,    0,    0,    0,    0,    0, 0, 0, 0, 0, 0, 0, 0});
  CHECK_PREDICATE(
      9, uint8_t,
      {0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0, 0, 0, 0, 0, 0, 0, 0,
       0,    0,    0,    0,    0,    0,    0,    0,    0, 0, 0, 0, 0, 0, 0, 0});
  CHECK_PREDICATE(10, uint8_t, {0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0, 0, 0,
                                0,   0,   0,   0,   0,   0,   0,   0,   0, 0, 0,
                                0,   0,   0,   0,   0,   0,   0,   0,   0, 0});
  CHECK_PREDICATE(11, uint8_t,
                  {0x1, 0, 0x1, 0, 0x1, 0, 0x1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                   0,   0, 0,   0, 0,   0, 0,   0, 0, 0, 0, 0, 0, 0, 0, 0});
  CHECK_PREDICATE(
      12, uint8_t,
      {0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0, 0, 0, 0, 0, 0, 0, 0,
       0,    0,    0,    0,    0,    0,    0,    0,    0, 0, 0, 0, 0, 0, 0, 0});
  CHECK_PREDICATE(
      13, uint8_t,
      {0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0, 0, 0, 0, 0, 0, 0, 0,
       0,    0,    0,    0,    0,    0,    0,    0,    0, 0, 0, 0, 0, 0, 0, 0});
  CHECK_PREDICATE(14, uint8_t, {0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0, 0, 0,
                                0,   0,   0,   0,   0,   0,   0,   0,   0, 0, 0,
                                0,   0,   0,   0,   0,   0,   0,   0,   0, 0});
  CHECK_PREDICATE(15, uint8_t,
                  {0x1, 0, 0x1, 0, 0x1, 0, 0x1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                   0,   0, 0,   0, 0,   0, 0,   0, 0, 0, 0, 0, 0, 0, 0, 0});
}

TEST_P(InstSve, zip) {
  // VL = 512-bits
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

  CHECK_NEON(4, double, {0.5, -0.5, 0.5, -0.5, 0.5, -0.5, 0.5, -0.5});
  CHECK_NEON(5, double, {0.75, -0.75, 0.75, -0.75, 0.75, -0.75, 0.75, -0.75});
  CHECK_NEON(10, float,
             {0.5, -0.75, 0.5, -0.75, 0.5, -0.75, 0.5, -0.75, 0.5, -0.75, 0.5,
              -0.75, 0.5, -0.75, 0.5, -0.75});
  CHECK_NEON(11, float,
             {-0.5, 0.75, -0.5, 0.75, -0.5, 0.75, -0.5, 0.75, -0.5, 0.75, -0.5,
              0.75, -0.5, 0.75, -0.5, 0.75});
}

INSTANTIATE_TEST_SUITE_P(AArch64, InstSve, ::testing::Values(EMULATION),
                         coreTypeToString);

}  // namespace