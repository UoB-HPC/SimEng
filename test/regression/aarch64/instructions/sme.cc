#include <algorithm>
#include <limits>

#include "AArch64RegressionTest.hh"

namespace {

using InstSme = AArch64RegressionTest;

#if SIMENG_LLVM_VERSION >= 14
TEST_P(InstSme, mova) {
  // 8-bit
  RUN_AARCH64(R"(
    smstart

    ptrue p0.s
    ptrue p1.s

    fdup z1.s, #1.0
    mov w0, #1
    index z2.s, #1, w0
    scvtf z2.s, p0/m, z2.s

    fdup z4.s, #5.0
    fdup z5.s, #10.0
    fdup z6.s, #5.0
    fdup z7.s, #10.0
    fmopa za0.s, p0/m, p1/m, z2.s, z1.s

    ptrue p2.b
    mov x2, #0
    mov x3, #2
    addvl x2, x2, #1
    sdiv x2, x2, x3
    whilelo p3.b, xzr, x2

    mov w12, #0
    mov w15, #2

    mova z4.b, p2/m, za0h.b[w12, #0]
    mova z5.b, p2/m, za0h.b[w12, #4]
    mova z6.b, p3/m, za0h.b[w15, #6]
    mova z7.b, p3/m, za0h.b[w15, #10]
  )");
  CHECK_NEON(4, float, fillNeon<float>({1}, SVL / 8));
  CHECK_NEON(5, float, fillNeon<float>({2}, SVL / 8));
  CHECK_NEON(6, float, fillNeonCombined<float>({3}, {5}, SVL / 8));
  CHECK_NEON(7, float, fillNeonCombined<float>({4}, {10}, SVL / 8));
}

TEST_P(InstSme, fmopa) {
  // 32-bit
  RUN_AARCH64(R"(
    smstart

    fdup z1.s, #2.0
    fdup z2.s, #5.0
    ptrue p0.s
    ptrue p1.s

    fmopa za0.s, p0/m, p1/m, z1.s, z2.s

    fdup z3.s, #3.0
    fdup z4.s, #8.0
    mov x0, #0
    mov x1, #8
    addvl x0, x0, #1
    udiv x0, x0, x1
    whilelo p2.s, xzr, x0

    fmopa za2.s, p0/m, p2/m, z3.s, z4.s
  )");
  for (int i = 0; i < (SVL / 32); i++) {
    CHECK_MAT_ROW(ARM64_REG_ZAS0, i, float,
                  fillNeon<float>({10.0f}, (SVL / 8)));
    CHECK_MAT_ROW(ARM64_REG_ZAS2, i, float,
                  fillNeon<float>({24.0f}, (SVL / 16)));
  }

  // 64-bit
  RUN_AARCH64(R"(
    smstart

    fdup z1.d, #2.0
    fdup z2.d, #5.0
    ptrue p0.d
    ptrue p1.d

    fmopa za0.d, p0/m, p1/m, z1.d, z2.d

    fdup z3.d, #3.0
    fdup z4.d, #8.0
    mov x0, #0
    mov x1, #16
    addvl x0, x0, #1
    udiv x0, x0, x1
    whilelo p2.d, xzr, x0

    fmopa za2.d, p0/m, p2/m, z3.d, z4.d
  )");
  for (int i = 0; i < (SVL / 64); i++) {
    CHECK_MAT_ROW(ARM64_REG_ZAD0, i, double,
                  fillNeon<double>({10.0}, (SVL / 8)));
    CHECK_MAT_ROW(ARM64_REG_ZAD2, i, double,
                  fillNeon<double>({24.0}, (SVL / 16)));
  }
}

TEST_P(InstSme, ld1d) {
  // Horizontal
  initialHeapData_.resize(SVL / 4);
  uint64_t* heap64 = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  std::vector<uint64_t> src = {0xDEADBEEF12345678, 0x98765432ABCDEF01};
  fillHeap<uint64_t>(heap64, src, SVL / 32);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    smstart

    mov x1, #1
    ptrue p0.d
    mov w12, #0
    # Load and broadcast values from heap
    ld1d {za0h.d[w12, 0]}, p0/z, [x0, x1, lsl #3]
    ld1d {za0h.d[w12, 1]}, p0/z, [x0]

    # Test for inactive lanes
    mov x1, #0
    mov x3, #16
    # TODO change to addsvl when implemented
    addvl x1, x1, #1
    udiv x1, x1, x3
    mov x2, #0
    whilelo p1.d, xzr, x1
    ld1d {za1h.d[w12, 1]}, p1/z, [x0, x2, lsl #3]
  )");
  CHECK_MAT_ROW(
      ARM64_REG_ZAD0, 0, uint64_t,
      fillNeon<uint64_t>({0x98765432ABCDEF01, 0xDEADBEEF12345678}, SVL / 8));
  CHECK_MAT_ROW(
      ARM64_REG_ZAD0, 1, uint64_t,
      fillNeon<uint64_t>({0xDEADBEEF12345678, 0x98765432ABCDEF01}, SVL / 8));
  CHECK_MAT_ROW(ARM64_REG_ZAD1, 1, uint64_t,
                fillNeonCombined<uint64_t>(
                    {0xDEADBEEF12345678, 0x98765432ABCDEF01}, {0}, SVL / 8));

  // Vertical
  initialHeapData_.resize(SVL / 4);
  uint64_t* heap64_vert = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  std::vector<uint64_t> src_vert = {0xDEADBEEF12345678, 0x98765432ABCDEF01};
  fillHeap<uint64_t>(heap64_vert, src_vert, SVL / 32);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    smstart

    mov x1, #1
    ptrue p0.d
    mov w12, #0
    # Load and broadcast values from heap
    ld1d {za0v.d[w12, 0]}, p0/z, [x0, x1, lsl #3]
    ld1d {za0v.d[w12, 1]}, p0/z, [x0]

    # Test for inactive lanes
    mov x1, #0
    mov x3, #16
    # TODO change to addsvl when implemented
    addvl x1, x1, #1
    udiv x1, x1, x3
    mov x2, #0
    whilelo p1.d, xzr, x1
    ld1d {za1v.d[w12, 1]}, p1/z, [x0, x2, lsl #3]
  )");
  CHECK_MAT_COL(
      ARM64_REG_ZAD0, 0, uint64_t,
      fillNeon<uint64_t>({0x98765432ABCDEF01, 0xDEADBEEF12345678}, SVL / 8));
  CHECK_MAT_COL(
      ARM64_REG_ZAD0, 1, uint64_t,
      fillNeon<uint64_t>({0xDEADBEEF12345678, 0x98765432ABCDEF01}, SVL / 8));
  CHECK_MAT_COL(ARM64_REG_ZAD1, 1, uint64_t,
                fillNeonCombined<uint64_t>(
                    {0xDEADBEEF12345678, 0x98765432ABCDEF01}, {0}, SVL / 8));
}

TEST_P(InstSme, ld1w) {
  // Horizontal
  initialHeapData_.resize(SVL / 4);
  uint32_t* heap32 = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  std::vector<uint32_t> src = {0xDEADBEEF, 0x12345678, 0x98765432, 0xABCDEF01};
  fillHeap<uint32_t>(heap32, src, SVL / 16);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    smstart

    mov x1, #1
    ptrue p0.s
    mov w12, #1
    # Load and broadcast values from heap
    ld1w {za0h.s[w12, 0]}, p0/z, [x0, x1, lsl #2]
    ld1w {za0h.s[w12, 2]}, p0/z, [x0]

    # Test for inactive lanes
    mov x1, #0
    mov x3, #8
    # TODO change to addsvl when implemented
    addvl x1, x1, #1
    udiv x1, x1, x3
    mov x2, #0
    whilelo p1.s, xzr, x1
    ld1w {za1h.s[w12, 0]}, p1/z, [x0, x2, lsl #2]
  )");
  CHECK_MAT_ROW(
      ARM64_REG_ZAS0, 1, uint64_t,
      fillNeon<uint64_t>({0x9876543212345678, 0xDEADBEEFABCDEF01}, SVL / 8));
  CHECK_MAT_ROW(
      ARM64_REG_ZAS0, 3, uint64_t,
      fillNeon<uint64_t>({0x12345678DEADBEEF, 0xABCDEF0198765432}, SVL / 8));
  CHECK_MAT_ROW(ARM64_REG_ZAS1, 1, uint64_t,
                fillNeonCombined<uint64_t>(
                    {0x12345678DEADBEEF, 0xABCDEF0198765432}, {0}, SVL / 8));

  // Vertical
  initialHeapData_.resize(SVL / 4);
  uint32_t* heap32_vert = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  std::vector<uint32_t> src_vert = {0xDEADBEEF, 0x12345678, 0x98765432,
                                    0xABCDEF01};
  fillHeap<uint32_t>(heap32_vert, src_vert, SVL / 16);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    smstart

    mov x1, #1
    ptrue p0.s
    mov w12, #1
    # Load and broadcast values from heap
    ld1w {za0v.s[w12, 0]}, p0/z, [x0, x1, lsl #2]
    ld1w {za0v.s[w12, 2]}, p0/z, [x0]

    # Test for inactive lanes
    mov x1, #0
    mov x3, #8
    # TODO change to addsvl when implemented
    addvl x1, x1, #1
    udiv x1, x1, x3
    mov x2, #0
    whilelo p1.s, xzr, x1
    ld1w {za1v.s[w12, 0]}, p1/z, [x0, x2, lsl #2]
  )");
  CHECK_MAT_COL(ARM64_REG_ZAS0, 1, uint32_t,
                fillNeon<uint32_t>(
                    {0x12345678, 0x98765432, 0xABCDEF01, 0xDEADBEEF}, SVL / 8));
  CHECK_MAT_COL(ARM64_REG_ZAS0, 3, uint32_t,
                fillNeon<uint32_t>(
                    {0xDEADBEEF, 0x12345678, 0x98765432, 0xABCDEF01}, SVL / 8));
  CHECK_MAT_COL(
      ARM64_REG_ZAS1, 1, uint32_t,
      fillNeonCombined<uint32_t>(
          {0xDEADBEEF, 0x12345678, 0x98765432, 0xABCDEF01}, {0}, SVL / 8));
}

TEST_P(InstSme, st1d) {
  // Horizontal
  initialHeapData_.resize(SVL / 4);
  uint64_t* heap64 = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  std::vector<uint64_t> src = {0xDEADBEEF12345678, 0x98765432ABCDEF01};
  fillHeap<uint64_t>(heap64, src, SVL / 32);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    smstart

    sub sp, sp, #4095
    mov x1, #0
    mov x4, #0
    addvl x4, x4, #1
    ptrue p0.d

    mov w12, #0
    ld1d {za0h.d[w12, 0]}, p0/z, [x0, x1, lsl #3]
    ld1d {za1h.d[w12, 1]}, p0/z, [x0, x1, lsl #3]
    st1d {za0h.d[w12, 0]}, p0, [sp, x1, lsl #3]
    st1d {za1h.d[w12, 1]}, p0, [x4]
  )");
  for (int i = 0; i < (SVL / 64); i++) {
    EXPECT_EQ(getMemoryValue<uint64_t>(
                  process_->getInitialProcessStackPointer() - 4095 + (i * 8)),
              src[i % 2]);
    EXPECT_EQ(getMemoryValue<uint64_t>((SVL / 8) + (i * 8)), src[i % 2]);
  }

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    smstart

    mov x2, #0
    mov x4, #16
    addvl x2, x2, #1
    udiv x2, x2, x4
    mov x3, #2
    whilelo p1.d, xzr, x2
    mov x5, #800

    mov w12, #0
    mov w13, #1
    ld1d {za3h.d[w12, 0]}, p1/z, [x0, x3, lsl #3]
    st1d {za3h.d[w12, 0]}, p1, [x5]
    ld1d {za1h.d[w13, 1]}, p1/z, [x0, x3, lsl #3]
    st1d {za1h.d[w13, 1]}, p1, [x5, x3, lsl #3]
  )");
  for (int i = 0; i < (SVL / 128); i++) {
    EXPECT_EQ(getMemoryValue<uint64_t>(800 + (i * 8)), src[i % 2]);
    EXPECT_EQ(getMemoryValue<uint64_t>(800 + 16 + (i * 8)), src[i % 2]);
  }

  // Vertical
  initialHeapData_.resize(SVL / 4);
  uint64_t* heap64_vert = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  std::vector<uint64_t> src_vert = {0xDEADBEEF12345678, 0x98765432ABCDEF01};
  fillHeap<uint64_t>(heap64_vert, src_vert, SVL / 32);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    smstart

    sub sp, sp, #4095
    mov x1, #0
    mov x4, #0
    addvl x4, x4, #1
    ptrue p0.d

    mov w12, #0
    ld1d {za0v.d[w12, 0]}, p0/z, [x0, x1, lsl #3]
    ld1d {za1v.d[w12, 1]}, p0/z, [x0, x1, lsl #3]
    st1d {za0v.d[w12, 0]}, p0, [sp, x1, lsl #3]
    st1d {za1v.d[w12, 1]}, p0, [x4]
  )");
  for (int i = 0; i < (SVL / 64); i++) {
    EXPECT_EQ(getMemoryValue<uint64_t>(
                  process_->getInitialProcessStackPointer() - 4095 + (i * 8)),
              src_vert[i % 2]);
    EXPECT_EQ(getMemoryValue<uint64_t>((SVL / 8) + (i * 8)), src_vert[i % 2]);
  }

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    smstart

    mov x2, #0
    mov x4, #16
    addvl x2, x2, #1
    udiv x2, x2, x4
    mov x3, #2
    whilelo p1.d, xzr, x2
    mov x5, #800

    mov w12, #0
    mov w13, #1
    ld1d {za3v.d[w12, 0]}, p1/z, [x0, x3, lsl #3]
    st1d {za3v.d[w12, 0]}, p1, [x5]
    ld1d {za1v.d[w13, 1]}, p1/z, [x0, x3, lsl #3]
    st1d {za1v.d[w13, 1]}, p1, [x5, x3, lsl #3]
  )");
  for (int i = 0; i < (SVL / 128); i++) {
    EXPECT_EQ(getMemoryValue<uint64_t>(800 + (i * 8)), src_vert[i % 2]);
    EXPECT_EQ(getMemoryValue<uint64_t>(800 + 16 + (i * 8)), src_vert[i % 2]);
  }
}

TEST_P(InstSme, st1w) {
  // Horizontal
  initialHeapData_.resize(SVL / 4);
  uint32_t* heap32 = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  std::vector<uint32_t> src = {0xDEADBEEF, 0x12345678, 0x98765432, 0xABCDEF01};
  fillHeap<uint32_t>(heap32, src, SVL / 16);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    smstart

    sub sp, sp, #4095
    mov x1, #0
    mov x4, #0
    addvl x4, x4, #1
    ptrue p0.s

    mov w12, #0
    ld1w {za0h.s[w12, 0]}, p0/z, [x0, x1, lsl #2]
    ld1w {za1h.s[w12, 1]}, p0/z, [x0, x1, lsl #2]
    st1w {za0h.s[w12, 0]}, p0, [sp, x1, lsl #2]
    st1w {za1h.s[w12, 1]}, p0, [x4]
  )");
  for (int i = 0; i < (SVL / 32); i++) {
    EXPECT_EQ(getMemoryValue<uint32_t>(
                  process_->getInitialProcessStackPointer() - 4095 + (i * 4)),
              src[i % 4]);
    EXPECT_EQ(getMemoryValue<uint32_t>((SVL / 8) + (i * 4)), src[i % 4]);
  }

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    smstart

    mov x2, #0
    mov x4, #8
    addvl x2, x2, #1
    udiv x2, x2, x4
    mov x3, #4
    whilelo p1.s, xzr, x2
    mov x5, #800

    mov w12, #0
    ld1w {za3h.s[w12, 0]}, p1/z, [x0, x3, lsl #2]
    st1w {za3h.s[w12, 0]}, p1, [x5]
    ld1w {za1h.s[w12, 2]}, p1/z, [x0, x3, lsl #2]
    st1w {za1h.s[w12, 2]}, p1, [x5, x3, lsl #2]
  )");
  for (int i = 0; i < (SVL / 64); i++) {
    EXPECT_EQ(getMemoryValue<uint32_t>(800 + (i * 4)), src[i % 4]);
    EXPECT_EQ(getMemoryValue<uint32_t>(800 + 16 + (i * 4)), src[i % 4]);
  }

  // Vertical
  initialHeapData_.resize(SVL / 4);
  uint32_t* heap32_vert = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  std::vector<uint32_t> src_vert = {0xDEADBEEF, 0x12345678, 0x98765432,
                                    0xABCDEF01};
  fillHeap<uint32_t>(heap32_vert, src_vert, SVL / 16);

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    smstart

    sub sp, sp, #4095
    mov x1, #0
    mov x4, #0
    addvl x4, x4, #1
    ptrue p0.s

    mov w12, #0
    ld1w {za0v.s[w12, 0]}, p0/z, [x0, x1, lsl #2]
    ld1w {za1v.s[w12, 1]}, p0/z, [x0, x1, lsl #2]
    st1w {za0v.s[w12, 0]}, p0, [sp, x1, lsl #2]
    st1w {za1v.s[w12, 1]}, p0, [x4]
  )");
  for (int i = 0; i < (SVL / 32); i++) {
    EXPECT_EQ(getMemoryValue<uint32_t>(
                  process_->getInitialProcessStackPointer() - 4095 + (i * 4)),
              src_vert[i % 4]);
    EXPECT_EQ(getMemoryValue<uint32_t>((SVL / 8) + (i * 4)), src_vert[i % 4]);
  }

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    smstart

    mov x2, #0
    mov x4, #8
    addvl x2, x2, #1
    udiv x2, x2, x4
    mov x3, #4
    whilelo p1.s, xzr, x2
    mov x5, #800

    mov w12, #0
    ld1w {za3v.s[w12, 0]}, p1/z, [x0, x3, lsl #2]
    st1w {za3v.s[w12, 0]}, p1, [x5]
    ld1w {za1v.s[w12, 2]}, p1/z, [x0, x3, lsl #2]
    st1w {za1v.s[w12, 2]}, p1, [x5, x3, lsl #2]
  )");
  for (int i = 0; i < (SVL / 64); i++) {
    EXPECT_EQ(getMemoryValue<uint32_t>(800 + (i * 4)), src_vert[i % 4]);
    EXPECT_EQ(getMemoryValue<uint32_t>(800 + 16 + (i * 4)), src_vert[i % 4]);
  }
}

TEST_P(InstSme, zero) {
  RUN_AARCH64(R"(
    smstart

    zero {za}
  )");
  for (int i = 0; i < (SVL / 8); i++) {
    CHECK_MAT_ROW(ARM64_REG_ZA, i, uint64_t, fillNeon<uint64_t>({0}, SVL / 8));
  }

  initialHeapData_.resize(SVL / 4);
  uint32_t* heap32_vert = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  std::vector<uint32_t> src_vert = {0xDEADBEEF, 0x12345678, 0x98765432,
                                    0xABCDEF01};
  fillHeap<uint32_t>(heap32_vert, src_vert, SVL / 16);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    smstart

    mov x1, #1
    ptrue p0.s
    mov w12, #1
    # Load and broadcast values from heap
    ld1w {za0v.s[w12, 0]}, p0/z, [x0, x1, lsl #2]
    ld1w {za1v.s[w12, 2]}, p0/z, [x0]

    # Test for inactive lanes
    mov x1, #0
    mov x3, #8
    # TODO change to addsvl when implemented
    addvl x1, x1, #1
    udiv x1, x1, x3
    mov x2, #0
    whilelo p1.s, xzr, x1
    ld1w {za2v.s[w12, 0]}, p1/z, [x0, x2, lsl #2]

    zero {za0.s, za2.s}
  )");
  for (int i = 0; i < (SVL / 32); i++) {
    CHECK_MAT_ROW(ARM64_REG_ZAS0, i, uint32_t,
                  fillNeon<uint32_t>({0}, SVL / 8));
    CHECK_MAT_ROW(ARM64_REG_ZAS2, i, uint32_t,
                  fillNeon<uint32_t>({0}, SVL / 8));
  }
  CHECK_MAT_COL(ARM64_REG_ZAS1, 3, uint32_t,
                fillNeon<uint32_t>(
                    {0xDEADBEEF, 0x12345678, 0x98765432, 0xABCDEF01}, SVL / 8));
}

INSTANTIATE_TEST_SUITE_P(AArch64, InstSme,
                         ::testing::ValuesIn(genCoreTypeSVLPairs(EMULATION)),
                         paramToString);
#else
GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(InstSme);
#endif

}  // namespace