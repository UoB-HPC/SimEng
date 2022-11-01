#include <algorithm>
#include <limits>

#include "AArch64RegressionTest.hh"

namespace {

using InstSme = AArch64RegressionTest;

#if SIMENG_LLVM_VERSION >= 14
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
    EXPECT_EQ(
        getMemoryValue<uint32_t>(process_->getStackPointer() - 4095 + (i * 4)),
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
    EXPECT_EQ(
        getMemoryValue<uint32_t>(process_->getStackPointer() - 4095 + (i * 4)),
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