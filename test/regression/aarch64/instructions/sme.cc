#include <algorithm>
#include <limits>

#include "AArch64RegressionTest.hh"

namespace {

using InstSme = AArch64RegressionTest;

#if SIMENG_LLVM_VERSION >= 14

TEST_P(InstSme, add) {
  // uint32_T, vgx2, vecs with ZA
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    smstart

    zero {za}

    # Pre-fill all of za with 96 (uint32_t)
    dup z0.b, #8
    dup z1.b, #3
    ptrue p0.b
    ptrue p1.b
    umopa za0.s, p0/m, p1/m, z0.b, z1.b
    umopa za1.s, p0/m, p1/m, z0.b, z1.b
    umopa za2.s, p0/m, p1/m, z0.b, z1.b
    umopa za3.s, p0/m, p1/m, z0.b, z1.b

    # Set 2 of the za rows
    mov w8, #1
    dup z0.s, #8
    dup z1.s, #3
    add za.s[w8, #1, vgx2], {z0.s, z1.s}
  )");
  const uint16_t zaStride = (SVL / 8) / 2;
  const uint16_t zaHalfIndex = 2;
  for (uint16_t i = 0; i < (SVL / 8); i++) {
    if (i == zaHalfIndex) {
      CHECK_MAT_ROW(AARCH64_REG_ZA, i, uint32_t,
                    fillNeon<uint32_t>({104}, (SVL / 8)));
    } else if (i == zaStride + zaHalfIndex) {
      CHECK_MAT_ROW(AARCH64_REG_ZA, i, uint32_t,
                    fillNeon<uint32_t>({99}, (SVL / 8)));
    } else {
      // un-effected rows should still be 96 throughout
      CHECK_MAT_ROW(AARCH64_REG_ZA, i, uint32_t,
                    fillNeon<uint32_t>({96}, (SVL / 8)));
    }
  }
}

TEST_P(InstSme, mova_tileToVec) {
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

TEST_P(InstSme, mova_zaToVecs) {
  // 2 vectors
  initialHeapData_.resize(SVL / 8);
  uint8_t* heap8 = reinterpret_cast<uint8_t*>(initialHeapData_.data());
  std::vector<uint8_t> src = {0, 1, 2,  3,  4,  5,  6,  7,
                              8, 9, 10, 11, 12, 13, 14, 15};
  fillHeap<uint8_t>(heap8, src, SVL / 8);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    smstart

    zero {za}

    # Pre-fill all of za with 96 (uint32_t)
    dup z1.b, #8
    dup z2.b, #3
    ptrue p0.b
    ptrue p1.b
    umopa za0.s, p0/m, p1/m, z1.b, z2.b
    umopa za1.s, p0/m, p1/m, z1.b, z2.b
    umopa za2.s, p0/m, p1/m, z1.b, z2.b
    umopa za3.s, p0/m, p1/m, z1.b, z2.b

    # Set 4 of the za rows
    mov w8, #1
    dup z4.b, #10
    dup z5.b, #11
    dup z6.b, #12
    dup z7.b, #13
    ld1b {z10.b}, p0/z, [x0]
    udot za.s[w8, #1, vgx4], {z4.b - z7.b}, z10.b[2]

    # Extravt un-updated values
    mov w9, #0
    mova {z20.d, z21.d}, za.d[w9, #0, vgx2]
    # Extract 0th and 2nd updated rows
    mov {z24.d, z25.d}, za.d[w8, #1, vgx2]
    # Extract 1st and 3rd updated rows (get new offset into each half)
    addvl x10, x10, #1
    mov x20, #4
    udiv x10, x10, x20
    mov {z26.d, z27.d}, za.d[w10, #2, vgx2]
  )");
  // Check extracted un-effected rows (two uint32_t values of 96 equal one
  // uint64_t value of 412316860512)
  CHECK_NEON(20, uint64_t, fillNeon<uint64_t>({412316860512}, SVL / 8));
  CHECK_NEON(21, uint64_t, fillNeon<uint64_t>({412316860512}, SVL / 8));
  // Check extracted effected rows (two uint32_t values concatonated into one
  // uint64_t value)
  CHECK_NEON(24, uint64_t, fillNeon<uint64_t>({2044404433372}, SVL / 8));
  CHECK_NEON(25, uint64_t, fillNeon<uint64_t>({2370821947944}, SVL / 8));
  CHECK_NEON(26, uint64_t, fillNeon<uint64_t>({2207613190658}, SVL / 8));
  CHECK_NEON(27, uint64_t, fillNeon<uint64_t>({2534030705230}, SVL / 8));

  // 4 vectors
  initialHeapData_.resize(SVL / 8);
  heap8 = reinterpret_cast<uint8_t*>(initialHeapData_.data());
  src = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
  fillHeap<uint8_t>(heap8, src, SVL / 8);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    smstart

    zero {za}

    # Pre-fill all of za with 96 (uint32_t)
    dup z1.b, #8
    dup z2.b, #3
    ptrue p0.b
    ptrue p1.b
    umopa za0.s, p0/m, p1/m, z1.b, z2.b
    umopa za1.s, p0/m, p1/m, z1.b, z2.b
    umopa za2.s, p0/m, p1/m, z1.b, z2.b
    umopa za3.s, p0/m, p1/m, z1.b, z2.b

    # Set 4 of the za rows
    mov w8, #1
    dup z4.b, #10
    dup z5.b, #11
    dup z6.b, #12
    dup z7.b, #13
    ld1b {z10.b}, p0/z, [x0]
    udot za.s[w8, #1, vgx4], {z4.b - z7.b}, z10.b[2]

    mov w9, #0
    mova {z20.d - z23.d}, za.d[w9, #0, vgx4]
    mov {z24.d - z27.d}, za.d[w8, #1, vgx4]
  )");
  // Check extracted un-effected rows (two uint32_t values of 96 equal one
  // uint64_t value of 412316860512)
  CHECK_NEON(20, uint64_t, fillNeon<uint64_t>({412316860512}, SVL / 8));
  CHECK_NEON(21, uint64_t, fillNeon<uint64_t>({412316860512}, SVL / 8));
  CHECK_NEON(22, uint64_t, fillNeon<uint64_t>({412316860512}, SVL / 8));
  CHECK_NEON(23, uint64_t, fillNeon<uint64_t>({412316860512}, SVL / 8));
  // Check extracted effected rows (two uint32_t values concatonated into one
  // uint64_t value)
  CHECK_NEON(24, uint64_t, fillNeon<uint64_t>({2044404433372}, SVL / 8));
  CHECK_NEON(25, uint64_t, fillNeon<uint64_t>({2207613190658}, SVL / 8));
  CHECK_NEON(26, uint64_t, fillNeon<uint64_t>({2370821947944}, SVL / 8));
  CHECK_NEON(27, uint64_t, fillNeon<uint64_t>({2534030705230}, SVL / 8));
}

TEST_P(InstSme, mova_tilesToVecs) {
  // uint8_t; 4 vectors
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

    mov w12, #0
    ptrue p0.s

    # Pre-fill first 4 rows of za0.b
    ld1w {za0h.s[w12, 0]}, p0/z, [x0]
    ld1w {za1h.s[w12, 0]}, p0/z, [x0]
    ld1w {za2h.s[w12, 0]}, p0/z, [x0]
    ld1w {za3h.s[w12, 0]}, p0/z, [x0]


    mova {z4.b-z7.b}, za0h.b[w12, 0:3]
    
    # Test Alias
    mov w13, #1
    dup z11.b, #3
    mov {z8.b-z11.b}, za0h.b[w13, 0:3]
  )");
  for (int i = 4; i <= 10; i++) {
    CHECK_NEON(
        i, uint8_t,
        fillNeon<uint8_t>({0xEF, 0xBE, 0xAD, 0xDE, 0x78, 0x56, 0x34, 0x12, 0x32,
                           0x54, 0x76, 0x98, 0x01, 0xEF, 0xCD, 0xAB},
                          SVL / 8));
  }
  CHECK_NEON(11, uint8_t, fillNeon<uint8_t>({0x00}, SVL / 8));
}

TEST_P(InstSme, fadd) {
  // Float, VGx2
  initialHeapData_.resize(SVL / 8);
  uint8_t* heap8 = reinterpret_cast<uint8_t*>(initialHeapData_.data());
  std::vector<uint8_t> src = {0, 1, 2,  3,  4,  5,  6,  7,
                              8, 9, 10, 11, 12, 13, 14, 15};
  fillHeap<uint8_t>(heap8, src, SVL / 8);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    smstart

    zero {za}

    # Pre-fill all of za with 24.0f
    fdup z1.s, #3.0
    fdup z2.s, #8.0
    ptrue p0.s
    ptrue p1.s
    fmopa za0.s, p0/m, p1/m, z1.s, z2.s
    fmopa za1.s, p0/m, p1/m, z1.s, z2.s
    fmopa za2.s, p0/m, p1/m, z1.s, z2.s
    fmopa za3.s, p0/m, p1/m, z1.s, z2.s

    # initialise registers
    mov w8, #1
    fdup z4.s, #-2.5
    fdup z5.s, #3.0

    fadd za.s[w8, #1, vgx2], {z4.s, z5.s}
  )");
  const uint16_t zaStride = (SVL / 8) / 2;
  const uint16_t zaHalfIndex = 2;
  for (uint16_t i = 0; i < (SVL / 8); i++) {
    if (i == zaHalfIndex) {
      CHECK_MAT_ROW(AARCH64_REG_ZA, i, float,
                    fillNeon<float>({21.5f}, (SVL / 8)));
    } else if (i == zaStride + zaHalfIndex) {
      CHECK_MAT_ROW(AARCH64_REG_ZA, i, float,
                    fillNeon<float>({27.0f}, (SVL / 8)));
    } else {
      // un-effected rows should still be 24.0f throughout
      CHECK_MAT_ROW(AARCH64_REG_ZA, i, float,
                    fillNeon<float>({24.0f}, (SVL / 8)));
    }
  }

  // Double, VGx2
  initialHeapData_.resize(SVL / 8);
  heap8 = reinterpret_cast<uint8_t*>(initialHeapData_.data());
  src = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
  fillHeap<uint8_t>(heap8, src, SVL / 8);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    smstart

    zero {za}

    # Pre-fill all of za with 24.0
    fdup z1.d, #3.0
    fdup z2.d, #8.0
    ptrue p0.d
    ptrue p1.d
    fmopa za0.d, p0/m, p1/m, z1.d, z2.d
    fmopa za1.d, p0/m, p1/m, z1.d, z2.d
    fmopa za2.d, p0/m, p1/m, z1.d, z2.d
    fmopa za3.d, p0/m, p1/m, z1.d, z2.d
    fmopa za4.d, p0/m, p1/m, z1.d, z2.d
    fmopa za5.d, p0/m, p1/m, z1.d, z2.d
    fmopa za6.d, p0/m, p1/m, z1.d, z2.d
    fmopa za7.d, p0/m, p1/m, z1.d, z2.d


    # initialise registers
    mov w8, #1
    fdup z4.d, #-2.5
    fdup z5.d, #3.0

    fadd za.d[w8, #1, vgx2], {z4.d, z5.d}
  )");
  for (uint16_t i = 0; i < (SVL / 8); i++) {
    if (i == zaHalfIndex) {
      CHECK_MAT_ROW(AARCH64_REG_ZA, i, double,
                    fillNeon<double>({21.5}, (SVL / 8)));
    } else if (i == zaStride + zaHalfIndex) {
      CHECK_MAT_ROW(AARCH64_REG_ZA, i, double,
                    fillNeon<double>({27.0}, (SVL / 8)));
    } else {
      // un-effected rows should still be 24.0f throughout
      CHECK_MAT_ROW(AARCH64_REG_ZA, i, double,
                    fillNeon<double>({24.0}, (SVL / 8)));
    }
  }
}

TEST_P(InstSme, fmla_multiVecs) {
  // float, vgx4
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    smstart

    zero {za}

    # Pre-fill all of za with 24.0f
    fdup z1.s, #3.0
    fdup z2.s, #8.0
    ptrue p0.s
    ptrue p1.s
    fmopa za0.s, p0/m, p1/m, z1.s, z2.s
    fmopa za1.s, p0/m, p1/m, z1.s, z2.s
    fmopa za2.s, p0/m, p1/m, z1.s, z2.s
    fmopa za3.s, p0/m, p1/m, z1.s, z2.s

    # initialise registers
    mov w8, #1
    fdup z4.s, #0.25
    fdup z5.s, #1.5
    fdup z6.s, #-0.5
    fdup z7.s, #-2.5
    fdup z8.s, #3.0
    fdup z9.s, #4.0
    fdup z10.s, #5.0
    fdup z11.s, #6.0

    fmla za.s[w8, #1, vgx4], {z4.s - z7.s}, {z8.s - z11.s}
  )");
  const uint16_t zaStride = (SVL / 8) / 4;
  const uint16_t zaQuartIndex = 2;
  for (uint16_t i = 0; i < (SVL / 8); i++) {
    // Effected rows all use same zm value of 2.0f
    if (i == zaQuartIndex) {
      CHECK_MAT_ROW(AARCH64_REG_ZA, i, float,
                    fillNeon<float>({24.75f}, (SVL / 8)));
    } else if (i == zaStride + zaQuartIndex) {
      CHECK_MAT_ROW(AARCH64_REG_ZA, i, float,
                    fillNeon<float>({30.0f}, (SVL / 8)));
    } else if (i == (2 * zaStride) + zaQuartIndex) {
      CHECK_MAT_ROW(AARCH64_REG_ZA, i, float,
                    fillNeon<float>({21.5f}, (SVL / 8)));
    } else if (i == (3 * zaStride) + zaQuartIndex) {
      CHECK_MAT_ROW(AARCH64_REG_ZA, i, float,
                    fillNeon<float>({9.0f}, (SVL / 8)));
    } else {
      // un-effected rows should still be 24.0f throughout
      CHECK_MAT_ROW(AARCH64_REG_ZA, i, float,
                    fillNeon<float>({24.0f}, (SVL / 8)));
    }
  }

  // double, vgx4
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    smstart

    zero {za}

    # Pre-fill all of za with 24.0
    fdup z1.d, #3.0
    fdup z2.d, #8.0
    ptrue p0.d
    ptrue p1.d
    fmopa za0.d, p0/m, p1/m, z1.d, z2.d
    fmopa za1.d, p0/m, p1/m, z1.d, z2.d
    fmopa za2.d, p0/m, p1/m, z1.d, z2.d
    fmopa za3.d, p0/m, p1/m, z1.d, z2.d
    fmopa za4.d, p0/m, p1/m, z1.d, z2.d
    fmopa za5.d, p0/m, p1/m, z1.d, z2.d
    fmopa za6.d, p0/m, p1/m, z1.d, z2.d
    fmopa za7.d, p0/m, p1/m, z1.d, z2.d

    # initialise registers
    mov w8, #1
    fdup z4.d, #0.25
    fdup z5.d, #1.5
    fdup z6.d, #-0.5
    fdup z7.d, #-2.5
    fdup z8.d, #3.0
    fdup z9.d, #4.0
    fdup z10.d, #5.0
    fdup z11.d, #6.0

    fmla za.d[w8, #1, vgx4], {z4.d - z7.d}, {z8.d - z11.d}
  )");
  for (uint16_t i = 0; i < (SVL / 8); i++) {
    // Effected rows all use same zm value of 2.0
    if (i == zaQuartIndex) {
      CHECK_MAT_ROW(AARCH64_REG_ZA, i, double,
                    fillNeon<double>({24.75}, (SVL / 8)));
    } else if (i == zaStride + zaQuartIndex) {
      CHECK_MAT_ROW(AARCH64_REG_ZA, i, double,
                    fillNeon<double>({30.0}, (SVL / 8)));
    } else if (i == (2 * zaStride) + zaQuartIndex) {
      CHECK_MAT_ROW(AARCH64_REG_ZA, i, double,
                    fillNeon<double>({21.5}, (SVL / 8)));
    } else if (i == (3 * zaStride) + zaQuartIndex) {
      CHECK_MAT_ROW(AARCH64_REG_ZA, i, double,
                    fillNeon<double>({9.0}, (SVL / 8)));
    } else {
      // un-effected rows should still be 24.0 throughout
      CHECK_MAT_ROW(AARCH64_REG_ZA, i, double,
                    fillNeon<double>({24.0}, (SVL / 8)));
    }
  }
}

TEST_P(InstSme, fmla_indexed_vgx4) {
  // float
  initialHeapData_.resize(SVL);
  float* heapf = reinterpret_cast<float*>(initialHeapData_.data());
  std::vector<float> srcf = {0.0f, 1.0f, 2.0f, 3.0f};
  fillHeap<float>(heapf, srcf, SVL / 4);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    smstart

    zero {za}

    # Pre-fill all of za with 24.0f
    fdup z1.s, #3.0
    fdup z2.s, #8.0
    ptrue p0.s
    ptrue p1.s
    fmopa za0.s, p0/m, p1/m, z1.s, z2.s
    fmopa za1.s, p0/m, p1/m, z1.s, z2.s
    fmopa za2.s, p0/m, p1/m, z1.s, z2.s
    fmopa za3.s, p0/m, p1/m, z1.s, z2.s

    # initialise registers
    mov w8, #1
    fdup z4.s, #0.25
    fdup z5.s, #1.5
    fdup z6.s, #-0.5
    fdup z7.s, #-2.5
    ld1w {z10.s}, p0/z, [x0]

    fmla za.s[w8, #1, vgx4], {z4.s - z7.s}, z10.s[2]
  )");
  const uint16_t zaStride = (SVL / 8) / 4;
  const uint16_t zaQuartIndex = 2;
  for (uint16_t i = 0; i < (SVL / 8); i++) {
    // Effected rows all use same zm value of 2.0f
    if (i == zaQuartIndex) {
      CHECK_MAT_ROW(AARCH64_REG_ZA, i, float,
                    fillNeon<float>({24.5f}, (SVL / 8)));
    } else if (i == zaStride + zaQuartIndex) {
      CHECK_MAT_ROW(AARCH64_REG_ZA, i, float,
                    fillNeon<float>({27.0f}, (SVL / 8)));
    } else if (i == (2 * zaStride) + zaQuartIndex) {
      CHECK_MAT_ROW(AARCH64_REG_ZA, i, float,
                    fillNeon<float>({23.0f}, (SVL / 8)));
    } else if (i == (3 * zaStride) + zaQuartIndex) {
      CHECK_MAT_ROW(AARCH64_REG_ZA, i, float,
                    fillNeon<float>({19.0f}, (SVL / 8)));
    } else {
      // un-effected rows should still be 24.0f throughout
      CHECK_MAT_ROW(AARCH64_REG_ZA, i, float,
                    fillNeon<float>({24.0f}, (SVL / 8)));
    }
  }

  // double
  initialHeapData_.resize(SVL);
  double* heapd = reinterpret_cast<double*>(initialHeapData_.data());
  std::vector<double> srcd = {2.0f, 3.0f};
  fillHeap<double>(heapd, srcd, SVL / 8);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    smstart

    zero {za}

    # Pre-fill all of za with 24.0f
    fdup z1.d, #3.0
    fdup z2.d, #8.0
    ptrue p0.d
    ptrue p1.d
    fmopa za0.d, p0/m, p1/m, z1.d, z2.d
    fmopa za1.d, p0/m, p1/m, z1.d, z2.d
    fmopa za2.d, p0/m, p1/m, z1.d, z2.d
    fmopa za3.d, p0/m, p1/m, z1.d, z2.d
    fmopa za4.d, p0/m, p1/m, z1.d, z2.d
    fmopa za5.d, p0/m, p1/m, z1.d, z2.d
    fmopa za6.d, p0/m, p1/m, z1.d, z2.d
    fmopa za7.d, p0/m, p1/m, z1.d, z2.d

    # initialise registers
    mov w8, #1
    fdup z4.d, #0.25
    fdup z5.d, #1.5
    fdup z6.d, #-0.5
    fdup z7.d, #-2.5
    ld1d {z10.d}, p0/z, [x0]

    fmla za.d[w8, #1, vgx4], {z4.d - z7.d}, z10.d[0]
  )");
  for (uint16_t i = 0; i < (SVL / 8); i++) {
    // Effected rows all use same zm value of 2.0f
    if (i == zaQuartIndex) {
      CHECK_MAT_ROW(AARCH64_REG_ZA, i, double,
                    fillNeon<double>({24.5}, (SVL / 8)));
    } else if (i == zaStride + zaQuartIndex) {
      CHECK_MAT_ROW(AARCH64_REG_ZA, i, double,
                    fillNeon<double>({27.0}, (SVL / 8)));
    } else if (i == (2 * zaStride) + zaQuartIndex) {
      CHECK_MAT_ROW(AARCH64_REG_ZA, i, double,
                    fillNeon<double>({23.0}, (SVL / 8)));
    } else if (i == (3 * zaStride) + zaQuartIndex) {
      CHECK_MAT_ROW(AARCH64_REG_ZA, i, double,
                    fillNeon<double>({19.0}, (SVL / 8)));
    } else {
      // un-effected rows should still be 24.0 throughout
      CHECK_MAT_ROW(AARCH64_REG_ZA, i, double,
                    fillNeon<double>({24.0}, (SVL / 8)));
    }
  }
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
  for (uint16_t i = 0; i < (SVL / 32); i++) {
    CHECK_MAT_ROW(AARCH64_REG_ZAS0, i, float,
                  fillNeon<float>({10.0f}, (SVL / 8)));
    CHECK_MAT_ROW(AARCH64_REG_ZAS2, i, float,
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
  for (uint16_t i = 0; i < (SVL / 64); i++) {
    CHECK_MAT_ROW(AARCH64_REG_ZAD0, i, double,
                  fillNeon<double>({10.0}, (SVL / 8)));
    CHECK_MAT_ROW(AARCH64_REG_ZAD2, i, double,
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
      AARCH64_REG_ZAD0, 0, uint64_t,
      fillNeon<uint64_t>({0x98765432ABCDEF01, 0xDEADBEEF12345678}, SVL / 8));
  CHECK_MAT_ROW(
      AARCH64_REG_ZAD0, 1, uint64_t,
      fillNeon<uint64_t>({0xDEADBEEF12345678, 0x98765432ABCDEF01}, SVL / 8));
  CHECK_MAT_ROW(AARCH64_REG_ZAD1, 1, uint64_t,
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
      AARCH64_REG_ZAD0, 0, uint64_t,
      fillNeon<uint64_t>({0x98765432ABCDEF01, 0xDEADBEEF12345678}, SVL / 8));
  CHECK_MAT_COL(
      AARCH64_REG_ZAD0, 1, uint64_t,
      fillNeon<uint64_t>({0xDEADBEEF12345678, 0x98765432ABCDEF01}, SVL / 8));
  CHECK_MAT_COL(AARCH64_REG_ZAD1, 1, uint64_t,
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
  CHECK_MAT_ROW(AARCH64_REG_ZAS0, 1, uint32_t,
                fillNeon<uint32_t>(
                    {0x12345678, 0x98765432, 0xABCDEF01, 0xDEADBEEF}, SVL / 8));
  CHECK_MAT_ROW(AARCH64_REG_ZAS0, 3, uint32_t,
                fillNeon<uint32_t>(
                    {0xDEADBEEF, 0x12345678, 0x98765432, 0xABCDEF01}, SVL / 8));
  CHECK_MAT_ROW(
      AARCH64_REG_ZAS1, 1, uint32_t,
      fillNeonCombined<uint32_t>(
          {0xDEADBEEF, 0x12345678, 0x98765432, 0xABCDEF01}, {0}, SVL / 8));

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
  CHECK_MAT_COL(AARCH64_REG_ZAS0, 1, uint32_t,
                fillNeon<uint32_t>(
                    {0x12345678, 0x98765432, 0xABCDEF01, 0xDEADBEEF}, SVL / 8));
  CHECK_MAT_COL(AARCH64_REG_ZAS0, 3, uint32_t,
                fillNeon<uint32_t>(
                    {0xDEADBEEF, 0x12345678, 0x98765432, 0xABCDEF01}, SVL / 8));
  CHECK_MAT_COL(
      AARCH64_REG_ZAS1, 1, uint32_t,
      fillNeonCombined<uint32_t>(
          {0xDEADBEEF, 0x12345678, 0x98765432, 0xABCDEF01}, {0}, SVL / 8));
}

TEST_P(InstSme, rdsvl) {
  RUN_AARCH64(R"(
    rdsvl x0, #-32
    rdsvl x1, #-3
    rdsvl x2, #0
    rdsvl x3, #3
    rdsvl x4, #31
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(0), (SVL / 8) * -32);
  EXPECT_EQ(getGeneralRegister<int64_t>(1), (SVL / 8) * -3);
  EXPECT_EQ(getGeneralRegister<int64_t>(2), 0);
  EXPECT_EQ(getGeneralRegister<int64_t>(3), (SVL / 8) * 3);
  EXPECT_EQ(getGeneralRegister<int64_t>(4), (SVL / 8) * 31);
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
  for (uint16_t i = 0; i < (SVL / 64); i++) {
    EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialStackPointer() -
                                       4095 + (i * 8)),
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
  for (uint16_t i = 0; i < (SVL / 128); i++) {
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
  for (uint16_t i = 0; i < (SVL / 64); i++) {
    EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialStackPointer() -
                                       4095 + (i * 8)),
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
  for (uint16_t i = 0; i < (SVL / 128); i++) {
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
  for (uint16_t i = 0; i < (SVL / 32); i++) {
    EXPECT_EQ(getMemoryValue<uint32_t>(process_->getInitialStackPointer() -
                                       4095 + (i * 4)),
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
  for (uint16_t i = 0; i < (SVL / 64); i++) {
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
  for (uint16_t i = 0; i < (SVL / 32); i++) {
    EXPECT_EQ(getMemoryValue<uint32_t>(process_->getInitialStackPointer() -
                                       4095 + (i * 4)),
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
  for (uint16_t i = 0; i < (SVL / 64); i++) {
    EXPECT_EQ(getMemoryValue<uint32_t>(800 + (i * 4)), src_vert[i % 4]);
    EXPECT_EQ(getMemoryValue<uint32_t>(800 + 16 + (i * 4)), src_vert[i % 4]);
  }
}

TEST_P(InstSme, udot_Indexed_vgx4) {
  // 8-bit to 32-bit widening
  initialHeapData_.resize(SVL / 8);
  uint8_t* heap8 = reinterpret_cast<uint8_t*>(initialHeapData_.data());
  std::vector<uint8_t> src = {0, 1, 2,  3,  4,  5,  6,  7,
                              8, 9, 10, 11, 12, 13, 14, 15};
  fillHeap<uint8_t>(heap8, src, SVL / 8);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    smstart

    zero {za}

    # Pre-fill all of za with 96 (uint32_t)
    dup z1.b, #8
    dup z2.b, #3
    ptrue p0.b
    ptrue p1.b
    umopa za0.s, p0/m, p1/m, z1.b, z2.b
    umopa za1.s, p0/m, p1/m, z1.b, z2.b
    umopa za2.s, p0/m, p1/m, z1.b, z2.b
    umopa za3.s, p0/m, p1/m, z1.b, z2.b

    # initialise registers
    mov w8, #1
    dup z4.b, #10
    dup z5.b, #11
    dup z6.b, #12
    dup z7.b, #13
    ld1b {z10.b}, p0/z, [x0]

    udot za.s[w8, #1, vgx4], {z4.b - z7.b}, z10.b[2]
  )");
  const uint16_t zaStride = (SVL / 8) / 4;
  const uint16_t zaQuartIndex = 2;
  for (uint16_t i = 0; i < (SVL / 8); i++) {
    // Effected rows all use same zm values of {8, 9, 10, 11}
    if (i == zaQuartIndex) {
      CHECK_MAT_ROW(AARCH64_REG_ZA, i, uint32_t,
                    fillNeon<uint32_t>({476}, (SVL / 8)));
    } else if (i == zaStride + zaQuartIndex) {
      CHECK_MAT_ROW(AARCH64_REG_ZA, i, uint32_t,
                    fillNeon<uint32_t>({514}, (SVL / 8)));
    } else if (i == (2 * zaStride) + zaQuartIndex) {
      CHECK_MAT_ROW(AARCH64_REG_ZA, i, uint32_t,
                    fillNeon<uint32_t>({552}, (SVL / 8)));
    } else if (i == (3 * zaStride) + zaQuartIndex) {
      CHECK_MAT_ROW(AARCH64_REG_ZA, i, uint32_t,
                    fillNeon<uint32_t>({590}, (SVL / 8)));
    } else {
      // un-effected rows should still be 96 throughout
      CHECK_MAT_ROW(AARCH64_REG_ZA, i, uint32_t,
                    fillNeon<uint32_t>({96}, (SVL / 8)));
    }
  }
}

TEST_P(InstSme, udot_vgx4) {
  // 8-bit to 32-bit widening
  initialHeapData_.resize(SVL / 8);
  uint8_t* heap8 = reinterpret_cast<uint8_t*>(initialHeapData_.data());
  std::vector<uint8_t> src = {0, 1, 2,  3,  4,  5,  6,  7,
                              8, 9, 10, 11, 12, 13, 14, 15};
  fillHeap<uint8_t>(heap8, src, SVL / 8);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    smstart

    zero {za}

    # Pre-fill all of za with 96 (uint32_t)
    dup z1.b, #8
    dup z2.b, #3
    ptrue p0.b
    ptrue p1.b
    umopa za0.s, p0/m, p1/m, z1.b, z2.b
    umopa za1.s, p0/m, p1/m, z1.b, z2.b
    umopa za2.s, p0/m, p1/m, z1.b, z2.b
    umopa za3.s, p0/m, p1/m, z1.b, z2.b

    # initialise registers
    mov w8, #1
    dup z4.b, #10
    dup z5.b, #11
    dup z6.b, #12
    dup z7.b, #13
    ld1b {z8.b}, p0/z, [x0]
    ld1b {z9.b}, p0/z, [x0]
    ld1b {z10.b}, p0/z, [x0]
    ld1b {z11.b}, p0/z, [x0]

    udot za.s[w8, #1, vgx4], {z4.b - z7.b}, {z8.b - z11.b}
  )");
  const uint16_t zaStride = (SVL / 8) / 4;
  const uint16_t zaQuartIndex = 2;
  for (uint16_t i = 0; i < (SVL / 8); i++) {
    if (i == zaQuartIndex) {
      CHECK_MAT_ROW(AARCH64_REG_ZA, i, uint32_t,
                    fillNeon<uint32_t>({156, 316, 476, 636}, (SVL / 8)));
    } else if (i == zaStride + zaQuartIndex) {
      CHECK_MAT_ROW(AARCH64_REG_ZA, i, uint32_t,
                    fillNeon<uint32_t>({162, 338, 514, 690}, (SVL / 8)));
    } else if (i == (2 * zaStride) + zaQuartIndex) {
      CHECK_MAT_ROW(AARCH64_REG_ZA, i, uint32_t,
                    fillNeon<uint32_t>({168, 360, 552, 744}, (SVL / 8)));
    } else if (i == (3 * zaStride) + zaQuartIndex) {
      CHECK_MAT_ROW(AARCH64_REG_ZA, i, uint32_t,
                    fillNeon<uint32_t>({174, 382, 590, 798}, (SVL / 8)));
    } else {
      // un-effected rows should still be 96 throughout
      CHECK_MAT_ROW(AARCH64_REG_ZA, i, uint32_t,
                    fillNeon<uint32_t>({96}, (SVL / 8)));
    }
  }
}

TEST_P(InstSme, uvdot_indexed_vgx4) {
  // 8-bit to 32-bit widening
  initialHeapData_.resize(SVL / 8);
  uint8_t* heap8 = reinterpret_cast<uint8_t*>(initialHeapData_.data());
  std::vector<uint8_t> src = {0, 1, 2,  3,  4,  5,  6,  7,
                              8, 9, 10, 11, 12, 13, 14, 15};
  fillHeap<uint8_t>(heap8, src, SVL / 8);
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    smstart

    zero {za}

    # Pre-fill all of za with 96 (uint32_t)
    dup z1.b, #8
    dup z2.b, #3
    ptrue p0.b
    ptrue p1.b
    umopa za0.s, p0/m, p1/m, z1.b, z2.b
    umopa za1.s, p0/m, p1/m, z1.b, z2.b
    umopa za2.s, p0/m, p1/m, z1.b, z2.b
    umopa za3.s, p0/m, p1/m, z1.b, z2.b

    # initialise registers
    mov w8, #1
    dup z4.b, #10
    dup z5.b, #11
    dup z6.b, #12
    dup z7.b, #13
    ld1b {z10.b}, p0/z, [x0]

    uvdot za.s[w8, #1, vgx4], {z4.b - z7.b}, z10.b[2]
  )");
  const uint16_t zaStride = (SVL / 8) / 4;
  const uint16_t zaQuartIndex = 2;
  for (uint16_t i = 0; i < (SVL / 8); i++) {
    // Effected rows all use same zm values of {8, 9, 10, 11}
    if (i == zaQuartIndex) {
      CHECK_MAT_ROW(AARCH64_REG_ZA, i, uint32_t,
                    fillNeon<uint32_t>({538}, (SVL / 8)));
    } else if (i == zaStride + zaQuartIndex) {
      CHECK_MAT_ROW(AARCH64_REG_ZA, i, uint32_t,
                    fillNeon<uint32_t>({538}, (SVL / 8)));
    } else if (i == (2 * zaStride) + zaQuartIndex) {
      CHECK_MAT_ROW(AARCH64_REG_ZA, i, uint32_t,
                    fillNeon<uint32_t>({538}, (SVL / 8)));
    } else if (i == (3 * zaStride) + zaQuartIndex) {
      CHECK_MAT_ROW(AARCH64_REG_ZA, i, uint32_t,
                    fillNeon<uint32_t>({538}, (SVL / 8)));
    } else {
      // un-effected rows should still be 96 throughout
      CHECK_MAT_ROW(AARCH64_REG_ZA, i, uint32_t,
                    fillNeon<uint32_t>({96}, (SVL / 8)));
    }
  }
}

TEST_P(InstSme, umopa) {
  // 32-bit
  RUN_AARCH64(R"(
    smstart

    dup z1.b, #8
    dup z2.b, #3
    ptrue p0.b
    ptrue p1.b

    zero {za}

    umopa za0.s, p0/m, p1/m, z1.b, z2.b

    dup z3.b, #7
    dup z4.b, #4
    mov x0, #0
    mov x1, #2
    addvl x0, x0, #1
    udiv x0, x0, x1
    whilelo p2.b, xzr, x0

    umopa za2.s, p0/m, p2/m, z3.b, z4.b
  )");
  for (uint16_t i = 0; i < (SVL / 32); i++) {
    CHECK_MAT_ROW(AARCH64_REG_ZAS0, i, uint32_t,
                  fillNeon<uint32_t>({96}, (SVL / 8)));
    CHECK_MAT_ROW(AARCH64_REG_ZAS2, i, uint32_t,
                  fillNeon<uint32_t>({112}, (SVL / 16)));
  }
}

TEST_P(InstSme, zero) {
  // ZT0
  RUN_AARCH64(R"(
    smstart

    zero {zt0}
  )");
  CHECK_TABLE(uint64_t, {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0});

  // ZA tiles
  RUN_AARCH64(R"(
    smstart

    zero {za}
  )");
  for (uint16_t i = 0; i < (SVL / 8); i++) {
    CHECK_MAT_ROW(AARCH64_REG_ZA, i, uint64_t,
                  fillNeon<uint64_t>({0}, SVL / 8));
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
  for (uint16_t i = 0; i < (SVL / 32); i++) {
    CHECK_MAT_ROW(AARCH64_REG_ZAS0, i, uint32_t,
                  fillNeon<uint32_t>({0}, SVL / 8));
    CHECK_MAT_ROW(AARCH64_REG_ZAS2, i, uint32_t,
                  fillNeon<uint32_t>({0}, SVL / 8));
  }
  CHECK_MAT_COL(AARCH64_REG_ZAS1, 3, uint32_t,
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