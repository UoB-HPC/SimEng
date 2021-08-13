#include <cmath>

#include "AArch64RegressionTest.hh"

namespace {

using InstFloat = AArch64RegressionTest;

TEST_P(InstFloat, fabd) {
  // 32-bit
  RUN_AARCH64(R"(
    fmov s0, 2.0
    fmov s1, -0.125
    fmov s2, 12.5
    fmov s3, 6.0
    fabd s4, s0, s1
    fabd s5, s2, s3
  )");
  CHECK_NEON(4, float, {2.125f, 0.f, 0.f, 0.f});
  CHECK_NEON(5, float, {6.5f, 0.f, 0.f, 0.f});

  // 64-bit
  RUN_AARCH64(R"(
    fmov d0, 2.0
    fmov d1, -0.125
    fmov d2, 12.5
    fmov d3, 6.0
    fabd d4, d0, d1
    fabd d5, d2, d3
  )");
  CHECK_NEON(4, double, {2.125, 0.0});
  CHECK_NEON(5, double, {6.5, 0.0});
}

TEST_P(InstFloat, fabs) {
  RUN_AARCH64(R"(
    fmov s0, 2.0
    fmov s1, -0.125
    fmov s2, 12.5
    fabs s3, s0
    fabs s4, s1
    fabs s5, s2
  )");
  CHECK_NEON(3, float, {2.f, 0.f, 0.f, 0.f});
  CHECK_NEON(4, float, {0.125f, 0.f, 0.f, 0.f});
  CHECK_NEON(5, float, {12.5f, 0.f, 0.f, 0.f});

  RUN_AARCH64(R"(
    fmov d0, 2.0
    fmov d1, -0.125
    fmov d2, 12.5
    fabs d3, d0
    fabs d4, d1
    fabs d5, d2
  )");
  CHECK_NEON(3, double, {2.0, 0.f});
  CHECK_NEON(4, double, {0.125, 0.f});
  CHECK_NEON(5, double, {12.5, 0.f});
}

TEST_P(InstFloat, fadd) {
  // 32-bit
  RUN_AARCH64(R"(
    fmov s0, 1.0
    fmov s1, -0.125
    fmov s2, 7.5
    fadd s3, s0, s1
    fadd s4, s0, s2
  )");
  CHECK_NEON(3, float, {0.875f, 0.f, 0.f, 0.f});
  CHECK_NEON(4, float, {8.5f, 0.f, 0.f, 0.f});

  // 64-bit
  RUN_AARCH64(R"(
    fmov d0, 1.0
    fmov d1, -0.125
    fmov d2, 7.5
    fadd d3, d0, d1
    fadd d4, d0, d2
  )");
  CHECK_NEON(3, double, {0.875f, 0.f});
  CHECK_NEON(4, double, {8.5f, 0.f});
}

TEST_P(InstFloat, fccmp) {
  // 32-bit
  RUN_AARCH64(R"(
    fmov s0, 0
    fmov s1, 10.5
    fmov s2, 1.25

    # fcmp 0, 0; eq = true; fcmp 10.5, 1.25; gt = true
    fcmp s0, s0
    fccmp s1, s2, 2, eq
    csetm w3, gt

    # fcmp 0, 0; ne = false; nzcv = 8; lt = true
    fcmp s0, s0
    fccmp s1, s2, 8, ne
    csetm w4, lt

    // # fcmp 10.5, 1.25; gt = true; fcmp 10.5, 0; lt = false
    fcmp s1, s2
    fccmp s1, s0, 10, gt
    csetm w5, lt

    # fcmp 1.25, 10.5; gt = false; nzcv = 8; ne = true
    fcmp s2, s1
    fccmp s2, s2, 8, gt
    csetm w6, ne
  )");
  EXPECT_EQ(getGeneralRegister<uint32_t>(3), -1);
  EXPECT_EQ(getGeneralRegister<uint32_t>(4), -1);
  EXPECT_EQ(getGeneralRegister<uint32_t>(5), 0);
  EXPECT_EQ(getGeneralRegister<uint32_t>(6), -1);

  // 64-bit
  RUN_AARCH64(R"(
    fmov d0, 0
    fmov d1, 10.5
    fmov d2, 1.25

    # fcmp 0, 0; eq = true; fcmp 10.5, 1.25; gt = true
    fcmp d0, d0
    fccmp d1, d2, 2, eq
    csetm w3, gt

    # fcmp 0, 0; ne = false; nzcv = 8; lt = true
    fcmp d0, d0
    fccmp d1, d2, 8, ne
    csetm w4, lt

    // # fcmp 10.5, 1.25; gt = true; fcmp 10.5, 0; lt = false
    fcmp d1, d2
    fccmp d1, d0, 10, gt
    csetm w5, lt

    # fcmp 1.25, 10.5; gt = false; nzcv = 8; ne = true
    fcmp d2, d1
    fccmp d2, d2, 8, gt
    csetm w6, ne
  )");
  EXPECT_EQ(getGeneralRegister<uint32_t>(3), -1);
  EXPECT_EQ(getGeneralRegister<uint32_t>(4), -1);
  EXPECT_EQ(getGeneralRegister<uint32_t>(5), 0);
  EXPECT_EQ(getGeneralRegister<uint32_t>(6), -1);
}

TEST_P(InstFloat, fcmp32) {
  // 1.25 == 1.25
  RUN_AARCH64(R"(
    fmov s0, 1.25
    fmov s1, 1.25
    fcmp s0, s1
  )");
  EXPECT_EQ(getNZCV(), 0b0110);

  // 1.25 > -1.25
  RUN_AARCH64(R"(
    fmov s0, 1.25
    fmov s1, -1.25
    fcmp s0, s1
  )");
  EXPECT_EQ(getNZCV(), 0b0010);

  // 1.25 < 10.5
  RUN_AARCH64(R"(
    fmov s0, 1.25
    fmov s1, 10.5
    fcmp s0, s1
  )");
  EXPECT_EQ(getNZCV(), 0b1000);

  // 1.25 > 0.0 (immediate)
  RUN_AARCH64(R"(
    fmov s0, 1.25
    fcmp s0, 0.0
  )");
  EXPECT_EQ(getNZCV(), 0b0010);

  // 1.0 vs NaN
  initialHeapData_.resize(8);
  reinterpret_cast<float*>(initialHeapData_.data())[0] = std::nan("");
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    fmov s0, 1.0
    ldr s1, [x0]
    fcmp s0, s1
  )");
  EXPECT_EQ(getNZCV(), 0b0011);
}

TEST_P(InstFloat, fcmp64) {
  // 1.25 == 1.25
  RUN_AARCH64(R"(
    fmov d0, 1.25
    fmov d1, 1.25
    fcmp d0, d1
  )");
  EXPECT_EQ(getNZCV(), 0b0110);

  // 1.25 > -1.25
  RUN_AARCH64(R"(
    fmov d0, 1.25
    fmov d1, -1.25
    fcmp d0, d1
  )");
  EXPECT_EQ(getNZCV(), 0b0010);

  // 1.25 < 10.5
  RUN_AARCH64(R"(
    fmov d0, 1.25
    fmov d1, 10.5
    fcmp d0, d1
  )");
  EXPECT_EQ(getNZCV(), 0b1000);

  // 1.25 > 0.0 (immediate)
  RUN_AARCH64(R"(
    fmov d0, 1.25
    fcmp d0, 0.0
  )");
  EXPECT_EQ(getNZCV(), 0b0010);

  // 1.0 vs NaN
  initialHeapData_.resize(8);
  reinterpret_cast<double*>(initialHeapData_.data())[0] = std::nan("");
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    fmov d0, 1.0
    ldr d1, [x0]
    fcmp d0, d1
  )");
  EXPECT_EQ(getNZCV(), 0b0011);
}

TEST_P(InstFloat, fcsel32) {
  // 1.25 == 1.25
  RUN_AARCH64(R"(
    fmov s0, 1.25
    fmov s1, 1.25
    fmov s2, 5.0
    fcmp s0, s1
    fcsel s3, s2, s1, eq
    fcsel s4, s2, s1, lo
    fcsel s5, s2, s1, gt
  )");
  CHECK_NEON(3, float, {5.f, 0.f, 0.f, 0.f});
  CHECK_NEON(4, float, {1.25f, 0.f, 0.f, 0.f});
  CHECK_NEON(5, float, {1.25f, 0.f, 0.f, 0.f});

  // 1.25 > -1.25
  RUN_AARCH64(R"(
    fmov s0, 1.25
    fmov s1, -1.25
    fmov s2, 5.0
    fcmp s0, s1
    fcsel s3, s2, s1, eq
    fcsel s4, s2, s1, lo
    fcsel s5, s2, s1, gt
  )");
  CHECK_NEON(3, float, {-1.25f, 0.f, 0.f, 0.f});
  CHECK_NEON(4, float, {-1.25f, 0.f, 0.f, 0.f});
  CHECK_NEON(5, float, {5.f, 0.f, 0.f, 0.f});

  // 1.25 < 10.5
  RUN_AARCH64(R"(
    fmov s0, 1.25
    fmov s1, 10.5
    fmov s2, 5.0
    fcmp s0, s1
    fcsel s3, s2, s1, eq
    fcsel s4, s2, s1, lo
    fcsel s5, s2, s1, gt
  )");
  CHECK_NEON(3, float, {10.5f, 0.f, 0.f, 0.f});
  CHECK_NEON(4, float, {5.f, 0.f, 0.f, 0.f});
  CHECK_NEON(5, float, {10.5f, 0.f, 0.f, 0.f});

  // 1.0 vs NaN
  initialHeapData_.resize(8);
  reinterpret_cast<float*>(initialHeapData_.data())[0] = std::nan("");
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    fmov s0, 1.0
    ldr s1, [x0]
    fmov s2, 5.0
    fcmp s0, s1
    fcsel s3, s2, s0, eq
    fcsel s4, s2, s0, lo
    fcsel s5, s2, s0, gt
  )");
  CHECK_NEON(3, float, {1.f, 0.f, 0.f, 0.f});
  CHECK_NEON(4, float, {1.f, 0.f, 0.f, 0.f});
  CHECK_NEON(5, float, {1.f, 0.f, 0.f, 0.f});
}

TEST_P(InstFloat, fcsel64) {
  // 1.25 == 1.25
  RUN_AARCH64(R"(
    fmov d0, 1.25
    fmov d1, 1.25
    fmov d2, 5.0
    fcmp d0, d1
    fcsel d3, d2, d1, eq
    fcsel d4, d2, d1, lo
    fcsel d5, d2, d1, gt
  )");
  CHECK_NEON(3, double, {5.0, 0.0});
  CHECK_NEON(4, double, {1.25, 0.0});
  CHECK_NEON(5, double, {1.25, 0.0});

  // 1.25 > -1.25
  RUN_AARCH64(R"(
    fmov d0, 1.25
    fmov d1, -1.25
    fmov d2, 5.0
    fcmp d0, d1
    fcsel d3, d2, d1, eq
    fcsel d4, d2, d1, lo
    fcsel d5, d2, d1, gt
  )");
  CHECK_NEON(3, double, {-1.25, 0.0});
  CHECK_NEON(4, double, {-1.25, 0.0});
  CHECK_NEON(5, double, {5.0, 0.0});

  // 1.25 < 10.5
  RUN_AARCH64(R"(
    fmov d0, 1.25
    fmov d1, 10.5
    fmov d2, 5.0
    fcmp d0, d1
    fcsel d3, d2, d1, eq
    fcsel d4, d2, d1, lo
    fcsel d5, d2, d1, gt
  )");
  CHECK_NEON(3, double, {10.5, 0.0});
  CHECK_NEON(4, double, {5.0, 0.0});
  CHECK_NEON(5, double, {10.5, 0.0});

  // 1.0 vs NaN
  initialHeapData_.resize(8);
  reinterpret_cast<double*>(initialHeapData_.data())[0] = std::nan("");
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    fmov d0, 1.0
    ldr d1, [x0]
    fmov d2, 5.0
    fcmp d0, d1
    fcsel d3, d2, d0, eq
    fcsel d4, d2, d0, lo
    fcsel d5, d2, d0, gt
  )");
  CHECK_NEON(3, double, {1.0, 0.0});
  CHECK_NEON(4, double, {1.0, 0.0});
  CHECK_NEON(5, double, {1.0, 0.0});
}

TEST_P(InstFloat, fcmeq_zero) {
  // Vector single-precision
  RUN_AARCH64(R"(
    # v0 = {0.5f, 0.5f, 0.5f, 0.5f}
    fmov v0.4s, #0.5

    # v1 = {0.f, 1.5f, 0.f, 1.5f}
    fmov v1.4s, #1.5
    mov v1.s[0], wzr
    mov v1.s[2], wzr

    # v2 = {2.5f, 0.f, 2.5f, 0.f}
    fmov v2.4s, #2.5
    mov v2.s[1], wzr
    mov v2.s[3], wzr

    fcmeq v4.4s, v0.4s, #0.0
    fcmeq v5.4s, v1.4s, #0.0
    fcmeq v6.4s, v2.4s, #0.0
    fcmeq v7.4s, v3.4s, #0.0
    fcmeq v8.2s, v0.2s, #0.0
    fcmeq v9.2s, v1.2s, #0.0
    fcmeq v10.2s, v2.2s, #0.0
    fcmeq v11.2s, v3.2s, #0.0
  )");
  CHECK_NEON(4, uint32_t, {0x00000000, 0x00000000, 0x00000000, 0x00000000});
  CHECK_NEON(5, uint32_t, {0xffffffff, 0x00000000, 0xffffffff, 0x00000000});
  CHECK_NEON(6, uint32_t, {0x00000000, 0xffffffff, 0x00000000, 0xffffffff});
  CHECK_NEON(7, uint32_t, {0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff});

  CHECK_NEON(8, uint32_t, {0x00000000, 0x00000000, 0x00000000, 0x00000000});
  CHECK_NEON(9, uint32_t, {0xffffffff, 0x00000000, 0x00000000, 0x00000000});
  CHECK_NEON(10, uint32_t, {0x00000000, 0xffffffff, 0x00000000, 0x00000000});
  CHECK_NEON(11, uint32_t, {0xffffffff, 0xffffffff, 0x00000000, 0x00000000});
}

TEST_P(InstFloat, fcvta) {
  // 64-bit
  initialHeapData_.resize(48);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  dheap[0] = -3.75;
  dheap[1] = -3.5;
  dheap[2] = -3.125;
  dheap[3] = 3.0;
  dheap[4] = 0.5;
  dheap[5] = 0.0;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldp d0, d1, [x0]
    ldp d2, d3, [x0, #16]
    ldp d4, d5, [x0, #32]
    fcvtas x6, d0
    fcvtas x7, d1
    fcvtas x8, d2
    fcvtas x9, d3
    fcvtas x10, d4
    fcvtas x11, d5
  )");
  EXPECT_EQ((getGeneralRegister<int64_t>(6)), -4);
  EXPECT_EQ((getGeneralRegister<int64_t>(7)), -4);
  EXPECT_EQ((getGeneralRegister<int64_t>(8)), -3);
  EXPECT_EQ((getGeneralRegister<int64_t>(9)), 3);
  EXPECT_EQ((getGeneralRegister<int64_t>(10)), 1);
  EXPECT_EQ((getGeneralRegister<int64_t>(11)), 0);

  // 32-bit
  dheap[0] = 3.75;
  dheap[1] = 3.5;
  dheap[2] = 3.125;
  dheap[3] = -3.0;
  dheap[4] = -0.5;
  dheap[5] = -0.0;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldp d0, d1, [x0]
    ldp d2, d3, [x0, #16]
    ldp d4, d5, [x0, #32]
    fcvtas w6, d0
    fcvtas w7, d1
    fcvtas w8, d2
    fcvtas w9, d3
    fcvtas w10, d4
    fcvtas w11, d5
  )");
  EXPECT_EQ((getGeneralRegister<int32_t>(6)), 4);
  EXPECT_EQ((getGeneralRegister<int32_t>(7)), 4);
  EXPECT_EQ((getGeneralRegister<int32_t>(8)), 3);
  EXPECT_EQ((getGeneralRegister<int32_t>(9)), -3);
  EXPECT_EQ((getGeneralRegister<int32_t>(10)), -1);
  EXPECT_EQ((getGeneralRegister<int32_t>(11)), -0);
}

TEST_P(InstFloat, fcvt) {
  initialHeapData_.resize(32);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  dheap[0] = 1.0;
  dheap[1] = -42.76;
  dheap[2] = -0.125;
  dheap[3] = 321.5;

  // 32-bit to 64-bit
  RUN_AARCH64(R"(
    fmov s0, 1.25
    fmov s1, -10.5
    fcvt d0, s0
    fcvt d1, s1
  )");
  CHECK_NEON(0, double, {1.25, 0.0});
  CHECK_NEON(1, double, {-10.5, 0.0});

  // 64-bit to 32-bit
  RUN_AARCH64(R"(
    fmov d0, 1.25
    fmov d1, -10.5
    fcvt s0, d0
    fcvt s1, d1
  )");
  CHECK_NEON(0, float, {1.25f, 0.f, 0.f, 0.f});
  CHECK_NEON(1, float, {-10.5f, 0.f, 0.f, 0.f});

  // Signed, round to zero
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldp d0, d1, [x0]
    ldp d2, d3, [x0, #16]
    fcvtzs w0, d0
    fcvtzs w1, d1
    fcvtzs w2, d2
    fcvtzs w3, d3
  )");
  EXPECT_EQ((getGeneralRegister<int32_t>(0)), 1);
  EXPECT_EQ((getGeneralRegister<int32_t>(1)), -42);
  EXPECT_EQ((getGeneralRegister<int32_t>(2)), 0);
  EXPECT_EQ((getGeneralRegister<int32_t>(3)), 321);

  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  fheap[0] = 1.0;
  fheap[1] = -42.76;
  fheap[2] = -0.125;
  fheap[3] = 321.5;

  // Signed, round to zero
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldp s0, s1, [x0]
    ldp s2, s3, [x0, #8]
    fcvtzs w0, s0
    fcvtzs w1, s1
    fcvtzs w2, s2
    fcvtzs w3, s3
  )");
  EXPECT_EQ((getGeneralRegister<int32_t>(0)), 1);
  EXPECT_EQ((getGeneralRegister<int32_t>(1)), -42);
  EXPECT_EQ((getGeneralRegister<int32_t>(2)), 0);
  EXPECT_EQ((getGeneralRegister<int32_t>(3)), 321);
}

TEST_P(InstFloat, fcvtl) {
  // 2 floats to 2 doubles
  RUN_AARCH64(R"(
    fmov v0.2s, 2.25
    fcvtl v1.2d, v0.2s
  )");
  CHECK_NEON(1, double, {static_cast<double>(2.25), static_cast<double>(2.25)});

  // 4 floats to 2 doubles
  RUN_AARCH64(R"(
    # Preparing {1.0, 2.0, 3.0, 4.0} for v0.4s
    mov w0, #0x3f800000
    mov w1, #0x40000000
    mov w2, #0x40400000
    mov w3, #0x40800000

    # inserting elements
    mov v0.s[0], w0
    mov v0.s[1], w1
    mov v0.s[2], w2
    mov v0.s[3], w3

    fcvtl2 v1.2d, v0.4s
  )");
  CHECK_NEON(1, double, {static_cast<double>(3.0), static_cast<double>(4.0)});
}

TEST_P(InstFloat, fcvtn) {
  // 2 doubles to 2 floats
  RUN_AARCH64(R"(
    fmov v0.2d, #0.125
    fcvtn v1.2s, v0.2d
  )");
  CHECK_NEON(1, float, {0.125f, 0.125f, 0.f, 0.f});

  // 2 doubles to 4 floats
  RUN_AARCH64(R"(
    fmov v0.2d, #0.125
    fcvtn2 v1.4s, v0.2d
  )");
  CHECK_NEON(1, float, {0.f, 0.f, 0.125f, 0.125f});
}

TEST_P(InstFloat, fdiv) {
  // FP32
  RUN_AARCH64(R"(
    fmov s0, 2.0
    fmov s1, -0.125
    fmov s2, 16
    fdiv s3, s0, s1
    fdiv s4, s0, s2
  )");
  CHECK_NEON(3, float, {-16.f, 0.f, 0.f, 0.f});
  CHECK_NEON(4, float, {0.125f, 0.f, 0.f, 0.f});

  // FP64
  RUN_AARCH64(R"(
    fmov d0, 2.0
    fmov d1, -0.125
    fmov d2, 12.5
    fdiv d3, d0, d1
    fdiv d4, d0, d2
  )");
  CHECK_NEON(3, double, {-16.0, 0.0});
  CHECK_NEON(4, double, {0.16, 0.0});
}

TEST_P(InstFloat, fmadd) {
  // 32-bit
  RUN_AARCH64(R"(
    fmov s0, 2.0
    fmov s1, -0.125
    fmov s2, 7.5
    fmadd s3, s0, s1, s2
    fmadd s4, s1, s2, s0
  )");
  CHECK_NEON(3, float, {7.25f, 0.f, 0.f, 0.f});
  CHECK_NEON(4, float, {1.0625f, 0.f, 0.f, 0.f});

  // 64-bit
  RUN_AARCH64(R"(
    fmov d0, 2.0
    fmov d1, -0.125
    fmov d2, 7.5
    fmadd d3, d0, d1, d2
    fmadd d4, d1, d2, d0
  )");
  CHECK_NEON(3, double, {7.25, 0.0});
  CHECK_NEON(4, double, {1.0625, 0.0});
}

TEST_P(InstFloat, fmaxnm) {
  // 32-bit numeric
  RUN_AARCH64(R"(
    fmov s0, 2.0
    fmov s1, -0.125
    fmov s2, 7.5
    fmaxnm s3, s0, s2
    fmaxnm s4, s1, s2
  )");
  CHECK_NEON(3, float, {7.5f, 0.f, 0.f, 0.f});
  CHECK_NEON(4, float, {7.5f, 0.f, 0.f, 0.f});

  // 32-bit with NAN
  initialHeapData_.resize(4);
  reinterpret_cast<float*>(initialHeapData_.data())[0] = std::nan("");
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    fmov s0, -2.0
    ldr s1, [x0]
    fmaxnm s2, s0, s1
  )");
  CHECK_NEON(2, float, {-2.0f, 0.f, 0.f, 0.f});

  // 64-bit numeric
  RUN_AARCH64(R"(
    fmov d0, 2.0
    fmov d1, -0.125
    fmov d2, 7.5
    fmaxnm d3, d0, d2
    fmaxnm d4, d1, d2
  )");
  CHECK_NEON(3, double, {7.5, 0.0});
  CHECK_NEON(4, double, {7.5, 0.0});

  // 64-bit with NAN
  initialHeapData_.resize(8);
  reinterpret_cast<double*>(initialHeapData_.data())[0] = std::nan("");
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    fmov d0, -2.0
    ldr d1, [x0]
    fmaxnm d2, d0, d1
  )");
  CHECK_NEON(2, double, {-2.0, 0.0});

  // 32-bit with NAN in s2
  RUN_AARCH64(R"(
    fmov s0, 2.0
    fmov s1, -0.125
    fsqrt s2, s1
    fmaxnm s3, s0, s1
    fmaxnm s4, s1, s0
    fmaxnm s5, s1, s2
    fmaxnm s6, s2, s1
  )");
  CHECK_NEON(3, float, {2.0f, 0.f, 0.f, 0.f});
  CHECK_NEON(4, float, {2.0f, 0.f, 0.f, 0.f});
  CHECK_NEON(5, float, {-0.125f, 0.f, 0.f, 0.f});
  CHECK_NEON(6, float, {-0.125f, 0.f, 0.f, 0.f});
}

TEST_P(InstFloat, fminnm) {
  // 64-bit
  RUN_AARCH64(R"(
    fmov d0, 2.0
    fmov d1, -0.125
    fmov d2, 7.5
    fminnm d3, d0, d2
    fminnm d4, d1, d2
  )");
  CHECK_NEON(3, double, {2.0, 0.0});
  CHECK_NEON(4, double, {-0.125, 0.0});

  // 64-bit with NAN
  initialHeapData_.resize(8);
  reinterpret_cast<double*>(initialHeapData_.data())[0] = std::nan("");
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    fmov d0, 2.0
    ldr d1, [x0]
    fminnm d2, d0, d1
  )");
  CHECK_NEON(2, double, {2.0, 0.0});

  // 32-bit with nan in s2
  RUN_AARCH64(R"(
    fmov s0, 2.0
    fmov s1, -0.125
    fsqrt s2, s1
    fminnm s3, s0, s1
    fminnm s4, s1, s0
    fminnm s5, s0, s2
    fminnm s6, s2, s0
  )");
  CHECK_NEON(3, float, {-0.125f, 0.f, 0.f, 0.f});
  CHECK_NEON(4, float, {-0.125f, 0.f, 0.f, 0.f});
  CHECK_NEON(5, float, {2.0f, 0.f, 0.f, 0.f});
  CHECK_NEON(6, float, {2.0f, 0.f, 0.f, 0.f});
}

TEST_P(InstFloat, fmov) {
  // FP32 scalar from immediate
  RUN_AARCH64(R"(
    fmov s0, 1.0
    fmov s1, -0.125
  )");
  CHECK_NEON(0, float, {1.0f, 0.f, 0.f, 0.f});
  CHECK_NEON(1, float, {-0.125f, 0.f, 0.f, 0.f});

  // FP32 scalar from register
  RUN_AARCH64(R"(
    fmov s0, 1.0
    fmov s1, -0.125
    fmov s2, s1
    fmov s3, s0
  )");
  CHECK_NEON(2, float, {-0.125f, 0.f, 0.f, 0.f});
  CHECK_NEON(3, float, {1.0f, 0.f, 0.f, 0.f});

  // FP32 general from scalar
  initialHeapData_.resize(8);
  reinterpret_cast<float*>(initialHeapData_.data())[0] = 128.5;
  reinterpret_cast<float*>(initialHeapData_.data())[1] = -0.0625;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr s1, [x0]
    ldr s2, [x0, #4]
    fmov w1, s1
    fmov w2, s2
  )");
  EXPECT_EQ((getGeneralRegister<float>(1)), 128.5);
  EXPECT_EQ((getGeneralRegister<float>(2)), -0.0625);

  // FP32 scalar from general
  initialHeapData_.resize(8);
  reinterpret_cast<float*>(initialHeapData_.data())[0] = 128.5;
  reinterpret_cast<float*>(initialHeapData_.data())[1] = -0.0625;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr w1, [x0]
    ldr w2, [x0, #4]
    fmov s0, w1
    fmov s1, w2
  )");
  CHECK_NEON(0, float, {128.5f, 0.f, 0.f, 0.f});
  CHECK_NEON(1, float, {-0.0625f, 0.f, 0.f, 0.f});

  // FP64 scalar from immediate
  RUN_AARCH64(R"(
    fmov d0, 1.0
    fmov d1, -0.125
  )");
  CHECK_NEON(0, double, {1.0, 0.0});
  CHECK_NEON(1, double, {-0.125, 0.0});

  // FP64 scalar from register
  RUN_AARCH64(R"(
    fmov d0, 1.0
    fmov d1, -0.125
    fmov d2, d1
    fmov d3, d0
  )");
  CHECK_NEON(2, double, {-0.125, 0.0});
  CHECK_NEON(3, double, {1.0, 0.0});

  // FP64 general from scalar
  initialHeapData_.resize(16);
  reinterpret_cast<double*>(initialHeapData_.data())[0] = 123.456;
  reinterpret_cast<double*>(initialHeapData_.data())[1] = -0.00032;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr d1, [x0]
    ldr d2, [x0, #8]
    fmov x1, d1
    fmov x2, d2
  )");
  EXPECT_EQ((getGeneralRegister<double>(1)), 123.456);
  EXPECT_EQ((getGeneralRegister<double>(2)), -0.00032);

  // FP64 scalar from general
  initialHeapData_.resize(16);
  reinterpret_cast<double*>(initialHeapData_.data())[0] = 123.456;
  reinterpret_cast<double*>(initialHeapData_.data())[1] = -0.00032;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr x1, [x0]
    ldr x2, [x0, #8]
    fmov d0, x1
    fmov d1, x2
  )");
  CHECK_NEON(0, double, {123.456, 0.0});
  CHECK_NEON(1, double, {-0.00032, 0.0});

  // FP64 top half to general
  initialHeapData_.resize(32);
  reinterpret_cast<double*>(initialHeapData_.data())[0] = 111.111;
  reinterpret_cast<double*>(initialHeapData_.data())[1] = 123.456;
  reinterpret_cast<double*>(initialHeapData_.data())[2] = 111.111;
  reinterpret_cast<double*>(initialHeapData_.data())[3] = -0.00032;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q1, [x0]
    ldr q2, [x0, #16]
    fmov x1, v1.d[1]
    fmov x2, v2.d[1]
  )");
  EXPECT_EQ((getGeneralRegister<double>(1)), 123.456);
  EXPECT_EQ((getGeneralRegister<double>(2)), -0.00032);

  // FP64 top half from general
  initialHeapData_.resize(32);
  reinterpret_cast<double*>(initialHeapData_.data())[0] = 123.456;
  reinterpret_cast<double*>(initialHeapData_.data())[1] = -0.00032;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr d1, [x0]
    ldr x2, [x0, #8]
    fmov v1.d[1], x2
  )");
  CHECK_NEON(1, double, {123.456, -0.00032});
}

TEST_P(InstFloat, fmsub) {
  // 32-bit
  RUN_AARCH64(R"(
    fmov s0, 2.0
    fmov s1, -0.125
    fmov s2, 7.5
    fmsub s3, s0, s1, s2
    fmsub s4, s1, s2, s0
  )");
  CHECK_NEON(3, float, {7.75f, 0.f, 0.f, 0.f});
  CHECK_NEON(4, float, {2.9375f, 0.f, 0.f, 0.f});

  // 64-bit
  RUN_AARCH64(R"(
    fmov d0, 2.0
    fmov d1, -0.125
    fmov d2, 7.5
    fmsub d3, d0, d1, d2
    fmsub d4, d1, d2, d0
  )");
  CHECK_NEON(3, double, {7.75, 0.0});
  CHECK_NEON(4, double, {2.9375, 0.0});
}

TEST_P(InstFloat, fmul) {
  // 32-bit
  RUN_AARCH64(R"(
    fmov s0, 2.0
    fmov s1, -0.125
    fmov s2, 7.5
    fmul s3, s0, s1
    fmul s4, s0, s2
  )");
  CHECK_NEON(3, float, {-0.25f, 0.f, 0.f, 0.f});
  CHECK_NEON(4, float, {15.f, 0.f, 0.f, 0.f});

  // 64-bit
  RUN_AARCH64(R"(
    fmov d0, 2.0
    fmov d1, -0.125
    fmov d2, 7.5
    fmul d3, d0, d1
    fmul d4, d0, d2
  )");
  CHECK_NEON(3, double, {-0.25, 0.0});
  CHECK_NEON(4, double, {15.0, 0.0});
}

TEST_P(InstFloat, fneg) {
  // 32-bit
  RUN_AARCH64(R"(
    fmov s0, 2.0
    fmov s1, -0.125
    fmov s2, 12.5
    fneg s3, s0
    fneg s4, s1
    fneg s5, s2
  )");
  CHECK_NEON(3, float, {-2.f, 0.f, 0.f, 0.f});
  CHECK_NEON(4, float, {0.125f, 0.f, 0.f, 0.f});
  CHECK_NEON(5, float, {-12.5f, 0.f, 0.f, 0.f});

  // 64-bit
  RUN_AARCH64(R"(
    fmov d0, 2.0
    fmov d1, -0.125
    fmov d2, 12.5
    fneg d3, d0
    fneg d4, d1
    fneg d5, d2
  )");
  CHECK_NEON(3, double, {-2.0, 0.0});
  CHECK_NEON(4, double, {0.125, 0.0});
  CHECK_NEON(5, double, {-12.5, 0.0});
}

TEST_P(InstFloat, fnmsub) {
  // 32-bit
  RUN_AARCH64(R"(
    fmov s0, 2.0
    fmov s1, -0.125
    fmov s2, 7.5
    fnmsub s3, s0, s1, s2
    fnmsub s4, s1, s2, s0
  )");
  CHECK_NEON(3, float, {-7.75f, 0.f, 0.f, 0.f});
  CHECK_NEON(4, float, {-2.9375f, 0.f, 0.f, 0.f});

  // 64-bit
  RUN_AARCH64(R"(
    fmov d0, 2.0
    fmov d1, -0.125
    fmov d2, 7.5
    fnmsub d3, d0, d1, d2
    fnmsub d4, d1, d2, d0
  )");
  CHECK_NEON(3, double, {-7.75, 0.0});
  CHECK_NEON(4, double, {-2.9375, 0.0});
}

TEST_P(InstFloat, fnmul) {
  // 64-bit
  RUN_AARCH64(R"(
    fmov d0, 2.0
    fmov d1, -0.125
    fmov d2, 7.5
    fnmul d3, d0, d1
    fnmul d4, d0, d2
  )");
  CHECK_NEON(3, double, {0.25, 0.0});
  CHECK_NEON(4, double, {-15.0, 0.0});

  // 32-bit
  RUN_AARCH64(R"(
    fmov s0, 2.0
    fmov s1, -0.125
    fmov s2, 7.5
    fnmul s3, s0, s1
    fnmul s4, s0, s2
  )");
  CHECK_NEON(3, float, {0.25, 0.0, 0.0, 0.0});
  CHECK_NEON(4, float, {-15.0, 0.0, 0.0, 0.0});
}

TEST_P(InstFloat, fsqrt) {
  // 32-bit
  RUN_AARCH64(R"(
    fmov s0, 2.0
    fmov s1, -0.125
    fsqrt s2, s0
    fsqrt s3, s1
  )");
  CHECK_NEON(2, float, {::sqrtf(2.f), 0.f, 0.f, 0.f});
  EXPECT_TRUE(std::isnan(getVectorRegisterElement<float, 0>(3)));
  EXPECT_EQ((getVectorRegisterElement<float, 1>(3)), 0.f);
  EXPECT_EQ((getVectorRegisterElement<float, 2>(3)), 0.f);
  EXPECT_EQ((getVectorRegisterElement<float, 3>(3)), 0.f);

  // 64-bit
  RUN_AARCH64(R"(
    fmov d0, 2.0
    fmov d1, -0.125
    fsqrt d2, d0
    fsqrt d3, d1
  )");
  CHECK_NEON(2, double, {::sqrt(2.0), 0.0});
  EXPECT_TRUE(std::isnan(getVectorRegisterElement<double, 0>(3)));
  EXPECT_EQ((getVectorRegisterElement<double, 1>(3)), 0.0);
}

TEST_P(InstFloat, frsqrte) {
  // single precision
  RUN_AARCH64(R"(
    fmov s0, 2.0
    fmov s1, -0.125

    frsqrte s3, s0
    frsqrte s4, s1
    frsqrte s5, s2
  )");
  CHECK_NEON(3, float, {1.f / sqrtf(2.f), 0.f, 0.f, 0.f});

  EXPECT_TRUE(std::isnan(getVectorRegisterElement<float, 0>(4)));
  EXPECT_EQ((getVectorRegisterElement<float, 1>(4)), 0.f);
  EXPECT_EQ((getVectorRegisterElement<float, 2>(4)), 0.f);
  EXPECT_EQ((getVectorRegisterElement<float, 3>(4)), 0.f);

  EXPECT_TRUE(std::isinf(getVectorRegisterElement<float, 0>(5)));
  EXPECT_EQ((getVectorRegisterElement<float, 1>(5)), 0.f);
  EXPECT_EQ((getVectorRegisterElement<float, 2>(5)), 0.f);
  EXPECT_EQ((getVectorRegisterElement<float, 3>(5)), 0.f);

  // double precision
  RUN_AARCH64(R"(
    fmov d1, 2.0
    fmov d2, -0.125
    fmov d4, 0.0
    frsqrte d0, d1
    frsqrte d3, d2
    frsqrte d5, d4
  )");
  CHECK_NEON(0, double, {1.0 / sqrt(2.0), 0.0});
  EXPECT_TRUE(std::isnan(getVectorRegisterElement<double, 0>(3)));
  EXPECT_EQ((getVectorRegisterElement<double, 1>(3)), 0.0);
  EXPECT_TRUE(std::isinf(getVectorRegisterElement<double, 0>(5)));
  EXPECT_EQ((getVectorRegisterElement<double, 1>(5)), 0.0);

  // Vector single precision
  RUN_AARCH64(R"(
    fmov v0.4s, 2.0
    fmov v1.4s, -0.125

    frsqrte v4.4s, v0.4s
    frsqrte v5.4s, v1.4s
    frsqrte v6.4s, v2.4s
  )");
  CHECK_NEON(4, float,
             {
                 1.f / sqrtf(2.f),
                 1.f / sqrtf(2.f),
                 1.f / sqrtf(2.f),
                 1.f / sqrtf(2.f),
             });

  EXPECT_TRUE(std::isnan(getVectorRegisterElement<float, 0>(5)));
  EXPECT_TRUE(std::isnan(getVectorRegisterElement<float, 1>(5)));
  EXPECT_TRUE(std::isnan(getVectorRegisterElement<float, 2>(5)));
  EXPECT_TRUE(std::isnan(getVectorRegisterElement<float, 3>(5)));

  EXPECT_TRUE(std::isinf(getVectorRegisterElement<float, 0>(6)));
  EXPECT_TRUE(std::isinf(getVectorRegisterElement<float, 1>(6)));
  EXPECT_TRUE(std::isinf(getVectorRegisterElement<float, 2>(6)));
  EXPECT_TRUE(std::isinf(getVectorRegisterElement<float, 3>(6)));

  // Vector single precision (2S)
  RUN_AARCH64(R"(
    fmov v0.4s, 2.0
    fmov v1.4s, -0.125

    frsqrte v4.2s, v0.2s
    frsqrte v5.2s, v1.2s
    frsqrte v6.2s, v2.2s
  )");
  CHECK_NEON(4, float, {1.f / sqrtf(2.f), 1.f / sqrtf(2.f), 0.f, 0.f});

  EXPECT_TRUE(std::isnan(getVectorRegisterElement<float, 0>(5)));
  EXPECT_TRUE(std::isnan(getVectorRegisterElement<float, 1>(5)));
  EXPECT_EQ((getVectorRegisterElement<float, 2>(5)), 0.f);
  EXPECT_EQ((getVectorRegisterElement<float, 3>(5)), 0.f);

  EXPECT_TRUE(std::isinf(getVectorRegisterElement<float, 0>(6)));
  EXPECT_TRUE(std::isinf(getVectorRegisterElement<float, 1>(6)));
  EXPECT_EQ((getVectorRegisterElement<float, 2>(6)), 0.f);
  EXPECT_EQ((getVectorRegisterElement<float, 3>(6)), 0.f);

  // Vector double precison
  RUN_AARCH64(R"(
    fmov v0.2d, 2.0
    fmov v1.2d, -0.125

    frsqrte v3.2d, v0.2d
    frsqrte v4.2d, v1.2d
    frsqrte v5.2d, v2.2d
  )");
  CHECK_NEON(3, double, {1.0 / sqrt(2.0), 1.0 / sqrt(2.0)});

  EXPECT_TRUE(std::isnan(getVectorRegisterElement<double, 0>(4)));
  EXPECT_TRUE(std::isnan(getVectorRegisterElement<double, 1>(4)));

  EXPECT_TRUE(std::isinf(getVectorRegisterElement<double, 0>(5)));
  EXPECT_TRUE(std::isinf(getVectorRegisterElement<double, 1>(5)));
}

TEST_P(InstFloat, frsqrts) {
  // Single precision
  RUN_AARCH64(R"(
    fmov s0, 1.25
    fmov s1, 2.0
    frsqrts s2, s1, s0
  )");
  CHECK_NEON(2, float, {(3.f - 1.25f * 2.f) / 2.f, 0.f, 0.f, 0.f});

  // Double precision
  RUN_AARCH64(R"(
    fmov d0, 1.25
    fmov d1, 2.0
    frsqrts d2, d1, d0 
  )");
  CHECK_NEON(2, double, {(3.0L - (1.25L * 2.0L)) / 2.0, 0.0});

  // Vector single precision
  RUN_AARCH64(R"(
    fmov v0.4s, 1.25
    fmov v1.4s, 2.0
    frsqrts v2.4s, v1.4s, v0.4s
  )");
  CHECK_NEON(2, float,
             {((3.f - (1.25f * 2.f)) / 2.f), ((3.f - (1.25f * 2.f)) / 2.f),
              ((3.f - (1.25f * 2.f)) / 2.f), ((3.f - (1.25f * 2.f)) / 2.f)});

  // Vector single precision (2S)
  RUN_AARCH64(R"(
    fmov v0.4s, 1.25
    fmov v1.4s, 2.0
    frsqrts v2.2s, v1.2s, v0.2s
  )");
  CHECK_NEON(
      2, float,
      {((3.f - (1.25f * 2.f)) / 2.f), ((3.f - (1.25f * 2.f)) / 2.f), 0.f, 0.f});

  // Vector double precision
  RUN_AARCH64(R"(
    fmov v0.2d, 1.25
    fmov v1.2d, 2.0
    frsqrts v2.2d, v1.2d, v0.2d
  )");
  CHECK_NEON(2, double,
             {(3.0L - (1.25L * 2.0L)) / 2.0, (3.0L - (1.25L * 2.0L)) / 2.0})
}

TEST_P(InstFloat, fsub) {
  // FP32
  RUN_AARCH64(R"(
    fmov s0, 1.0
    fmov s1, -0.125
    fmov s2, 7.5
    fsub s3, s0, s1
    fsub s4, s0, s2
  )");
  CHECK_NEON(3, float, {1.125f, 0.f, 0.f, 0.f});
  CHECK_NEON(4, float, {-6.5f, 0.f, 0.f, 0.f});

  // FP64
  RUN_AARCH64(R"(
    fmov d0, 1.0
    fmov d1, -0.125
    fmov d2, 7.5
    fsub d3, d0, d1
    fsub d4, d0, d2
  )");
  CHECK_NEON(3, double, {1.125, 0.0});
  CHECK_NEON(4, double, {-6.5, 0.0});
}

TEST_P(InstFloat, scvtf) {
  // 32-bit integer
  initialHeapData_.resize(16);
  int32_t* heap32 = reinterpret_cast<int32_t*>(initialHeapData_.data());
  heap32[0] = 1;
  heap32[1] = -1;
  heap32[2] = INT32_MAX;
  heap32[3] = INT32_MIN;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # Load and convert integer values
    ldp s0, s1, [x0]
    scvtf s0, s0
    scvtf s1, s1
    ldp s2, s3, [x0, #8]
    scvtf s2, s2
    scvtf s3, s3

    # Load and convert integer values (via general)
    ldp w1, w2, [x0]
    scvtf s4, w1
    scvtf s5, w2
    ldp w3, w4, [x0, #8]
    scvtf s6, w3
    scvtf s7, w4

    # Load and convert integer values to double precision (via general)
    ldp w1, w2, [x0]
    scvtf d8, w1
    scvtf d9, w2
    ldp w3, w4, [x0, #8]
    scvtf d10, w3
    scvtf d11, w4
  )");
  CHECK_NEON(0, float, {1.f, 0.f, 0.f, 0.f});
  CHECK_NEON(1, float, {-1.f, 0.f, 0.f, 0.f});
  CHECK_NEON(2, float, {static_cast<float>(INT32_MAX), 0.f, 0.f, 0.f});
  CHECK_NEON(3, float, {static_cast<float>(INT32_MIN), 0.f, 0.f, 0.f});
  CHECK_NEON(4, float, {1.f, 0.f, 0.f, 0.f});
  CHECK_NEON(5, float, {-1.f, 0.f, 0.f, 0.f});
  CHECK_NEON(6, float, {static_cast<float>(INT32_MAX), 0.f, 0.f, 0.f});
  CHECK_NEON(7, float, {static_cast<float>(INT32_MIN), 0.f, 0.f, 0.f});
  CHECK_NEON(8, double, {1.0, 0.0});
  CHECK_NEON(9, double, {-1.0, 0.0});
  CHECK_NEON(10, double, {static_cast<double>(INT32_MAX), 0.0});
  CHECK_NEON(11, double, {static_cast<double>(INT32_MIN), 0.0});

  // 64-bit integer
  initialHeapData_.resize(32);
  int64_t* heap64 = reinterpret_cast<int64_t*>(initialHeapData_.data());
  heap64[0] = 1;
  heap64[1] = -1;
  heap64[2] = INT64_MAX;
  heap64[3] = INT64_MIN;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # Load and convert integer values
    ldp d0, d1, [x0]
    scvtf d0, d0
    scvtf d1, d1
    ldp d2, d3, [x0, #16]
    scvtf d2, d2
    scvtf d3, d3

    # Load and convert integer values (via general)
    ldp x1, x2, [x0]
    scvtf d4, x1
    scvtf d5, x2
    ldp x3, x4, [x0, #16]
    scvtf d6, x3
    scvtf d7, x4

    # Load and convert integer values to single precision (via general)
    ldp x1, x2, [x0]
    scvtf s8, x1
    scvtf s9, x2
    ldp x3, x4, [x0, #16]
    scvtf s10, x3
    scvtf s11, x4
  )");
  CHECK_NEON(0, double, {1.0, 0.0});
  CHECK_NEON(1, double, {-1.0, 0.0});
  CHECK_NEON(2, double, {static_cast<double>(INT64_MAX), 0.0});
  CHECK_NEON(3, double, {static_cast<double>(INT64_MIN), 0.0});
  CHECK_NEON(4, double, {1.0, 0.0});
  CHECK_NEON(5, double, {-1.0, 0.0});
  CHECK_NEON(6, double, {static_cast<double>(INT64_MAX), 0.0});
  CHECK_NEON(7, double, {static_cast<double>(INT64_MIN), 0.0});
  CHECK_NEON(8, float, {1.f, 0.f, 0.f, 0.f});
  CHECK_NEON(9, float, {-1.f, 0.f, 0.f, 0.f});
  CHECK_NEON(10, float, {static_cast<float>(INT64_MAX), 0.f, 0.f, 0.f});
  CHECK_NEON(11, float, {static_cast<float>(INT64_MIN), 0.f, 0.f, 0.f});
}

TEST_P(InstFloat, ucvtf) {
  // 32-bit integer
  initialHeapData_.resize(16);
  uint32_t* heap32 = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap32[0] = 1;
  heap32[1] = 65537;
  heap32[2] = UINT32_MAX;
  heap32[3] = 0;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # Load and convert integer values
    ldp s0, s1, [x0]
    ucvtf s0, s0
    ucvtf s1, s1
    ldp s2, s3, [x0, #8]
    ucvtf s2, s2
    ucvtf s3, s3

    # Load and convert integer values (via general)
    ldp w1, w2, [x0]
    ucvtf s4, w1
    ucvtf s5, w2
    ldp w3, w4, [x0, #8]
    ucvtf s6, w3
    ucvtf s7, w4

    # Load and convert integer values to double precision (via general)
    ldp w1, w2, [x0]
    ucvtf d8, w1
    ucvtf d9, w2
    ldp w3, w4, [x0, #8]
    ucvtf d10, w3
    ucvtf d11, w4
  )");
  CHECK_NEON(0, float, {1.f, 0.f, 0.f, 0.f});
  CHECK_NEON(1, float, {65537.f, 0.f, 0.f, 0.f});
  CHECK_NEON(2, float, {static_cast<float>(UINT32_MAX), 0.f, 0.f, 0.f});
  CHECK_NEON(3, float, {0.f, 0.f, 0.f, 0.f});
  CHECK_NEON(4, float, {1.f, 0.f, 0.f, 0.f});
  CHECK_NEON(5, float, {65537.f, 0.f, 0.f, 0.f});
  CHECK_NEON(6, float, {static_cast<float>(UINT32_MAX), 0.f, 0.f, 0.f});
  CHECK_NEON(7, float, {0.f, 0.f, 0.f, 0.f});
  CHECK_NEON(8, double, {1.0, 0.0});
  CHECK_NEON(9, double, {65537.0, 0.0});
  CHECK_NEON(10, double, {static_cast<double>(UINT32_MAX), 0.0});
  CHECK_NEON(11, double, {0.0, 0.0});

  // 64-bit integer
  initialHeapData_.resize(32);
  uint64_t* heap64 = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  heap64[0] = 1;
  heap64[1] = (UINT64_C(1) << 48);
  heap64[2] = UINT64_MAX;
  heap64[3] = 0;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # Load and convert integer values
    ldp d0, d1, [x0]
    ucvtf d0, d0
    ucvtf d1, d1
    ldp d2, d3, [x0, #16]
    ucvtf d2, d2
    ucvtf d3, d3

    # Load and convert integer values (via general)
    ldp x1, x2, [x0]
    ucvtf d4, x1
    ucvtf d5, x2
    ldp x3, x4, [x0, #16]
    ucvtf d6, x3
    ucvtf d7, x4

    # Load and convert integer values to single precision (via general)
    ldp x1, x2, [x0]
    ucvtf s8, x1
    ucvtf s9, x2
    ldp x3, x4, [x0, #16]
    ucvtf s10, x3
    ucvtf s11, x4
  )");
  CHECK_NEON(0, double, {1.0, 0.0});
  CHECK_NEON(1, double, {static_cast<double>(UINT64_C(1) << 48), 0.0});
  CHECK_NEON(2, double, {static_cast<double>(UINT64_MAX), 0.0});
  CHECK_NEON(3, double, {0.0, 0.0});
  CHECK_NEON(4, double, {1.0, 0.0});
  CHECK_NEON(5, double, {static_cast<double>(UINT64_C(1) << 48), 0.0});
  CHECK_NEON(6, double, {static_cast<double>(UINT64_MAX), 0.0});
  CHECK_NEON(7, double, {0.0, 0.0});
  CHECK_NEON(8, float, {1.f, 0.f, 0.f, 0.f});
  CHECK_NEON(9, float, {static_cast<float>(UINT64_C(1) << 48), 0.f, 0.f, 0.f});
  CHECK_NEON(10, float, {static_cast<float>(UINT64_MAX), 0.f, 0.f, 0.f});
  CHECK_NEON(11, float, {0.f, 0.f, 0.f, 0.f});
}

INSTANTIATE_TEST_SUITE_P(AArch64, InstFloat, ::testing::Values(EMULATION),
                         coreTypeToString);

}  // namespace