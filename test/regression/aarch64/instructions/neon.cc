#include "AArch64RegressionTest.hh"

#include <cmath>

namespace {

using InstNeon = AArch64RegressionTest;

TEST_P(InstNeon, bsl) {
  initialHeapData_.resize(32);
  double* heap = reinterpret_cast<double*>(initialHeapData_.data());
  heap[0] = 1.0;
  heap[1] = -42.76;
  heap[2] = -0.125;
  heap[3] = 0.0;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]
    fcmge v2.2d, v0.2d, 0.0
    fcmge v3.2d, v1.2d, 0.0
    bsl v2.16b, v0.16b, v1.16b
    bsl v3.16b, v0.16b, v1.16b
  )");
  EXPECT_EQ((getVectorRegisterElement<double, 0>(2)), 1.0);
  EXPECT_EQ((getVectorRegisterElement<double, 1>(2)), 0.0);
  EXPECT_EQ((getVectorRegisterElement<double, 0>(3)), -0.125);
  EXPECT_EQ((getVectorRegisterElement<double, 1>(3)), -42.76);
}

TEST_P(InstNeon, dup) {
  initialHeapData_.resize(32);
  uint64_t* heap = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  heap[0] = 42;
  heap[1] = 1ul << 63;
  heap[2] = -1;
  heap[3] = 7;

  // 64-bit vector lane to scalar
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]
    dup d2, v0.d[0]
    dup d3, v0.d[1]

    # Check mov alias works as well
    mov d4, v1.d[0]
    mov d5, v1.d[1]
  )");
  EXPECT_EQ((getVectorRegisterElement<uint64_t, 0>(2)), 42);
  EXPECT_EQ((getVectorRegisterElement<uint64_t, 1>(2)), 0);
  EXPECT_EQ((getVectorRegisterElement<uint64_t, 0>(3)), 1ul << 63);
  EXPECT_EQ((getVectorRegisterElement<uint64_t, 1>(3)), 0);
  EXPECT_EQ((getVectorRegisterElement<uint64_t, 0>(4)), -1);
  EXPECT_EQ((getVectorRegisterElement<uint64_t, 1>(4)), 0);
  EXPECT_EQ((getVectorRegisterElement<uint64_t, 0>(5)), 7);
  EXPECT_EQ((getVectorRegisterElement<uint64_t, 1>(5)), 0);

  // 64-bit scalar to vector
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr x1, [x0]
    ldr x2, [x0, #8]
    ldr q0, [x0, #16]
    dup v2.2d, x1
    dup v3.2d, x2
    dup v4.2d, v0.d[0]
    dup v5.2d, v0.d[1]
  )");
  EXPECT_EQ((getVectorRegisterElement<uint64_t, 0>(2)), 42);
  EXPECT_EQ((getVectorRegisterElement<uint64_t, 1>(2)), 42);
  EXPECT_EQ((getVectorRegisterElement<uint64_t, 0>(3)), 1ul << 63);
  EXPECT_EQ((getVectorRegisterElement<uint64_t, 1>(3)), 1ul << 63);
  EXPECT_EQ((getVectorRegisterElement<uint64_t, 0>(4)), -1);
  EXPECT_EQ((getVectorRegisterElement<uint64_t, 1>(4)), -1);
  EXPECT_EQ((getVectorRegisterElement<uint64_t, 0>(5)), 7);
  EXPECT_EQ((getVectorRegisterElement<uint64_t, 1>(5)), 7);
}

TEST_P(InstNeon, fabs) {
  initialHeapData_.resize(32);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  fheap[0] = 1.0;
  fheap[1] = -42.75;
  fheap[2] = -2.5;
  fheap[3] = 32768;
  fheap[4] = -0.125;
  fheap[5] = 321.0;
  fheap[6] = -0.0;
  fheap[7] = std::nanf("");
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]
    fabs v2.4s, v0.4s
    fabs v3.4s, v1.4s
  )");
  EXPECT_EQ((getVectorRegisterElement<float, 0>(2)), 1.0);
  EXPECT_EQ((getVectorRegisterElement<float, 1>(2)), 42.75);
  EXPECT_EQ((getVectorRegisterElement<float, 2>(2)), 2.5);
  EXPECT_EQ((getVectorRegisterElement<float, 3>(2)), 32768);
  EXPECT_EQ((getVectorRegisterElement<float, 0>(3)), 0.125);
  EXPECT_EQ((getVectorRegisterElement<float, 1>(3)), 321.0);
  EXPECT_EQ((getVectorRegisterElement<float, 2>(3)), 0.0);
  EXPECT_TRUE(std::isnan(getVectorRegisterElement<float, 3>(3)));

  initialHeapData_.resize(32);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  dheap[0] = 1.0;
  dheap[1] = -42.76;
  dheap[2] = -0.125;
  dheap[3] = 321.0;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]
    fabs v2.2d, v0.2d
    fabs v3.2d, v1.2d
  )");
  EXPECT_EQ((getVectorRegisterElement<double, 0>(2)), 1.0);
  EXPECT_EQ((getVectorRegisterElement<double, 1>(2)), 42.76);
  EXPECT_EQ((getVectorRegisterElement<double, 0>(3)), 0.125);
  EXPECT_EQ((getVectorRegisterElement<double, 1>(3)), 321.0);
}

TEST_P(InstNeon, fcmge) {
  initialHeapData_.resize(32);
  double* heap = reinterpret_cast<double*>(initialHeapData_.data());
  heap[0] = 1.0;
  heap[1] = -42.76;
  heap[2] = -0.125;
  heap[3] = 0.0;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]
    fcmge v2.2d, v0.2d, 0.0
    fcmge v3.2d, v1.2d, 0.0
  )");
  EXPECT_EQ((getVectorRegisterElement<uint64_t, 0>(2)), -1);
  EXPECT_EQ((getVectorRegisterElement<uint64_t, 1>(2)), 0);
  EXPECT_EQ((getVectorRegisterElement<uint64_t, 0>(3)), 0);
  EXPECT_EQ((getVectorRegisterElement<uint64_t, 1>(3)), -1);
}

TEST_P(InstNeon, fcvt) {
  initialHeapData_.resize(32);
  double* heap = reinterpret_cast<double*>(initialHeapData_.data());
  heap[0] = 1.0;
  heap[1] = -42.76;
  heap[2] = -0.125;
  heap[3] = 321.5;

  // Signed, round to zero
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]
    fcvtzs v2.2d, v0.2d
    fcvtzs v3.2d, v1.2d
  )");
  EXPECT_EQ((getVectorRegisterElement<int64_t, 0>(2)), 1.0);
  EXPECT_EQ((getVectorRegisterElement<int64_t, 1>(2)), -42);
  EXPECT_EQ((getVectorRegisterElement<int64_t, 0>(3)), 0.0);
  EXPECT_EQ((getVectorRegisterElement<int64_t, 1>(3)), 321);
}

TEST_P(InstNeon, fdiv) {
  initialHeapData_.resize(32);
  double* heap = reinterpret_cast<double*>(initialHeapData_.data());
  heap[0] = 1.0;
  heap[1] = -42.5;
  heap[2] = -0.125;
  heap[3] = 16.0;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]
    fdiv v2.2d, v0.2d, v1.2d
  )");
  EXPECT_EQ((getVectorRegisterElement<double, 0>(2)), -8.0);
  EXPECT_EQ((getVectorRegisterElement<double, 1>(2)), -2.65625);
}

TEST_P(InstNeon, fmov) {
  // FP64 vector from immediate
  RUN_AARCH64(R"(
    fmov v0.2d, 1.0
    fmov v1.2d, -0.125
  )");
  EXPECT_EQ((getVectorRegisterElement<double, 0>(0)), 1.0);
  EXPECT_EQ((getVectorRegisterElement<double, 1>(0)), 1.0);
  EXPECT_EQ((getVectorRegisterElement<double, 0>(1)), -0.125);
  EXPECT_EQ((getVectorRegisterElement<double, 1>(1)), -0.125);
}

TEST_P(InstNeon, fmul) {
  // 32-bit
  initialHeapData_.resize(32);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  fheap[0] = 2.0;
  fheap[1] = -42.75;
  fheap[2] = -0.125;
  fheap[3] = 321.0;
  fheap[4] = -2.5;
  fheap[5] = 32768;
  fheap[6] = -0.0;
  fheap[7] = std::nanf("");
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]
    fmul v2.4s, v0.4s, v1.4s
    fmul s3, s0, v1.s[2]
    fmul s4, s1, v1.s[0]
    fmul s5, s0, v0.s[1]
    fmul s6, s0, v1.s[3]
  )");
  EXPECT_EQ((getVectorRegisterElement<float, 0>(2)), -5.f);
  EXPECT_EQ((getVectorRegisterElement<float, 1>(2)), -1400832.f);
  EXPECT_EQ((getVectorRegisterElement<float, 2>(2)), 0.f);
  EXPECT_TRUE(std::isnan(getVectorRegisterElement<float, 3>(2)));
  EXPECT_EQ((getVectorRegisterElement<float, 0>(3)), -0.f);
  EXPECT_EQ((getVectorRegisterElement<float, 1>(3)), 0.f);
  EXPECT_EQ((getVectorRegisterElement<float, 2>(3)), 0.f);
  EXPECT_EQ((getVectorRegisterElement<float, 3>(3)), 0.f);
  EXPECT_EQ((getVectorRegisterElement<float, 0>(4)), 6.25f);
  EXPECT_EQ((getVectorRegisterElement<float, 1>(4)), 0.f);
  EXPECT_EQ((getVectorRegisterElement<float, 2>(4)), 0.f);
  EXPECT_EQ((getVectorRegisterElement<float, 3>(4)), 0.f);
  EXPECT_EQ((getVectorRegisterElement<float, 0>(5)), -85.5f);
  EXPECT_EQ((getVectorRegisterElement<float, 1>(5)), 0.f);
  EXPECT_EQ((getVectorRegisterElement<float, 2>(5)), 0.f);
  EXPECT_EQ((getVectorRegisterElement<float, 3>(5)), 0.f);
  EXPECT_TRUE(std::isnan(getVectorRegisterElement<float, 0>(6)));
  EXPECT_EQ((getVectorRegisterElement<float, 1>(6)), 0.f);
  EXPECT_EQ((getVectorRegisterElement<float, 2>(6)), 0.f);
  EXPECT_EQ((getVectorRegisterElement<float, 3>(6)), 0.f);

  // 64-bit
  initialHeapData_.resize(32);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  dheap[0] = 2.0;
  dheap[1] = -42.76;
  dheap[2] = -0.125;
  dheap[3] = 321.0;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]
    fmul v2.2d, v0.2d, v1.2d
    fmul d3, d0, v1.d[1]
    fmul d4, d1, v1.d[0]
  )");
  EXPECT_EQ((getVectorRegisterElement<double, 0>(2)), -0.25);
  EXPECT_EQ((getVectorRegisterElement<double, 1>(2)), -13725.96);
  EXPECT_EQ((getVectorRegisterElement<double, 0>(3)), 642.0);
  EXPECT_EQ((getVectorRegisterElement<double, 1>(3)), 0.0);
  EXPECT_EQ((getVectorRegisterElement<double, 0>(4)), 0.015625);
  EXPECT_EQ((getVectorRegisterElement<double, 1>(4)), 0.0);
}

TEST_P(InstNeon, fneg) {
  initialHeapData_.resize(32);
  double* heap = reinterpret_cast<double*>(initialHeapData_.data());
  heap[0] = 1.0;
  heap[1] = -42.76;
  heap[2] = -0.125;
  heap[3] = 321.0;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]
    fneg v2.2d, v0.2d
    fneg v3.2d, v1.2d
  )");
  EXPECT_EQ((getVectorRegisterElement<double, 0>(2)), -1.0);
  EXPECT_EQ((getVectorRegisterElement<double, 1>(2)), 42.76);
  EXPECT_EQ((getVectorRegisterElement<double, 0>(3)), 0.125);
  EXPECT_EQ((getVectorRegisterElement<double, 1>(3)), -321.0);
}

TEST_P(InstNeon, fsub) {
  initialHeapData_.resize(32);
  double* heap = reinterpret_cast<double*>(initialHeapData_.data());
  heap[0] = 1.0;
  heap[1] = -42.76;
  heap[2] = -0.125;
  heap[3] = 321.0;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]
    fsub v2.2d, v0.2d, v1.2d
  )");
  EXPECT_EQ((getVectorRegisterElement<double, 0>(2)), 1.125);
  EXPECT_EQ((getVectorRegisterElement<double, 1>(2)), -363.76);
}

TEST_P(InstNeon, movi) {
  // scalar, 64-bit
  RUN_AARCH64(R"(
    movi d0, #65280
    movi d1, -1
  )");
  EXPECT_EQ((getVectorRegisterElement<uint64_t, 0>(0)), 65280u);
  EXPECT_EQ((getVectorRegisterElement<uint64_t, 1>(0)), 0);
  EXPECT_EQ((getVectorRegisterElement<uint64_t, 0>(1)), -1);
  EXPECT_EQ((getVectorRegisterElement<uint64_t, 1>(1)), 0);

  // vector, 32-bit
  RUN_AARCH64(R"(
    movi v0.4s, 42
    movi v1.4s, 42, lsl #8
    movi v2.4s, 3, lsl #24
    movi v3.2s, 42
    movi v4.2s, 42, lsl #8
    movi v5.2s, 3, lsl #24
  )");
  EXPECT_EQ((getVectorRegisterElement<uint32_t, 0>(0)), 42u);
  EXPECT_EQ((getVectorRegisterElement<uint32_t, 1>(0)), 42u);
  EXPECT_EQ((getVectorRegisterElement<uint32_t, 2>(0)), 42u);
  EXPECT_EQ((getVectorRegisterElement<uint32_t, 3>(0)), 42u);

  EXPECT_EQ((getVectorRegisterElement<uint32_t, 0>(1)), (42u << 8));
  EXPECT_EQ((getVectorRegisterElement<uint32_t, 1>(1)), (42u << 8));
  EXPECT_EQ((getVectorRegisterElement<uint32_t, 2>(1)), (42u << 8));
  EXPECT_EQ((getVectorRegisterElement<uint32_t, 3>(1)), (42u << 8));

  EXPECT_EQ((getVectorRegisterElement<uint32_t, 0>(2)), (3u << 24));
  EXPECT_EQ((getVectorRegisterElement<uint32_t, 1>(2)), (3u << 24));
  EXPECT_EQ((getVectorRegisterElement<uint32_t, 2>(2)), (3u << 24));
  EXPECT_EQ((getVectorRegisterElement<uint32_t, 3>(2)), (3u << 24));

  EXPECT_EQ((getVectorRegisterElement<uint32_t, 0>(3)), 42u);
  EXPECT_EQ((getVectorRegisterElement<uint32_t, 1>(3)), 42u);
  EXPECT_EQ((getVectorRegisterElement<uint32_t, 2>(3)), 0u);
  EXPECT_EQ((getVectorRegisterElement<uint32_t, 3>(3)), 0u);

  EXPECT_EQ((getVectorRegisterElement<uint32_t, 0>(4)), (42u << 8));
  EXPECT_EQ((getVectorRegisterElement<uint32_t, 1>(4)), (42u << 8));
  EXPECT_EQ((getVectorRegisterElement<uint32_t, 2>(4)), 0u);
  EXPECT_EQ((getVectorRegisterElement<uint32_t, 3>(4)), 0u);

  EXPECT_EQ((getVectorRegisterElement<uint32_t, 0>(5)), (3u << 24));
  EXPECT_EQ((getVectorRegisterElement<uint32_t, 1>(5)), (3u << 24));
  EXPECT_EQ((getVectorRegisterElement<uint32_t, 2>(5)), 0u);
  EXPECT_EQ((getVectorRegisterElement<uint32_t, 3>(5)), 0u);
}

TEST_P(InstNeon, orr) {
  initialHeapData_.resize(32);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0xDEADBEEF;
  heap[1] = 0x12345678;
  heap[2] = 0x98765432;
  heap[3] = 0xABCDEF01;
  heap[4] = 0xF0F0F0F0;
  heap[5] = 0x77777777;
  heap[6] = 0xEEEEEEEE;
  heap[7] = 0x0F0F0F0F;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]
    orr v2.16b, v0.16b, v1.16b

    # Test mov alias as well
    mov v3.16b, v0.16b
  )");
  EXPECT_EQ((getVectorRegisterElement<uint32_t, 0>(2)), 0xFEFDFEFF);
  EXPECT_EQ((getVectorRegisterElement<uint32_t, 1>(2)), 0x7777777F);
  EXPECT_EQ((getVectorRegisterElement<uint32_t, 2>(2)), 0xFEFEFEFE);
  EXPECT_EQ((getVectorRegisterElement<uint32_t, 3>(2)), 0xAFCFEF0F);
  EXPECT_EQ((getVectorRegisterElement<uint32_t, 0>(3)), 0xDEADBEEF);
  EXPECT_EQ((getVectorRegisterElement<uint32_t, 1>(3)), 0x12345678);
  EXPECT_EQ((getVectorRegisterElement<uint32_t, 2>(3)), 0x98765432);
  EXPECT_EQ((getVectorRegisterElement<uint32_t, 3>(3)), 0xABCDEF01);
}

TEST_P(InstNeon, smax) {
  initialHeapData_.resize(32);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 1;
  heap[1] = -42;
  heap[2] = 321;
  heap[3] = -1;

  heap[4] = 2;
  heap[5] = -1;
  heap[6] = -321;
  heap[7] = 123;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]
    smax v2.4s, v0.4s, v1.4s
  )");
  EXPECT_EQ((getVectorRegisterElement<uint32_t, 0>(2)), 2);
  EXPECT_EQ((getVectorRegisterElement<uint32_t, 1>(2)), -1);
  EXPECT_EQ((getVectorRegisterElement<uint32_t, 2>(2)), 321);
  EXPECT_EQ((getVectorRegisterElement<uint32_t, 3>(2)), 123);
}

TEST_P(InstNeon, smin) {
  initialHeapData_.resize(32);
  int32_t* heap = reinterpret_cast<int32_t*>(initialHeapData_.data());
  heap[0] = 1;
  heap[1] = -42;
  heap[2] = 321;
  heap[3] = -1;

  heap[4] = 2;
  heap[5] = -1;
  heap[6] = -321;
  heap[7] = 123;

  // smin (element-wise)
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]
    smin v2.4s, v0.4s, v1.4s
  )");
  EXPECT_EQ((getVectorRegisterElement<int32_t, 0>(2)), 1);
  EXPECT_EQ((getVectorRegisterElement<int32_t, 1>(2)), -42);
  EXPECT_EQ((getVectorRegisterElement<int32_t, 2>(2)), -321);
  EXPECT_EQ((getVectorRegisterElement<int32_t, 3>(2)), -1);

  // sminv (across vector)
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]
    sminv s0, v0.4s
    sminv s1, v1.4s
  )");
  EXPECT_EQ((getVectorRegisterElement<int32_t, 0>(0)), -42);
  EXPECT_EQ((getVectorRegisterElement<int32_t, 0>(1)), -321);
}

TEST_P(InstNeon, umov) {
  initialHeapData_.resize(16);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 42;
  heap[1] = 1u << 31;
  heap[2] = -1;
  heap[3] = 7;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    umov w0, v0.s[0]
    umov w1, v0.s[1]

    # Check mov alias works as well
    mov  w2, v0.s[2]
    mov  w3, v0.s[3]
  )");
  EXPECT_EQ((getGeneralRegister<uint32_t>(0)), 42);
  EXPECT_EQ((getGeneralRegister<uint32_t>(1)), 1u << 31);
  EXPECT_EQ((getGeneralRegister<uint32_t>(2)), -1);
  EXPECT_EQ((getGeneralRegister<uint32_t>(3)), 7);
}

TEST_P(InstNeon, xtn) {
  initialHeapData_.resize(32);
  uint64_t* heap = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  heap[0] = 42;
  heap[1] = 1u << 31;
  heap[2] = -1;
  heap[3] = 7;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # Load and narrow integer values
    ldr q0, [x0]
    ldr q1, [x0, #16]
    xtn v2.2s, v0.2d
    xtn2 v2.4s, v1.2d
  )");
  EXPECT_EQ((getVectorRegisterElement<uint32_t, 0>(2)), 42);
  EXPECT_EQ((getVectorRegisterElement<uint32_t, 1>(2)), 1u << 31);
  EXPECT_EQ((getVectorRegisterElement<uint32_t, 2>(2)), -1);
  EXPECT_EQ((getVectorRegisterElement<uint32_t, 3>(2)), 7);
}

INSTANTIATE_TEST_SUITE_P(AArch64, InstNeon, ::testing::Values(EMULATION),
                         coreTypeToString);

}  // namespace
