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
  CHECK_NEON(2, double, {1.0, 0.0});
  CHECK_NEON(3, double, {-0.125, -42.76});
}

TEST_P(InstNeon, dup) {
  initialHeapData_.resize(32);
  uint32_t* heap32 = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap32[0] = 42;
  heap32[1] = (1u << 31);
  heap32[2] = UINT32_MAX;
  heap32[3] = 7;
  heap32[4] = 1;
  heap32[5] = (1u << 31) - 1;
  heap32[6] = 0;
  heap32[7] = 0xDEADBEEF;

  // 32-bit vector lane to scalar
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]
    dup s2, v0.s[0]
    dup s3, v0.s[1]
    dup s4, v0.s[2]
    dup s5, v0.s[3]

    # Check mov alias works as well
    mov s6, v1.s[0]
    mov s7, v1.s[1]
    mov s8, v1.s[2]
    mov s9, v1.s[3]
  )");
  CHECK_NEON(2, uint32_t, {42, 0, 0, 0});
  CHECK_NEON(3, uint32_t, {(1u << 31), 0, 0, 0});
  CHECK_NEON(4, uint32_t, {UINT32_MAX, 0, 0, 0});
  CHECK_NEON(5, uint32_t, {7, 0, 0, 0});
  CHECK_NEON(6, uint32_t, {1, 0, 0, 0});
  CHECK_NEON(7, uint32_t, {(1u << 31) - 1, 0, 0, 0});
  CHECK_NEON(8, uint32_t, {0, 0, 0, 0});
  CHECK_NEON(9, uint32_t, {0xDEADBEEF, 0, 0, 0});

  // 32-bit scalar to vector
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr w1, [x0]
    ldr w2, [x0, #4]
    ldr q0, [x0, #16]
    dup v2.4s, w1
    dup v3.4s, w2
    dup v4.4s, v0.s[0]
    dup v5.4s, v0.s[1]
    dup v6.4s, v0.s[2]
    dup v7.4s, v0.s[3]
  )");
  CHECK_NEON(2, uint32_t, {42, 42, 42, 42});
  CHECK_NEON(3, uint32_t, {(1u << 31), (1u << 31), (1u << 31), (1u << 31)});
  CHECK_NEON(4, uint32_t, {1, 1, 1, 1});
  CHECK_NEON(5, uint32_t,
             {(1u << 31) - 1, (1u << 31) - 1, (1u << 31) - 1, (1u << 31) - 1});
  CHECK_NEON(6, uint32_t, {0, 0, 0, 0});
  CHECK_NEON(7, uint32_t, {0xDEADBEEF, 0xDEADBEEF, 0xDEADBEEF, 0xDEADBEEF});

  uint64_t* heap64 = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  heap64[0] = 42;
  heap64[1] = 1ul << 63;
  heap64[2] = UINT64_MAX;
  heap64[3] = 7;

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
  CHECK_NEON(2, uint64_t, {42, 0});
  CHECK_NEON(3, uint64_t, {1ul << 63, 0});
  CHECK_NEON(4, uint64_t, {UINT64_MAX, 0});
  CHECK_NEON(5, uint64_t, {7, 0});

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
  CHECK_NEON(2, uint64_t, {42, 42});
  CHECK_NEON(3, uint64_t, {1ul << 63, 1ul << 63});
  CHECK_NEON(4, uint64_t, {UINT64_MAX, UINT64_MAX});
  CHECK_NEON(5, uint64_t, {7, 7});
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
  CHECK_NEON(2, float, {1.f, 42.75f, 2.5f, 32768.f});
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
  CHECK_NEON(2, double, {1.0, 42.76});
  CHECK_NEON(3, double, {0.125, 321.0});
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
  CHECK_NEON(2, uint64_t, {UINT64_MAX, 0});
  CHECK_NEON(3, uint64_t, {0, UINT64_MAX});
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
  CHECK_NEON(2, int64_t, {1, -42});
  CHECK_NEON(3, int64_t, {0, 321});
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
  CHECK_NEON(2, double, {-8.0, -2.65625});
}

TEST_P(InstNeon, fmov) {
  // FP32 vector from immediate
  RUN_AARCH64(R"(
    fmov v0.4s, 1.0
    fmov v1.4s, -0.125
  )");
  CHECK_NEON(0, float, {1.f, 1.f, 1.f, 1.f});
  CHECK_NEON(1, float, {-0.125f, -0.125f, -0.125f, -0.125f});

  // FP64 vector from immediate
  RUN_AARCH64(R"(
    fmov v0.2d, 1.0
    fmov v1.2d, -0.125
  )");
  CHECK_NEON(0, double, {1.f, 1.f});
  CHECK_NEON(1, double, {-0.125, -0.125});
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
  CHECK_NEON(3, float, {-0.f, 0.f, 0.f, 0.f});
  CHECK_NEON(4, float, {6.25f, 0.f, 0.f, 0.f});
  CHECK_NEON(5, float, {-85.5f, 0.f, 0.f, 0.f});
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
  CHECK_NEON(2, double, {-0.25, -13725.96});
  CHECK_NEON(3, double, {642.0, 0.0});
  CHECK_NEON(4, double, {0.015625, 0.0});
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
  CHECK_NEON(2, double, {-1.0, 42.76});
  CHECK_NEON(3, double, {0.125, -321.0});
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
  CHECK_NEON(2, double, {1.125, -363.76});
}

TEST_P(InstNeon, movi) {
  // scalar, 64-bit
  RUN_AARCH64(R"(
    movi d0, #65280
    movi d1, -1
  )");
  CHECK_NEON(0, uint64_t, {65280u, 0});
  CHECK_NEON(1, uint64_t, {UINT64_MAX, 0});

  // vector, 32-bit
  RUN_AARCH64(R"(
    movi v0.4s, 42
    movi v1.4s, 42, lsl #8
    movi v2.4s, 3, lsl #24
    movi v3.2s, 42
    movi v4.2s, 42, lsl #8
    movi v5.2s, 3, lsl #24
  )");
  CHECK_NEON(0, uint32_t, {42u, 42u, 42u, 42u});
  CHECK_NEON(1, uint32_t, {(42u << 8), (42u << 8), (42u << 8), (42u << 8)});
  CHECK_NEON(2, uint32_t, {(3u << 24), (3u << 24), (3u << 24), (3u << 24)});
  CHECK_NEON(3, uint32_t, {42u, 42u, 0, 0});
  CHECK_NEON(4, uint32_t, {(42u << 8), (42u << 8), 0, 0});
  CHECK_NEON(5, uint32_t, {(3u << 24), (3u << 24), 0, 0});
}

TEST_P(InstNeon, mvni) {
  // 16-bit
  RUN_AARCH64(R"(
    mvni v0.8h, 42
    mvni v1.8h, 42, lsl #8
    mvni v3.4h, 42
    mvni v4.4h, 42, lsl #8
  )");
  CHECK_NEON(0, uint16_t,
             {static_cast<uint16_t>(~42), static_cast<uint16_t>(~42),
              static_cast<uint16_t>(~42), static_cast<uint16_t>(~42),
              static_cast<uint16_t>(~42), static_cast<uint16_t>(~42),
              static_cast<uint16_t>(~42), static_cast<uint16_t>(~42)});
  CHECK_NEON(
      1, uint16_t,
      {static_cast<uint16_t>(~(42u << 8)), static_cast<uint16_t>(~(42u << 8)),
       static_cast<uint16_t>(~(42u << 8)), static_cast<uint16_t>(~(42u << 8)),
       static_cast<uint16_t>(~(42u << 8)), static_cast<uint16_t>(~(42u << 8)),
       static_cast<uint16_t>(~(42u << 8)), static_cast<uint16_t>(~(42u << 8))});
  CHECK_NEON(3, uint16_t,
             {static_cast<uint16_t>(~42), static_cast<uint16_t>(~42),
              static_cast<uint16_t>(~42), static_cast<uint16_t>(~42),
              static_cast<uint16_t>(0), static_cast<uint16_t>(0),
              static_cast<uint16_t>(0), static_cast<uint16_t>(0)});
  CHECK_NEON(
      4, uint16_t,
      {static_cast<uint16_t>(~(42u << 8)), static_cast<uint16_t>(~(42u << 8)),
       static_cast<uint16_t>(~(42u << 8)), static_cast<uint16_t>(~(42u << 8)),
       static_cast<uint16_t>(0), static_cast<uint16_t>(0),
       static_cast<uint16_t>(0), static_cast<uint16_t>(0)});

  // 32-bit
  RUN_AARCH64(R"(
    mvni v0.4s, 42
    mvni v1.4s, 42, lsl #8
    mvni v2.4s, 3, lsl #24
    mvni v3.2s, 42
    mvni v4.2s, 42, lsl #8
    mvni v5.2s, 3, lsl #24
  )");
  CHECK_NEON(0, uint32_t, {~42u, ~42u, ~42u, ~42u});
  CHECK_NEON(1, uint32_t, {~(42u << 8), ~(42u << 8), ~(42u << 8), ~(42u << 8)});
  CHECK_NEON(2, uint32_t, {~(3u << 24), ~(3u << 24), ~(3u << 24), ~(3u << 24)});
  CHECK_NEON(3, uint32_t, {~42u, ~42u, 0, 0});
  CHECK_NEON(4, uint32_t, {~(42u << 8), ~(42u << 8), 0, 0});
  CHECK_NEON(5, uint32_t, {~(3u << 24), ~(3u << 24), 0, 0});
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
  CHECK_NEON(2, uint32_t, {0xFEFDFEFF, 0x7777777F, 0xFEFEFEFE, 0xAFCFEF0F});
  CHECK_NEON(3, uint32_t, {0xDEADBEEF, 0x12345678, 0x98765432, 0xABCDEF01});
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
  CHECK_NEON(2, int32_t, {2, -1, 321, 123});
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
  CHECK_NEON(2, int32_t, {1, -42, -321, -1});

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
  CHECK_NEON(0, int32_t, {-42, 0, 0, 0});
  CHECK_NEON(1, int32_t, {-321, 0, 0, 0});
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
  heap[2] = UINT32_MAX;
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
  CHECK_NEON(2, uint32_t, {42, (1u << 31), UINT32_MAX, 7});
}

INSTANTIATE_TEST_SUITE_P(AArch64, InstNeon, ::testing::Values(EMULATION),
                         coreTypeToString);

}  // namespace
