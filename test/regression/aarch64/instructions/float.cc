#include "AArch64RegressionTest.hh"

#include <cmath>

namespace {

using InstFloat = AArch64RegressionTest;

TEST_P(InstFloat, fadd) {
  RUN_AARCH64(R"(
    fmov d0, 1.0
    fmov d1, -0.125
    fmov d2, 7.5
    fadd d3, d0, d1
    fadd d4, d0, d2
  )");
  EXPECT_EQ((getVectorRegisterElement<double, 0>(3)), 0.875);
  EXPECT_EQ((getVectorRegisterElement<double, 1>(3)), 0.0);
  EXPECT_EQ((getVectorRegisterElement<double, 0>(4)), 8.5);
  EXPECT_EQ((getVectorRegisterElement<double, 1>(4)), 0.0);
}

TEST_P(InstFloat, fcmp) {
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

TEST_P(InstFloat, fcsel) {
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
  EXPECT_EQ((getVectorRegisterElement<double, 0>(3)), 5.0);
  EXPECT_EQ((getVectorRegisterElement<double, 0>(4)), 1.25);
  EXPECT_EQ((getVectorRegisterElement<double, 0>(5)), 1.25);

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
  EXPECT_EQ((getVectorRegisterElement<double, 0>(3)), -1.25);
  EXPECT_EQ((getVectorRegisterElement<double, 0>(4)), -1.25);
  EXPECT_EQ((getVectorRegisterElement<double, 0>(5)), 5.0);

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
  EXPECT_EQ((getVectorRegisterElement<double, 0>(3)), 10.5);
  EXPECT_EQ((getVectorRegisterElement<double, 0>(4)), 5.0);
  EXPECT_EQ((getVectorRegisterElement<double, 0>(5)), 10.5);

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
  EXPECT_EQ((getVectorRegisterElement<double, 0>(3)), 1.0);
  EXPECT_EQ((getVectorRegisterElement<double, 0>(4)), 1.0);
  EXPECT_EQ((getVectorRegisterElement<double, 0>(5)), 1.0);
}

TEST_P(InstFloat, fcvt) {
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
}

TEST_P(InstFloat, fdiv) {
  RUN_AARCH64(R"(
    fmov d0, 2.0
    fmov d1, -0.125
    fmov d2, 12.5
    fdiv d3, d0, d1
    fdiv d4, d0, d2
  )");
  EXPECT_EQ((getVectorRegisterElement<double, 0>(3)), -16);
  EXPECT_EQ((getVectorRegisterElement<double, 1>(3)), 0.0);
  EXPECT_EQ((getVectorRegisterElement<double, 0>(4)), 0.16);
  EXPECT_EQ((getVectorRegisterElement<double, 1>(4)), 0.0);
}

TEST_P(InstFloat, fmadd) {
  RUN_AARCH64(R"(
    fmov d0, 2.0
    fmov d1, -0.125
    fmov d2, 7.5
    fmadd d3, d0, d1, d2
    fmadd d4, d1, d2, d0
  )");
  EXPECT_EQ((getVectorRegisterElement<double, 0>(3)), 7.25);
  EXPECT_EQ((getVectorRegisterElement<double, 1>(3)), 0.0);
  EXPECT_EQ((getVectorRegisterElement<double, 0>(4)), 1.0625);
  EXPECT_EQ((getVectorRegisterElement<double, 1>(4)), 0.0);
}

TEST_P(InstFloat, fmov) {
  // FP64 scalar from immediate
  RUN_AARCH64(R"(
    fmov d0, 1.0
    fmov d1, -0.125
  )");
  EXPECT_EQ((getVectorRegisterElement<double, 0>(0)), 1.0);
  EXPECT_EQ((getVectorRegisterElement<double, 1>(0)), 0.0);
  EXPECT_EQ((getVectorRegisterElement<double, 0>(1)), -0.125);
  EXPECT_EQ((getVectorRegisterElement<double, 1>(1)), 0.0);

  // FP64 scalar from register
  RUN_AARCH64(R"(
    fmov d0, 1.0
    fmov d1, -0.125
    fmov d2, d1
    fmov d3, d0
  )");
  EXPECT_EQ((getVectorRegisterElement<double, 0>(2)), -0.125);
  EXPECT_EQ((getVectorRegisterElement<double, 1>(2)), 0.0);
  EXPECT_EQ((getVectorRegisterElement<double, 0>(3)), 1.0);
  EXPECT_EQ((getVectorRegisterElement<double, 1>(3)), 0.0);

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
  EXPECT_EQ((getVectorRegisterElement<double, 0>(0)), 123.456);
  EXPECT_EQ((getVectorRegisterElement<double, 1>(0)), 0.0);
  EXPECT_EQ((getVectorRegisterElement<double, 0>(1)), -0.00032);
  EXPECT_EQ((getVectorRegisterElement<double, 1>(1)), 0.0);
}

TEST_P(InstFloat, fmul) {
  RUN_AARCH64(R"(
    fmov d0, 2.0
    fmov d1, -0.125
    fmov d2, 7.5
    fmul d3, d0, d1
    fmul d4, d0, d2
  )");
  EXPECT_EQ((getVectorRegisterElement<double, 0>(3)), -0.25);
  EXPECT_EQ((getVectorRegisterElement<double, 1>(3)), 0.0);
  EXPECT_EQ((getVectorRegisterElement<double, 0>(4)), 15.0);
  EXPECT_EQ((getVectorRegisterElement<double, 1>(4)), 0.0);
}

TEST_P(InstFloat, fneg) {
  RUN_AARCH64(R"(
    fmov d0, 2.0
    fmov d1, -0.125
    fmov d2, 12.5
    fneg d3, d0
    fneg d4, d1
    fneg d5, d2
  )");
  EXPECT_EQ((getVectorRegisterElement<double, 0>(3)), -2.0);
  EXPECT_EQ((getVectorRegisterElement<double, 1>(3)), 0.0);
  EXPECT_EQ((getVectorRegisterElement<double, 0>(4)), 0.125);
  EXPECT_EQ((getVectorRegisterElement<double, 1>(4)), 0.0);
  EXPECT_EQ((getVectorRegisterElement<double, 0>(5)), -12.5);
  EXPECT_EQ((getVectorRegisterElement<double, 1>(5)), 0.0);
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
  EXPECT_EQ((getVectorRegisterElement<float, 0>(3)), 1.125);
  EXPECT_EQ((getVectorRegisterElement<float, 1>(3)), 0.0);
  EXPECT_EQ((getVectorRegisterElement<float, 2>(3)), 0.0);
  EXPECT_EQ((getVectorRegisterElement<float, 3>(3)), 0.0);
  EXPECT_EQ((getVectorRegisterElement<float, 0>(4)), -6.5);
  EXPECT_EQ((getVectorRegisterElement<float, 1>(4)), 0.0);
  EXPECT_EQ((getVectorRegisterElement<float, 2>(4)), 0.0);
  EXPECT_EQ((getVectorRegisterElement<float, 3>(4)), 0.0);

  // FP64
  RUN_AARCH64(R"(
    fmov d0, 1.0
    fmov d1, -0.125
    fmov d2, 7.5
    fsub d3, d0, d1
    fsub d4, d0, d2
  )");
  EXPECT_EQ((getVectorRegisterElement<double, 0>(3)), 1.125);
  EXPECT_EQ((getVectorRegisterElement<double, 1>(3)), 0.0);
  EXPECT_EQ((getVectorRegisterElement<double, 0>(4)), -6.5);
  EXPECT_EQ((getVectorRegisterElement<double, 1>(4)), 0.0);
}

TEST_P(InstFloat, scvtf) {
  initialHeapData_.resize(32);
  int64_t* heap = reinterpret_cast<int64_t*>(initialHeapData_.data());
  heap[0] = 1;
  heap[1] = -1;
  heap[2] = INT64_MAX;
  heap[3] = INT64_MIN;

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
  )");
  EXPECT_EQ((getVectorRegisterElement<double, 0>(0)), 1.0);
  EXPECT_EQ((getVectorRegisterElement<double, 0>(1)), -1.0);
  EXPECT_EQ((getVectorRegisterElement<double, 0>(2)),
            static_cast<double>(INT64_MAX));
  EXPECT_EQ((getVectorRegisterElement<double, 0>(3)),
            static_cast<double>(INT64_MIN));
}

INSTANTIATE_TEST_SUITE_P(AArch64, InstFloat, ::testing::Values(EMULATION),
                         coreTypeToString);

}  // namespace
