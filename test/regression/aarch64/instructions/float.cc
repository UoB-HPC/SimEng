#include "AArch64RegressionTest.hh"

#include <cmath>

namespace {

using InstFloat = AArch64RegressionTest;

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
  RUN_AARCH64(R"(
    fmov d0, 1.0
    fmov d1, -0.125
  )");
  EXPECT_EQ((getVectorRegisterElement<double, 0>(0)), 1.0);
  EXPECT_EQ((getVectorRegisterElement<double, 1>(0)), 0.0);
  EXPECT_EQ((getVectorRegisterElement<double, 0>(1)), -0.125);
  EXPECT_EQ((getVectorRegisterElement<double, 1>(1)), 0.0);
}

TEST_P(InstFloat, fsub) {
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
