#include "AArch64RegressionTest.hh"

namespace {

using InstLoad = AArch64RegressionTest;

TEST_P(InstLoad, ldrb) {
  initialHeapData_.resize(8);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0xDEADBEEF;
  heap[1] = 0x12345678;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldrb w1, [x0], 1
    ldrb w2, [x0]
    ldrb w3, [x0, 1]!
    ldrb w4, [x0, 2]

    mov w5, 1
    ldrb w6, [x0, w5, uxtw]
    mov w5, 3
    ldrb w7, [x0, x5]
  )");
  EXPECT_EQ(getGeneralRegister<uint32_t>(1), 0xEF);
  EXPECT_EQ(getGeneralRegister<uint32_t>(2), 0xBE);
  EXPECT_EQ(getGeneralRegister<uint32_t>(3), 0xAD);
  EXPECT_EQ(getGeneralRegister<uint32_t>(4), 0x78);
  EXPECT_EQ(getGeneralRegister<uint32_t>(6), 0xDE);
  EXPECT_EQ(getGeneralRegister<uint32_t>(7), 0x56);
}

// Test that ldr with pre-index mode updates the base pointer correctly.
TEST_P(InstLoad, ldrxpre) {
  initialHeapData_.resize(24);
  uint64_t* heap = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  heap[0] = -1;
  heap[1] = 0xDEADBEEF;
  heap[2] = 0x12345678;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # Load two values from heap using pre-index mode
    ldr x1, [x0, #8]!
    ldr x2, [x0, #8]!
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(0), process_->getHeapStart() + 16);
  EXPECT_EQ(getGeneralRegister<uint32_t>(1), 0xDEADBEEF);
  EXPECT_EQ(getGeneralRegister<uint32_t>(2), 0x12345678);
}

TEST_P(InstLoad, ldr_vector) {
  initialHeapData_.resize(32);
  double* heap = reinterpret_cast<double*>(initialHeapData_.data());
  heap[0] = 1.0;
  heap[1] = 123.456;
  heap[2] = -0.00032;
  heap[3] = 123456;

  // ldr 128-bit
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # Load values from heap
    ldr q0, [x0]
    ldr q1, [x0, #16]
  )");
  EXPECT_EQ((getVectorRegisterElement<double, 0>(0)), 1.0);
  EXPECT_EQ((getVectorRegisterElement<double, 1>(0)), 123.456);
  EXPECT_EQ((getVectorRegisterElement<double, 0>(1)), -0.00032);
  EXPECT_EQ((getVectorRegisterElement<double, 1>(1)), 123456);

  // ldur 128-bit
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # Load values from heap
    ldur q0, [x0]
    ldur q1, [x0, #16]
  )");
  EXPECT_EQ((getVectorRegisterElement<double, 0>(0)), 1.0);
  EXPECT_EQ((getVectorRegisterElement<double, 1>(0)), 123.456);
  EXPECT_EQ((getVectorRegisterElement<double, 0>(1)), -0.00032);
  EXPECT_EQ((getVectorRegisterElement<double, 1>(1)), 123456);
}

TEST_P(InstLoad, ldpd) {
  initialHeapData_.resize(32);
  double* heap = reinterpret_cast<double*>(initialHeapData_.data());
  heap[0] = 1.0;
  heap[1] = 123.456;
  heap[2] = -0.00032;
  heap[3] = 123456;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # Load values from heap
    ldp d0, d1, [x0]
    ldp d2, d3, [x0, #16]
  )");
  EXPECT_EQ((getVectorRegisterElement<double, 0>(0)), 1.0);
  EXPECT_EQ((getVectorRegisterElement<double, 1>(0)), 0);
  EXPECT_EQ((getVectorRegisterElement<double, 0>(1)), 123.456);
  EXPECT_EQ((getVectorRegisterElement<double, 1>(1)), 0);
  EXPECT_EQ((getVectorRegisterElement<double, 0>(2)), -0.00032);
  EXPECT_EQ((getVectorRegisterElement<double, 1>(2)), 0);
  EXPECT_EQ((getVectorRegisterElement<double, 0>(3)), 123456);
  EXPECT_EQ((getVectorRegisterElement<double, 1>(3)), 0);
}

TEST_P(InstLoad, ldrsw) {
  initialHeapData_.resize(8);
  int32_t* heap = reinterpret_cast<int32_t*>(initialHeapData_.data());
  heap[0] = -2;
  heap[1] = INT32_MAX;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # Load 32-bit values from heap and sign-extend to 64-bits
    ldrsw x1, [x0]
    ldrsw x2, [x0, #4]
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(1), -2);
  EXPECT_EQ(getGeneralRegister<int64_t>(2), INT32_MAX);
}

INSTANTIATE_TEST_SUITE_P(AArch64, InstLoad, ::testing::Values(EMULATION),
                         coreTypeToString);

}  // namespace
