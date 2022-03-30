#include <stdlib.h>
#include <sys/syscall.h>

#include <cstring>
#include <fstream>
#include <string>

#include "AArch64RegressionTest.hh"

namespace {

using MicroOp = AArch64RegressionTest;

TEST_P(MicroOp, loadPairD) {
  initialHeapData_.resize(48);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  dheap[0] = 1.0;
  dheap[1] = -1.0;
  dheap[2] = 123.45;
  dheap[3] = -123.45;
  dheap[4] = 3.0;
  dheap[5] = -3.0;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldp d1, d2, [x0], #16
    ldp d3, d4, [x0, #0]
    ldp d5, d6, [x0, #16]
    ldp d7, d8, [x0, #-16]!
  )");
  CHECK_NEON(1, double, {1.0});
  CHECK_NEON(2, double, {-1.0});
  CHECK_NEON(3, double, {123.45});
  CHECK_NEON(4, double, {-123.45});
  CHECK_NEON(5, double, {3.0});
  CHECK_NEON(6, double, {-3.0});
  CHECK_NEON(7, double, {1.0});
  CHECK_NEON(8, double, {-1.0});
}

TEST_P(MicroOp, loadPairQ) {
  initialHeapData_.resize(96);
  uint64_t* heap64 = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  heap64[0] = 0xABBACAFEABBACAFE;
  heap64[1] = 0x1234567898765432;
  heap64[2] = 0xABCDEFABCDEFABCD;
  heap64[3] = 0xCAFEABBACAFEABBA;
  heap64[4] = 0x9876543212345678;
  heap64[5] = 0xFEDCBAFEDCBAFEDC;
  heap64[6] = 0xABBACAFEABBACAFE;
  heap64[7] = 0x1234567898765432;
  heap64[8] = 0xABCDEFABCDEFABCD;
  heap64[9] = 0xCAFEABBACAFEABBA;
  heap64[10] = 0x9876543212345678;
  heap64[11] = 0xFEDCBAFEDCBAFEDC;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldp q1, q2, [x0], #32
    ldp q3, q4, [x0, #0]
    ldp q5, q6, [x0, #32]
    ldp q7, q8, [x0, #-32]!
  )");
  CHECK_NEON(1, uint64_t, {0xABBACAFEABBACAFE, 0x1234567898765432});
  CHECK_NEON(2, uint64_t, {0xABCDEFABCDEFABCD, 0xCAFEABBACAFEABBA});
  CHECK_NEON(3, uint64_t, {0x9876543212345678, 0xFEDCBAFEDCBAFEDC});
  CHECK_NEON(4, uint64_t, {0xABBACAFEABBACAFE, 0x1234567898765432});
  CHECK_NEON(5, uint64_t, {0xABCDEFABCDEFABCD, 0xCAFEABBACAFEABBA});
  CHECK_NEON(6, uint64_t, {0x9876543212345678, 0xFEDCBAFEDCBAFEDC});
  CHECK_NEON(7, uint64_t, {0xABBACAFEABBACAFE, 0x1234567898765432});
  CHECK_NEON(8, uint64_t, {0xABCDEFABCDEFABCD, 0xCAFEABBACAFEABBA});
}

TEST_P(MicroOp, loadPairS) {
  initialHeapData_.resize(24);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  fheap[0] = 1.0f;
  fheap[1] = -1.0f;
  fheap[2] = 123.45f;
  fheap[3] = -123.45f;
  fheap[4] = 3.0f;
  fheap[5] = -3.0f;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldp s1, s2, [x0], #8
    ldp s3, s4, [x0, #0]
    ldp s5, s6, [x0, #8]
    ldp s7, s8, [x0, #-8]!
  )");
  CHECK_NEON(1, float, {1.0f});
  CHECK_NEON(2, float, {-1.0f});
  CHECK_NEON(3, float, {123.45f});
  CHECK_NEON(4, float, {-123.45f});
  CHECK_NEON(5, float, {3.0f});
  CHECK_NEON(6, float, {-3.0f});
  CHECK_NEON(7, float, {1.0f});
  CHECK_NEON(8, float, {-1.0f});
}

TEST_P(MicroOp, loadPairW) {
  initialHeapData_.resize(24);
  uint32_t* heap32 = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap32[0] = 0xABBACAFE;
  heap32[1] = 0x12345678;
  heap32[2] = 0xABCDEFAB;
  heap32[3] = 0xCAFEABBA;
  heap32[4] = 0x98765432;
  heap32[5] = 0xFEDCBAFE;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldp w1, w2, [x0], #8
    ldp w3, w4, [x0, #0]
    ldp w5, w6, [x0, #8]
    ldp w7, w8, [x0, #-8]!
  )");
  EXPECT_EQ(getGeneralRegister<uint32_t>(1), 0xABBACAFE);
  EXPECT_EQ(getGeneralRegister<uint32_t>(2), 0x12345678);
  EXPECT_EQ(getGeneralRegister<uint32_t>(3), 0xABCDEFAB);
  EXPECT_EQ(getGeneralRegister<uint32_t>(4), 0xCAFEABBA);
  EXPECT_EQ(getGeneralRegister<uint32_t>(5), 0x98765432);
  EXPECT_EQ(getGeneralRegister<uint32_t>(6), 0xFEDCBAFE);
  EXPECT_EQ(getGeneralRegister<uint32_t>(7), 0xABBACAFE);
  EXPECT_EQ(getGeneralRegister<uint32_t>(8), 0x12345678);
}

TEST_P(MicroOp, loadPairX) {
  initialHeapData_.resize(48);
  uint64_t* heap64 = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  heap64[0] = 0xABBACAFEABBACAFE;
  heap64[1] = 0x1234567898765432;
  heap64[2] = 0xABCDEFABCDEFABCD;
  heap64[3] = 0xCAFEABBACAFEABBA;
  heap64[4] = 0x9876543212345678;
  heap64[5] = 0xFEDCBAFEDCBAFEDC;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldp x1, x2, [x0], #16
    ldp x3, x4, [x0, #0]
    ldp x5, x6, [x0, #16]
    ldp x7, x8, [x0, #-16]!
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(1), 0xABBACAFEABBACAFE);
  EXPECT_EQ(getGeneralRegister<uint64_t>(2), 0x1234567898765432);
  EXPECT_EQ(getGeneralRegister<uint64_t>(3), 0xABCDEFABCDEFABCD);
  EXPECT_EQ(getGeneralRegister<uint64_t>(4), 0xCAFEABBACAFEABBA);
  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0x9876543212345678);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0xFEDCBAFEDCBAFEDC);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 0xABBACAFEABBACAFE);
  EXPECT_EQ(getGeneralRegister<uint64_t>(8), 0x1234567898765432);
}

TEST_P(MicroOp, loadPairReorder) {
  initialHeapData_.resize(64);
  uint64_t* heap64 = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  heap64[0] = 0xABBACAFEABBACAFE;
  heap64[1] = 0x1234567898765432;
  heap64[2] = 0xABCDEFABCDEFABCD;
  heap64[3] = 0xCAFEABBACAFEABBA;
  heap64[4] = 0x9876543212345678;
  heap64[5] = 0xFEDCBAFEDCBAFEDC;
  heap64[6] = 0x1234567898765432;
  heap64[7] = 0xCAFEABBACAFEABBA;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, x0
    mov x4, x0
    mov x6, x0
    mov x7, x0

    ldp x1, x2, [x1, #0]
    ldp x3, x4, [x4, #16]
    ldp x5, x6, [x6, #32]
    ldp x7, x8, [x7, #48]
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(1), 0xABBACAFEABBACAFE);
  EXPECT_EQ(getGeneralRegister<uint64_t>(2), 0x1234567898765432);
  EXPECT_EQ(getGeneralRegister<uint64_t>(3), 0xABCDEFABCDEFABCD);
  EXPECT_EQ(getGeneralRegister<uint64_t>(4), 0xCAFEABBACAFEABBA);
  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0x9876543212345678);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0xFEDCBAFEDCBAFEDC);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 0x1234567898765432);
  EXPECT_EQ(getGeneralRegister<uint64_t>(8), 0xCAFEABBACAFEABBA);
}

TEST_P(MicroOp, loadB) {
  initialHeapData_.resize(4);
  uint8_t* heap8 = reinterpret_cast<uint8_t*>(initialHeapData_.data());
  heap8[0] = 0xAB;
  heap8[1] = 0xBA;
  heap8[2] = 0xCA;
  heap8[3] = 0xFE;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr b1, [x0], #1
    ldr b2, [x0, #0]
    ldr b3, [x0, #1]
    ldr b4, [x0, #-1]!
  )");
  CHECK_NEON(1, uint8_t, {0xAB});
  CHECK_NEON(2, uint8_t, {0xBA});
  CHECK_NEON(3, uint8_t, {0xCA});
  CHECK_NEON(4, uint8_t, {0xAB});
}

TEST_P(MicroOp, loadD) {
  initialHeapData_.resize(32);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  dheap[0] = 1.0;
  dheap[1] = -1.0;
  dheap[2] = 123.45;
  dheap[3] = -123.45;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr d1, [x0], #8
    ldr d2, [x0, #0]
    ldr d3, [x0, #8]
    ldr d4, [x0, #-8]!
  )");
  CHECK_NEON(1, double, {1.0});
  CHECK_NEON(2, double, {-1.0});
  CHECK_NEON(3, double, {123.45});
  CHECK_NEON(4, double, {1.0});
}

TEST_P(MicroOp, loadH) {
  initialHeapData_.resize(8);
  uint16_t* heap16 = reinterpret_cast<uint16_t*>(initialHeapData_.data());
  heap16[0] = 0xABBA;
  heap16[1] = 0xCAFE;
  heap16[2] = 0x1234;
  heap16[3] = 0x5678;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr h1, [x0], #2
    ldr h2, [x0, #0]
    ldr h3, [x0, #2]
    ldr h4, [x0, #-2]!
  )");
  CHECK_NEON(1, uint16_t, {0xABBA});
  CHECK_NEON(2, uint16_t, {0xCAFE});
  CHECK_NEON(3, uint16_t, {0x1234});
  CHECK_NEON(4, uint16_t, {0xABBA});
}

TEST_P(MicroOp, loadQ) {
  initialHeapData_.resize(64);
  uint64_t* heap64 = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  heap64[0] = 0xABBACAFEABBACAFE;
  heap64[1] = 0x1234567898765432;
  heap64[2] = 0xABCDEFABCDEFABCD;
  heap64[3] = 0xCAFEABBACAFEABBA;
  heap64[4] = 0x9876543212345678;
  heap64[5] = 0xFEDCBAFEDCBAFEDC;
  heap64[6] = 0xABBACAFEABBACAFE;
  heap64[7] = 0x1234567898765432;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q1, [x0], #16
    ldr q2, [x0, #0]
    ldr q3, [x0, #16]
    ldr q4, [x0, #-16]!
  )");
  CHECK_NEON(1, uint64_t, {0xABBACAFEABBACAFE, 0x1234567898765432});
  CHECK_NEON(2, uint64_t, {0xABCDEFABCDEFABCD, 0xCAFEABBACAFEABBA});
  CHECK_NEON(3, uint64_t, {0x9876543212345678, 0xFEDCBAFEDCBAFEDC});
  CHECK_NEON(4, uint64_t, {0xABBACAFEABBACAFE, 0x1234567898765432});
}

TEST_P(MicroOp, loadS) {
  initialHeapData_.resize(16);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  fheap[0] = 1.0f;
  fheap[1] = -1.0f;
  fheap[2] = 123.45f;
  fheap[3] = -123.45f;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr s1, [x0], #4
    ldr s2, [x0, #0]
    ldr s3, [x0, #4]
    ldr s4, [x0, #-4]!
  )");
  CHECK_NEON(1, float, {1.0f});
  CHECK_NEON(2, float, {-1.0f});
  CHECK_NEON(3, float, {123.45f});
  CHECK_NEON(4, float, {1.0f});
}

TEST_P(MicroOp, loadW) {
  initialHeapData_.resize(16);
  uint32_t* heap32 = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap32[0] = 0xABBACAFE;
  heap32[1] = 0x12345678;
  heap32[2] = 0xABCDEFAB;
  heap32[3] = 0xCAFEABBA;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr x1, [x0], #4
    ldr x2, [x0, #0]
    ldr x3, [x0, #4]
    ldr x4, [x0, #-4]!
  )");
  EXPECT_EQ(getGeneralRegister<uint32_t>(1), 0xABBACAFE);
  EXPECT_EQ(getGeneralRegister<uint32_t>(2), 0x12345678);
  EXPECT_EQ(getGeneralRegister<uint32_t>(3), 0xABCDEFAB);
  EXPECT_EQ(getGeneralRegister<uint32_t>(4), 0xABBACAFE);
}

TEST_P(MicroOp, loadX) {
  initialHeapData_.resize(32);
  uint64_t* heap64 = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  heap64[0] = 0xABBACAFEABBACAFE;
  heap64[1] = 0x1234567898765432;
  heap64[2] = 0xABCDEFABCDEFABCD;
  heap64[3] = 0xCAFEABBACAFEABBA;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr x1, [x0], #8
    ldr x2, [x0, #0]
    ldr x3, [x0, #8]
    ldr x4, [x0, #-8]!
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(1), 0xABBACAFEABBACAFE);
  EXPECT_EQ(getGeneralRegister<uint64_t>(2), 0x1234567898765432);
  EXPECT_EQ(getGeneralRegister<uint64_t>(3), 0xABCDEFABCDEFABCD);
  EXPECT_EQ(getGeneralRegister<uint64_t>(4), 0xABBACAFEABBACAFE);
}

TEST_P(MicroOp, storePairD) {
  RUN_AARCH64(R"(
    fmov d0, #-5.0
    fmov d1, #-3.5
    fmov d2, #-1.5
    fmov d3, #-0.5
    fmov d4, #0.5
    fmov d5, #1.5
    fmov d6, #3.5
    fmov d7, #5.0

    sub sp, sp, #1024

    stp d0, d1, [sp], #32
    stp d2, d3, [sp, #0]
    stp d4, d5, [sp, #16]
    stp d6, d7, [sp, #-16]!
  )");
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 1024), -5.0);
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 1016), -3.5);
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 1008), 3.5);
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 1000), 5.0);
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 992), -1.5);
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 984), -0.5);
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 976), 0.5);
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 968), 1.5);
}

TEST_P(MicroOp, storePairQ) {
  initialHeapData_.resize(128);
  uint64_t* heap64 = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  heap64[0] = 0xABBACAFEABBACAFE;
  heap64[1] = 0x1234567898765432;
  heap64[2] = 0xABCDEFABCDEFABCD;
  heap64[3] = 0xCAFEABBACAFEABBA;
  heap64[4] = 0x9876543212345678;
  heap64[5] = 0xFEDCBAFEDCBAFEDC;
  heap64[6] = 0xABBACAFEABBACAFE;
  heap64[7] = 0x1234567898765432;
  heap64[8] = 0xABBACAFEABBACAFE;
  heap64[9] = 0x1234567898765432;
  heap64[10] = 0xABCDEFABCDEFABCD;
  heap64[11] = 0xCAFEABBACAFEABBA;
  heap64[12] = 0x9876543212345678;
  heap64[13] = 0xFEDCBAFEDCBAFEDC;
  heap64[14] = 0xABBACAFEABBACAFE;
  heap64[15] = 0x1234567898765432;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldp q0, q1, [x0, #0]
    ldp q2, q3, [x0, #32]
    ldp q4, q5, [x0, #64]
    ldp q6, q7, [x0, #96]

    sub sp, sp, #1024

    stp q0, q1, [sp], #64
    stp q2, q3, [sp, #0]
    stp q4, q5, [sp, #32]
    stp q6, q7, [sp, #-32]!
  )");
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 1024),
            0xABBACAFEABBACAFE);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 1016),
            0x1234567898765432);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 1008),
            0xABCDEFABCDEFABCD);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 1000),
            0xCAFEABBACAFEABBA);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 992),
            0x9876543212345678);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 984),
            0xFEDCBAFEDCBAFEDC);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 976),
            0xABBACAFEABBACAFE);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 968),
            0x1234567898765432);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 960),
            0x9876543212345678);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 952),
            0xFEDCBAFEDCBAFEDC);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 944),
            0xABBACAFEABBACAFE);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 936),
            0x1234567898765432);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 928),
            0xABBACAFEABBACAFE);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 920),
            0x1234567898765432);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 912),
            0xABCDEFABCDEFABCD);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 904),
            0xCAFEABBACAFEABBA);
}

TEST_P(MicroOp, storePairS) {
  RUN_AARCH64(R"(
    fmov s0, #-5.0
    fmov s1, #-3.5
    fmov s2, #-1.5
    fmov s3, #-0.5
    fmov s4, #0.5
    fmov s5, #1.5
    fmov s6, #3.5
    fmov s7, #5.0

    sub sp, sp, #1024

    stp s0, s1, [sp], #16
    stp s2, s3, [sp, #0]
    stp s4, s5, [sp, #8]
    stp s6, s7, [sp, #-8]!
  )");
  EXPECT_EQ(getMemoryValue<float>(process_->getStackPointer() - 1024), -5.0f);
  EXPECT_EQ(getMemoryValue<float>(process_->getStackPointer() - 1020), -3.5f);
  EXPECT_EQ(getMemoryValue<float>(process_->getStackPointer() - 1016), 3.5f);
  EXPECT_EQ(getMemoryValue<float>(process_->getStackPointer() - 1012), 5.0f);
  EXPECT_EQ(getMemoryValue<float>(process_->getStackPointer() - 1008), -1.5f);
  EXPECT_EQ(getMemoryValue<float>(process_->getStackPointer() - 1004), -0.5f);
  EXPECT_EQ(getMemoryValue<float>(process_->getStackPointer() - 1000), 0.5f);
  EXPECT_EQ(getMemoryValue<float>(process_->getStackPointer() - 996), 1.5f);
}

TEST_P(MicroOp, storePairW) {
  RUN_AARCH64(R"(
    mov w0, #12
    mov w1, #24
    mov w2, #36
    mov w3, #48
    mov w4, #60
    mov w5, #72
    mov w6, #84
    mov w7, #96

    sub sp, sp, #1024

    stp w0, w1, [sp], #16
    stp w2, w3, [sp, #0]
    stp w4, w5, [sp, #8]
    stp w6, w7, [sp, #-8]!
  )");
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() - 1024), 12);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() - 1020), 24);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() - 1016), 84);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() - 1012), 96);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() - 1008), 36);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() - 1004), 48);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() - 1000), 60);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() - 996), 72);
}

TEST_P(MicroOp, storePairX) {
  RUN_AARCH64(R"(
    mov x0, #12
    mov x1, #24
    mov x2, #36
    mov x3, #48
    mov x4, #60
    mov x5, #72
    mov x6, #84
    mov x7, #96

    sub sp, sp, #1024

    stp x0, x1, [sp], #32
    stp x2, x3, [sp, #0]
    stp x4, x5, [sp, #16]
    stp x6, x7, [sp, #-16]!
  )");
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 1024), 12);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 1016), 24);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 1008), 84);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 1000), 96);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 992), 36);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 984), 48);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 976), 60);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 968), 72);
}

TEST_P(MicroOp, storeB) {
  initialHeapData_.resize(32);
  uint64_t* heap64 = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  heap64[0] = 0xAB;
  heap64[1] = 0xBA;
  heap64[2] = 0xCA;
  heap64[3] = 0xFE;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr d0, [x0, #0]
    ldr d1, [x0, #8]
    ldr d2, [x0, #16]
    ldr d3, [x0, #24]

    sub sp, sp, #1024

    str b0, [sp], #2
    str b1, [sp, #0]
    str b2, [sp, #1]
    str b3, [sp, #-1]!
  )");
  EXPECT_EQ(getMemoryValue<uint8_t>(process_->getStackPointer() - 1024), 0xAB);
  EXPECT_EQ(getMemoryValue<uint8_t>(process_->getStackPointer() - 1023), 0xFE);
  EXPECT_EQ(getMemoryValue<uint8_t>(process_->getStackPointer() - 1022), 0xBA);
  EXPECT_EQ(getMemoryValue<uint8_t>(process_->getStackPointer() - 1021), 0xCA);
}

TEST_P(MicroOp, storeD) {
  RUN_AARCH64(R"(
    fmov d0, #-3.0
    fmov d1, #-1.5
    fmov d2, #1.5
    fmov d3, #3.0

    sub sp, sp, #1024

    str d0, [sp], #16
    str d1, [sp, #0]
    str d2, [sp, #8]
    str d3, [sp, #-8]!
  )");
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 1024), -3.0);
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 1016), 3.0);
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 1008), -1.5);
  EXPECT_EQ(getMemoryValue<double>(process_->getStackPointer() - 1000), 1.5);
}

TEST_P(MicroOp, storeH) {
  initialHeapData_.resize(32);
  uint64_t* heap64 = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  heap64[0] = 0xABBA;
  heap64[1] = 0xCAFE;
  heap64[2] = 0x1234;
  heap64[3] = 0x5678;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr d0, [x0, #0]
    ldr d1, [x0, #8]
    ldr d2, [x0, #16]
    ldr d3, [x0, #24]

    sub sp, sp, #1024

    str h0, [sp], #4
    str h1, [sp, #0]
    str h2, [sp, #2]
    str h3, [sp, #-2]!
  )");
  EXPECT_EQ(getMemoryValue<uint16_t>(process_->getStackPointer() - 1024),
            0xABBA);
  EXPECT_EQ(getMemoryValue<uint16_t>(process_->getStackPointer() - 1022),
            0x5678);
  EXPECT_EQ(getMemoryValue<uint16_t>(process_->getStackPointer() - 1020),
            0xCAFE);
  EXPECT_EQ(getMemoryValue<uint16_t>(process_->getStackPointer() - 1018),
            0x1234);
}

TEST_P(MicroOp, storeQ) {
  initialHeapData_.resize(64);
  uint64_t* heap64 = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  heap64[0] = 0xABBACAFEABBACAFE;
  heap64[1] = 0x1234567898765432;
  heap64[2] = 0xABCDEFABCDEFABCD;
  heap64[3] = 0xCAFEABBACAFEABBA;
  heap64[4] = 0x9876543212345678;
  heap64[5] = 0xFEDCBAFEDCBAFEDC;
  heap64[6] = 0xABBACAFEABBACAFE;
  heap64[7] = 0x1234567898765432;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0, #0]
    ldr q1, [x0, #16]
    ldr q2, [x0, #32]
    ldr q3, [x0, #48]

    sub sp, sp, #1024

    str q0, [sp], #32
    str q1, [sp, #0]
    str q2, [sp, #16]
    str q3, [sp, #-16]!
  )");
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 1024),
            0xABBACAFEABBACAFE);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 1016),
            0x1234567898765432);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 1008),
            0xABBACAFEABBACAFE);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 1000),
            0x1234567898765432);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 992),
            0xABCDEFABCDEFABCD);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 984),
            0xCAFEABBACAFEABBA);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 976),
            0x9876543212345678);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 968),
            0xFEDCBAFEDCBAFEDC);
}

TEST_P(MicroOp, storeS) {
  RUN_AARCH64(R"(
    fmov s0, #-3.0
    fmov s1, #-1.5
    fmov s2, #1.5
    fmov s3, #3.0

    sub sp, sp, #1024

    str s0, [sp], #8
    str s1, [sp, #0]
    str s2, [sp, #4]
    str s3, [sp, #-4]!
  )");
  EXPECT_EQ(getMemoryValue<float>(process_->getStackPointer() - 1024), -3.0f);
  EXPECT_EQ(getMemoryValue<float>(process_->getStackPointer() - 1020), 3.0f);
  EXPECT_EQ(getMemoryValue<float>(process_->getStackPointer() - 1016), -1.5f);
  EXPECT_EQ(getMemoryValue<float>(process_->getStackPointer() - 1012), 1.5f);
}

TEST_P(MicroOp, storeW) {
  RUN_AARCH64(R"(
    mov w0, #12
    mov w1, #24
    mov w2, #36
    mov w3, #48

    sub sp, sp, #1024

    str w0, [sp], #8
    str w1, [sp, #0]
    str w2, [sp, #4]
    str w3, [sp, #-4]!
  )");
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() - 1024), 12);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() - 1020), 48);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() - 1016), 24);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() - 1012), 36);
}

TEST_P(MicroOp, storeX) {
  RUN_AARCH64(R"(
    mov x0, #12
    mov x1, #24
    mov x2, #36
    mov x3, #48

    sub sp, sp, #1024

    str x0, [sp], #16
    str x1, [sp, #0]
    str x2, [sp, #8]
    str x3, [sp, #-8]!
  )");
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 1024), 12);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 1016), 48);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 1008), 24);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 1000), 36);
}

TEST_P(MicroOp, storeThenLoad) {
  RUN_AARCH64(R"(
    mov x0, #12
    mov x1, #24
    mov x2, #36
    mov x3, #48

    sub sp, sp, #1024

    str x0, [sp], #16
    str x1, [sp, #0]
    str x2, [sp, #8]
    str x3, [sp, #-8]!

    sub sp, sp, #8

    ldr x5, [sp], #16
    ldr x6, [sp, #0]
    ldr x7, [sp, #8]
    ldr x8, [sp, #-8]!
  )");
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 1024), 12);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 1016), 48);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 1008), 24);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 1000), 36);
  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 12);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 24);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 36);
  EXPECT_EQ(getGeneralRegister<uint64_t>(8), 48);
}

TEST_P(MicroOp, storeThenLoadPair) {
  RUN_AARCH64(R"(
    mov x0, #12
    mov x1, #24
    mov x2, #36
    mov x3, #48
    mov x4, #60
    mov x5, #72
    mov x6, #84
    mov x7, #96

    sub sp, sp, #1024

    stp x0, x1, [sp], #32
    stp x2, x3, [sp, #0]
    stp x4, x5, [sp, #16]
    stp x6, x7, [sp, #-16]!

    sub sp, sp, #16

    ldp x8, x9, [sp], #32
    ldp x10, x11, [sp, #0]
    ldp x12, x13, [sp, #16]
    ldp x14, x15, [sp, #-16]!
  )");
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 1024), 12);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 1016), 24);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 1008), 84);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 1000), 96);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 992), 36);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 984), 48);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 976), 60);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getStackPointer() - 968), 72);
  EXPECT_EQ(getGeneralRegister<uint64_t>(8), 12);
  EXPECT_EQ(getGeneralRegister<uint64_t>(9), 24);
  EXPECT_EQ(getGeneralRegister<uint64_t>(10), 36);
  EXPECT_EQ(getGeneralRegister<uint64_t>(11), 48);
  EXPECT_EQ(getGeneralRegister<uint64_t>(12), 60);
  EXPECT_EQ(getGeneralRegister<uint64_t>(13), 72);
  EXPECT_EQ(getGeneralRegister<uint64_t>(14), 84);
  EXPECT_EQ(getGeneralRegister<uint64_t>(15), 96);
}

INSTANTIATE_TEST_SUITE_P(
    AArch64, MicroOp,
    ::testing::Values(
        std::make_tuple(EMULATION, YAML::Load("{Micro-Operations: True}")),
        std::make_tuple(INORDER, YAML::Load("{Micro-Operations: True}")),
        std::make_tuple(OUTOFORDER, YAML::Load("{Micro-Operations: True}"))),
    paramToString);

}  // namespace
