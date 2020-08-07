#include "AArch64RegressionTest.hh"

namespace {

using InstSve = AArch64RegressionTest;

TEST_P(InstSve, addvl) {
  // 64-bits
  RUN_AARCH64(R"(
    mov x0, #42
    mov x1, #8
    mov x2, #1024

    addvl x3, x0, #4
    addvl x4, x1, #31
    addvl x5, x2, #-32
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(3), 298);
  EXPECT_EQ(getGeneralRegister<int64_t>(4), 1992);
  EXPECT_EQ(getGeneralRegister<int64_t>(5), -1024);
}

TEST_P(InstSve, and) {
  // VL = 512-bits
  RUN_AARCH64(R"(
    mov x0, #8

    ptrue p0.s
    ptrue p1.s
    whilelo p2.s, xzr, x0

    and p3.b, p0/z, p1.b, p0.b
    and p4.b, p2/z, p1.b, p0.b
    
  )");
  CHECK_PREDICATE(3, uint32_t, {0x11111111, 0x11111111, 0, 0, 0, 0, 0, 0});
  CHECK_PREDICATE(4, uint32_t, {0x11111111, 0, 0, 0, 0, 0, 0, 0});
}

TEST_P(InstSve, cnt) {
  // VL = 512-bits
  // pattern = all
  RUN_AARCH64(R"(
    cntb x0
    cnth x1
    cntw x2
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(0), 64);
  EXPECT_EQ(getGeneralRegister<int64_t>(1), 32);
  EXPECT_EQ(getGeneralRegister<int64_t>(2), 16);
}

TEST_P(InstSve, dec) {
  // VL = 512-bits
  // pattern = all
  RUN_AARCH64(R"(
    mov x0, #128
    decb x0
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(0), 64);
}

TEST_P(InstSve, dups) {
  // VL = 512-bit
  // 32-bit arrangement
  RUN_AARCH64(R"(
    dup z0.s, #7
    dup z1.s, #-7
    fdup z2.s, #0.5
    fdup z3.s, #-0.5
    
    fmov s4, #14.5
    fmov s5, #-14.5
    # check for alias
    mov z6.s, s4
    mov z7.s, s5
  )");

  CHECK_NEON(0, int32_t, {7, 7, 7, 7, 7, 7, 7, 7,
                           7, 7, 7, 7, 7, 7, 7, 7});
  CHECK_NEON(1, int32_t, {-7, -7, -7, -7, -7, -7, -7, -7,
                           -7, -7, -7, -7, -7, -7, -7, -7});
  CHECK_NEON(2, float, {0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f,
                          0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f, 0.5f});
  CHECK_NEON(3, float, {-0.5f, -0.5f, -0.5f, -0.5f, -0.5f, -0.5f, -0.5f, -0.5f,
                          -0.5f, -0.5f, -0.5f, -0.5f, -0.5f, -0.5f, -0.5f, -0.5f});
  CHECK_NEON(6, float, {14.5f, 14.5f, 14.5f, 14.5f, 14.5f, 14.5f, 14.5f, 14.5f,
                          14.5f, 14.5f, 14.5f, 14.5f, 14.5f, 14.5f, 14.5f, 14.5f});
  CHECK_NEON(7, float, {-14.5f, -14.5f, -14.5f, -14.5f, -14.5f, -14.5f, -14.5f, -14.5f,
                          -14.5f, -14.5f, -14.5f, -14.5f, -14.5f, -14.5f, -14.5f, -14.5f});
}

TEST_P(InstSve, inc) {
  // VL = 512-bits
  // pattern = all
  RUN_AARCH64(R"(
    mov x0, #64
    mov x1, #128
    incb x0
    incw x1
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(0), 128);
  EXPECT_EQ(getGeneralRegister<int64_t>(1), 144);
}

TEST_P(InstSve, fabs) {
  // VL = 512-bits
  // float
  initialHeapData_.resize(64);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  fheap[0] = 1.0;
  fheap[1] = -42.76;
  fheap[2] = -0.125;
  fheap[3] = 0.0;
  fheap[4] = 40.26;
  fheap[5] = -684.72;
  fheap[6] = -0.15;
  fheap[7] = 107.86;

  fheap[8] = -34.71f;
  fheap[9] = -0.917f;
  fheap[10] = 0.0f;
  fheap[11] = 80.72f;
  fheap[12] = -125.67f;
  fheap[13] = -0.01f;
  fheap[14] = 701.90f;
  fheap[15] = 7.0f;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #8
    whilelo p0.s, xzr, x2
    ptrue p1.s
    
    ld1w {z0.s}, p1/z, [x0, x1, lsl #2]
    ld1w {z1.s}, p0/z, [x0, x2, lsl #2]

    fabs z2.s, p1/m, z0.s
    fabs z3.s, p0/m, z1.s
  )");

  CHECK_NEON(2, float, {1.0f, 42.76f, 0.125f, 0.0f, 40.26f, 684.72f, 0.15f, 
                        107.86f, 34.71f, 0.917f, 0.0f, 80.72f, 125.67f, 0.01f, 
                        701.90f, 7.0f});
  CHECK_NEON(3, float, {34.71f, 0.917f, 0.0f, 80.72f, 125.67f, 0.01f, 
                        701.90f, 7.0f, 0, 0, 0, 0, 0, 0, 0, 0});
}

TEST_P(InstSve, fadd) {
  // VL = 512-bits
  // float
  initialHeapData_.resize(68);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  fheap[0] = 1.0;
  fheap[1] = -42.76;
  fheap[2] = -0.125;
  fheap[3] = 0.0;
  fheap[4] = 40.26;
  fheap[5] = -684.72;
  fheap[6] = -0.15;
  fheap[7] = 107.86;

  fheap[8] = -34.71f;
  fheap[9] = -0.917f;
  fheap[10] = 0.0f;
  fheap[11] = 80.72f;
  fheap[12] = -125.67f;
  fheap[13] = -0.01f;
  fheap[14] = 701.90f;
  fheap[15] = 7.0f;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #8
    whilelo p0.s, xzr, x2
    
    ld1w {z0.s}, p0/z, [x0, x1, lsl #2]
    ld1w {z1.s}, p0/z, [x0, x2, lsl #2]

    fadd z2.s, z1.s, z0.s
  )");

  CHECK_NEON(2, float, {-33.71f, -43.677f, -0.125f, 80.72f,
                        -85.41f, -684.73f, 701.75f, 114.86f, 
                        0, 0, 0, 0, 0, 0, 0, 0});
}

TEST_P(InstSve, fcmge) {
  // VL = 512-bits
  // float
  initialHeapData_.resize(68);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  fheap[0] = 1.0;
  fheap[1] = -42.76;
  fheap[2] = -0.125;
  fheap[3] = 0.0;
  fheap[4] = 40.26;
  fheap[5] = -684.72;
  fheap[6] = -0.15;
  fheap[7] = 107.86;

  fheap[8] = -34.71f;
  fheap[9] = -0.917f;
  fheap[10] = 0.0f;
  fheap[11] = 80.72f;
  fheap[12] = -125.67f;
  fheap[13] = -0.01f;
  fheap[14] = 701.90f;
  fheap[15] = 7.0f;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #8
    whilelo p0.s, xzr, x2
    
    ld1w {z0.s}, p0/z, [x0, x1, lsl #2]

    fcmge p1.s, p0/z, z0.s, #0.0
  )");
  
  CHECK_PREDICATE(1, uint32_t, {0x10011001, 0, 0, 0, 0, 0, 0, 0});
}

TEST_P(InstSve, fcmgt) {
  // VL = 512-bits
  // float
  initialHeapData_.resize(68);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  fheap[0] = 1.0;
  fheap[1] = -42.76;
  fheap[2] = -0.125;
  fheap[3] = 0.0;
  fheap[4] = 40.26;
  fheap[5] = -684.72;
  fheap[6] = -0.15;
  fheap[7] = 107.86;

  fheap[8] = -34.71f;
  fheap[9] = -0.917f;
  fheap[10] = 0.0f;
  fheap[11] = 80.72f;
  fheap[12] = -125.67f;
  fheap[13] = -0.01f;
  fheap[14] = 701.90f;
  fheap[15] = 7.0f;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #8
    whilelo p0.s, xzr, x2
    ptrue p1.s
    
    ld1w {z0.s}, p1/z, [x0, x1, lsl #2]
    ld1w {z1.s}, p0/z, [x0, x2, lsl #2]

    fcmgt p2.s, p0/z, z0.s, z1.s
  )");
  
  CHECK_PREDICATE(2, uint32_t, {0x10010001, 0, 0, 0, 0, 0, 0, 0});
}

TEST_P(InstSve, fcmlt) {
  // VL = 512-bits
  // float
  initialHeapData_.resize(68);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  fheap[0] = 1.0;
  fheap[1] = -42.76;
  fheap[2] = -0.125;
  fheap[3] = 0.0;
  fheap[4] = 40.26;
  fheap[5] = -684.72;
  fheap[6] = -0.15;
  fheap[7] = 107.86;

  fheap[8] = -34.71f;
  fheap[9] = -0.917f;
  fheap[10] = 0.0f;
  fheap[11] = 80.72f;
  fheap[12] = -125.67f;
  fheap[13] = -0.01f;
  fheap[14] = 701.90f;
  fheap[15] = 7.0f;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #8
    whilelo p0.s, xzr, x2
    
    ld1w {z0.s}, p0/z, [x0, x1, lsl #2]

    fcmlt p1.s, p0/z, z0.s, #0.0
  )");
  
  CHECK_PREDICATE(1, uint32_t, {0x01100110, 0, 0, 0, 0, 0, 0, 0});
}

TEST_P(InstSve, fmad) {
  // VL = 512-bits
  // float
  initialHeapData_.resize(68);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  fheap[0] = 1.0;
  fheap[1] = -42.76;
  fheap[2] = -0.125;
  fheap[3] = 0.0;
  fheap[4] = 40.26;
  fheap[5] = -684.72;
  fheap[6] = -0.15;
  fheap[7] = 107.86;

  fheap[8] = -34.71f;
  fheap[9] = -0.917f;
  fheap[10] = 0.0f;
  fheap[11] = 80.72f;
  fheap[12] = -125.67f;
  fheap[13] = -0.01f;
  fheap[14] = 701.90f;
  fheap[15] = 7.0f;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #8
    whilelo p0.s, xzr, x2
    ptrue p1.s
    
    ld1w {z0.s}, p0/z, [x0, x1, lsl #2]
    ld1w {z1.s}, p0/z, [x0, x2, lsl #2]
    ld1w {z2.s}, p1/z, [x0, x1, lsl #2]

    fmad z2.s, p0/m, z1.s, z0.s
  )");

  CHECK_NEON(2, float, {-33.71f, -3.54907989502f, -0.125f, 0.0f,
                        -5019.2142f, -677.872741699f, -105.4350113f, 862.88f,
                        -34.71f, -0.917f, 0.0f, 80.72f,
                        -125.67f, -0.01f, 701.90f, 7.0f});
}

TEST_P(InstSve, fmla) {
  // VL = 512-bits
  // float
  initialHeapData_.resize(68);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  fheap[0] = 1.0;
  fheap[1] = -42.76;
  fheap[2] = -0.125;
  fheap[3] = 0.0;
  fheap[4] = 40.26;
  fheap[5] = -684.72;
  fheap[6] = -0.15;
  fheap[7] = 107.86;

  fheap[8] = -34.71f;
  fheap[9] = -0.917f;
  fheap[10] = 0.0f;
  fheap[11] = 80.72f;
  fheap[12] = -125.67f;
  fheap[13] = -0.01f;
  fheap[14] = 701.90f;
  fheap[15] = 7.0f;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #8
    whilelo p0.s, xzr, x2
    ptrue p1.s
    
    ld1w {z0.s}, p0/z, [x0, x1, lsl #2]
    ld1w {z1.s}, p0/z, [x0, x2, lsl #2]
    ld1w {z2.s}, p1/z, [x0, x1, lsl #2]

    fmla z2.s, p0/m, z1.s, z0.s
  )");

  CHECK_NEON(2, float, {-33.71f, -3.54907989502f, -0.125f, 0.0f,
                        -5019.2142f, -677.872741699f, -105.4350113f, 862.88f,
                        -34.71f, -0.917f, 0.0f, 80.72f,
                        -125.67f, -0.01f, 701.90f, 7.0f});
}

TEST_P(InstSve, fmsb) {
  // VL = 512-bits
  // float
  initialHeapData_.resize(68);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  fheap[0] = 1.0;
  fheap[1] = -42.76;
  fheap[2] = -0.125;
  fheap[3] = 0.0;
  fheap[4] = 40.26;
  fheap[5] = -684.72;
  fheap[6] = -0.15;
  fheap[7] = 107.86;

  fheap[8] = -34.71f;
  fheap[9] = -0.917f;
  fheap[10] = 0.0f;
  fheap[11] = 80.72f;
  fheap[12] = -125.67f;
  fheap[13] = -0.01f;
  fheap[14] = 701.90f;
  fheap[15] = 7.0f;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #8
    whilelo p0.s, xzr, x2
    ptrue p1.s
    
    ld1w {z0.s}, p0/z, [x0, x1, lsl #2]
    ld1w {z1.s}, p0/z, [x0, x2, lsl #2]
    ld1w {z2.s}, p1/z, [x0, x1, lsl #2]

    fmsb z2.s, p0/m, z1.s, z0.s
  )");

  CHECK_NEON(2, float, {35.71f, -81.970916748f, -0.125f, 0.0f,
                        5099.73388672f, -691.567199707f, 105.135009766f, -647.16003418f,
                        -34.71f, -0.917f, 0.0f, 80.72f,
                        -125.67f, -0.01f, 701.90f, 7.0f});
}

TEST_P(InstSve, fmul) {
  // VL = 512-bits
  // float
  initialHeapData_.resize(68);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  fheap[0] = 1.0;
  fheap[1] = -42.76;
  fheap[2] = -0.125;
  fheap[3] = 0.0;
  fheap[4] = 40.26;
  fheap[5] = -684.72;
  fheap[6] = -0.15;
  fheap[7] = 107.86;

  fheap[8] = -34.71f;
  fheap[9] = -0.917f;
  fheap[10] = 0.0f;
  fheap[11] = 80.72f;
  fheap[12] = -125.67f;
  fheap[13] = -0.01f;
  fheap[14] = 701.90f;
  fheap[15] = 7.0f;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #8
    whilelo p0.s, xzr, x2
    
    ld1w {z0.s}, p0/z, [x0, x1, lsl #2]
    ld1w {z1.s}, p0/z, [x0, x2, lsl #2]

    fmul z2.s, z1.s, z0.s
    fmul z0.s, p0/m, z0.s, #0.5
  )");

  CHECK_NEON(2, float, {-34.71f, 39.2109184265f, 0.0f, 0.0f,
                        -5059.4742f, 6.84719944f, -105.285011292f, 755.02f, 
                        0, 0, 0, 0, 0, 0, 0, 0});
  CHECK_NEON(0, float, {0.5f, -21.38f, -0.0625f, 0, 
                        20.13f, -342.36f, -0.075f, 53.93f, 
                        0, 0, 0, 0, 0, 0, 0, 0});
}

TEST_P(InstSve, fneg) {
  // VL = 512-bits
  // float
  initialHeapData_.resize(64);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  fheap[0] = 1.0;
  fheap[1] = -42.76;
  fheap[2] = -0.125;
  fheap[3] = 0.0;
  fheap[4] = 40.26;
  fheap[5] = -684.72;
  fheap[6] = -0.15;
  fheap[7] = 107.86;

  fheap[8] = -34.71f;
  fheap[9] = -0.917f;
  fheap[10] = 0.0f;
  fheap[11] = 80.72f;
  fheap[12] = -125.67f;
  fheap[13] = -0.01f;
  fheap[14] = 701.90f;
  fheap[15] = 7.0f;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #8
    whilelo p0.s, xzr, x2
    ptrue p1.s
    
    ld1w {z0.s}, p1/z, [x0, x1, lsl #2]
    ld1w {z1.s}, p0/z, [x0, x2, lsl #2]

    fneg z2.s, p1/m, z0.s
    fneg z3.s, p0/m, z1.s
  )");

  CHECK_NEON(2, float, {-1.0f, 42.76f, 0.125f, -0.0f, -40.26f, 684.72f, 0.15f, 
                        -107.86f, 34.71f, 0.917f, -0.0f, -80.72f, 125.67f, 0.01f, 
                        -701.90f, -7.0f});
  CHECK_NEON(3, float, {34.71f, 0.917f, -0.0f, -80.72f, 125.67f, 0.01f, 
                        -701.90f, -7.0f, 0, 0, 0, 0, 0, 0, 0, 0});
}

TEST_P(InstSve, fsqrt) {
  // VL = 512-bits
  // float
  initialHeapData_.resize(68);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  fheap[0] = 1.0;
  fheap[1] = 42.76;
  fheap[2] = 0.125;
  fheap[3] = 0.0;
  fheap[4] = 40.26;
  fheap[5] = 684.72;
  fheap[6] = 0.15;
  fheap[7] = 107.86;

  fheap[8] = 34.71f;
  fheap[9] = 0.917f;
  fheap[10] = 0.0f;
  fheap[11] = 80.72f;
  fheap[12] = 125.67f;
  fheap[13] = 0.01f;
  fheap[14] = 701.90f;
  fheap[15] = 7.0f;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #8
    whilelo p0.s, xzr, x2
    ptrue p1.s
    
    ld1w {z0.s}, p1/z, [x0, x1, lsl #2]
    ld1w {z1.s}, p0/z, [x0, x2, lsl #2]

    fsqrt z2.s, p1/m, z0.s
    fsqrt z3.s, p0/m, z1.s
  )");

  CHECK_NEON(2, float, {1, 6.53911304473876953125f, 0.3535533845424652099609375f, 
                        0, 6.34507656097412109375f, 26.1671543121337890625f, 
                        0.3872983455657958984375f, 10.38556671142578125f,
                        5.891519069671630859375f, 0.95760118961334228515625f, 
                        0, 8.98443126678466796875f,
                        11.21026325225830078125f, 0.1f, 
                        26.493396759033203125f, 2.6457512378692626953125f});
  CHECK_NEON(3, float, {5.891519069671630859375f, 0.95760118961334228515625f, 
                        0, 8.98443126678466796875f, 11.21026325225830078125f, 
                        0.1f, 26.493396759033203125f, 2.6457512378692626953125f,
                        0, 0, 0, 0, 0, 0, 0, 0});
}

TEST_P(InstSve, fsub) {
  // VL = 512-bits
  // float
  initialHeapData_.resize(68);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  fheap[0] = 1.0;
  fheap[1] = -42.76;
  fheap[2] = -0.125;
  fheap[3] = 0.0;
  fheap[4] = 40.26;
  fheap[5] = -684.72;
  fheap[6] = -0.15;
  fheap[7] = 107.86;

  fheap[8] = -34.71f;
  fheap[9] = -0.917f;
  fheap[10] = 0.0f;
  fheap[11] = 80.72f;
  fheap[12] = -125.67f;
  fheap[13] = -0.01f;
  fheap[14] = 701.90f;
  fheap[15] = 7.0f;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #8
    whilelo p0.s, xzr, x2
    
    ld1w {z0.s}, p0/z, [x0, x1, lsl #2]
    ld1w {z1.s}, p0/z, [x0, x2, lsl #2]

    fsub z2.s, z1.s, z0.s
  )");

  CHECK_NEON(2, float, {-35.71f, 41.843f, 0.125f, 80.72f,
                        -165.93f, 684.709960938f, 702.050048828f, -100.86f, 
                        0, 0, 0, 0, 0, 0, 0, 0});
}

TEST_P(InstSve, ld1rw) {
  // VL = 512-bits
  // 32-bit
  initialHeapData_.resize(8);
  uint32_t* heap32 = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap32[0] = 0xDEADBEEF;
  heap32[1] = 0x12345678;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # Load and broadcast values from heap
    ptrue p0.s
    ld1rw {z0.s}, p0/z, [x0]
    ld1rw {z1.s}, p0/z, [x0, #4]
    # Test for inactive lanes
    mov x1, #8
    whilelo p1.s, xzr, x1
    ld1rw {z2.s}, p1/z, [x0]
    ld1rw {z3.s}, p1/z, [x0, #4]
  )");
  CHECK_NEON(0, uint64_t, {0xDEADBEEFDEADBEEF, 0xDEADBEEFDEADBEEF, 
                           0xDEADBEEFDEADBEEF, 0xDEADBEEFDEADBEEF,
                           0xDEADBEEFDEADBEEF, 0xDEADBEEFDEADBEEF, 
                           0xDEADBEEFDEADBEEF, 0xDEADBEEFDEADBEEF});
  CHECK_NEON(1, uint64_t, {0x1234567812345678, 0x1234567812345678, 
                           0x1234567812345678, 0x1234567812345678,
                           0x1234567812345678, 0x1234567812345678, 
                           0x1234567812345678, 0x1234567812345678});
  CHECK_NEON(2, uint64_t, {0xDEADBEEFDEADBEEF, 0xDEADBEEFDEADBEEF, 
                           0xDEADBEEFDEADBEEF, 0xDEADBEEFDEADBEEF});
  CHECK_NEON(3, uint64_t, {0x1234567812345678, 0x1234567812345678, 
                           0x1234567812345678, 0x1234567812345678});
}

TEST_P(InstSve, ld1w) {
  // VL = 512-bits
  // 32-bit
  initialHeapData_.resize(128);
  uint32_t* heap32 = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap32[0] = 0xDEADBEEF;
  heap32[1] = 0x12345678;
  heap32[2] = 0x98765432;
  heap32[3] = 0xABCDEF01;
  heap32[4] = 0xDEADBEEF;
  heap32[5] = 0x12345678;
  heap32[6] = 0x98765432;
  heap32[7] = 0xABCDEF01;
  heap32[8] = 0xDEADBEEF;
  heap32[9] = 0x12345678;
  heap32[10] = 0x98765432;
  heap32[11] = 0xABCDEF01;
  heap32[12] = 0xDEADBEEF;
  heap32[13] = 0x12345678;
  heap32[14] = 0x98765432;
  heap32[15] = 0xABCDEF01;
  heap32[16] = 0xDEADBEEF;
  heap32[17] = 0xABCDEF01;
  heap32[18] = 0x98765432;
  heap32[19] = 0x12345678;
  heap32[20] = 0xDEADBEEF;
  heap32[21] = 0xABCDEF01;
  heap32[22] = 0x98765432;
  heap32[23] = 0x12345678;
  heap32[24] = 0xDEADBEEF;
  heap32[25] = 0xABCDEF01;
  heap32[26] = 0x98765432;
  heap32[27] = 0x12345678;
  heap32[28] = 0xDEADBEEF;
  heap32[29] = 0xABCDEF01;
  heap32[30] = 0x98765432;
  heap32[31] = 0x12345678;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #1
    ptrue p0.s
    # Load and broadcast values from heap    
    ld1w {z0.s}, p0/z, [x0, x1, lsl #2]
    ld1w {z2.s}, p0/z, [x0]

    # Test for inactive lanes
    mov x1, #8
    mov x2, #0
    whilelo p1.s, xzr, x1
    ld1w {z1.s}, p1/z, [x0, x2, lsl #2]
    ld1w {z3.s}, p1/z, [x0, #1, mul vl]
  )");
  CHECK_NEON(0, uint64_t, {0x9876543212345678, 0xDEADBEEFABCDEF01,
                           0x9876543212345678, 0xDEADBEEFABCDEF01,
                           0x9876543212345678, 0xDEADBEEFABCDEF01,
                           0x9876543212345678, 0xDEADBEEFABCDEF01});
  CHECK_NEON(1, uint64_t, {0x12345678DEADBEEF, 0xABCDEF0198765432, 
                           0x12345678DEADBEEF, 0xABCDEF0198765432});
  CHECK_NEON(2, uint64_t, {0x12345678DEADBEEF, 0xABCDEF0198765432, 
                           0x12345678DEADBEEF, 0xABCDEF0198765432, 
                           0x12345678DEADBEEF, 0xABCDEF0198765432, 
                           0x12345678DEADBEEF, 0xABCDEF0198765432});
  CHECK_NEON(3, uint64_t, {0xABCDEF01DEADBEEF, 0x1234567898765432, 
                           0xABCDEF01DEADBEEF, 0x1234567898765432, 
                           0, 0, 0, 0});
}

TEST_P(InstSve, orr) {
  // VL = 512-bits
  RUN_AARCH64(R"(
    mov x0, #8

    # Test varying permutations of active and inactive lanes
    #ptrue p0.s
    #ptrue p1.s
    #ptrue p2.s
    #orr p3.b, p0/z, p1.b, p2.b
    #whilelo p1.s, xzr, x0
    #orr p4.b, p0/z, p1.b, p2.b
    #whilelo p2.s, xzr, x0
    #orr p5.b, p0/z, p1.b, p2.b
    whilelo p0.s, xzr, x0
    ptrue p1.s
    #ptrue p2.s
    #orr p6.b, p0/z, p1.b, p2.b

    # Check mov alias
    mov p7.b, p0.b
    mov p8.b, p1.b

    mov z0.s, #4
    mov z1.d, z0.d
  )");  
  // CHECK_PREDICATE(3, uint32_t, {0x11111111, 0x11111111, 0, 0, 0, 0, 0, 0});
  // CHECK_PREDICATE(4, uint32_t, {0x11111111, 0x11111111, 0, 0, 0, 0, 0, 0});
  // CHECK_PREDICATE(5, uint32_t, {0x11111111, 0, 0, 0, 0, 0, 0, 0});
  // CHECK_PREDICATE(6, uint32_t, {0x11111111, 0, 0, 0, 0, 0, 0, 0});
  CHECK_PREDICATE(7, uint32_t, {0x11111111, 0, 0, 0, 0, 0, 0, 0});
  CHECK_PREDICATE(8, uint32_t, {0x11111111, 0x11111111, 0, 0, 0, 0, 0, 0});

  CHECK_NEON(1, uint64_t, {0x400000004, 0x400000004, 0x400000004, 0x400000004,
                           0x400000004, 0x400000004, 0x400000004, 0x400000004});
}

TEST_P(InstSve, ptest) {
  // VL = 512-bits
  RUN_AARCH64(R"(
    ptrue p0.s
    ptest p0, p0.b
  )");
  EXPECT_EQ(getNZCV(), 0b1010);

  RUN_AARCH64(R"(
    ptrue p0.s
    mov x0, #8
    whilelo p1.s, xzr, x0
    ptest p1, p0.b
  )");
  EXPECT_EQ(getNZCV(), 0b1010);
}

TEST_P(InstSve, ptrue) {
  // VL = 512-bits
  // 32-bit arrangement
  RUN_AARCH64(R"(
    ptrue p0.s
  )");
  CHECK_PREDICATE(0, uint32_t, {286331153, 286331153, 0, 0, 0, 0, 0, 0});
}

TEST_P(InstSve, sel) {
  // VL = 512-bits
  // 32-bit
  initialHeapData_.resize(128);
  uint32_t* heap32 = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap32[0] = 0xDEADBEEF;
  heap32[1] = 0x12345678;
  heap32[2] = 0x98765432;
  heap32[3] = 0xABCDEF01;
  heap32[4] = 0xDEADBEEF;
  heap32[5] = 0x12345678;
  heap32[6] = 0x98765432;
  heap32[7] = 0xABCDEF01;
  heap32[8] = 0xDEADBEEF;
  heap32[9] = 0x12345678;
  heap32[10] = 0x98765432;
  heap32[11] = 0xABCDEF01;
  heap32[12] = 0xDEADBEEF;
  heap32[13] = 0x12345678;
  heap32[14] = 0x98765432;
  heap32[15] = 0xABCDEF01;
  
  heap32[16] = 0xABCDEF01;
  heap32[17] = 0x98765432;
  heap32[18] = 0x12345678;
  heap32[19] = 0xDEADBEEF;
  heap32[20] = 0xABCDEF01;
  heap32[21] = 0x98765432;
  heap32[22] = 0x12345678;
  heap32[23] = 0xDEADBEEF;
  heap32[24] = 0xABCDEF01;
  heap32[25] = 0x98765432;
  heap32[26] = 0x12345678;
  heap32[27] = 0xDEADBEEF;
  heap32[28] = 0xABCDEF01;
  heap32[29] = 0x98765432;
  heap32[30] = 0x12345678;
  heap32[31] = 0xDEADBEEF;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x2, #16
    ptrue p0.s  
    ld1w {z0.s}, p0/z, [x0, x1, lsl #2]
    ld1w {z1.s}, p0/z, [x0, x2, lsl #2]

    mov x3, #8
    whilelo p1.s, xzr, x3
    
    sel z2.s, p1, z0.s, z1.s
  )");
  CHECK_NEON(2, uint64_t, {0x12345678DEADBEEF, 0xABCDEF0198765432,
                           0x12345678DEADBEEF, 0xABCDEF0198765432,
                           0x98765432ABCDEF01, 0xDEADBEEF12345678,
                           0x98765432ABCDEF01, 0xDEADBEEF12345678});
}

TEST_P(InstSve, st1w) {
  // VL = 512-bit
  // 32-bit arrangement
  initialHeapData_.resize(64);
  uint32_t* heap32 = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap32[0] = 0xDEADBEEF;
  heap32[1] = 0x12345678;
  heap32[2] = 0x98765432;
  heap32[3] = 0xABCDEF01;
  heap32[4] = 0xDEADBEEF;
  heap32[5] = 0x12345678;
  heap32[6] = 0x98765432;
  heap32[7] = 0xABCDEF01;
  heap32[8] = 0xDEADBEEF;
  heap32[9] = 0x12345678;
  heap32[10] = 0x98765432;
  heap32[11] = 0xABCDEF01;
  heap32[12] = 0xDEADBEEF;
  heap32[13] = 0x12345678;
  heap32[14] = 0x98765432;
  heap32[15] = 0xABCDEF01;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #0
    mov x4, #64
    ptrue p0.s
    ld1w {z0.s}, p0/z, [x0, x1, lsl #2]
    ld1w {z2.s}, p0/z, [x0, x1, lsl #2]
    st1w {z0.s}, p0, [sp, x1, lsl #2]
    st1w {z2.s}, p0, [x4]

    mov x2, #8
    mov x3, #4
    whilelo p1.s, xzr, x2
    ld1w {z1.s}, p1/z, [x0, x3, lsl #2]
    // ld1w {z3.s}, p1/z, [x0, x3, lsl #2]
    st1w {z1.s}, p1, [x2, x3, lsl #2]
    // st1w {z3.s}, p1, [x2, #4, mul vl]
  )");
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer()), 0xDEADBEEF);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() + 4), 0x12345678);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() + 8), 0x98765432);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() + 12), 0xABCDEF01);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() + 16), 0xDEADBEEF);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() + 20), 0x12345678);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() + 24), 0x98765432);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() + 28), 0xABCDEF01);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() + 32), 0xDEADBEEF);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() + 36), 0x12345678);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() + 40), 0x98765432);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() + 44), 0xABCDEF01);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() + 48), 0xDEADBEEF);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() + 52), 0x12345678);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() + 56), 0x98765432);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getStackPointer() + 60), 0xABCDEF01);

  EXPECT_EQ(getMemoryValue<uint32_t>(64), 0xDEADBEEF);
  EXPECT_EQ(getMemoryValue<uint32_t>(64 + 4), 0x12345678);
  EXPECT_EQ(getMemoryValue<uint32_t>(64 + 8), 0x98765432);
  EXPECT_EQ(getMemoryValue<uint32_t>(64 + 12), 0xABCDEF01);
  EXPECT_EQ(getMemoryValue<uint32_t>(64 + 16), 0xDEADBEEF);
  EXPECT_EQ(getMemoryValue<uint32_t>(64 + 20), 0x12345678);
  EXPECT_EQ(getMemoryValue<uint32_t>(64 + 24), 0x98765432);
  EXPECT_EQ(getMemoryValue<uint32_t>(64 + 28), 0xABCDEF01);
  EXPECT_EQ(getMemoryValue<uint32_t>(64 + 32), 0xDEADBEEF);
  EXPECT_EQ(getMemoryValue<uint32_t>(64 + 36), 0x12345678);
  EXPECT_EQ(getMemoryValue<uint32_t>(64 + 40), 0x98765432);
  EXPECT_EQ(getMemoryValue<uint32_t>(64 + 44), 0xABCDEF01);
  EXPECT_EQ(getMemoryValue<uint32_t>(64 + 48), 0xDEADBEEF);
  EXPECT_EQ(getMemoryValue<uint32_t>(64 + 52), 0x12345678);
  EXPECT_EQ(getMemoryValue<uint32_t>(64 + 56), 0x98765432);
  EXPECT_EQ(getMemoryValue<uint32_t>(64 + 60), 0xABCDEF01);

  EXPECT_EQ(getMemoryValue<uint32_t>(8 + 16), 0xDEADBEEF);
  EXPECT_EQ(getMemoryValue<uint32_t>(8 + 20), 0x12345678);
  EXPECT_EQ(getMemoryValue<uint32_t>(8 + 24), 0x98765432);
  EXPECT_EQ(getMemoryValue<uint32_t>(8 + 28), 0xABCDEF01);
  EXPECT_EQ(getMemoryValue<uint32_t>(8 + 32), 0xDEADBEEF);
  EXPECT_EQ(getMemoryValue<uint32_t>(8 + 36), 0x12345678);
  EXPECT_EQ(getMemoryValue<uint32_t>(8 + 40), 0x98765432);
  EXPECT_EQ(getMemoryValue<uint32_t>(8 + 44), 0xABCDEF01);

  // EXPECT_EQ(getMemoryValue<uint32_t>(264), 0xDEADBEEF);
  // EXPECT_EQ(getMemoryValue<uint32_t>(264 + 4), 0x12345678);
  // EXPECT_EQ(getMemoryValue<uint32_t>(264 + 8), 0x98765432);
  // EXPECT_EQ(getMemoryValue<uint32_t>(264 + 12), 0xABCDEF01);
  // EXPECT_EQ(getMemoryValue<uint32_t>(264 + 16), 0xDEADBEEF);
  // EXPECT_EQ(getMemoryValue<uint32_t>(264 + 20), 0x12345678);
  // EXPECT_EQ(getMemoryValue<uint32_t>(264 + 24), 0x98765432);
  // EXPECT_EQ(getMemoryValue<uint32_t>(264 + 28), 0xABCDEF01);
}

TEST_P(InstSve, whilelo) {
  // VL = 512-bits
  // 32-bit arrangement, 64-bit source operands
  RUN_AARCH64(R"(
    mov x0, #16
    mov x1, #8
    mov x2, #11
    mov x3, #5

    whilelo p0.s, xzr, x0
    whilelo p1.s, x1, x0
    whilelo p2.s, x2, x0
    whilelo p3.s, x3, x0
    whilelo p4.s, xzr, xzr
  )");
  CHECK_PREDICATE(0, uint32_t, {286331153, 286331153, 0, 0, 0, 0, 0, 0});
  CHECK_PREDICATE(1, uint32_t, {286331153, 0, 0, 0, 0, 0, 0, 0});
  CHECK_PREDICATE(2, uint32_t, {69905, 0, 0, 0, 0, 0, 0, 0});
  CHECK_PREDICATE(3, uint32_t, {286331153, 273, 0, 0, 0, 0, 0, 0});
  CHECK_PREDICATE(4, uint32_t, {0, 0, 0, 0, 0, 0, 0, 0});
}

INSTANTIATE_TEST_SUITE_P(AArch64, InstSve, ::testing::Values(EMULATION),
                         coreTypeToString);

}  // namespace
