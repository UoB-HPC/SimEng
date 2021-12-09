#include <cmath>

#include "AArch64RegressionTest.hh"

namespace {

using InstNeon = AArch64RegressionTest;

TEST_P(InstNeon, add) {
  // 8-bit vector
  initialHeapData_.resize(32);
  uint8_t* heap8 = reinterpret_cast<uint8_t*>(initialHeapData_.data());
  heap8[0] = 0;
  heap8[1] = 0xFF;
  heap8[2] = 0xF0;
  heap8[3] = 0x55;
  heap8[4] = 0xAB;
  heap8[5] = 0xEF;
  heap8[6] = 0xFF;
  heap8[7] = 0x52;
  heap8[8] = heap8[0];
  heap8[9] = heap8[1];
  heap8[10] = heap8[2];
  heap8[11] = heap8[3];
  heap8[12] = heap8[4];
  heap8[13] = heap8[5];
  heap8[14] = heap8[6];
  heap8[15] = heap8[7];

  heap8[16] = 0;
  heap8[17] = 0x01;
  heap8[18] = 0x0F;
  heap8[19] = 0xAA;
  heap8[20] = 0xCD;
  heap8[21] = 0x12;
  heap8[22] = 0xFF;
  heap8[23] = 0x87;
  heap8[24] = heap8[16];
  heap8[25] = heap8[17];
  heap8[26] = heap8[18];
  heap8[27] = heap8[19];
  heap8[28] = heap8[20];
  heap8[29] = heap8[21];
  heap8[30] = heap8[22];
  heap8[31] = heap8[23];

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]
    add v2.16b, v1.16b, v0.16b
    add v3.8b, v1.8b, v0.8b
  )");
  CHECK_NEON(2, uint8_t,
             {0, 0, 0xFF, 0xFF, 0x78, 0x01, 0xFE, 0xD9, 0, 0, 0xFF, 0xFF, 0x78,
              0x01, 0xFE, 0xD9});
  CHECK_NEON(
      3, uint8_t,
      {0, 0, 0xFF, 0xFF, 0x78, 0x01, 0xFE, 0xD9, 0, 0, 0, 0, 0, 0, 0, 0});

  // 16-bit vector (8h)
  initialHeapData_.resize(32);
  uint16_t* heap16 = reinterpret_cast<uint16_t*>(initialHeapData_.data());
  heap16[0] = 0xDEAD;
  heap16[1] = 0xBEEF;
  heap16[2] = 0xF0F0;
  heap16[3] = 0xFFFF;
  heap16[4] = 0;
  heap16[5] = 0x1234;
  heap16[6] = 0x5678;
  heap16[7] = 0x5555;

  heap16[8] = 0xBEEF;
  heap16[9] = 0xDEAD;
  heap16[10] = 0x0F0F;
  heap16[11] = 0x0001;
  heap16[12] = 0;
  heap16[13] = 0x1234;
  heap16[14] = 0x5678;
  heap16[15] = 0xAAAA;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]
    add v2.8h, v1.8h, v0.8h
  )");
  CHECK_NEON(2, uint16_t,
             {0x9D9C, 0x9D9C, 0xFFFF, 0, 0, 0x2468, 0xACF0, 0xFFFF});

  // 16-bit vector (4h)
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #8]
    ldr q2, [x0, #16]
    ldr q3, [x0, #24]
    add v4.4h, v0.4h, v2.4h
    add v5.4h, v1.4h, v3.4h
  )");
  CHECK_NEON(4, uint16_t, {0x9D9C, 0x9D9C, 0xFFFF, 0, 0, 0, 0, 0});
  CHECK_NEON(5, uint16_t, {0, 0x2468, 0xACF0, 0xFFFF, 0, 0, 0, 0});

  // 32-bit vector (4s)
  initialHeapData_.resize(32);
  uint32_t* heap32 = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap32[0] = 0xDEADBEEF;
  heap32[1] = 0x01234567;
  heap32[2] = 0x89ABCDEF;
  heap32[3] = 0x0F0F0F0F;

  heap32[4] = 0xF0F0F0F0;
  heap32[5] = 0xF0F0F0F0;
  heap32[6] = 0xDEADBEEF;
  heap32[7] = 0xDEADBEEF;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]
    add v2.4s, v0.4s, v1.4s
  )");
  CHECK_NEON(2, uint32_t,
             {0xDEADBEEFu + 0xF0F0F0F0u, 0x01234567u + 0x0F0F0F0F0u,
              0x89ABCDEFu + 0xDEADBEEFu, 0x0F0F0F0Fu + 0xDEADBEEFu});

  // 32-bit vector (2s)
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]
    add v2.2s, v0.2s, v1.2s
  )");
  CHECK_NEON(2, uint32_t,
             {0xDEADBEEFu + 0xF0F0F0F0u, 0x01234567u + 0x0F0F0F0F0u, 0, 0});

  // 64-bit scalar
  initialHeapData_.resize(32);
  uint64_t* heap64 = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  heap64[0] = 0xDEADBEEF;
  heap64[1] = 0x01234567;
  heap64[2] = 0x89ABCDEF;
  heap64[3] = 0x0F0F0F0F;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr d0, [x0]
    ldr d1, [x0, #8]
    ldr d2, [x0, #16]
    ldr d3, [x0, #24]
    add d4, d0, d2
    add d5, d1, d3
  )");
  CHECK_NEON(4, uint64_t, {0x168598CDE});
  CHECK_NEON(5, uint64_t, {0x10325476});

  // 64-bit vector
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]
    
    add v2.2d, v1.2d, v0.2d
  )");
  CHECK_NEON(2, uint64_t, {0x168598CDE, 0x10325476});
}

TEST_P(InstNeon, addp) {
  // 8-bit
  initialHeapData_.resize(32);
  uint8_t* heap8 = reinterpret_cast<uint8_t*>(initialHeapData_.data());
  for (int i = 0; i < 32; i++) {
    heap8[i] = i;
  }
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]
    addp v2.16b, v0.16b, v1.16b
  )");
  CHECK_NEON(2, uint8_t,
             {1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61});

  // 16-bit
  initialHeapData_.resize(32);
  uint16_t* heap16 = reinterpret_cast<uint16_t*>(initialHeapData_.data());
  heap16[0] = 0x0123;
  heap16[1] = 0x4567;
  heap16[2] = 0x89AB;
  heap16[3] = 0xCDEF;
  heap16[4] = 0xF0F0;
  heap16[5] = 0xF0F0;
  heap16[6] = 0x0F0F;
  heap16[7] = 0x0F0F;
  heap16[8] = 0xFFFF;
  heap16[9] = 0xFFFF;
  heap16[10] = 0x0000;
  heap16[11] = 0x0000;
  heap16[12] = 0xDEAD;
  heap16[13] = 0xBEEF;
  heap16[14] = 0xABBA;
  heap16[15] = 0xABBA;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]
    addp v2.8h, v0.8h, v1.8h
  )");
  CHECK_NEON(2, uint16_t,
             {static_cast<uint16_t>(0x0123 + 0x4567),
              static_cast<uint16_t>(0x89AB + 0xCDEF),
              static_cast<uint16_t>(0xF0F0 + 0xF0F0),
              static_cast<uint16_t>(0x0F0F + 0x0F0F),
              static_cast<uint16_t>(0xFFFF + 0xFFFF),
              static_cast<uint16_t>(0x0000 + 0x0000),
              static_cast<uint16_t>(0xDEAD + 0xBEEF),
              static_cast<uint16_t>(0xABBA + 0xABBA)});

  // 32-bit
  initialHeapData_.resize(32);
  uint32_t* heap32 = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap32[0] = 0xDEADBEEF;
  heap32[1] = 0x01234567;
  heap32[2] = 0x89ABCDEF;
  heap32[3] = 0x0F0F0F0F;
  heap32[4] = 0xF0F0F0F0;
  heap32[5] = 0xF0F0F0F0;
  heap32[6] = 0xDEADBEEF;
  heap32[7] = 0xDEADBEEF;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]
    addp v2.4s, v0.4s, v1.4s
  )");
  CHECK_NEON(2, uint32_t,
             {0xDEADBEEFu + 0x01234567u, 0x89ABCDEFu + 0x0F0F0F0Fu,
              0xF0F0F0F0u + 0xF0F0F0F0u, 0xDEADBEEFu + 0xDEADBEEFu});

  // 64-bit
  initialHeapData_.resize(32);
  uint64_t* heap64 = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  heap64[0] = 0xDEADBEEFul;
  heap64[1] = 0x01234567ul << 8;
  heap64[2] = 0x89ABCDEFul;
  heap64[3] = 0x0F0F0F0Ful << 16;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]
    addp v2.2d, v0.2d, v1.2d
    addp d3, v0.2d
  )");
  CHECK_NEON(2, uint64_t,
             {0xDEADBEEFul + (0x01234567ul << 8),
              0x89ABCDEFul + (0x0F0F0F0Ful << 16)});
  CHECK_NEON(3, uint64_t, {0xDEADBEEFul + (0x01234567ul << 8), 0});
}

TEST_P(InstNeon, addv) {
  // 8-bit
  initialHeapData_.resize(16);
  uint8_t* heap8 = reinterpret_cast<uint8_t*>(initialHeapData_.data());
  for (int i = 0; i < 16; i++) {
    heap8[i] = (i + 1);
  }

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    addv b1, v0.8b
  )");

  CHECK_NEON(1, uint8_t, {36});
}

TEST_P(InstNeon, and) {
  initialHeapData_.resize(32);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0xDEADBEEF;
  heap[1] = 0xDEADBEEF;
  heap[2] = 0xDEADBEEF;
  heap[3] = 0xDEADBEEF;
  heap[4] = 0x01234567;
  heap[5] = 0x89ABCDEF;
  heap[6] = 0x0F0F0F0F;
  heap[7] = 0xF0F0F0F0;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]
    and v2.16b, v0.16b, v1.16b
  )");
  CHECK_NEON(2, uint32_t,
             {0xDEADBEEF & 0x01234567, 0xDEADBEEF & 0x89ABCDEF,
              0xDEADBEEF & 0x0F0F0F0F, 0xDEADBEEF & 0xF0F0F0F0});

  initialHeapData_.resize(16);
  uint32_t* heap8b = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap8b[0] = 0xDEADBEEF;
  heap8b[1] = 0xDEADBEEF;
  heap8b[2] = 0x01234567;
  heap8b[3] = 0x89ABCDEF;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #8]
    and v2.8b, v0.8b, v1.8b
  )");
  CHECK_NEON(2, uint32_t,
             {0xDEADBEEF & 0x01234567, 0xDEADBEEF & 0x89ABCDEF, 0, 0});
}

TEST_P(InstNeon, bic) {
  // Vector, immediate
  initialHeapData_.resize(32);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0xDEADBEEF;
  heap[1] = 0x12345678;
  heap[2] = 0x89ABCDEF;
  heap[3] = 0xF0F0F0F0;
  heap[4] = 0xDEADBEEF;
  heap[5] = 0x12345678;
  heap[6] = 0x89ABCDEF;
  heap[7] = 0xF0F0F0F0;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]
    bic v0.4s, #0x80, lsl #24
    bic v1.4s, #0xFF
  )");
  CHECK_NEON(0, uint32_t, {0x5eadbeef, 0x12345678, 0x9abcdef, 0x70f0f0f0});
  CHECK_NEON(1, uint32_t, {0xdeadbe00, 0x12345600, 0x89abcd00, 0xf0f0f000});

  // Vector, register
  RUN_AARCH64(R"(
    movi v0.16b, #0x00
    movi v1.16b, #0x0f
    movi v2.16b, #0xff
    movi v3.16b, #0xf0

    # v.16b
    bic v10.16b, v0.16b, v0.16b
    bic v11.16b, v2.16b, v0.16b
    bic v12.16b, v1.16b, v3.16b
    bic v13.16b, v2.16b, v1.16b

    # v.8b
    bic v14.8b, v0.8b, v0.8b
    bic v15.8b, v2.8b, v0.8b
    bic v16.8b, v1.8b, v3.8b
    bic v17.8b, v2.8b, v1.8b
  )");
  CHECK_NEON(10, uint8_t,
             {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00});
  CHECK_NEON(11, uint8_t,
             {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
              0xff, 0xff, 0xff, 0xff, 0xff});
  CHECK_NEON(12, uint8_t,
             {0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f,
              0x0f, 0x0f, 0x0f, 0x0f, 0x0f});
  CHECK_NEON(13, uint8_t,
             {0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0,
              0xf0, 0xf0, 0xf0, 0xf0, 0xf0});
  CHECK_NEON(14, uint8_t,
             {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00});
  CHECK_NEON(15, uint8_t,
             {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00});
  CHECK_NEON(16, uint8_t,
             {0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x0f, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00});
  CHECK_NEON(17, uint8_t,
             {0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0xf0, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00});
}

TEST_P(InstNeon, bif) {
  initialHeapData_.resize(48);
  double* heap = reinterpret_cast<double*>(initialHeapData_.data());
  heap[0] = 1.0;
  heap[1] = -42.76;
  heap[2] = 0.0;
  heap[3] = 0.0;
  heap[4] = 1.0;
  heap[5] = 1.0;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]
    ldr q2, [x0, #32]
    bif v3.16b, v0.16b, v1.16b
    bif v4.16b, v0.16b, v2.16b
  )");
  CHECK_NEON(3, double, {1.0, -42.76});
  CHECK_NEON(4, double, {0.0, -2.67249999999999987565502124198});
}

TEST_P(InstNeon, bit) {
  initialHeapData_.resize(48);
  double* heap = reinterpret_cast<double*>(initialHeapData_.data());
  heap[0] = 1.0;
  heap[1] = -42.76;
  heap[2] = 0.0;
  heap[3] = 0.0;
  heap[4] = 1.0;
  heap[5] = 1.0;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]
    ldr q2, [x0, #32]
    bit v3.16b, v0.16b, v1.16b
    bit v4.16b, v0.16b, v2.16b
  )");
  CHECK_NEON(3, double, {0.0, 0.0});
  CHECK_NEON(4, double, {1.0, 1.78005908680576110647218617387E-307});
}

TEST_P(InstNeon, bsl) {
  // Float
  initialHeapData_.resize(32);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  fheap[0] = 7.0f;
  fheap[1] = -34.71f;
  fheap[2] = -0.917f;
  fheap[3] = 0.0f;
  fheap[4] = 80.72f;
  fheap[5] = -125.67f;
  fheap[6] = 701.90f;
  fheap[7] = 0.0f;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]
    fcmge v2.2s, v0.2s, v1.2s
    fcmge v3.4s, v1.4s, v0.4s
  )");
  CHECK_NEON(2, uint32_t, {0, UINT32_MAX, 0, 0});
  CHECK_NEON(3, uint32_t, {UINT32_MAX, 0, UINT32_MAX, UINT32_MAX});

  // Double
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

    fcmge v4.2d, v0.2d, v1.2d
  )");
  CHECK_NEON(2, double, {1.0, 0.0});
  CHECK_NEON(3, double, {-0.125, -42.76});
  CHECK_NEON(4, uint64_t, {UINT64_MAX, 0});
}

TEST_P(InstNeon, cmeq) {
  // 8-bit
  initialHeapData_.resize(32);
  uint8_t* heap8 = reinterpret_cast<uint8_t*>(initialHeapData_.data());
  for (int i = 0; i < 16; i++) {
    heap8[i] = i;
    heap8[i + 16] = i;
  }
  heap8[3] = 0;
  heap8[6] = 0;
  heap8[12] = 0;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]
    cmeq v2.16b, v0.16b, v1.16b
    cmeq v3.16b, v0.16b, 0
  )");
  CHECK_NEON(2, uint8_t,
             {0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
              0xFF, 0x00, 0xFF, 0xFF, 0xFF});
  CHECK_NEON(3, uint8_t,
             {0xFF, 0x00, 0x00, 0xFF, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00,
              0x00, 0xFF, 0x00, 0x00, 0x00});

  // 32-bit
  initialHeapData_.resize(128);
  uint32_t* heap32 = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap32[0] = 10;
  heap32[1] = 11;
  heap32[2] = 12;
  heap32[3] = 13;

  heap32[4] = 13;
  heap32[5] = 11;
  heap32[6] = 12;
  heap32[7] = 10;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]
    cmeq v2.4s, v0.4s, v1.4s
  )");
  CHECK_NEON(2, uint32_t, {0, 0xFFFFFFFFu, 0xFFFFFFFFu, 0});
}

TEST_P(InstNeon, cmhi) {
  initialHeapData_.resize(32);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 42;
  heap[1] = 7;
  heap[2] = UINT32_MAX;
  heap[3] = 7;
  heap[4] = 1;
  heap[5] = (1u << 31) - 1;
  heap[6] = 0;
  heap[7] = 7;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]
    cmhi v2.4s, v0.4s, v1.4s
    cmhi v3.4s, v1.4s, v0.4s
  )");
  CHECK_NEON(2, uint32_t, {0xFFFFFFFF, 0x0, 0xFFFFFFFF, 0x0});
  CHECK_NEON(3, uint32_t, {0x0, 0xFFFFFFFF, 0x0, 0x0});
}

TEST_P(InstNeon, cnt) {
  initialHeapData_.resize(16);
  uint64_t* heap64 = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  heap64[0] = 0xFF00EE00DD00CC00;
  heap64[1] = 0x9900880077006600;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    cnt v1.8b, v0.8b
  )");

  CHECK_NEON(1, uint8_t, {0, 4, 0, 6, 0, 6, 0, 8});
}

TEST_P(InstNeon, dup) {
  initialHeapData_.resize(8);
  uint16_t* heap16 = reinterpret_cast<uint16_t*>(initialHeapData_.data());
  heap16[0] = 42;
  heap16[1] = (1u << 15);
  heap16[2] = UINT16_MAX;
  heap16[3] = 7;

  // 16-bit scalar to vector
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr w1, [x0]
    ldr w2, [x0, #2]
    ldr w3, [x0, #4]
    ldr w4, [x0, #6]
    dup v2.4h, w1
    dup v3.4h, w2
    dup v4.4h, w3
    dup v5.4h, w4
  )");
  CHECK_NEON(2, uint16_t, {42, 42, 42, 42});
  CHECK_NEON(3, uint16_t, {(1u << 15), (1u << 15), (1u << 15), (1u << 15)});
  CHECK_NEON(4, uint16_t, {UINT16_MAX, UINT16_MAX, UINT16_MAX, UINT16_MAX});
  CHECK_NEON(5, uint16_t, {7, 7, 7, 7});

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

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr w1, [x0]
    ldr w2, [x0, #4]
    ldr q0, [x0, #16]
    dup v2.2s, w1
    dup v3.2s, w2
    dup v4.2s, v0.s[0]
    dup v5.2s, v0.s[1]
    dup v6.2s, v0.s[2]
    dup v7.2s, v0.s[3]
  )");
  CHECK_NEON(2, uint32_t, {42, 42, 0, 0});
  CHECK_NEON(3, uint32_t, {(1u << 31), (1u << 31), 0, 0});
  CHECK_NEON(4, uint32_t, {1, 1, 0, 0});
  CHECK_NEON(5, uint32_t, {(1u << 31) - 1, (1u << 31) - 1, 0, 0});
  CHECK_NEON(6, uint32_t, {0, 0, 0, 0});
  CHECK_NEON(7, uint32_t, {0xDEADBEEF, 0xDEADBEEF, 0, 0});

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

TEST_P(InstNeon, eor) {
  initialHeapData_.resize(32);
  uint8_t* heap = reinterpret_cast<uint8_t*>(initialHeapData_.data());
  for (int i = 0; i < 16; i++) {
    heap[i] = i;
    heap[i + 16] = i + 1;
  }
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]
    eor v2.16b, v0.16b, v1.16b
    eor v3.8b, v0.8b, v1.8b
  )");
  CHECK_NEON(2, uint8_t, {1, 3, 1, 7, 1, 3, 1, 15, 1, 3, 1, 7, 1, 3, 1, 31});
  CHECK_NEON(3, uint8_t, {1, 3, 1, 7, 1, 3, 1, 15, 0, 0, 0, 0, 0, 0, 0, 0});
}

TEST_P(InstNeon, ext) {
  RUN_AARCH64(R"(
    movi v0.16b, #0xAB
    movi v1.16b, #0xFF
    movi v2.16b, #0xDE
    movi v3.16b, #0xBB

    ext v4.16b, v0.16b, v1.16b, #9
    ext v5.16b, v1.16b, v0.16b, #13

    ext v6.8b, v2.8b, v3.8b, #3
    ext v7.8b, v3.8b, v2.8b, #7
  )");
  CHECK_NEON(4, uint8_t,
             {0xABu, 0xABu, 0xABu, 0xABu, 0xABu, 0xABu, 0xABu, 0xFFu, 0xFFu,
              0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu});
  CHECK_NEON(5, uint8_t,
             {0xFFu, 0xFFu, 0xFFu, 0xABu, 0xABu, 0xABu, 0xABu, 0xABu, 0xABu,
              0xABu, 0xABu, 0xABu, 0xABu, 0xABu, 0xABu, 0xABu});
  CHECK_NEON(6, uint8_t,
             {0xDEu, 0xDEu, 0xDEu, 0xDEu, 0xDEu, 0xBBu, 0xBBu, 0xBBu, 0, 0, 0,
              0, 0, 0, 0, 0});
  CHECK_NEON(7, uint8_t,
             {0xBBu, 0xDEu, 0xDEu, 0xDEu, 0xDEu, 0xDEu, 0xDEu, 0xDEu, 0, 0, 0,
              0, 0, 0, 0, 0});
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

TEST_P(InstNeon, faddp) {
  // // 64-bit
  // initialHeapData_.resize(32);
  // double* heap64 = reinterpret_cast<double*>(initialHeapData_.data());
  // heap64[0] = 0xDEADBEEFul;
  // heap64[1] = 0x01234567ul << 8;
  // RUN_AARCH64(R"(
  //   # Get heap address
  //   mov x0, 0
  //   mov x8, 214
  //   svc #0

  //   ldr q0, [x0]
  //   faddp d0, v0.2d
  // )");
  // CHECK_NEON(0, double, {0xDEADBEEFul + (0x01234567ul << 8), 0.0});

  // V.4S
  RUN_AARCH64(R"(
    fmov v0.4s, #0.25
    fmov v1.4s, #3.75
    faddp v2.4s, v1.4s, v0.4s
  )");
  CHECK_NEON(2, float, {7.5f, 7.5f, 0.5f, 0.5f});

  // V.2S
  RUN_AARCH64(R"(
    fmov v0.2s, #0.25
    fmov v1.2s, #3.75
    faddp v2.2s, v1.2s, v0.2s
  )");
  CHECK_NEON(2, float, {7.5f, 0.5f, 0.f, 0.f});

  // V.2D
  RUN_AARCH64(R"(
    fmov v0.2d, #0.25
    fmov v1.2d, #3.75
    faddp v2.2d, v1.2d, v0.2d
  )");
  CHECK_NEON(2, double, {7.5, 0.5});
}
TEST_P(InstNeon, fadd) {
  initialHeapData_.resize(64);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  dheap[0] = 1.0;
  dheap[1] = -42.76;
  dheap[2] = -0.125;
  dheap[3] = 0.0;
  dheap[4] = 40.26;
  dheap[5] = -684.72;
  dheap[6] = -0.15;
  dheap[7] = 107.86;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]
    ldr q2, [x0, #32]
    ldr q3, [x0, #48]
    fadd v4.2d, v0.2d, v1.2d
    fadd v5.2d, v2.2d, v3.2d
  )");
  CHECK_NEON(4, double, {0.875, -42.76});
  CHECK_NEON(5, double, {40.11, -576.86});

  initialHeapData_.resize(32);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  fheap[0] = 7.0f;
  fheap[1] = -34.71f;
  fheap[2] = -0.917f;
  fheap[3] = 0.0f;
  fheap[4] = 80.72f;
  fheap[5] = -125.67f;
  fheap[6] = -0.01f;
  fheap[7] = 701.90f;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]
    fadd v2.4s, v0.4s, v1.4s
  )");
  CHECK_NEON(2, float, {87.72f, -160.38, -0.927f, 701.90f});
}
TEST_P(InstNeon, fcmge) {
  initialHeapData_.resize(32);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  dheap[0] = 1.0;
  dheap[1] = -42.76;
  dheap[2] = -0.125;
  dheap[3] = 0.0;

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

  initialHeapData_.resize(32);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  fheap[0] = 7.0f;
  fheap[1] = -34.71f;
  fheap[2] = -0.917f;
  fheap[3] = 0.0f;
  fheap[4] = 80.72f;
  fheap[5] = -125.67f;
  fheap[6] = 701.90f;
  fheap[7] = -0.01f;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]
    fcmge v2.4s, v0.4s, 0.0
    fcmge v3.4s, v1.4s, 0.0
  )");
  CHECK_NEON(2, uint32_t, {UINT32_MAX, 0, 0, UINT32_MAX});
  CHECK_NEON(3, uint32_t, {UINT32_MAX, 0, UINT32_MAX, 0});
}
TEST_P(InstNeon, fcmgt) {
  // Float
  initialHeapData_.resize(32);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  fheap[0] = 7.0f;
  fheap[1] = -34.71f;
  fheap[2] = -0.917f;
  fheap[3] = 0.0f;
  fheap[4] = 80.72f;
  fheap[5] = -125.67f;
  fheap[6] = 701.90f;
  fheap[7] = -0.01f;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]
    fcmgt v2.4s, v0.4s, v1.4s

    fcmgt v3.2s, v1.2s, #0.0
    fcmgt v4.4s, v0.4s, #0.0
  )");
  CHECK_NEON(2, uint32_t, {0, UINT32_MAX, 0, UINT32_MAX});
  CHECK_NEON(3, uint32_t, {UINT32_MAX, 0, 0, 0});
  CHECK_NEON(4, uint32_t, {UINT32_MAX, 0, 0, 0});

  // Double
  initialHeapData_.resize(32);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  dheap[0] = 7.0;
  dheap[1] = -34.71;
  dheap[2] = -0.917;
  dheap[3] = 0.0;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]
    
    fcmgt v2.2d, v0.2d, #0.0
    fcmgt v3.2d, v1.2d, #0.0
  )");
  CHECK_NEON(2, uint64_t, {UINT64_MAX, 0});
  CHECK_NEON(3, uint64_t, {0, 0});
}
TEST_P(InstNeon, fcmlt) {
  // Float
  initialHeapData_.resize(32);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  fheap[0] = 7.0f;
  fheap[1] = -34.71f;
  fheap[2] = -0.917f;
  fheap[3] = 0.0f;
  fheap[4] = 80.72f;
  fheap[5] = -125.67f;
  fheap[6] = 701.90f;
  fheap[7] = -0.01f;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]
    fcmlt v2.4s, v0.4s, 0.0
    fcmlt v3.4s, v1.4s, 0.0

    fcmlt v4.2s, v0.2s, 0.0
    fcmlt v5.2s, v1.2s, 0.0
  )");
  CHECK_NEON(2, uint32_t, {0, UINT32_MAX, UINT32_MAX, 0});
  CHECK_NEON(3, uint32_t, {0, UINT32_MAX, 0, UINT32_MAX});
  CHECK_NEON(4, uint32_t, {0, UINT32_MAX, 0, 0});
  CHECK_NEON(5, uint32_t, {0, UINT32_MAX, 0, 0});

  // Double
  initialHeapData_.resize(32);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  dheap[0] = 7.0;
  dheap[1] = -34.71;
  dheap[2] = -0.917;
  dheap[3] = 0.0;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]

    fcmlt v2.2d, v0.2d, 0.0
    fcmlt v3.2d, v1.2d, 0.0
  )");
  CHECK_NEON(2, uint64_t, {0, UINT64_MAX});
  CHECK_NEON(3, uint64_t, {UINT64_MAX, 0});
}
TEST_P(InstNeon, fcvt) {
  initialHeapData_.resize(32);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  dheap[0] = 1.0;
  dheap[1] = -42.76;
  dheap[2] = -0.125;
  dheap[3] = 321.5;

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

TEST_P(InstNeon, fcvtl) {
  initialHeapData_.resize(32);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  fheap[0] = 1.0;
  fheap[1] = -33.5;
  fheap[2] = -0.255;
  fheap[3] = 555.3;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #8]
    fcvtl v2.2d, v0.2s
    fcvtl v3.2d, v1.2s
  )");
  CHECK_NEON(2, double, {1.0, -33.5});
  CHECK_NEON(3, double, {-0.255, 555.3});
}

TEST_P(InstNeon, fcvtl2) {
  initialHeapData_.resize(32);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  fheap[0] = 1.0;
  fheap[1] = -33.5;
  fheap[2] = -0.255;
  fheap[3] = 555.3;
  fheap[4] = 998.2;
  fheap[5] = -369.0;
  fheap[6] = -0.00155;
  fheap[7] = 9986.2;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]
    fcvtl2 v2.2d, v0.4s
    fcvtl2 v3.2d, v1.4s
  )");
  CHECK_NEON(2, double, {-0.255, 555.3});
  CHECK_NEON(3, double, {-0.00155, 9986.2});
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

// TEST_P(InstNeon, fmla){
//   initialHeapData_.resize(48);
//   float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
//   fheap[0] = 7.0;
//   fheap[1] = -3.4;
//   fheap[2] = -0.16;
//   fheap[3] = 0.0;

//   fheap[4] = 8.72;
//   fheap[5] = -1.67;
//   fheap[6] = 7.90;
//   fheap[7] = -0.01;

//   fheap[8] = 1.0;
//   fheap[9] = -4.3;
//   fheap[10] = -0.1;
//   fheap[11] = 0.0;

//   RUN_AARCH64(R"(
//     # Get heap address
//     mov x0, 0
//     mov x8, 214
//     svc #0

//     ldr q0, [x0]
//     ldr q1, [x0, #16]
//     ldr q2, [x0, #32]
//     fmla v2.4s, v0.4s, v1.4s
//     fmla v3.4s, v0.4s, v2.s[0]
//   )");
//   CHECK_NEON(2, float, {62.04, 1.378, -1.364, 0.0});
//   CHECK_NEON(3, float, {434.28, -210.936, -9.9264, 0.0});
// }

TEST_P(InstNeon, fmls) {
  // vector, 32-bit
  initialHeapData_.resize(48);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  fheap[0] = 7.0;
  fheap[1] = -3.4;
  fheap[2] = -0.16;
  fheap[3] = 0.0;

  fheap[4] = 8.72;
  fheap[5] = -1.67;
  fheap[6] = 7.90;
  fheap[7] = -0.01;

  fheap[8] = 1.0;
  fheap[9] = -4.3;
  fheap[10] = -0.1;
  fheap[11] = 0.0;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]
    ldr q2, [x0, #32]
    mov w1, #0
    dup v3.4s, w1
    fmls v2.4s, v0.4s, v1.4s
    fmls v3.4s, v0.4s, v2.s[0]
  )");
  CHECK_NEON(2, float, {-60.04, -9.978, 1.164, 0.0});
  CHECK_NEON(3, float, {420.28, -204.136, -9.6064, 0.0});

  // vector, 64-bit
  initialHeapData_.resize(48);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  dheap[0] = -3.4;
  dheap[1] = 0.0;

  dheap[2] = 8.72;
  dheap[3] = -1.67;

  dheap[4] = -4.3;
  dheap[5] = -0.1;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]
    ldr q2, [x0, #32]
    fmls v2.2d, v0.2d, v1.2d
  )");
  CHECK_NEON(2, double, {25.348, -0.1});
}

// TEST_P(InstNeon, fmaxnm){
//   // numeric
//   initialHeapData_.resize(32);
//   double* heapA = reinterpret_cast<double*>(initialHeapData_.data());
//   heapA[0] = 6.0;
//   heapA[1] = 17.0;
//   heapA[2] = 4.0;
//   heapA[3] = -73.0;

//   RUN_AARCH64(R"(
//     # Get heap address
//     mov x0, 0
//     mov x8, 214
//     svc #0

//     ldr q0, [x0]
//     ldr q1, [x0, #16]
//     fmaxnm v2.2d, v0.2d, v1.2d
//   )");
//   CHECK_NEON(2, double, {6.0, 17.0});

//   // with NAN
//   initialHeapData_.resize(32);
//   double* heapB = reinterpret_cast<double*>(initialHeapData_.data());
//   heapB[0] = 6.0;
//   heapB[1] = 17.0;
//   heapB[2] = std::nan("");
//   heapB[3] = std::nan("");

//   RUN_AARCH64(R"(
//     # Get heap address
//     mov x0, 0
//     mov x8, 214
//     svc #0

//     ldr q0, [x0]
//     ldr q1, [x0, #16]
//     fmaxnm v2.2d, v0.2d, v1.2d
//   )");
//   CHECK_NEON(2, double, {6.0, 17.0});
// }

// TEST_P(InstNeon, fminnm){
//   // numeric
//   initialHeapData_.resize(32);
//   double* heapA = reinterpret_cast<double*>(initialHeapData_.data());
//   heapA[0] = 5.0;
//   heapA[1] = 10.0;
//   heapA[2] = 1.0;
//   heapA[3] = -14.0;

//   RUN_AARCH64(R"(
//     # Get heap address
//     mov x0, 0
//     mov x8, 214
//     svc #0

//     ldr q0, [x0]
//     ldr q1, [x0, #16]
//     fminnm v2.2d, v0.2d, v1.2d
//   )");
//   CHECK_NEON(2, double, {1.0, -14.0});

//   // with NAN
//   initialHeapData_.resize(32);
//   double* heapB = reinterpret_cast<double*>(initialHeapData_.data());
//   heapB[0] = 5.0;
//   heapB[1] = 10.0;
//   heapB[2] = std::nan("");
//   heapB[3] = std::nan("");

//   RUN_AARCH64(R"(
//     # Get heap address
//     mov x0, 0
//     mov x8, 214
//     svc #0

//     ldr q0, [x0]
//     ldr q1, [x0, #16]
//     fminnm v2.2d, v0.2d, v1.2d
//   )");
//   CHECK_NEON(2, double, {5.0, 10.0});
// }

// TEST_P(InstNeon, fmaxnmp){
//   // numeric
//   initialHeapData_.resize(32);
//   double* heapA = reinterpret_cast<double*>(initialHeapData_.data());
//   heapA[0] = 6.0;
//   heapA[1] = 17.0;

//   RUN_AARCH64(R"(
//     # Get heap address
//     mov x0, 0
//     mov x8, 214
//     svc #0

//     ldr q0, [x0]
//     fmaxnmp d0, v0.2d
//   )");
//   CHECK_NEON(0, double, {17.0, 0.0});

//   // with NAN
//   initialHeapData_.resize(32);
//   double* heapB = reinterpret_cast<double*>(initialHeapData_.data());
//   heapB[0] = 6.0;
//   heapB[1] = std::nan("");

//   RUN_AARCH64(R"(
//     # Get heap address
//     mov x0, 0
//     mov x8, 214
//     svc #0

//     ldr q0, [x0]
//     fmaxnmp d0, v0.2d
//   )");
//   CHECK_NEON(0, double, {6.0, 0.0});
// }

// TEST_P(InstNeon, fminnmp){
//   // numeric
//   initialHeapData_.resize(32);
//   double* heapA = reinterpret_cast<double*>(initialHeapData_.data());
//   heapA[0] = 6.0;
//   heapA[1] = 17.0;

//   RUN_AARCH64(R"(
//     # Get heap address
//     mov x0, 0
//     mov x8, 214
//     svc #0

//     ldr q0, [x0]
//     fminnmp d0, v0.2d
//   )");
//   CHECK_NEON(0, double, {6.0, 0.0});

//   // with NAN
//   initialHeapData_.resize(32);
//   double* heapB = reinterpret_cast<double*>(initialHeapData_.data());
//   heapB[0] = 6.0;
//   heapB[1] = std::nan("");

//   RUN_AARCH64(R"(
//     # Get heap address
//     mov x0, 0
//     mov x8, 214
//     svc #0

//     ldr q0, [x0]
//     fminnmp d0, v0.2d
//   )");
//   CHECK_NEON(0, double, {6.0, 0.0});
// }

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

  // FP32 vector (64-bit) from immediate
  RUN_AARCH64(R"(
    fmov v0.2s, 1.0
    fmov v1.2s, -0.125
  )");
  CHECK_NEON(0, float, {1.f, 1.f, 0.f, 0.f});
  CHECK_NEON(1, float, {-0.125f, -0.125f, 0.f, 0.f});
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
    fmul v3.4s, v1.4s, v0.s[0]
    fmul s4, s0, v1.s[2]
    fmul s5, s1, v1.s[0]
    fmul s6, s0, v0.s[1]
    fmul s7, s0, v1.s[3]
    fmul v8.2s, v0.2s, v1.2s
    fmul v9.2s, v1.2s, v0.s[0]
  )");
  EXPECT_EQ((getVectorRegisterElement<float, 0>(2)), -5.f);
  EXPECT_EQ((getVectorRegisterElement<float, 1>(2)), -1400832.f);
  EXPECT_EQ((getVectorRegisterElement<float, 2>(2)), 0.f);
  EXPECT_TRUE(std::isnan(getVectorRegisterElement<float, 3>(2)));
  EXPECT_EQ((getVectorRegisterElement<float, 0>(3)), -5.f);
  EXPECT_EQ((getVectorRegisterElement<float, 1>(3)), 65536.f);
  EXPECT_EQ((getVectorRegisterElement<float, 2>(3)), -0.f);
  EXPECT_TRUE(std::isnan(getVectorRegisterElement<float, 3>(3)));
  CHECK_NEON(4, float, {-0.f, 0.f, 0.f, 0.f});
  CHECK_NEON(5, float, {6.25f, 0.f, 0.f, 0.f});
  CHECK_NEON(6, float, {-85.5f, 0.f, 0.f, 0.f});
  EXPECT_TRUE(std::isnan(getVectorRegisterElement<float, 0>(7)));
  EXPECT_EQ((getVectorRegisterElement<float, 1>(7)), 0.f);
  EXPECT_EQ((getVectorRegisterElement<float, 2>(7)), 0.f);
  EXPECT_EQ((getVectorRegisterElement<float, 3>(7)), 0.f);
  CHECK_NEON(8, float, {-5.0f, -1400832.0f, 0.0f, 0.0f});
  CHECK_NEON(9, float, {-5.0f, 65536.0f, 0.0f, 0.0f});

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
    fmul v5.2d, v1.2d, v0.d[0]
  )");
  CHECK_NEON(2, double, {-0.25, -13725.96});
  CHECK_NEON(3, double, {642.0, 0.0});
  CHECK_NEON(4, double, {0.015625, 0.0});
  CHECK_NEON(5, double, {-0.25, 642.0});
}

TEST_P(InstNeon, fneg) {
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
    fneg v2.2d, v0.2d
    fneg v3.2d, v1.2d
  )");
  CHECK_NEON(2, double, {-1.0, 42.76});
  CHECK_NEON(3, double, {0.125, -321.0});

  initialHeapData_.resize(32);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  fheap[0] = 1.0;
  fheap[1] = -42.76;
  fheap[2] = -0.125;
  fheap[3] = 321.0;
  fheap[4] = 2.0;
  fheap[5] = -1.0;
  fheap[6] = -321.0;
  fheap[7] = 123.0;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]
    fneg v2.4s, v0.4s
    fneg v3.4s, v1.4s
  )");
  CHECK_NEON(2, float, {-1.0, 42.76, 0.125, -321.0});
  CHECK_NEON(3, float, {-2.0, 1.0, 321.0, -123.0});
}

TEST_P(InstNeon, frinta) {
  // 64-bit negative
  initialHeapData_.resize(48);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  dheap[0] = -3.75;
  dheap[1] = -3.5;
  dheap[2] = -3.125;
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
    frinta d6, d0
    frinta d7, d1
    frinta d8, d2
    frinta d9, d3
    frinta d10, d4
    frinta d11, d5
  )");
  CHECK_NEON(6, double, {-4});
  CHECK_NEON(7, double, {-4});
  CHECK_NEON(8, double, {-3});
  CHECK_NEON(9, double, {-3});
  CHECK_NEON(10, double, {-1});
  CHECK_NEON(11, double, {-0});

  // 64-bit positive
  dheap[0] = 3.75;
  dheap[1] = 3.5;
  dheap[2] = 3.125;
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
    frinta d6, d0
    frinta d7, d1
    frinta d8, d2
    frinta d9, d3
    frinta d10, d4
    frinta d11, d5
  )");
  CHECK_NEON(6, double, {4});
  CHECK_NEON(7, double, {4});
  CHECK_NEON(8, double, {3});
  CHECK_NEON(9, double, {3});
  CHECK_NEON(10, double, {1});
  CHECK_NEON(11, double, {0});
}

TEST_P(InstNeon, fsqrt) {
  // vector, 32-bit, 4 elements
  initialHeapData_.resize(32);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  fheap[0] = 1.0;
  fheap[1] = 42.76;
  fheap[2] = 0.125;
  fheap[3] = 321.0;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    fsqrt v2.4s, v0.4s
  )");
  CHECK_NEON(2, float, {1.0, 6.53911309, 0.3535533906, 17.91647287});

  // vector, 64-bit, 2 elements
  initialHeapData_.resize(32);
  double* dheap = reinterpret_cast<double*>(initialHeapData_.data());
  dheap[0] = 1.0;
  dheap[1] = 42.76;
  dheap[2] = 0.125;
  dheap[3] = 321.0;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]
    fsqrt v2.2d, v0.2d
    fsqrt v3.2d, v1.2d
  )");
  CHECK_NEON(2, double, {1.0, 6.53911308971});
  CHECK_NEON(3, double, {0.35355339059, 17.9164728672});
}

TEST_P(InstNeon, fsub) {
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
    fsub v2.2d, v0.2d, v1.2d
  )");
  CHECK_NEON(2, double, {1.125, -363.76});

  initialHeapData_.resize(32);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  fheap[0] = 1.0;
  fheap[1] = -42.76;
  fheap[2] = -0.125;
  fheap[3] = 321.0;
  fheap[4] = 2.0;
  fheap[5] = -1.0;
  fheap[6] = -321.0;
  fheap[7] = 123.0;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]
    fsub v2.4s, v0.4s, v1.4s
  )");
  CHECK_NEON(2, float, {-1.0, -41.76, 320.875, 198.0});
}

TEST_P(InstNeon, ins) {
  // 32-bit
  initialHeapData_.resize(32);
  float* fheap = reinterpret_cast<float*>(initialHeapData_.data());
  fheap[0] = 1.0f;
  fheap[1] = -42.76f;
  fheap[2] = -0.125f;
  fheap[3] = 321.0f;
  fheap[4] = 2.0f;
  fheap[5] = -1.0f;
  fheap[6] = -321.0f;
  fheap[7] = 123.0f;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]
    ins v0.s[0], v1.s[3]
    ins v0.s[1], v1.s[2]
    ins v0.s[3], v1.s[0]
    ins v1.s[3], v0.s[2]
  )");
  CHECK_NEON(0, float, {123.0f, -321.f, -0.125f, 2.0f});
  CHECK_NEON(1, float, {2.0f, -1.0f, -321.0f, -0.125f});

  // 64-bit
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
    ldr q2, [x0]
    ins v2.d[0], v1.d[1]
    ins v1.d[1], v0.d[0]
    ins v0.d[0], v2.d[0]
  )");
  CHECK_NEON(0, double, {321.0, -42.76});
  CHECK_NEON(1, double, {-0.125, 1.0});
  CHECK_NEON(2, double, {321.0, -42.76});
}

TEST_P(InstNeon, mov_from_general) {
  // from general to byte
  RUN_AARCH64(R"(
    mov w0, #0x01
    mov w1, #0x04
    mov w2, #0x07
    mov w3, #0x0A

    # inserting elements
    mov v0.b[1], w0
    mov v0.b[4], w1
    mov v0.b[7], w2
    mov v0.b[10], w3
  )");
  CHECK_NEON(0, uint8_t,
             {0x00, 0x01, 0x00, 0x00, 0x04, 0x00, 0x00, 0x07, 0x00, 0x00, 0x0A,
              0x00, 0x00, 0x00, 0x00, 0x00});

  // from general to half precision
  RUN_AARCH64(R"(
    mov w0, #0x1010
    mov w1, #0x3030
    mov w2, #0x5050
    mov w3, #0x7070

    # inserting elements
    mov v0.h[1], w0
    mov v0.h[3], w1
    mov v0.h[5], w2
    mov v0.h[7], w3
  )");
  CHECK_NEON(0, uint16_t,
             {0x0000, 0x1010, 0x0000, 0x3030, 0x0000, 0x5050, 0x0000, 0x7070});

  // from general to single precision
  RUN_AARCH64(R"(
    mov w0, #0x3f800000
    mov w1, #0x40000000
    mov w2, #0x40400000
    mov w3, #0x40800000

    # inserting elements
    mov v0.s[0], w0
    mov v0.s[1], w1
    mov v0.s[2], w2
    mov v0.s[3], w3
  )");
  CHECK_NEON(0, float, {1.f, 2.f, 3.f, 4.f});

  // from general to double precision
  RUN_AARCH64(R"(
    mov x0, #100
    mov x1, #200

    # inserting elemetns
    mov v0.d[0], x0
    mov v0.d[1], x1
  )");
  CHECK_NEON(0, uint64_t, {100UL, 200UL})
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

  // vector 8-bit
  RUN_AARCH64(R"(
    movi v0.16b, #1
    movi v1.8b, #2
  )");
  CHECK_NEON(0, uint8_t,
             {static_cast<uint8_t>(1), static_cast<uint8_t>(1),
              static_cast<uint8_t>(1), static_cast<uint8_t>(1),
              static_cast<uint8_t>(1), static_cast<uint8_t>(1),
              static_cast<uint8_t>(1), static_cast<uint8_t>(1),
              static_cast<uint8_t>(1), static_cast<uint8_t>(1),
              static_cast<uint8_t>(1), static_cast<uint8_t>(1),
              static_cast<uint8_t>(1), static_cast<uint8_t>(1),
              static_cast<uint8_t>(1), static_cast<uint8_t>(1)})
  CHECK_NEON(1, uint8_t,
             {static_cast<uint8_t>(2), static_cast<uint8_t>(2),
              static_cast<uint8_t>(2), static_cast<uint8_t>(2),
              static_cast<uint8_t>(2), static_cast<uint8_t>(2),
              static_cast<uint8_t>(2), static_cast<uint8_t>(2), 0, 0, 0, 0, 0,
              0, 0, 0})
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

TEST_P(InstNeon, not ) {
  initialHeapData_.resize(128);
  uint8_t* heap = reinterpret_cast<uint8_t*>(initialHeapData_.data());
  heap[0] = 0b11111111;
  heap[1] = 0b00000000;
  heap[2] = 0b01010101;
  heap[3] = 0b11001100;
  heap[4] = 0b00000001;
  heap[5] = 0b00000011;
  heap[6] = 0b00000111;
  heap[7] = 0b00001111;
  heap[8] = 0b00011111;
  heap[9] = 0b00111111;
  heap[10] = 0b01111111;
  heap[11] = 0b10000000;
  heap[12] = 0b11000000;
  heap[13] = 0b11100000;
  heap[14] = 0b11110000;
  heap[15] = 0b11111001;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]

    not v1.16b, v0.16b
    not v2.8b, v0.8b
  )");
  CHECK_NEON(
      1, uint8_t,
      {static_cast<uint8_t>(0b00000000), static_cast<uint8_t>(0b11111111),
       static_cast<uint8_t>(0b10101010), static_cast<uint8_t>(0b00110011),
       static_cast<uint8_t>(0b11111110), static_cast<uint8_t>(0b11111100),
       static_cast<uint8_t>(0b11111000), static_cast<uint8_t>(0b11110000),
       static_cast<uint8_t>(0b11100000), static_cast<uint8_t>(0b11000000),
       static_cast<uint8_t>(0b10000000), static_cast<uint8_t>(0b01111111),
       static_cast<uint8_t>(0b00111111), static_cast<uint8_t>(0b00011111),
       static_cast<uint8_t>(0b00001111), static_cast<uint8_t>(0b00000110)});
  CHECK_NEON(
      2, uint8_t,
      {static_cast<uint8_t>(0b00000000), static_cast<uint8_t>(0b11111111),
       static_cast<uint8_t>(0b10101010), static_cast<uint8_t>(0b00110011),
       static_cast<uint8_t>(0b11111110), static_cast<uint8_t>(0b11111100),
       static_cast<uint8_t>(0b11111000), static_cast<uint8_t>(0b11110000), 0, 0,
       0, 0, 0, 0, 0, 0});
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
  // 8-bit
  initialHeapData_.resize(16);
  uint8_t* heap8 = reinterpret_cast<uint8_t*>(initialHeapData_.data());
  for (int i = 0; i < 16; i++) {
    heap8[i] = (i + 1) * 15;
  }

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    umov w0, v0.b[0]
    umov w1, v0.b[15]
  )");
  EXPECT_EQ((getGeneralRegister<uint8_t>(0)), 15);
  EXPECT_EQ((getGeneralRegister<uint8_t>(1)), 240);

  // 32-bit
  initialHeapData_.resize(16);
  uint32_t* heap32 = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap32[0] = 42;
  heap32[1] = 1u << 31;
  heap32[2] = -1;
  heap32[3] = 7;

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

  // 64-bit
  initialHeapData_.resize(16);
  uint64_t* heap64 = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  heap64[0] = 42;
  heap64[1] = 1ul << 63;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    umov x0, v0.d[0]
    umov x1, v0.d[1]

    # Check mov alias works as well
    mov  x2, v0.d[0]
    mov  x3, v0.d[1]
  )");
  EXPECT_EQ((getGeneralRegister<uint64_t>(0)), 42);
  EXPECT_EQ((getGeneralRegister<uint64_t>(1)), 1ul << 63);
  EXPECT_EQ((getGeneralRegister<uint64_t>(2)), 42);
  EXPECT_EQ((getGeneralRegister<uint64_t>(3)), 1ul << 63);
}

TEST_P(InstNeon, scvtf) {
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
    ldr q0, [x0]
    ldr q1, [x0, #16]
    scvtf v0.2d, v0.2d
    scvtf v1.2d, v1.2d
  )");
  CHECK_NEON(0, double, {1.0, -1.0});
  CHECK_NEON(1, double,
             {static_cast<double>(INT64_MAX), static_cast<double>(INT64_MIN)});

  // 32-bit integer
  initialHeapData_.resize(32);
  int32_t* heap32 = reinterpret_cast<int32_t*>(initialHeapData_.data());
  heap32[0] = 1;
  heap32[1] = -2;
  heap32[2] = -1;
  heap32[3] = 2;
  heap32[4] = INT32_MIN;
  heap32[5] = INT32_MAX;
  heap32[6] = INT32_MAX;
  heap32[7] = INT32_MIN;

  // Vector of 2
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # Load and convert integer values
    ldr q0, [x0]
    ldr q1, [x0, #16]
    scvtf v0.2s, v0.2s
    scvtf v1.2s, v1.2s
  )");
  CHECK_NEON(0, float, {1.0f, -2.0f, 0.0f, 0.0f});
  CHECK_NEON(1, float,
             {static_cast<float>(INT32_MIN), static_cast<float>(INT32_MAX),
              0.0f, 0.0f});

  // Vector of 4
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # Load and convert integer values
    ldr q0, [x0]
    ldr q1, [x0, #16]
    scvtf v0.4s, v0.4s
    scvtf v1.4s, v1.4s
  )");
  CHECK_NEON(0, float, {1.0f, -2.0f, -1.0f, 2.0f});
  CHECK_NEON(1, float,
             {static_cast<float>(INT32_MIN), static_cast<float>(INT32_MAX),
              static_cast<float>(INT32_MAX), static_cast<float>(INT32_MIN)});
}

TEST_P(InstNeon, shl) {
  initialHeapData_.resize(32);
  uint32_t* heap32 = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap32[0] = 0xDEADBEEF;
  heap32[1] = 0x12345678;
  heap32[2] = 0x98765432;
  heap32[3] = 0xABCDEF01;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]

    shl v1.4s, v0.4s, #2
  )");
  CHECK_NEON(
      1, uint32_t,
      {0xDEADBEEF << 2, 0x12345678 << 2, 0x98765432 << 2, 0xABCDEF01 << 2});

  uint64_t* heap64 = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  heap64[0] = 0x12345678;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr d0, [x0]

    shl d1, d0, #2
  )");

  CHECK_NEON(1, uint64_t, {0x12345678 << 2, 0});
}

TEST_P(InstNeon, sshll) {
  initialHeapData_.resize(32);
  int32_t* heap = reinterpret_cast<int32_t*>(initialHeapData_.data());
  heap[0] = 31;
  heap[1] = -333;
  heap[2] = (INT32_MAX - 3) >> 2;
  heap[3] = -7;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #8]
    sshll v2.2d, v0.2s, #0
    sshll v3.2d, v1.2s, #2
    sshll2 v4.2d, v0.4s, #0
    sshll2 v5.2d, v0.4s, #2
  )");
  CHECK_NEON(2, int64_t, {31, -333});
  CHECK_NEON(3, int64_t, {(INT32_MAX - 3), -28});
  CHECK_NEON(4, int64_t, {(INT32_MAX - 3) >> 2, -7});
  CHECK_NEON(5, int64_t, {(INT32_MAX - 3), -28});
}

TEST_P(InstNeon, sshr) {
  initialHeapData_.resize(32);
  int32_t* heap = reinterpret_cast<int32_t*>(initialHeapData_.data());
  heap[0] = 32;
  heap[1] = -333;
  heap[2] = (INT32_MAX);
  heap[3] = -28;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    sshr v2.4s, v0.4s, #2
  )");
  CHECK_NEON(2, int32_t, {8, -84, 536870911, -7});
}

TEST_P(InstNeon, sub) {
  initialHeapData_.resize(32);
  uint32_t* heap32 = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap32[0] = 0xF0F0F0F0;
  heap32[1] = 0xF0F0F0F0;
  heap32[2] = 0xDEADBEEF;
  heap32[3] = 0x89ABCDEF;

  heap32[4] = 0xDEADBEEF;
  heap32[5] = 0x01234567;
  heap32[6] = 0x89ABCDEF;
  heap32[7] = 0x01234567;

  // 8-bit
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]
    sub v2.8b, v0.8b, v1.8b
    sub v3.16b, v0.16b, v1.16b
  )");
  CHECK_NEON(
      2, uint8_t,
      {static_cast<uint8_t>(0xF0 - 0xEF), static_cast<uint8_t>(0xF0 - 0xBE),
       static_cast<uint8_t>(0xF0 - 0xAD), static_cast<uint8_t>(0xF0 - 0xDE),
       static_cast<uint8_t>(0xF0 - 0x67), static_cast<uint8_t>(0xF0 - 0x45),
       static_cast<uint8_t>(0xF0 - 0x23), static_cast<uint8_t>(0xF0 - 0x01), 0u,
       0u, 0u, 0u, 0u, 0u, 0u, 0u});
  CHECK_NEON(
      3, uint8_t,
      {static_cast<uint8_t>(0xF0 - 0xEF), static_cast<uint8_t>(0xF0 - 0xBE),
       static_cast<uint8_t>(0xF0 - 0xAD), static_cast<uint8_t>(0xF0 - 0xDE),
       static_cast<uint8_t>(0xF0 - 0x67), static_cast<uint8_t>(0xF0 - 0x45),
       static_cast<uint8_t>(0xF0 - 0x23), static_cast<uint8_t>(0xF0 - 0x01),
       static_cast<uint8_t>(0xEF - 0xEF), static_cast<uint8_t>(0xBE - 0xCD),
       static_cast<uint8_t>(0xAD - 0xAB), static_cast<uint8_t>(0xDE - 0x89),
       static_cast<uint8_t>(0xEF - 0x67), static_cast<uint8_t>(0xCD - 0x45),
       static_cast<uint8_t>(0xAB - 0x23), static_cast<uint8_t>(0x89 - 0x01)});

  // 16-bit
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]
    sub v2.4h, v0.4h, v1.4h
    sub v3.8h, v0.8h, v1.8h
  )");
  CHECK_NEON(2, uint16_t,
             {static_cast<uint16_t>(0xF0F0 - 0xBEEF),
              static_cast<uint16_t>(0xF0F0 - 0xDEAD),
              static_cast<uint16_t>(0xF0F0 - 0x4567),
              static_cast<uint16_t>(0xF0F0 - 0x0123), 0u, 0u, 0u, 0u});
  CHECK_NEON(3, uint16_t,
             {static_cast<uint16_t>(0xF0F0 - 0xBEEF),
              static_cast<uint16_t>(0xF0F0 - 0xDEAD),
              static_cast<uint16_t>(0xF0F0 - 0x4567),
              static_cast<uint16_t>(0xF0F0 - 0x0123),
              static_cast<uint16_t>(0xBEEF - 0xCDEF),
              static_cast<uint16_t>(0xDEAD - 0x89AB),
              static_cast<uint16_t>(0xCDEF - 0x4567),
              static_cast<uint16_t>(0x89AB - 0x0123)});

  // 32-bit
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]
    sub v2.2s, v0.2s, v1.2s
    sub v3.4s, v0.4s, v1.4s
  )");
  CHECK_NEON(2, uint32_t,
             {0xF0F0F0F0u - 0xDEADBEEFu, 0xF0F0F0F0u - 0x01234567u, 0u, 0u});
  CHECK_NEON(3, uint32_t,
             {0xF0F0F0F0u - 0xDEADBEEFu, 0xF0F0F0F0u - 0x01234567u,
              0xDEADBEEFu - 0x89ABCDEFu, 0x89ABCDEFu - 0x01234567u});

  // 64-bit
  initialHeapData_.resize(64);
  uint64_t* heap64 = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  heap64[0] = 0xF0F0F0F0F0F0F0F0;
  heap64[1] = 0xDEADBEEF89ABCDEF;

  heap64[2] = 0xDEADBEEF01234567;
  heap64[3] = 0x89ABCDEF01234567;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]
    sub v2.2d, v0.2d, v1.2d
  )");
  CHECK_NEON(2, uint64_t,
             {0xF0F0F0F0F0F0F0F0u - 0xDEADBEEF01234567u,
              0xDEADBEEF89ABCDEFu - 0x89ABCDEF01234567u});

  // 64-bit single element
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #16]
    sub d2, d0, d1
  )");
  CHECK_NEON(2, uint64_t, {0xF0F0F0F0F0F0F0F0u - 0xDEADBEEF01234567u, 0});
}

TEST_P(InstNeon, ushll) {
  // ushll half precision to single precision
  initialHeapData_.resize(32);
  uint16_t* heap16 = reinterpret_cast<uint16_t*>(initialHeapData_.data());
  heap16[0] = 31;
  heap16[1] = 333;
  heap16[2] = (UINT16_MAX);
  heap16[3] = 7;
  heap16[4] = 42;
  heap16[5] = 1u << 13;
  heap16[6] = 702;
  heap16[7] = 0;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]
    ldr q1, [x0, #8]
    ushll v2.4s, v0.4h, #0
    ushll v3.4s, v1.4h, #2
    ushll v4.4s, v0.4h, #15
  )");
  CHECK_NEON(2, uint32_t, {31, 333, (UINT16_MAX), 7});
  CHECK_NEON(3, uint32_t, {168, 1u << 15, 2808, 0});
  CHECK_NEON(4, uint32_t, {31 << 15, 333 << 15, (UINT16_MAX) << 15, 7 << 15});

  // ushll2 half precision to single precision
  heap16[4] = 0;
  heap16[5] = (UINT16_MAX);
  heap16[6] = 1u << 13;
  heap16[7] = 27;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr q0, [x0]

    ushll2 v1.4s, v0.8h, #0
    ushll2 v2.4s, v0.8h, #8
    ushll2 v3.4s, v0.8h, #15
  )");
  CHECK_NEON(1, uint32_t, {0, (UINT16_MAX), 1u << 13, 27});
  CHECK_NEON(2, uint32_t, {0, (UINT16_MAX) << 8, 1u << 21, 27 << 8});
  CHECK_NEON(3, uint32_t, {0, (UINT16_MAX) << 15, 1u << 28, 27 << 15});

  // ushll byte to half precision
  initialHeapData_.resize(16);
  uint8_t* heap8 = reinterpret_cast<uint8_t*>(initialHeapData_.data());
  heap8[0] = 0x7F;
  heap8[1] = (UINT8_MAX);
  heap8[2] = 0xAA;
  heap8[3] = 0x80;
  heap8[4] = 0;
  heap8[5] = 0xbc;
  heap8[6] = 0xde;
  heap8[7] = 0xf0;
  heap8[8] = 0x11;
  heap8[9] = 0x22;
  heap8[10] = 0x33;
  heap8[11] = 0x44;
  heap8[12] = 0x55;
  heap8[13] = 0x66;
  heap8[14] = 0x77;
  heap8[15] = 0;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, #0
    mov x8, #214
    svc #0

    ldr q0, [x0]

    ushll v2.8h, v0.8b, #0
    ushll v3.8h, v0.8b, #4
    ushll v4.8h, v0.8b, #7
  )");
  CHECK_NEON(2, uint16_t, {0x7F, (UINT8_MAX), 0xAA, 0x80, 0, 0xbc, 0xde, 0xf0});
  CHECK_NEON(3, uint16_t,
             {0x7F << 4, (UINT8_MAX) << 4, 0xAA << 4, 0x80 << 4, 0, 0xbc << 4,
              0xde << 4, 0xf0 << 4});
  CHECK_NEON(4, uint16_t,
             {0x7F << 7, (UINT8_MAX) << 7, 0xAA << 7, 0x80 << 7, 0, 0xbc << 7,
              0xde << 7, 0xf0 << 7});

  // ushll2 byte to half precision
  heap8[8] = heap8[0];
  heap8[9] = heap8[1];
  heap8[10] = heap8[2];
  heap8[11] = heap8[3];
  heap8[12] = heap8[4];
  heap8[13] = heap8[5];
  heap8[14] = heap8[6];
  heap8[15] = heap8[7];
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, #0
    mov x8, #214
    svc #0

    ldr q0, [x0]

    ushll2 v2.8h, v0.16b, #0
    ushll2 v3.8h, v0.16b, #4
    ushll2 v4.8h, v0.16b, #7
  )");
  CHECK_NEON(2, uint16_t, {0x7F, (UINT8_MAX), 0xAA, 0x80, 0, 0xbc, 0xde, 0xf0});
  CHECK_NEON(3, uint16_t,
             {0x7F << 4, (UINT8_MAX) << 4, 0xAA << 4, 0x80 << 4, 0, 0xbc << 4,
              0xde << 4, 0xf0 << 4});
  CHECK_NEON(4, uint16_t,
             {0x7F << 7, (UINT8_MAX) << 7, 0xAA << 7, 0x80 << 7, 0, 0xbc << 7,
              0xde << 7, 0xf0 << 7});
}

TEST_P(InstNeon, xtn) {
  initialHeapData_.resize(32);
  uint64_t* dheap = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  dheap[0] = 42;
  dheap[1] = 1u << 31;
  dheap[2] = UINT32_MAX;
  dheap[3] = 7;

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

  initialHeapData_.resize(16);
  uint32_t* fheap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  fheap[0] = 42;
  fheap[1] = 1u << 15;
  fheap[2] = UINT16_MAX;
  fheap[3] = 7;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # Load and narrow integer values
    ldr q0, [x0]
    ldr q1, [x0, #16]
    xtn v2.4h, v0.4s
  )");
  CHECK_NEON(2, uint16_t, {42, (1u << 15), UINT16_MAX, 7, 0, 0, 0, 0});
}

INSTANTIATE_TEST_SUITE_P(AArch64, InstNeon,
                         ::testing::Values(std::make_tuple(EMULATION,
                                                           YAML::Load("{}"))),
                         paramToString);

}  // namespace