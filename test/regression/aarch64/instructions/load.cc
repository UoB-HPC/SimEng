#include "AArch64RegressionTest.hh"

namespace {

using InstLoad = AArch64RegressionTest;

TEST_P(InstLoad, ld1r) {
  // 8-bit
  initialHeapData_.resize(12);
  uint32_t* heapi32 = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heapi32[0] = 0xDEADBEEF;
  heapi32[1] = 0x12345678;
  heapi32[2] = 0xABCDEFAB;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # Load values from heap
    ld1r {v0.16b}, [x0]
    ld1r {v1.8b}, [x0], 1
    ld1r {v2.16b}, [x0], 1
    ld1r {v3.8b}, [x0]
  )");
  CHECK_NEON(0, uint8_t,
             {0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF,
              0xEF, 0xEF, 0xEF, 0xEF, 0xEF});
  CHECK_NEON(
      1, uint8_t,
      {0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0xEF, 0, 0, 0, 0, 0, 0, 0, 0});
  CHECK_NEON(2, uint8_t,
             {0xBE, 0xBE, 0xBE, 0xBE, 0xBE, 0xBE, 0xBE, 0xBE, 0xBE, 0xBE, 0xBE,
              0xBE, 0xBE, 0xBE, 0xBE, 0xBE});
  CHECK_NEON(
      3, uint8_t,
      {0xAD, 0xAD, 0xAD, 0xAD, 0xAD, 0xAD, 0xAD, 0xAD, 0, 0, 0, 0, 0, 0, 0, 0});

  // 16-bit
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # Load values from heap
    ld1r {v0.8h}, [x0]
    ld1r {v1.4h}, [x0], 2
    ld1r {v2.8h}, [x0], 2
    ld1r {v3.4h}, [x0]
  )");
  CHECK_NEON(0, uint16_t,
             {0xBEEF, 0xBEEF, 0xBEEF, 0xBEEF, 0xBEEF, 0xBEEF, 0xBEEF, 0xBEEF});
  CHECK_NEON(1, uint16_t, {0xBEEF, 0xBEEF, 0xBEEF, 0xBEEF, 0, 0, 0, 0});
  CHECK_NEON(2, uint16_t,
             {0xDEAD, 0xDEAD, 0xDEAD, 0xDEAD, 0xDEAD, 0xDEAD, 0xDEAD, 0xDEAD});
  CHECK_NEON(3, uint16_t, {0x5678, 0x5678, 0x5678, 0x5678, 0, 0, 0, 0});

  // 32-bit
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # Load values from heap
    ld1r {v0.4s}, [x0]
    ld1r {v1.2s}, [x0], 4
    ld1r {v2.4s}, [x0], 4
    ld1r {v3.2s}, [x0]
  )");
  CHECK_NEON(0, uint32_t, {0xDEADBEEF, 0xDEADBEEF, 0xDEADBEEF, 0xDEADBEEF});
  CHECK_NEON(1, uint32_t, {0xDEADBEEF, 0xDEADBEEF, 0, 0});
  CHECK_NEON(2, uint32_t, {0x12345678, 0x12345678, 0x12345678, 0x12345678});
  CHECK_NEON(3, uint32_t, {0xABCDEFAB, 0xABCDEFAB, 0, 0});

  // 64-bit
  initialHeapData_.resize(24);
  uint64_t* heapi64 = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  heapi64[0] = 0xDEADBEEFDEADFEEB;
  heapi64[1] = 0x1234567898765432;
  heapi64[2] = 0xABCDEFABCDEFABCD;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # Load values from heap
    ld1r {v0.2d}, [x0]
    ld1r {v1.1d}, [x0], 8
    ld1r {v2.2d}, [x0], 8
    ld1r {v3.1d}, [x0]
  )");
  CHECK_NEON(0, uint64_t, {0xDEADBEEFDEADFEEB, 0xDEADBEEFDEADFEEB});
  CHECK_NEON(1, uint64_t, {0xDEADBEEFDEADFEEB, 0});
  CHECK_NEON(2, uint64_t, {0x1234567898765432, 0x1234567898765432});
  CHECK_NEON(3, uint64_t, {0xABCDEFABCDEFABCD, 0});
}

TEST_P(InstLoad, ld1_single_struct) {
  // 32-bit
  initialHeapData_.resize(8);
  uint32_t* heapi32 = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heapi32[0] = 0xDEADBEEF;
  heapi32[1] = 0x12345678;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # Load values from heap
    ld1r {v0.4s}, [x0]
    ld1r {v1.4s}, [x0]
    ld1r {v2.4s}, [x0]
    ld1r {v3.4s}, [x0], 4
    ld1 {v0.s}[0], [x0]
    ld1 {v1.s}[1], [x0]
    ld1 {v2.s}[2], [x0]
    ld1 {v3.s}[3], [x0]
  )");
  CHECK_NEON(0, uint32_t, {0x12345678, 0xDEADBEEF, 0xDEADBEEF, 0xDEADBEEF});
  CHECK_NEON(1, uint32_t, {0xDEADBEEF, 0x12345678, 0xDEADBEEF, 0xDEADBEEF});
  CHECK_NEON(2, uint32_t, {0xDEADBEEF, 0xDEADBEEF, 0x12345678, 0xDEADBEEF});
  CHECK_NEON(3, uint32_t, {0xDEADBEEF, 0xDEADBEEF, 0xDEADBEEF, 0x12345678});

  // 64-bit
  initialHeapData_.resize(32);
  uint64_t* heapi64 = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  heapi64[0] = 0xDEADBEEF;
  heapi64[1] = UINT64_C(0x12345678) << 16;
  heapi64[2] = UINT64_C(0x98765432) << 8;
  heapi64[3] = UINT64_C(0xABCDEF12) << 4;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # Load values from heap
    ld1r {v0.4s}, [x0]
    ld1r {v1.4s}, [x0]
    ld1r {v2.4s}, [x0]
    add x0, x0, #8
    ld1 {v0.d}[0], [x0], 8
    ld1 {v1.d}[1], [x0]
    ld1 {v2.d}[0], [x0], 8
  )");
  CHECK_NEON(0, uint64_t, {UINT64_C(0x12345678) << 16, 0xDEADBEEFDEADBEEF});
  CHECK_NEON(1, uint64_t, {0xDEADBEEFDEADBEEF, UINT64_C(0x98765432) << 8});
  CHECK_NEON(2, uint64_t, {UINT64_C(0x98765432) << 8, 0xDEADBEEFDEADBEEF});
}

TEST_P(InstLoad, ld1_tworeg) {  // 128-bit
  initialHeapData_.resize(64);
  uint64_t* heapi64 = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  heapi64[0] = UINT64_C(0xDEADBEEF) << 32;
  heapi64[1] = UINT64_C(0x12345678) << 16;
  heapi64[2] = UINT64_C(0x98765432) << 8;
  heapi64[3] = UINT64_C(0xABCDEF12) << 4;
  heapi64[4] = UINT64_C(0xDEADBEEF) << 4;
  heapi64[5] = UINT64_C(0x12345678) << 8;
  heapi64[6] = UINT64_C(0x98765432) << 16;
  heapi64[7] = UINT64_C(0xABCDEF12) << 32;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # Load values from heap
    ld1 {v0.16b, v1.16b}, [x0], 32
    ld1 {v2.16b, v3.16b}, [x0]
  )");
  CHECK_NEON(0, uint64_t, {(0xDEADBEEFull << 32), (0x12345678ull << 16)});
  CHECK_NEON(1, uint64_t, {(0x98765432ull << 8), (0xABCDEF12ull << 4)});
  CHECK_NEON(2, uint64_t, {(0xDEADBEEFull << 4), (0x12345678ull << 8)});
  CHECK_NEON(3, uint64_t, {(0x98765432ull << 16), (0xABCDEF12ull << 32)});
}

TEST_P(InstLoad, ld1_multi_struct) {
  initialHeapData_.resize(64);
  uint64_t* heap = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  heap[0] = 0x66554433221100FF;
  heap[1] = 0xEEDDCCBBAA998877;
  heap[2] = 0x66554433221100FF;
  heap[3] = 0xEEDDCCBBAA998877;
  heap[4] = 0x66554433221100FF;
  heap[5] = 0xEEDDCCBBAA998877;
  heap[6] = 0x66554433221100FF;
  heap[7] = 0xEEDDCCBBAA998877;

  // One reg, 16b elements
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #16

    # Load values from heap
    ld1 {v0.16b}, [x0]

    # save heap address before post index
    mov x10, x0

    # Load values from heap with imm post-index
    ld1 {v1.16b}, [x0], #16

    # save heap address after post index
    mov x11, x0
    sub x0, x0, #16

    # Load values from heap with reg post-index
    ld1 {v2.16b}, [x0], x1

    mov x12, x0
  )");

  CHECK_NEON(0, uint8_t,
             {0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
              0xAA, 0xBB, 0xCC, 0xDD, 0xEE});
  CHECK_NEON(1, uint8_t,
             {0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
              0xAA, 0xBB, 0xCC, 0xDD, 0xEE});
  EXPECT_EQ(getGeneralRegister<uint64_t>(11),
            getGeneralRegister<uint64_t>(10) + 16);
  EXPECT_EQ(getGeneralRegister<uint64_t>(12),
            getGeneralRegister<uint64_t>(10) + 16);

  // Two reg, 16b elements
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #32

    # Load values from heap
    ld1 {v0.16b, v1.16b}, [x0]

    # save heap address before post index
    mov x10, x0

    # Load values from heap with imm post-index
    ld1 {v2.16b, v3.16b}, [x0], #32

    # save heap address after post index
    mov x11, x0
    sub x0, x0, #32

    # Load values from heap with reg post-index
    ld1 {v4.16b, v5.16b}, [x0], x1

    mov x12, x0
  )");

  CHECK_NEON(0, uint8_t,
             {0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
              0xAA, 0xBB, 0xCC, 0xDD, 0xEE});
  CHECK_NEON(1, uint8_t,
             {0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
              0xAA, 0xBB, 0xCC, 0xDD, 0xEE});
  CHECK_NEON(2, uint8_t,
             {0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
              0xAA, 0xBB, 0xCC, 0xDD, 0xEE});
  CHECK_NEON(3, uint8_t,
             {0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
              0xAA, 0xBB, 0xCC, 0xDD, 0xEE});
  CHECK_NEON(4, uint8_t,
             {0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
              0xAA, 0xBB, 0xCC, 0xDD, 0xEE});
  CHECK_NEON(5, uint8_t,
             {0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
              0xAA, 0xBB, 0xCC, 0xDD, 0xEE});
  EXPECT_EQ(getGeneralRegister<uint64_t>(11),
            getGeneralRegister<uint64_t>(10) + 32);
  EXPECT_EQ(getGeneralRegister<uint64_t>(12),
            getGeneralRegister<uint64_t>(10) + 32);

  // Two reg, 2d elements
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #32

    # Load values from heap
    ld1 {v0.2d, v1.2d}, [x0]

    # save heap address before post index
    mov x10, x0

    # Load values from heap with imm post-index
    ld1 {v2.2d, v3.2d}, [x0], #32

    # save heap address after post index
    mov x11, x0
    sub x0, x0, #32

    # Load values from heap with reg post-index
    ld1 {v4.2d, v5.2d}, [x0], x1

    mov x12, x0
  )");

  CHECK_NEON(0, uint64_t, {0x66554433221100FF, 0xEEDDCCBBAA998877});
  CHECK_NEON(1, uint64_t, {0x66554433221100FF, 0xEEDDCCBBAA998877});
  CHECK_NEON(2, uint64_t, {0x66554433221100FF, 0xEEDDCCBBAA998877});
  CHECK_NEON(3, uint64_t, {0x66554433221100FF, 0xEEDDCCBBAA998877});
  CHECK_NEON(4, uint64_t, {0x66554433221100FF, 0xEEDDCCBBAA998877});
  CHECK_NEON(5, uint64_t, {0x66554433221100FF, 0xEEDDCCBBAA998877});
  EXPECT_EQ(getGeneralRegister<uint64_t>(11),
            getGeneralRegister<uint64_t>(10) + 32);
  EXPECT_EQ(getGeneralRegister<uint64_t>(12),
            getGeneralRegister<uint64_t>(10) + 32);

  // Two reg, 4s elements
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #32

    # Load values from heap
    ld1 {v0.4s, v1.4s}, [x0]

    # save heap address before post index
    mov x10, x0

    # Load values from heap with imm post-index
    ld1 {v2.4s, v3.4s}, [x0], #32

    # save heap address after post index
    mov x11, x0
    sub x0, x0, #32

    # Load values from heap with reg post-index
    ld1 {v4.4s, v5.4s}, [x0], x1

    mov x12, x0
  )");

  CHECK_NEON(0, uint32_t, {0x221100FF, 0x66554433, 0xAA998877, 0xEEDDCCBB});
  CHECK_NEON(1, uint32_t, {0x221100FF, 0x66554433, 0xAA998877, 0xEEDDCCBB});
  CHECK_NEON(2, uint32_t, {0x221100FF, 0x66554433, 0xAA998877, 0xEEDDCCBB});
  CHECK_NEON(3, uint32_t, {0x221100FF, 0x66554433, 0xAA998877, 0xEEDDCCBB});
  CHECK_NEON(4, uint32_t, {0x221100FF, 0x66554433, 0xAA998877, 0xEEDDCCBB});
  CHECK_NEON(5, uint32_t, {0x221100FF, 0x66554433, 0xAA998877, 0xEEDDCCBB});
  EXPECT_EQ(getGeneralRegister<uint64_t>(11),
            getGeneralRegister<uint64_t>(10) + 32);
  EXPECT_EQ(getGeneralRegister<uint64_t>(12),
            getGeneralRegister<uint64_t>(10) + 32);

  // Four reg, 16b elements
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #64

    # Load values from heap
    ld1 {v0.16b, v1.16b, v2.16b, v3.16b}, [x0]

    # save heap address before post index
    mov x10, x0

    # Load values from heap with imm post-index
    ld1 {v4.16b, v5.16b, v6.16b, v7.16b}, [x0], #64

    # save heap address after post index
    mov x11, x0
    sub x0, x0, #64

    # Load values from heap with reg post-index
    ld1 {v8.16b, v9.16b, v10.16b, v11.16b}, [x0], x1

    mov x12, x0
  )");

  CHECK_NEON(0, uint8_t,
             {0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
              0xAA, 0xBB, 0xCC, 0xDD, 0xEE});
  CHECK_NEON(1, uint8_t,
             {0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
              0xAA, 0xBB, 0xCC, 0xDD, 0xEE});
  CHECK_NEON(2, uint8_t,
             {0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
              0xAA, 0xBB, 0xCC, 0xDD, 0xEE});
  CHECK_NEON(3, uint8_t,
             {0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
              0xAA, 0xBB, 0xCC, 0xDD, 0xEE});
  CHECK_NEON(4, uint8_t,
             {0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
              0xAA, 0xBB, 0xCC, 0xDD, 0xEE});
  CHECK_NEON(5, uint8_t,
             {0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
              0xAA, 0xBB, 0xCC, 0xDD, 0xEE});
  CHECK_NEON(6, uint8_t,
             {0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
              0xAA, 0xBB, 0xCC, 0xDD, 0xEE});
  CHECK_NEON(7, uint8_t,
             {0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
              0xAA, 0xBB, 0xCC, 0xDD, 0xEE});
  CHECK_NEON(8, uint8_t,
             {0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
              0xAA, 0xBB, 0xCC, 0xDD, 0xEE});
  CHECK_NEON(9, uint8_t,
             {0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
              0xAA, 0xBB, 0xCC, 0xDD, 0xEE});
  CHECK_NEON(10, uint8_t,
             {0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
              0xAA, 0xBB, 0xCC, 0xDD, 0xEE});
  CHECK_NEON(11, uint8_t,
             {0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
              0xAA, 0xBB, 0xCC, 0xDD, 0xEE});
  EXPECT_EQ(getGeneralRegister<uint64_t>(11),
            getGeneralRegister<uint64_t>(10) + 64);
  EXPECT_EQ(getGeneralRegister<uint64_t>(12),
            getGeneralRegister<uint64_t>(10) + 64);

  // Four reg, 2d elements
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #64

    # Load values from heap
    ld1 {v0.2d, v1.2d, v2.2d, v3.2d}, [x0]

    # save heap address before post index
    mov x10, x0

    # Load values from heap with imm post-index
    ld1 {v4.2d, v5.2d, v6.2d, v7.2d}, [x0], #64

    # save heap address after post index
    mov x11, x0
    sub x0, x0, #64

    # Load values from heap with reg post-index
    ld1 {v8.2d, v9.2d, v10.2d, v11.2d}, [x0], x1

    mov x12, x0
  )");

  CHECK_NEON(0, uint64_t, {0x66554433221100FF, 0xEEDDCCBBAA998877});
  CHECK_NEON(1, uint64_t, {0x66554433221100FF, 0xEEDDCCBBAA998877});
  CHECK_NEON(2, uint64_t, {0x66554433221100FF, 0xEEDDCCBBAA998877});
  CHECK_NEON(3, uint64_t, {0x66554433221100FF, 0xEEDDCCBBAA998877});
  CHECK_NEON(4, uint64_t, {0x66554433221100FF, 0xEEDDCCBBAA998877});
  CHECK_NEON(5, uint64_t, {0x66554433221100FF, 0xEEDDCCBBAA998877});
  CHECK_NEON(6, uint64_t, {0x66554433221100FF, 0xEEDDCCBBAA998877});
  CHECK_NEON(7, uint64_t, {0x66554433221100FF, 0xEEDDCCBBAA998877});
  CHECK_NEON(8, uint64_t, {0x66554433221100FF, 0xEEDDCCBBAA998877});
  CHECK_NEON(9, uint64_t, {0x66554433221100FF, 0xEEDDCCBBAA998877});
  CHECK_NEON(10, uint64_t, {0x66554433221100FF, 0xEEDDCCBBAA998877});
  CHECK_NEON(11, uint64_t, {0x66554433221100FF, 0xEEDDCCBBAA998877});
  EXPECT_EQ(getGeneralRegister<uint64_t>(11),
            getGeneralRegister<uint64_t>(10) + 64);
  EXPECT_EQ(getGeneralRegister<uint64_t>(12),
            getGeneralRegister<uint64_t>(10) + 64);

  // Four reg, 4s elements
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x1, #64

    # Load values from heap
    ld1 {v0.4s, v1.4s, v2.4s, v3.4s}, [x0]

    # save heap address before post index
    mov x10, x0

    # Load values from heap with imm post-index
    ld1 {v4.4s, v5.4s, v6.4s, v7.4s}, [x0], #64

    # save heap address after post index
    mov x11, x0
    sub x0, x0, #64

    # Load values from heap with reg post-index
    ld1 {v8.4s, v9.4s, v10.4s, v11.4s}, [x0], x1

    mov x12, x0
  )");

  CHECK_NEON(0, uint32_t, {0x221100FF, 0x66554433, 0xAA998877, 0xEEDDCCBB});
  CHECK_NEON(1, uint32_t, {0x221100FF, 0x66554433, 0xAA998877, 0xEEDDCCBB});
  CHECK_NEON(2, uint32_t, {0x221100FF, 0x66554433, 0xAA998877, 0xEEDDCCBB});
  CHECK_NEON(3, uint32_t, {0x221100FF, 0x66554433, 0xAA998877, 0xEEDDCCBB});
  CHECK_NEON(4, uint32_t, {0x221100FF, 0x66554433, 0xAA998877, 0xEEDDCCBB});
  CHECK_NEON(5, uint32_t, {0x221100FF, 0x66554433, 0xAA998877, 0xEEDDCCBB});
  CHECK_NEON(6, uint32_t, {0x221100FF, 0x66554433, 0xAA998877, 0xEEDDCCBB});
  CHECK_NEON(7, uint32_t, {0x221100FF, 0x66554433, 0xAA998877, 0xEEDDCCBB});
  CHECK_NEON(8, uint32_t, {0x221100FF, 0x66554433, 0xAA998877, 0xEEDDCCBB});
  CHECK_NEON(9, uint32_t, {0x221100FF, 0x66554433, 0xAA998877, 0xEEDDCCBB});
  CHECK_NEON(10, uint32_t, {0x221100FF, 0x66554433, 0xAA998877, 0xEEDDCCBB});
  CHECK_NEON(11, uint32_t, {0x221100FF, 0x66554433, 0xAA998877, 0xEEDDCCBB});
  EXPECT_EQ(getGeneralRegister<uint64_t>(11),
            getGeneralRegister<uint64_t>(10) + 64);
  EXPECT_EQ(getGeneralRegister<uint64_t>(12),
            getGeneralRegister<uint64_t>(10) + 64);
}

TEST_P(InstLoad, ld2_multi_struct) {
  // 32-bit Post index
  initialHeapData_.resize(64);
  float* heap = reinterpret_cast<float*>(initialHeapData_.data());
  heap[0] = 0.25;
  heap[1] = 2.0;
  heap[2] = 1.25;
  heap[3] = 7.5;
  heap[4] = 0.125;
  heap[5] = 0.75;
  heap[6] = 5.0;
  heap[7] = -0.5;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # Simple version does not alter x0
    ld2 {v4.4s, v5.4s}, [x0]

    # Save heap address before ld2 post index
    mov x10, x0

    # Load values from heap, post index x0
    ld2 {v0.4s, v1.4s}, [x0], #32
    
    # Save heap address after ld2
    mov x11, x0

    mov x0, x10
    mov x1, #48
    ld2 {v2.4s, v3.4s}, [x0], x1
    mov x12, x0
		
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(11),
            getGeneralRegister<uint64_t>(10) + 32);
  CHECK_NEON(0, float, {0.25f, 1.25f, 0.125f, 5.0f});
  CHECK_NEON(1, float, {2.0f, 7.5f, 0.75f, -0.5f});
  EXPECT_EQ(getGeneralRegister<uint64_t>(12),
            getGeneralRegister<uint64_t>(10) + 48);
  CHECK_NEON(2, float, {0.25f, 1.25f, 0.125f, 5.0f});
  CHECK_NEON(3, float, {2.0f, 7.5f, 0.75f, -0.5f});
  CHECK_NEON(4, float, {0.25f, 1.25f, 0.125f, 5.0f});
  CHECK_NEON(5, float, {2.0f, 7.5f, 0.75f, -0.5f});
}

TEST_P(InstLoad, ldadd) {
  // 32-bit
  RUN_AARCH64(R"(
    sub sp, sp, #1024
    mov w0, #16
    mov w1, #32
    mov w2, #48
    mov w3, #64
    mov w4, #80
    mov w5, #96
    mov w6, #112
    mov w7, #128

    str w0, [sp], #32
    str w1, [sp], #32
    str w2, [sp], #32
    str w3, [sp], #32

    sub sp, sp, #128

    ldaddal w5, w4, [sp]
    add sp, sp, #32
    ldadda w1, w1, [sp]
    add sp, sp, #32
    ldaddl w7, w6, [sp]
    add sp, sp, #32
    ldadd w3, w3, [sp]
  )");

  EXPECT_EQ(getGeneralRegister<uint32_t>(0), 16);
  EXPECT_EQ(getGeneralRegister<uint32_t>(1), 32);
  EXPECT_EQ(getGeneralRegister<uint32_t>(2), 48);
  EXPECT_EQ(getGeneralRegister<uint32_t>(3), 64);
  EXPECT_EQ(getGeneralRegister<uint32_t>(4), 16);
  EXPECT_EQ(getGeneralRegister<uint32_t>(5), 96);
  EXPECT_EQ(getGeneralRegister<uint32_t>(6), 48);
  EXPECT_EQ(getGeneralRegister<uint32_t>(7), 128);

  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getInitialStackPointer() - 1024),
            112);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getInitialStackPointer() - 992),
            64);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getInitialStackPointer() - 960),
            176);
  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getInitialStackPointer() - 928),
            128);

  // 64-bit
  RUN_AARCH64(R"(
    sub sp, sp, #1024
    mov x0, #16
    mov x1, #32
    mov x2, #48
    mov x3, #64
    mov x4, #80
    mov x5, #96
    mov x6, #112
    mov x7, #128

    str x0, [sp], #64
    str x1, [sp], #64
    str x2, [sp], #64
    str x3, [sp], #64

    sub sp, sp, #256

    ldaddal x5, x4, [sp]
    add sp, sp, #64
    ldadda x1, x1, [sp]
    add sp, sp, #64
    ldaddl x7, x6, [sp]
    add sp, sp, #64
    ldadd x3, x3, [sp]
  )");

  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 16);
  EXPECT_EQ(getGeneralRegister<uint64_t>(1), 32);
  EXPECT_EQ(getGeneralRegister<uint64_t>(2), 48);
  EXPECT_EQ(getGeneralRegister<uint64_t>(3), 64);
  EXPECT_EQ(getGeneralRegister<uint64_t>(4), 16);
  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 96);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 48);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 128);

  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialStackPointer() - 1024),
            112);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialStackPointer() - 960),
            64);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialStackPointer() - 896),
            176);
  EXPECT_EQ(getMemoryValue<uint64_t>(process_->getInitialStackPointer() - 832),
            128);
}

TEST_P(InstLoad, ldset) {
  // 32-bit
  RUN_AARCH64(R"(
    sub sp, sp, #1024
    mov w0, #16
    mov w1, #32
    mov w2, #48
    mov w3, #64
    mov w4, #10
    mov w5, #20
    mov w6, #30
    mov w7, #40

    str w0, [sp], #32
    str w1, [sp], #32
    str w2, [sp], #32
    str w3, [sp], #32

    sub sp, sp, #128

    ldseta w4, w4, [sp]
  )");

  EXPECT_EQ(getGeneralRegister<uint32_t>(0), 16);
  EXPECT_EQ(getGeneralRegister<uint32_t>(1), 32);
  EXPECT_EQ(getGeneralRegister<uint32_t>(2), 48);
  EXPECT_EQ(getGeneralRegister<uint32_t>(3), 64);
  EXPECT_EQ(getGeneralRegister<uint32_t>(4), 16);

  EXPECT_EQ(getMemoryValue<uint32_t>(process_->getInitialStackPointer() - 1024),
            26);
}

TEST_P(InstLoad, ldar) {
  initialHeapData_.resize(8);
  uint64_t* heap = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  heap[0] = 0xDEADBEEF12345678;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldar x1, [x0]
    ldar w2, [x0]
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(1), 0xDEADBEEF12345678);
  EXPECT_EQ(getGeneralRegister<uint32_t>(2), 0x12345678);
}

TEST_P(InstLoad, ldarb) {
  initialHeapData_.resize(8);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0xDEADBEEF;
  heap[1] = 0x12345678;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    ldarb w1, [x0]
    add x0, x0, #1
    ldarb w2, [x0]
    add x0, x0, #1
    ldarb w3, [x0]
    add x0, x0, #1
    ldarb w4, [x0]
    add x0, x0, #1
    ldarb w5, [x0]
    add x0, x0, #1
    ldarb w6, [x0]
    add x0, x0, #1
    ldarb w7, [x0]
    add x0, x0, #1
    ldarb w8, [x0]
  )");
  EXPECT_EQ(getGeneralRegister<uint32_t>(1), 0xEF);
  EXPECT_EQ(getGeneralRegister<uint32_t>(2), 0xBE);
  EXPECT_EQ(getGeneralRegister<uint32_t>(3), 0xAD);
  EXPECT_EQ(getGeneralRegister<uint32_t>(4), 0xDE);
  EXPECT_EQ(getGeneralRegister<uint32_t>(5), 0x78);
  EXPECT_EQ(getGeneralRegister<uint32_t>(6), 0x56);
  EXPECT_EQ(getGeneralRegister<uint32_t>(7), 0x34);
  EXPECT_EQ(getGeneralRegister<uint32_t>(8), 0x12);

  RUN_AARCH64(R"(
    sub sp, sp, #1024
    mov w0, #16
    mov w1, #32
    mov w2, #48
    mov w3, #64
    str w0, [sp], #32
    str w1, [sp], #32
    str w2, [sp], #32
    str w3, [sp], #32
    sub sp, sp, #128
    ldarb w4, [sp]
    add sp, sp, #32
    ldarb w5, [sp]
    add sp, sp, #32
    ldarb w6, [sp]
    add sp, sp, #32
    ldarb w7, [sp]
  )");

  EXPECT_EQ(getGeneralRegister<uint32_t>(4), 16);
  EXPECT_EQ(getGeneralRegister<uint32_t>(5), 32);
  EXPECT_EQ(getGeneralRegister<uint32_t>(6), 48);
  EXPECT_EQ(getGeneralRegister<uint32_t>(7), 64);
}

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

TEST_P(InstLoad, ldrd) {
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

    ldr d1, [x0], 8
    ldr d2, [x0]
    ldr d3, [x0, 8]!
    ldr d4, [x0, 8]

    mov w5, -8
    ldr d6, [x0, w5, sxtw]
    mov x5, 8
    ldr d7, [x0, x5]
    mov x5, 1
    ldr d8, [x0, x5, lsl 3]
  )");
  EXPECT_EQ((getVectorRegisterElement<double, 0>(1)), 1.0);
  EXPECT_EQ((getVectorRegisterElement<double, 0>(2)), 123.456);
  EXPECT_EQ((getVectorRegisterElement<double, 0>(3)), -0.00032);
  EXPECT_EQ((getVectorRegisterElement<double, 0>(4)), 123456);
  EXPECT_EQ((getVectorRegisterElement<double, 0>(6)), 123.456);
  EXPECT_EQ((getVectorRegisterElement<double, 0>(7)), 123456);
  EXPECT_EQ((getVectorRegisterElement<double, 0>(8)), 123456);
}

TEST_P(InstLoad, ldrh) {
  initialHeapData_.resize(8);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0xDEADBEEF;
  heap[1] = 0x12345678;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldrh w1, [x0], 2
    ldrh w2, [x0]
    ldrh w3, [x0, 2]!
    ldrh w4, [x0, 2]

    mov w5, -2
    ldrh w6, [x0, w5, sxtw]
    mov w5, 2
    ldrh w7, [x0, x5]
  )");
  EXPECT_EQ(getGeneralRegister<uint32_t>(1), 0xBEEF);
  EXPECT_EQ(getGeneralRegister<uint32_t>(2), 0xDEAD);
  EXPECT_EQ(getGeneralRegister<uint32_t>(3), 0x5678);
  EXPECT_EQ(getGeneralRegister<uint32_t>(4), 0x1234);
  EXPECT_EQ(getGeneralRegister<uint32_t>(6), 0xDEAD);
  EXPECT_EQ(getGeneralRegister<uint32_t>(7), 0x1234);
}

TEST_P(InstLoad, ldr_fp32) {
  initialHeapData_.resize(16);
  float* heap = reinterpret_cast<float*>(initialHeapData_.data());
  heap[0] = 128.5;
  heap[1] = -0.0625;
  heap[2] = -32;
  heap[3] = 0.125;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr s1, [x0], 4
    ldr s2, [x0]
    ldr s3, [x0, 4]!
    ldr s4, [x0, 4]

    mov w5, -4
    ldr s6, [x0, w5, sxtw]
    mov w5, 4
    ldr s7, [x0, x5]
  )");
  CHECK_NEON(1, float, {128.5f, 0.f, 0.f, 0.f});
  CHECK_NEON(2, float, {-0.0625f, 0.f, 0.f, 0.f});
  CHECK_NEON(3, float, {-32.f, 0.f, 0.f, 0.f});
  CHECK_NEON(4, float, {0.125f, 0.f, 0.f, 0.f});
  CHECK_NEON(6, float, {-0.0625f, 0.f, 0.f, 0.f});
  CHECK_NEON(7, float, {0.125f, 0.f, 0.f, 0.f});
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

TEST_P(InstLoad, ldrxrow) {
  initialHeapData_.resize(64);
  uint64_t* heap = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  heap[0] = -1;
  heap[1] = 0xDEADBEEF;
  heap[2] = 0x12345678;
  heap[3] = 0x98765432;
  heap[4] = 0xABCDEF12;
  heap[5] = 0xDEADBEEF;
  heap[6] = 0x12345678;
  heap[7] = 0x98765432;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov w9, 8
    mov w10, 2
    mov w11, -2
    mov x6, 96
    ldr x1, [x0, w9, uxtw #0]
    ldr x2, [x0, w10, uxtw #3]
    ldr x3, [x0, w9, sxtw #0]
    ldr x4, [x0, w10, sxtw #3]
    ldr x5, [x6, w11, sxtw #3]
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(1), 0xDEADBEEF);
  EXPECT_EQ(getGeneralRegister<uint64_t>(2), 0x12345678);
  EXPECT_EQ(getGeneralRegister<uint64_t>(3), 0xDEADBEEF);
  EXPECT_EQ(getGeneralRegister<uint64_t>(4), 0x12345678);
  EXPECT_EQ(getGeneralRegister<int64_t>(5), 0x12345678);
  // EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0x12345678);
}

TEST_P(InstLoad, ldrxrox) {
  initialHeapData_.resize(64);
  uint64_t* heap = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  heap[0] = -1;
  heap[1] = 0xDEADBEEF;
  heap[2] = 0x12345678;
  heap[3] = 0x98765432;
  heap[4] = 0xABCDEF12;
  heap[5] = 0xDEADBEEF;
  heap[6] = 0x12345678;
  heap[7] = 0x98765432;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x5, 8
    mov x6, 2
    ldr x1, [x0, x5]
    ldr x2, [x0, x6, lsl #3]
  )");
  EXPECT_EQ(getGeneralRegister<uint32_t>(1), 0xDEADBEEF);
  EXPECT_EQ(getGeneralRegister<uint32_t>(2), 0x12345678);
}

TEST_P(InstLoad, ldr_vector) {
  initialHeapData_.resize(48);
  double* heap = reinterpret_cast<double*>(initialHeapData_.data());
  heap[0] = 1.0;
  heap[1] = 123.456;
  heap[2] = -0.00032;
  heap[3] = 123456;
  heap[4] = -14;
  heap[5] = 2;

  // ldr 128-bit
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # Load values from heap
    ldr q0, [x0], #16
    ldr q1, [x0]
    ldr q2, [x0, #16]
  )");
  CHECK_NEON(0, double, {1.0, 123.456});
  CHECK_NEON(1, double, {-0.00032, 123456});
  CHECK_NEON(2, double, {-14, 2});

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
  CHECK_NEON(0, double, {1.0, 123.456});
  CHECK_NEON(1, double, {-0.00032, 123456});
}

TEST_P(InstLoad, ldur_neon) {
  initialHeapData_.resize(48);
  float* heap = reinterpret_cast<float*>(initialHeapData_.data());
  heap[0] = 1.0f;
  heap[1] = 123.456f;
  heap[2] = -0.00032f;
  heap[3] = 123456.0f;

  // ldur 32-bit
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # Load values from heap
    ldur s0, [x0]
    ldur s1, [x0, #4]
    add x0, x0, #12
    ldur s2, [x0]
    ldur s3, [x0, #-4]
  )");
  CHECK_NEON(0, float, {1.0f});
  CHECK_NEON(1, float, {123.456f});
  CHECK_NEON(2, float, {123456.0f});
  CHECK_NEON(3, float, {-0.00032f});
}

TEST_P(InstLoad, ldurh) {
  initialHeapData_.resize(16);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0xDEADBEEF;
  heap[1] = 0x12345678;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # Load values from heap
    ldurh w1, [x0]
    ldurh w2, [x0, #2]
    ldurh w3, [x0, #4]
  )");
  EXPECT_EQ(getGeneralRegister<uint32_t>(1), 0x0000BEEF);
  EXPECT_EQ(getGeneralRegister<uint32_t>(2), 0x0000DEAD);
  EXPECT_EQ(getGeneralRegister<uint32_t>(3), 0x00005678);
}

TEST_P(InstLoad, ldrw) {
  initialHeapData_.resize(16);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0xDEADBEEF;
  heap[1] = 0x12345678;
  heap[2] = 0x98765432;
  heap[3] = 0xABCDEF12;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldr w1, [x0], 4
    ldr w2, [x0]
    ldr w3, [x0, 4]!
    ldr w4, [x0, 4]

    mov w5, -4
    ldr w6, [x0, w5, sxtw]
    mov x5, 4
    mov x9, 1
    ldr w7, [x0, x5]
    ldr w8, [x0, x9, lsl #2]
  )");
  EXPECT_EQ(getGeneralRegister<uint32_t>(1), 0xDEADBEEF);
  EXPECT_EQ(getGeneralRegister<uint32_t>(2), 0x12345678);
  EXPECT_EQ(getGeneralRegister<uint32_t>(3), 0x98765432);
  EXPECT_EQ(getGeneralRegister<uint32_t>(4), 0xABCDEF12);
  EXPECT_EQ(getGeneralRegister<uint32_t>(6), 0x12345678);
  EXPECT_EQ(getGeneralRegister<uint32_t>(7), 0xABCDEF12);
  EXPECT_EQ(getGeneralRegister<uint32_t>(8), 0xABCDEF12);
}

TEST_P(InstLoad, ldpsw) {
  // 32-bit signed integer
  initialHeapData_.resize(16);
  uint32_t* heapi32 = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heapi32[0] = 0xDEADBEEF;
  heapi32[1] = 0x12345678;
  heapi32[2] = 0x98765432;
  heapi32[3] = 0xABCDEF12;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # Load values from heap
    ldpsw x1, x2, [x0]
    ldpsw x3, x4, [x0, #8]
    add x0, x0, #8
    ldpsw x5, x6, [x0, #-8]
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(1), 0x00000000DEADBEEF);
  EXPECT_EQ(getGeneralRegister<int64_t>(2), 0x0000000012345678);
  EXPECT_EQ(getGeneralRegister<int64_t>(3), 0x0000000098765432);
  EXPECT_EQ(getGeneralRegister<int64_t>(4), 0x00000000ABCDEF12);
  EXPECT_EQ(getGeneralRegister<int64_t>(5), 0x00000000DEADBEEF);
  EXPECT_EQ(getGeneralRegister<int64_t>(6), 0x0000000012345678);
}

TEST_P(InstLoad, ldp) {
  // 32-bit integer
  initialHeapData_.resize(16);
  uint32_t* heapi32 = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heapi32[0] = 0xDEADBEEF;
  heapi32[1] = 0x12345678;
  heapi32[2] = 0x98765432;
  heapi32[3] = 0xABCDEF12;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # Load values from heap
    ldp w1, w2, [x0]
    ldp w3, w4, [x0, #8]
  )");
  EXPECT_EQ((getGeneralRegister<uint32_t>(1)), 0xDEADBEEF);
  EXPECT_EQ((getGeneralRegister<uint32_t>(2)), 0x12345678);
  EXPECT_EQ((getGeneralRegister<uint32_t>(3)), 0x98765432);
  EXPECT_EQ((getGeneralRegister<uint32_t>(4)), 0xABCDEF12);

  // 64-bit integer
  initialHeapData_.resize(64);
  uint64_t* heapi64 = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  heapi64[0] = UINT64_C(0xDEADBEEF) << 32;
  heapi64[1] = UINT64_C(0x12345678) << 16;
  heapi64[2] = UINT64_C(0x98765432) << 8;
  heapi64[3] = UINT64_C(0xABCDEF12) << 4;
  heapi64[4] = UINT64_C(0xDEADBEEF) << 4;
  heapi64[5] = UINT64_C(0x12345678) << 8;
  heapi64[6] = UINT64_C(0x98765432) << 16;
  heapi64[7] = UINT64_C(0xABCDEF12) << 32;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # Load values from heap
    ldp x1, x2, [x0], 16
    ldp x3, x4, [x0]
    ldp x5, x6, [x0, 16]!
    ldp x7, x8, [x0, 16]
  )");
  EXPECT_EQ((getGeneralRegister<uint64_t>(1)), 0xDEADBEEFull << 32);
  EXPECT_EQ((getGeneralRegister<uint64_t>(2)), 0x12345678ull << 16);
  EXPECT_EQ((getGeneralRegister<uint64_t>(3)), 0x98765432ull << 8);
  EXPECT_EQ((getGeneralRegister<uint64_t>(4)), 0xABCDEF12ull << 4);
  EXPECT_EQ((getGeneralRegister<uint64_t>(5)), 0xDEADBEEFull << 4);
  EXPECT_EQ((getGeneralRegister<uint64_t>(6)), 0x12345678ull << 8);
  EXPECT_EQ((getGeneralRegister<uint64_t>(7)), 0x98765432ull << 16);
  EXPECT_EQ((getGeneralRegister<uint64_t>(8)), 0xABCDEF12ull << 32);

  // FP32
  initialHeapData_.resize(16);
  float* heap32 = reinterpret_cast<float*>(initialHeapData_.data());
  heap32[0] = 1.0;
  heap32[1] = 128.5;
  heap32[2] = -0.0625;
  heap32[3] = 123456;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # Load values from heap
    ldp s0, s1, [x0]
    ldp s2, s3, [x0, #8]
  )");
  CHECK_NEON(0, float, {1.f, 0.f, 0.f, 0.f});
  CHECK_NEON(1, float, {128.5f, 0.f, 0.f, 0.f});
  CHECK_NEON(2, float, {-0.0625f, 0.f, 0.f, 0.f});
  CHECK_NEON(3, float, {123456.f, 0.f, 0.f, 0.f});

  // FP64
  initialHeapData_.resize(64);
  double* heap64 = reinterpret_cast<double*>(initialHeapData_.data());
  heap64[0] = 1.0;
  heap64[1] = 123.456;
  heap64[2] = -0.00032;
  heap64[3] = 123456;
  heap64[4] = 2.0;
  heap64[5] = -0.125;
  heap64[6] = 7.5;
  heap64[7] = 16.0;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # Load values from heap
    ldp d0, d1, [x0], #16
    ldp d2, d3, [x0]
    ldp d4, d5, [x0, #16]!
    ldp d6, d7, [x0, #16]
  )");

  CHECK_NEON(0, double, {1.0, 0.0});
  CHECK_NEON(1, double, {123.456, 0.0});
  CHECK_NEON(2, double, {-0.00032, 0.0});
  CHECK_NEON(3, double, {123456.0, 0.0});
  CHECK_NEON(4, double, {2.0, 0.0});
  CHECK_NEON(5, double, {-0.125, 0.0});
  CHECK_NEON(6, double, {7.5, 0.0});
  CHECK_NEON(7, double, {16.0, 0.0});

  // 128-bit
  initialHeapData_.resize(80);
  heapi64 = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  heapi64[0] = UINT64_C(0xDEADBEEF) << 32;
  heapi64[1] = UINT64_C(0x12345678) << 16;
  heapi64[2] = UINT64_C(0x98765432) << 8;
  heapi64[3] = UINT64_C(0xABCDEF12) << 4;
  heapi64[4] = UINT64_C(0xDEADBEEF) << 4;
  heapi64[5] = UINT64_C(0x12345678) << 8;
  heapi64[6] = UINT64_C(0x98765432) << 16;
  heapi64[7] = UINT64_C(0xABCDEF12) << 32;
  heapi64[8] = UINT64_C(0xDEADBEEF) << 40;
  heapi64[9] = UINT64_C(0x12345678) << 48;
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    # Load values from heap
    ldp q0, q1, [x0], 16
    ldp q2, q3, [x0]
    ldp q4, q5, [x0, 16]!
    ldp q6, q7, [x0, 16]
  )");
  CHECK_NEON(0, uint64_t, {(0xDEADBEEFull << 32), (0x12345678ull << 16)});
  CHECK_NEON(1, uint64_t, {(0x98765432ull << 8), (0xABCDEF12ull << 4)});
  CHECK_NEON(2, uint64_t, {(0x98765432ull << 8), (0xABCDEF12ull << 4)});
  CHECK_NEON(3, uint64_t, {(0xDEADBEEFull << 4), (0x12345678ull << 8)});
  CHECK_NEON(4, uint64_t, {(0xDEADBEEFull << 4), (0x12345678ull << 8)});
  CHECK_NEON(5, uint64_t, {(0x98765432ull << 16), (0xABCDEF12ull << 32)});
  CHECK_NEON(6, uint64_t, {(0x98765432ull << 16), (0xABCDEF12ull << 32)});
  CHECK_NEON(7, uint64_t, {(0xDEADBEEFull << 40), (0x12345678ull << 48)});
}

TEST_P(InstLoad, ldrsb) {
  initialHeapData_.resize(4);
  int8_t* heap = reinterpret_cast<int8_t*>(initialHeapData_.data());
  heap[0] = -2;
  heap[1] = INT8_MAX;
  heap[2] = -5;
  heap[3] = 64;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x5, 1
    # Load 8-bit values from heap and sign-extend to 32-bits
    ldrsb w1, [x0, x5, sxtx]

    # Load 8-bit values from heap and sign-extend to 64-bits
    ldrsb x2, [x0]
    ldrsb x3, [x0, #3]
  )");
  EXPECT_EQ(getGeneralRegister<int32_t>(1), INT8_MAX);
  EXPECT_EQ(getGeneralRegister<int64_t>(2), -2);
  EXPECT_EQ(getGeneralRegister<int64_t>(3), 64);
}

TEST_P(InstLoad, ldrsh) {
  initialHeapData_.resize(8);
  int16_t* heap = reinterpret_cast<int16_t*>(initialHeapData_.data());
  heap[0] = -2;
  heap[1] = INT16_MAX;
  heap[2] = -5;
  heap[3] = 256;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    mov x5, 1
    # Load 16-bit values from heap and sign-extend to 32-bits
    ldrsh w1, [x0]
    ldrsh w2, [x0, x5, lsl #1]

    mov w5, 4
    mov x6, 6
    # Load 16-bit values from heap and sign-extend to 64-bits
    ldrsh x3, [x0, w5, sxtw]
    ldrsh x4, [x0, x6, sxtx]
  )");
  EXPECT_EQ(getGeneralRegister<int32_t>(1), -2);
  EXPECT_EQ(getGeneralRegister<int32_t>(2), INT16_MAX);
  EXPECT_EQ(getGeneralRegister<int64_t>(3), -5);
  EXPECT_EQ(getGeneralRegister<int64_t>(4), 256);
}

TEST_P(InstLoad, ldrsw) {
  initialHeapData_.resize(16);
  int32_t* heap = reinterpret_cast<int32_t*>(initialHeapData_.data());
  heap[0] = -2;
  heap[1] = INT32_MAX;
  heap[2] = -5;
  heap[3] = 256;

  // ldrsw
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    mov x6, 1
    mov w7, 2
    # Load 32-bit values from heap and sign-extend to 64-bits
    ldrsw x1, [x0, #4]
    ldrsw x2, [x0], #4
    ldrsw x3, [x0]
    ldrsw x4, [x0, x6, lsl #2]
    ldrsw x5, [x0, w7, sxtw #2]
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(1), INT32_MAX);
  EXPECT_EQ(getGeneralRegister<int64_t>(2), -2);
  EXPECT_EQ(getGeneralRegister<int64_t>(3), INT32_MAX);
  EXPECT_EQ(getGeneralRegister<int64_t>(4), -5);
  EXPECT_EQ(getGeneralRegister<int64_t>(5), 256);

  // ldursw
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    # Load 32-bit values from heap and sign-extend to 64-bits
    ldursw x1, [x0]
    ldursw x2, [x0, #4]
    ldursw x3, [x0, #8]
    ldursw x4, [x0, #12]
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(1), -2);
  EXPECT_EQ(getGeneralRegister<int64_t>(2), INT32_MAX);
  EXPECT_EQ(getGeneralRegister<int64_t>(3), -5);
  EXPECT_EQ(getGeneralRegister<int64_t>(4), 256);
}

TEST_P(InstLoad, ldaxr) {
  initialHeapData_.resize(8);
  uint64_t* heap = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  heap[0] = 0xFEDCBA987654321;

  // 8-bit
  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0

    ldaxrb w1, [x0]
    ldaxrh w2, [x0]
    ldaxr w3, [x0]
    ldaxr x4, [x0]
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(1), 0x000000000000021);
  EXPECT_EQ(getGeneralRegister<uint64_t>(2), 0x000000000004321);
  EXPECT_EQ(getGeneralRegister<uint64_t>(3), 0x000000087654321);
  EXPECT_EQ(getGeneralRegister<uint64_t>(4), 0xFEDCBA987654321);
}

TEST_P(InstLoad, ldxr) {
  // 32-bit
  initialHeapData_.resize(16);
  uint32_t* heap32 = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap32[0] = -2;
  heap32[1] = INT32_MAX;
  heap32[2] = -5;
  heap32[3] = 256;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    mov x5, 1

    ldxr x1, [x0]
    add x0, x0, 4
    ldxr x2, [x0]
    add x0, x0, 4
    ldxr x3, [x0]
    add x0, x0, 4
    ldxr x4, [x0]
  )");
  EXPECT_EQ(getGeneralRegister<uint32_t>(1), -2);
  EXPECT_EQ(getGeneralRegister<uint32_t>(2), INT32_MAX);
  EXPECT_EQ(getGeneralRegister<uint32_t>(3), -5);
  EXPECT_EQ(getGeneralRegister<uint32_t>(4), 256);

  // 64-bit
  initialHeapData_.resize(32);
  uint64_t* heap64 = reinterpret_cast<uint64_t*>(initialHeapData_.data());
  heap64[0] = -4;
  heap64[1] = INT64_MAX;
  heap64[2] = -10;
  heap64[3] = 512;

  RUN_AARCH64(R"(
    # Get heap address
    mov x0, 0
    mov x8, 214
    svc #0
    mov x5, 1

    ldxr x1, [x0]
    add x0, x0, 8
    ldxr x2, [x0]
    add x0, x0, 8
    ldxr x3, [x0]
    add x0, x0, 8
    ldxr x4, [x0]
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(1), -4);
  EXPECT_EQ(getGeneralRegister<uint64_t>(2), INT64_MAX);
  EXPECT_EQ(getGeneralRegister<uint64_t>(3), -10);
  EXPECT_EQ(getGeneralRegister<uint64_t>(4), 512);
}

INSTANTIATE_TEST_SUITE_P(AArch64, InstLoad,
                         ::testing::Values(std::make_tuple(EMULATION, "{}")),
                         paramToString);

}  // namespace
