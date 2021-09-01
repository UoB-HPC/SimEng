#include "RISCVRegressionTest.hh"

namespace {

using InstAtomic = RISCVRegressionTest;

TEST_P(InstAtomic, lr) {
  initialHeapData_.resize(16);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0xDEADBEEF;
  heap[1] = 0x12345678;
  heap[2] = 0xFEEBDAED;
  heap[3] = 0x87654321;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    lr.w t6, (a0)
    addi a0, a0, 4
    lr.w t5, (a0)

  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 0xFFFFFFFFDEADBEEF);
  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0x012345678);

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    lr.w.aq t6, (a0)
    addi a0, a0, 4
    lr.w.aq t5, (a0)

  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 0xFFFFFFFFDEADBEEF);
  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0x012345678);

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    lr.w.aqrl t6, (a0)
    addi a0, a0, 4
    lr.w.aqrl t5, (a0)

  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 0xFFFFFFFFDEADBEEF);
  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0x012345678);

  // Software should not set only the RL bit, but this is not guaranteed
  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    lr.w.rl t6, (a0)
    addi a0, a0, 4
    lr.w.rl t5, (a0)

  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 0xFFFFFFFFDEADBEEF);
  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0x012345678);

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    lr.d t6, (a0)
    addi a0, a0, 4
    lr.d t5, (a0)

  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 0x12345678DEADBEEF);
  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0xFEEBDAED12345678);

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    lr.d.aq t6, (a0)
    addi a0, a0, 4
    lr.d.aq t5, (a0)

  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 0x12345678DEADBEEF);
  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0xFEEBDAED12345678);

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    lr.d.aqrl t6, (a0)
    addi a0, a0, 4
    lr.d.aqrl t5, (a0)

  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 0x12345678DEADBEEF);
  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0xFEEBDAED12345678);

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    lr.d.rl t6, (a0)
    addi a0, a0, 4
    lr.d.rl t5, (a0)

  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 0x12345678DEADBEEF);
  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0xFEEBDAED12345678);
}

TEST_P(InstAtomic, sc_w) {
  initialHeapData_.resize(16);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0xDEADBEEF;
  heap[1] = 0x12345678;
  heap[2] = 0xFEEBDAED;
  heap[3] = 0x87654321;
  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    li t5, 15
    li t6, 987

    sc.w t5, t6, (a0)
  )");

  auto heapStart = process_->getHeapStart();

  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 987);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart), 987);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 4), 0x12345678);
}

TEST_P(InstAtomic, sc_w_aq) {
  // Software should not set only the AQ bit, but this is not guaranteed

  initialHeapData_.resize(16);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0xDEADBEEF;
  heap[1] = 0x12345678;
  heap[2] = 0xFEEBDAED;
  heap[3] = 0x87654321;
  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    li t5, 15
    li t6, 987

    sc.w.aq t5, t6, (a0)
  )");

  auto heapStart = process_->getHeapStart();

  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 987);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart), 987);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 4), 0x12345678);
}

TEST_P(InstAtomic, sc_w_rl) {
  initialHeapData_.resize(16);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0xDEADBEEF;
  heap[1] = 0x12345678;
  heap[2] = 0xFEEBDAED;
  heap[3] = 0x87654321;
  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    li t5, 15
    li t6, 987

    sc.w.rl t5, t6, (a0)
  )");

  auto heapStart = process_->getHeapStart();

  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 987);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart), 987);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 4), 0x12345678);
}

TEST_P(InstAtomic, sc_w_aq_rl) {
  initialHeapData_.resize(16);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0xDEADBEEF;
  heap[1] = 0x12345678;
  heap[2] = 0xFEEBDAED;
  heap[3] = 0x87654321;
  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    li t5, 15
    li t6, 987

    sc.w.aqrl t5, t6, (a0)
  )");

  auto heapStart = process_->getHeapStart();

  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 987);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart), 987);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 4), 0x12345678);
}

TEST_P(InstAtomic, sc_d) {
  initialHeapData_.resize(16);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0xDEADBEEF;
  heap[1] = 0x12345678;
  heap[2] = 0xFEEBDAED;
  heap[3] = 0x87654321;
  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    li t5, 987
    lui t6, 0x12365
    slli t6, t6, 32
    addi t6, t6, 0x1EF

    addi a0, a0, 2

    sc.d t5, t6, (a0)
  )");

  auto heapStart = process_->getHeapStart();

  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 0x12365000000001EF);
  EXPECT_EQ(getMemoryValue<uint64_t>(heapStart), 0x5000000001EFBEEF);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 8), 0xFEEB1236);
}

TEST_P(InstAtomic, sc_d_aq) {
  initialHeapData_.resize(16);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0xDEADBEEF;
  heap[1] = 0x12345678;
  heap[2] = 0xFEEBDAED;
  heap[3] = 0x87654321;
  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    li t5, 987
    lui t6, 0x12365
    slli t6, t6, 32
    addi t6, t6, 0x1EF

    addi a0, a0, 2

    sc.d.aq t5, t6, (a0)
  )");

  auto heapStart = process_->getHeapStart();

  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 0x12365000000001EF);
  EXPECT_EQ(getMemoryValue<uint64_t>(heapStart), 0x5000000001EFBEEF);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 8), 0xFEEB1236);
}

TEST_P(InstAtomic, sc_d_rl) {
  initialHeapData_.resize(16);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0xDEADBEEF;
  heap[1] = 0x12345678;
  heap[2] = 0xFEEBDAED;
  heap[3] = 0x87654321;
  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    li t5, 987
    lui t6, 0x12365
    slli t6, t6, 32
    addi t6, t6, 0x1EF

    addi a0, a0, 2

    sc.d.rl t5, t6, (a0)
  )");

  auto heapStart = process_->getHeapStart();

  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 0x12365000000001EF);
  EXPECT_EQ(getMemoryValue<uint64_t>(heapStart), 0x5000000001EFBEEF);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 8), 0xFEEB1236);
}

TEST_P(InstAtomic, sc_d_aq_rl) {
  initialHeapData_.resize(16);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0xDEADBEEF;
  heap[1] = 0x12345678;
  heap[2] = 0xFEEBDAED;
  heap[3] = 0x87654321;
  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    li t5, 987
    lui t6, 0x12365
    slli t6, t6, 32
    addi t6, t6, 0x1EF

    addi a0, a0, 2

    sc.d.aqrl t5, t6, (a0)
  )");

  auto heapStart = process_->getHeapStart();

  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 0x12365000000001EF);
  EXPECT_EQ(getMemoryValue<uint64_t>(heapStart), 0x5000000001EFBEEF);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 8), 0xFEEB1236);
}

TEST_P(InstAtomic, amoswap_w) {
  initialHeapData_.resize(16);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0xDEADBEEF;
  heap[1] = 0x12345678;
  heap[2] = 0xFEEBDAED;
  heap[3] = 0x77654321;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    li t0, 21
    li t1, 84

    amoswap.w t0, t1, (a0)

    li t5, 34
    li t6, 987
    addi a0, a0, 12

    amoswap.w t5, t6, (a0)
  )");

  auto heapStart = process_->getHeapStart();

  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0xFFFFFFFFDEADBEEF);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 84);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart), 84);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 4), 0x12345678);

  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0x0000000077654321);
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 987);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 8), 0xFEEBDAED);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 12), 987);
}

TEST_P(InstAtomic, amoswap_w_aq) {
  initialHeapData_.resize(16);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0xDEADBEEF;
  heap[1] = 0x12345678;
  heap[2] = 0xFEEBDAED;
  heap[3] = 0x77654321;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    li t0, 21
    li t1, 84

    amoswap.w.aq t0, t1, (a0)

    li t5, 34
    li t6, 987
    addi a0, a0, 12

    amoswap.w.aq t5, t6, (a0)
  )");

  auto heapStart = process_->getHeapStart();

  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0xFFFFFFFFDEADBEEF);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 84);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart), 84);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 4), 0x12345678);

  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0x0000000077654321);
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 987);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 8), 0xFEEBDAED);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 12), 987);
}

TEST_P(InstAtomic, amoswap_w_rl) {
  initialHeapData_.resize(16);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0xDEADBEEF;
  heap[1] = 0x12345678;
  heap[2] = 0xFEEBDAED;
  heap[3] = 0x77654321;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    li t0, 21
    li t1, 84

    amoswap.w.rl t0, t1, (a0)

    li t5, 34
    li t6, 987
    addi a0, a0, 12

    amoswap.w.rl t5, t6, (a0)
  )");

  auto heapStart = process_->getHeapStart();

  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0xFFFFFFFFDEADBEEF);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 84);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart), 84);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 4), 0x12345678);

  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0x0000000077654321);
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 987);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 8), 0xFEEBDAED);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 12), 987);
}

TEST_P(InstAtomic, amoswap_w_aq_rl) {
  initialHeapData_.resize(16);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0xDEADBEEF;
  heap[1] = 0x12345678;
  heap[2] = 0xFEEBDAED;
  heap[3] = 0x77654321;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    li t0, 21
    li t1, 84

    amoswap.w.aqrl t0, t1, (a0)

    li t5, 34
    li t6, 987
    addi a0, a0, 12

    amoswap.w.aqrl t5, t6, (a0)
  )");

  auto heapStart = process_->getHeapStart();

  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0xFFFFFFFFDEADBEEF);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 84);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart), 84);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 4), 0x12345678);

  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0x0000000077654321);
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 987);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 8), 0xFEEBDAED);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 12), 987);
}

TEST_P(InstAtomic, amoswap_d) {
  initialHeapData_.resize(24);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0xDEADBEEF;
  heap[1] = 0x12345678;
  heap[2] = 0xFEEBDAED;
  heap[3] = 0x77654321;
  heap[4] = 0x12365478;
  heap[5] = 0xFFEEFFEE;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    li t0, 21
    li t1, 84

    amoswap.d t0, t1, (a0)

    li t5, 34
    lui t6, 0x80000
    slli t6, t6, 32
    addi t6, t6, 987
    addi a0, a0, 12

    amoswap.d t5, t6, (a0)
  )");

  auto heapStart = process_->getHeapStart();

  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0x12345678DEADBEEF);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 84);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart), 84);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 4), 0x00000000);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 8), 0xFEEBDAED);

  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0x1236547877654321);
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 0x80000000000003DB);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 8), 0xFEEBDAED);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 12), 0x000003DB);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 16), 0x80000000);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 20), 0xFFEEFFEE);
}

TEST_P(InstAtomic, amoswap_d_aq) {
  initialHeapData_.resize(24);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0xDEADBEEF;
  heap[1] = 0x12345678;
  heap[2] = 0xFEEBDAED;
  heap[3] = 0x77654321;
  heap[4] = 0x12365478;
  heap[5] = 0xFFEEFFEE;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    li t0, 21
    li t1, 84

    amoswap.d.aq t0, t1, (a0)

    li t5, 34
    lui t6, 0x80000
    slli t6, t6, 32
    addi t6, t6, 987
    addi a0, a0, 12

    amoswap.d.aq t5, t6, (a0)
  )");

  auto heapStart = process_->getHeapStart();

  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0x12345678DEADBEEF);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 84);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart), 84);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 4), 0x00000000);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 8), 0xFEEBDAED);

  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0x1236547877654321);
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 0x80000000000003DB);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 8), 0xFEEBDAED);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 12), 0x000003DB);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 16), 0x80000000);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 20), 0xFFEEFFEE);
}

TEST_P(InstAtomic, amoswap_d_rl) {
  initialHeapData_.resize(24);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0xDEADBEEF;
  heap[1] = 0x12345678;
  heap[2] = 0xFEEBDAED;
  heap[3] = 0x77654321;
  heap[4] = 0x12365478;
  heap[5] = 0xFFEEFFEE;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    li t0, 21
    li t1, 84

    amoswap.d.rl t0, t1, (a0)

    li t5, 34
    lui t6, 0x80000
    slli t6, t6, 32
    addi t6, t6, 987
    addi a0, a0, 12

    amoswap.d.rl t5, t6, (a0)
  )");

  auto heapStart = process_->getHeapStart();

  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0x12345678DEADBEEF);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 84);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart), 84);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 4), 0x00000000);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 8), 0xFEEBDAED);

  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0x1236547877654321);
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 0x80000000000003DB);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 8), 0xFEEBDAED);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 12), 0x000003DB);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 16), 0x80000000);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 20), 0xFFEEFFEE);
}

TEST_P(InstAtomic, amoswap_d_aq_rl) {
  initialHeapData_.resize(24);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0xDEADBEEF;
  heap[1] = 0x12345678;
  heap[2] = 0xFEEBDAED;
  heap[3] = 0x77654321;
  heap[4] = 0x12365478;
  heap[5] = 0xFFEEFFEE;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    li t0, 21
    li t1, 84

    amoswap.d.aqrl t0, t1, (a0)

    li t5, 34
    lui t6, 0x80000
    slli t6, t6, 32
    addi t6, t6, 987
    addi a0, a0, 12

    amoswap.d.aqrl t5, t6, (a0)
  )");

  auto heapStart = process_->getHeapStart();

  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0x12345678DEADBEEF);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 84);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart), 84);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 4), 0x00000000);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 8), 0xFEEBDAED);

  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0x1236547877654321);
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 0x80000000000003DB);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 8), 0xFEEBDAED);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 12), 0x000003DB);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 16), 0x80000000);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 20), 0xFFEEFFEE);
}

TEST_P(InstAtomic, amoadd_w) {
  initialHeapData_.resize(24);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0xDEADBEEF;
  heap[1] = 0x12345678;
  heap[2] = 0xFEEBDAED;
  heap[3] = 0x7FFFFFFF;
  heap[4] = 0x12365478;
  heap[5] = 0xFFFFFFFF;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    li t0, 21
    li t1, 84

    amoadd.w t1, t0, (a0)

    li t5, 34
    lui t6, 0x80000
    slli t6, t6, 32
    addi t6, t6, 987
    addi a0, a0, 12

    amoadd.w t5, t6, (a0)
  )");

  auto heapStart = process_->getHeapStart();

  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 21);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0xFFFFFFFFDEADBEEF);
  EXPECT_EQ(getMemoryValue<uint64_t>(heapStart), 0x12345678DEADBF04);

  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0x7FFFFFFF);
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 0x80000000000003DB);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 8), 0xFEEBDAED);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 12),
            0x800003DA);  // +ve + +ve = -ve as per GDB
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 16), 0x12365478);
}

TEST_P(InstAtomic, amoadd_w_aq) {
  initialHeapData_.resize(24);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0xDEADBEEF;
  heap[1] = 0x12345678;
  heap[2] = 0xFEEBDAED;
  heap[3] = 0x7FFFFFFF;
  heap[4] = 0x12365478;
  heap[5] = 0xFFFFFFFF;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    li t0, 21
    li t1, 84

    amoadd.w.aq t1, t0, (a0)

    li t5, 34
    lui t6, 0x80000
    slli t6, t6, 32
    addi t6, t6, 987
    addi a0, a0, 12

    amoadd.w.aq t5, t6, (a0)
  )");

  auto heapStart = process_->getHeapStart();

  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 21);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0xFFFFFFFFDEADBEEF);
  EXPECT_EQ(getMemoryValue<uint64_t>(heapStart), 0x12345678DEADBF04);

  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0x7FFFFFFF);
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 0x80000000000003DB);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 8), 0xFEEBDAED);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 12),
            0x800003DA);  // +ve + +ve = -ve as per GDB
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 16), 0x12365478);
}

TEST_P(InstAtomic, amoadd_w_rl) {
  initialHeapData_.resize(24);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0xDEADBEEF;
  heap[1] = 0x12345678;
  heap[2] = 0xFEEBDAED;
  heap[3] = 0x7FFFFFFF;
  heap[4] = 0x12365478;
  heap[5] = 0xFFFFFFFF;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    li t0, 21
    li t1, 84

    amoadd.w.rl t1, t0, (a0)

    li t5, 34
    lui t6, 0x80000
    slli t6, t6, 32
    addi t6, t6, 987
    addi a0, a0, 12

    amoadd.w.rl t5, t6, (a0)
  )");

  auto heapStart = process_->getHeapStart();

  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 21);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0xFFFFFFFFDEADBEEF);
  EXPECT_EQ(getMemoryValue<uint64_t>(heapStart), 0x12345678DEADBF04);

  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0x7FFFFFFF);
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 0x80000000000003DB);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 8), 0xFEEBDAED);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 12),
            0x800003DA);  // +ve + +ve = -ve as per GDB
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 16), 0x12365478);
}

TEST_P(InstAtomic, amoadd_w_aq_rl) {
  initialHeapData_.resize(24);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0xDEADBEEF;
  heap[1] = 0x12345678;
  heap[2] = 0xFEEBDAED;
  heap[3] = 0x7FFFFFFF;
  heap[4] = 0x12365478;
  heap[5] = 0xFFFFFFFF;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    li t0, 21
    li t1, 84

    amoadd.w.aqrl t1, t0, (a0)

    li t5, 34
    lui t6, 0x80000
    slli t6, t6, 32
    addi t6, t6, 987
    addi a0, a0, 12

    amoadd.w.aqrl t5, t6, (a0)
  )");

  auto heapStart = process_->getHeapStart();

  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 21);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0xFFFFFFFFDEADBEEF);
  EXPECT_EQ(getMemoryValue<uint64_t>(heapStart), 0x12345678DEADBF04);

  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0x7FFFFFFF);
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 0x80000000000003DB);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 8), 0xFEEBDAED);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 12),
            0x800003DA);  // +ve + +ve = -ve as per GDB
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 16), 0x12365478);
}

// TODO add aq rl tests for all instructions below, ommited as currenlty
// they have the same functionality

TEST_P(InstAtomic, amoadd_d) {
  initialHeapData_.resize(24);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0xDEADBEEF;
  heap[1] = 0x12345678;
  heap[2] = 0xFEEBDAED;
  heap[3] = 0xFFFFFFFF;
  heap[4] = 0x7FFFFFFF;
  heap[5] = 0x12365478;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    li t0, 21
    li t1, 84

    amoadd.d t1, t0, (a0)

    li t5, 34
    li t6, 987
    addi a0, a0, 12

    amoadd.d t5, t6, (a0)
  )");

  auto heapStart = process_->getHeapStart();

  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 21);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0x12345678DEADBEEF);
  EXPECT_EQ(getMemoryValue<uint64_t>(heapStart), 0x12345678DEADBF04);

  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0x7FFFFFFFFFFFFFFF);
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 0x00000000000003DB);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 8), 0xFEEBDAED);
  EXPECT_EQ(getMemoryValue<uint64_t>(heapStart + 12),
            0x80000000000003DA);  // +ve + +ve = -ve as per GDB
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 20),
            0x12365478);  // +ve + +ve = -ve as per GDB
}

TEST_P(InstAtomic, amoand_w) {
  initialHeapData_.resize(24);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0xB3333333;
  heap[1] = 0x12345678;
  heap[2] = 0xFEEBDAED;
  heap[3] = 0xFFFFFFFF;
  heap[4] = 0x7FFFFFFF;
  heap[5] = 0x12365478;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    li t0, 0x5555555555555555   # 0b0101 ...
    li t1, 84

    amoand.w t1, t0, (a0)
  )");

  auto heapStart = process_->getHeapStart();

  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0x5555555555555555);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0xFFFFFFFFB3333333);
  EXPECT_EQ(getMemoryValue<uint64_t>(heapStart), 0x1234567811111111);  // 0b0001
}

TEST_P(InstAtomic, amoand_d) {
  initialHeapData_.resize(24);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0x33333333;
  heap[1] = 0x33333333;
  heap[2] = 0xFEEBDAED;
  heap[3] = 0xFFFFFFFF;
  heap[4] = 0x7FFFFFFF;
  heap[5] = 0x12365478;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    li t0, 0x5555555555555555   # 0b0101 ...
    li t1, 84

    amoand.d t1, t0, (a0)
  )");

  auto heapStart = process_->getHeapStart();

  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0x5555555555555555);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0x3333333333333333);
  EXPECT_EQ(getMemoryValue<uint64_t>(heapStart), 0x1111111111111111);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 8), 0xFEEBDAED);
}

TEST_P(InstAtomic, amoor_w) {
  initialHeapData_.resize(24);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0xB3333333;
  heap[1] = 0x12345678;
  heap[2] = 0xFEEBDAED;
  heap[3] = 0xFFFFFFFF;
  heap[4] = 0x7FFFFFFF;
  heap[5] = 0x12365478;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    li t0, 0x5555555555555555   # 0b0101 ...
    li t1, 84

    amoor.w t1, t0, (a0)
  )");

  auto heapStart = process_->getHeapStart();

  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0x5555555555555555);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0xFFFFFFFFB3333333);
  EXPECT_EQ(getMemoryValue<uint64_t>(heapStart), 0x12345678F7777777);  // 0b0111
}

TEST_P(InstAtomic, amoor_d) {
  initialHeapData_.resize(24);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0x33333333;
  heap[1] = 0x33333333;
  heap[2] = 0xFEEBDAED;
  heap[3] = 0xFFFFFFFF;
  heap[4] = 0x7FFFFFFF;
  heap[5] = 0x12365478;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    li t0, 0x5555555555555555   # 0b0101 ...
    li t1, 84

    amoor.d t1, t0, (a0)
  )");

  auto heapStart = process_->getHeapStart();

  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0x5555555555555555);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0x3333333333333333);
  EXPECT_EQ(getMemoryValue<uint64_t>(heapStart), 0x7777777777777777);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 8), 0xFEEBDAED);
}

TEST_P(InstAtomic, amoxor_w) {
  initialHeapData_.resize(24);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0xB3333333;
  heap[1] = 0x12345678;
  heap[2] = 0xFEEBDAED;
  heap[3] = 0xFFFFFFFF;
  heap[4] = 0x7FFFFFFF;
  heap[5] = 0x12365478;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    li t0, 0x5555555555555555   # 0b0101 ...
    li t1, 84

    amoxor.w t1, t0, (a0)
  )");

  auto heapStart = process_->getHeapStart();

  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0x5555555555555555);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0xFFFFFFFFB3333333);
  EXPECT_EQ(getMemoryValue<uint64_t>(heapStart), 0x12345678E6666666);  // 0b0110
}

TEST_P(InstAtomic, amoxor_d) {
  initialHeapData_.resize(24);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0x33333333;
  heap[1] = 0x33333333;
  heap[2] = 0xFEEBDAED;
  heap[3] = 0xFFFFFFFF;
  heap[4] = 0x7FFFFFFF;
  heap[5] = 0x12365478;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    li t0, 0x5555555555555555   # 0b0101 ...
    li t1, 84

    amoxor.d t1, t0, (a0)
  )");

  auto heapStart = process_->getHeapStart();

  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0x5555555555555555);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0x3333333333333333);
  EXPECT_EQ(getMemoryValue<uint64_t>(heapStart), 0x6666666666666666);
  EXPECT_EQ(getMemoryValue<uint32_t>(heapStart + 8), 0xFEEBDAED);
}

TEST_P(InstAtomic, amomin_w) {
  // tests verified with gdb on riscv fedora on qemu
  initialHeapData_.resize(24);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0x33333333;
  heap[1] = 0x12345678;
  heap[2] = 0x9EEBDAED;
  heap[3] = 0xFFFFFFFF;
  heap[4] = 0x7FFFFFFF;
  heap[5] = 0x12365478;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    li t0, 0x0000000000555555
    li t1, 84

    amomin.w t1, t0, (a0)
  )");

  auto heapStart = process_->getHeapStart();

  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0x0000000000555555);  // small +ve
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0x0000000033333333);  // large +ve
  EXPECT_EQ(getMemoryValue<uint64_t>(heapStart), 0x1234567800555555);

  heap[0] = 0xB3333333;
  heap[1] = 0x12345678;
  heap[2] = 0x9EEBDAED;
  heap[3] = 0xFFFFFFFF;
  heap[4] = 0x7FFFFFFF;
  heap[5] = 0x12365478;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    li t0, 0xF000000055555555
    li t1, 84

    amomin.w t1, t0, (a0)
  )");

  heapStart = process_->getHeapStart();

  EXPECT_EQ(getGeneralRegister<uint64_t>(5),
            0xF000000055555555);  // (+ve word),  large -ve double
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0xFFFFFFFFB3333333);  // small -ve
  EXPECT_EQ(getMemoryValue<uint64_t>(heapStart), 0x12345678B3333333);

  heap[0] = 0x03333333;
  heap[1] = 0x12345678;
  heap[2] = 0x9EEBDAED;
  heap[3] = 0xFFFFFFFF;
  heap[4] = 0x7FFFFFFF;
  heap[5] = 0x12365478;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    li t0, 0xF000000055555555
    li t1, 84

    amomin.w t1, t0, (a0)
  )");

  heapStart = process_->getHeapStart();

  EXPECT_EQ(getGeneralRegister<uint64_t>(5),
            0xF000000055555555);  // (large +ve word), -ve double
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0x0000000003333333);  // small +ve
  EXPECT_EQ(getMemoryValue<uint64_t>(heapStart), 0x1234567803333333);
}

TEST_P(InstAtomic, amomin_d) {
  initialHeapData_.resize(24);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0xB3333333;
  heap[1] = 0x12345678;
  heap[2] = 0xFEEBDAED;
  heap[3] = 0x12345678;
  heap[4] = 0x7FFFFFFF;
  heap[5] = 0x12365478;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    li t0, 0xF555555555555555
    li t1, 84

    amomin.d t1, t0, (a0)

    addi a0, a0, 8

    li t5, 0x0034567899999999   # 0b0101 ...
    li t6, 84

    amomin.d t6, t5, (a0)
  )");

  auto heapStart = process_->getHeapStart();

  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0xF555555555555555);  // -ve
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0x12345678B3333333);  // +ve
  EXPECT_EQ(getMemoryValue<uint64_t>(heapStart), 0xF555555555555555);

  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0x0034567899999999);  // small +ve
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 0x12345678FEEBDAED);  // large +ve
  EXPECT_EQ(getMemoryValue<uint64_t>(heapStart + 8), 0x0034567899999999);
}

TEST_P(InstAtomic, amominu_w) {
  // tests verified with gdb on riscv fedora on qemu
  initialHeapData_.resize(24);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0x33333333;
  heap[1] = 0x12345678;
  heap[2] = 0x9EEBDAED;
  heap[3] = 0xFFFFFFFF;
  heap[4] = 0x7FFFFFFF;
  heap[5] = 0x12365478;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    li t0, 0x0000000000555555
    li t1, 84

    amominu.w t1, t0, (a0)
  )");

  auto heapStart = process_->getHeapStart();

  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0x0000000000555555);  // small +ve
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0x0000000033333333);  // large +ve
  EXPECT_EQ(getMemoryValue<uint64_t>(heapStart), 0x1234567800555555);

  heap[0] = 0xB3333333;
  heap[1] = 0x12345678;
  heap[2] = 0x9EEBDAED;
  heap[3] = 0xFFFFFFFF;
  heap[4] = 0x7FFFFFFF;
  heap[5] = 0x12365478;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    li t0, 0xF000000055555555
    li t1, 84

    amominu.w t1, t0, (a0)
  )");

  heapStart = process_->getHeapStart();

  EXPECT_EQ(getGeneralRegister<uint64_t>(5),
            0xF000000055555555);  // (small +ve word),  large -ve double
  EXPECT_EQ(getGeneralRegister<uint64_t>(6),
            0xFFFFFFFFB3333333);  // (large +ve), small -ve
  EXPECT_EQ(getMemoryValue<uint64_t>(heapStart), 0x1234567855555555);

  heap[0] = 0x03333333;
  heap[1] = 0x12345678;
  heap[2] = 0x9EEBDAED;
  heap[3] = 0xFFFFFFFF;
  heap[4] = 0x7FFFFFFF;
  heap[5] = 0x12365478;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    li t0, 0xF000000055555555
    li t1, 84

    amominu.w t1, t0, (a0)
  )");

  heapStart = process_->getHeapStart();

  EXPECT_EQ(getGeneralRegister<uint64_t>(5),
            0xF000000055555555);  // (large +ve word), -ve double
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0x0000000003333333);  // small +ve
  EXPECT_EQ(getMemoryValue<uint64_t>(heapStart), 0x1234567803333333);
}

TEST_P(InstAtomic, amominu_d) {
  initialHeapData_.resize(24);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0xB3333333;
  heap[1] = 0x12345678;
  heap[2] = 0xFEEBDAED;
  heap[3] = 0x12345678;
  heap[4] = 0x7FFFFFFF;
  heap[5] = 0x12365478;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    li t0, 0xF555555555555555   # 0b0101 ...
    li t1, 84

    amominu.d t1, t0, (a0)

    addi a0, a0, 8

    li t5, 0x0034567899999999   # 0b0101 ...
    li t6, 84

    amominu.d t6, t5, (a0)
  )");

  auto heapStart = process_->getHeapStart();

  EXPECT_EQ(getGeneralRegister<uint64_t>(5),
            0xF555555555555555);  // (large +ve), -ve
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0x12345678B3333333);  // +ve
  EXPECT_EQ(getMemoryValue<uint64_t>(heapStart), 0x12345678B3333333);

  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0x0034567899999999);  // small +ve
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 0x12345678FEEBDAED);  // large +ve
  EXPECT_EQ(getMemoryValue<uint64_t>(heapStart + 8), 0x0034567899999999);
}

TEST_P(InstAtomic, amomax_w) {
  // tests verified with gdb on riscv fedora on qemu
  initialHeapData_.resize(24);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0x33333333;
  heap[1] = 0x12345678;
  heap[2] = 0x9EEBDAED;
  heap[3] = 0xFFFFFFFF;
  heap[4] = 0x7FFFFFFF;
  heap[5] = 0x12365478;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    li t0, 0x0000000000555555
    li t1, 84

    amomax.w t1, t0, (a0)
  )");

  auto heapStart = process_->getHeapStart();

  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0x0000000000555555);  // small +ve
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0x0000000033333333);  // large +ve
  EXPECT_EQ(getMemoryValue<uint64_t>(heapStart), 0x1234567833333333);

  heap[0] = 0xB3333333;
  heap[1] = 0x12345678;
  heap[2] = 0x9EEBDAED;
  heap[3] = 0xFFFFFFFF;
  heap[4] = 0x7FFFFFFF;
  heap[5] = 0x12365478;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    li t0, 0xF000000055555555
    li t1, 84

    amomax.w t1, t0, (a0)
  )");

  heapStart = process_->getHeapStart();

  EXPECT_EQ(getGeneralRegister<uint64_t>(5),
            0xF000000055555555);  // (+ve word),  large -ve double
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0xFFFFFFFFB3333333);  // small -ve
  EXPECT_EQ(getMemoryValue<uint64_t>(heapStart), 0x1234567855555555);

  heap[0] = 0x03333333;
  heap[1] = 0x12345678;
  heap[2] = 0x9EEBDAED;
  heap[3] = 0xFFFFFFFF;
  heap[4] = 0x7FFFFFFF;
  heap[5] = 0x12365478;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    li t0, 0xF000000055555555
    li t1, 84

    amomax.w t1, t0, (a0)
  )");

  heapStart = process_->getHeapStart();

  EXPECT_EQ(getGeneralRegister<uint64_t>(5),
            0xF000000055555555);  // (large +ve word), -ve double
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0x0000000003333333);  // small +ve
  EXPECT_EQ(getMemoryValue<uint64_t>(heapStart), 0x1234567855555555);
}

TEST_P(InstAtomic, amomax_d) {
  initialHeapData_.resize(24);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0xB3333333;
  heap[1] = 0x12345678;
  heap[2] = 0xFEEBDAED;
  heap[3] = 0x12345678;
  heap[4] = 0x7FFFFFFF;
  heap[5] = 0x12365478;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    li t0, 0xF555555555555555   # 0b0101 ...
    li t1, 84

    amomax.d t1, t0, (a0)

    addi a0, a0, 8

    li t5, 0x0034567899999999   # 0b0101 ...
    li t6, 84

    amomax.d t6, t5, (a0)
  )");

  auto heapStart = process_->getHeapStart();

  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0xF555555555555555);  // -ve
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0x12345678B3333333);  // +ve
  EXPECT_EQ(getMemoryValue<uint64_t>(heapStart), 0x12345678B3333333);

  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0x0034567899999999);  // small +ve
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 0x12345678FEEBDAED);  // large +ve
  EXPECT_EQ(getMemoryValue<uint64_t>(heapStart + 8), 0x12345678FEEBDAED);
}

TEST_P(InstAtomic, amomaxu_w) {
  // tests verified with gdb on riscv fedora on qemu
  initialHeapData_.resize(24);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0x33333333;
  heap[1] = 0x12345678;
  heap[2] = 0x9EEBDAED;
  heap[3] = 0xFFFFFFFF;
  heap[4] = 0x7FFFFFFF;
  heap[5] = 0x12365478;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    li t0, 0x0000000000555555
    li t1, 84

    amomaxu.w t1, t0, (a0)
  )");

  auto heapStart = process_->getHeapStart();

  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0x0000000000555555);  // small +ve
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0x0000000033333333);  // large +ve
  EXPECT_EQ(getMemoryValue<uint64_t>(heapStart), 0x1234567833333333);

  heap[0] = 0xB3333333;
  heap[1] = 0x12345678;
  heap[2] = 0x9EEBDAED;
  heap[3] = 0xFFFFFFFF;
  heap[4] = 0x7FFFFFFF;
  heap[5] = 0x12365478;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    li t0, 0xF000000055555555
    li t1, 84

    amomaxu.w t1, t0, (a0)
  )");

  heapStart = process_->getHeapStart();

  EXPECT_EQ(getGeneralRegister<uint64_t>(5),
            0xF000000055555555);  // (small +ve word),  large -ve double
  EXPECT_EQ(getGeneralRegister<uint64_t>(6),
            0xFFFFFFFFB3333333);  // (large +ve), small -ve
  EXPECT_EQ(getMemoryValue<uint64_t>(heapStart), 0x12345678B3333333);

  heap[0] = 0x03333333;
  heap[1] = 0x12345678;
  heap[2] = 0x9EEBDAED;
  heap[3] = 0xFFFFFFFF;
  heap[4] = 0x7FFFFFFF;
  heap[5] = 0x12365478;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    li t0, 0xF000000055555555
    li t1, 84

    amomaxu.w t1, t0, (a0)
  )");

  heapStart = process_->getHeapStart();

  EXPECT_EQ(getGeneralRegister<uint64_t>(5),
            0xF000000055555555);  // (large +ve word), -ve double
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0x0000000003333333);  // small +ve
  EXPECT_EQ(getMemoryValue<uint64_t>(heapStart), 0x1234567855555555);
}

TEST_P(InstAtomic, amomaxu_d) {
  initialHeapData_.resize(24);
  uint32_t* heap = reinterpret_cast<uint32_t*>(initialHeapData_.data());
  heap[0] = 0xB3333333;
  heap[1] = 0x12345678;
  heap[2] = 0xFEEBDAED;
  heap[3] = 0x12345678;
  heap[4] = 0x7FFFFFFF;
  heap[5] = 0x12365478;

  RUN_RISCV(R"(
    # Get heap address
    li a7, 214
    ecall

    li t0, 0xF555555555555555   # 0b0101 ...
    li t1, 84

    amomaxu.d t1, t0, (a0)

    addi a0, a0, 8

    li t5, 0x0034567899999999   # 0b0101 ...
    li t6, 84

    amomaxu.d t6, t5, (a0)
  )");

  auto heapStart = process_->getHeapStart();

  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0xF555555555555555);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 0x12345678B3333333);
  EXPECT_EQ(getMemoryValue<uint64_t>(heapStart), 0xF555555555555555);

  EXPECT_EQ(getGeneralRegister<uint64_t>(30), 0x0034567899999999);
  EXPECT_EQ(getGeneralRegister<uint64_t>(31), 0x12345678FEEBDAED);
  EXPECT_EQ(getMemoryValue<uint64_t>(heapStart + 8), 0x12345678FEEBDAED);
}

// TODO AMOMIN AMOMINU AMOMAX AMOMAXU

INSTANTIATE_TEST_SUITE_P(RISCV, InstAtomic,
                         ::testing::Values(EMULATION, INORDER),
                         coreTypeToString);

}  // namespace
