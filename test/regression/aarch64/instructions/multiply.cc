#include "AArch64RegressionTest.hh"

namespace {

using InstMul = AArch64RegressionTest;
using namespace simeng::arch::aarch64::InstructionGroups;

TEST_P(InstMul, maddw) {
  RUN_AARCH64(R"(
    movz w0, #7
    movz w1, #6
    movz w2, #5
    madd w3, w0, w1, w2
  )");
  EXPECT_EQ(getGeneralRegister<uint32_t>(3), 47u);
}

TEST_P(InstMul, msub) {
  // 32-bit
  RUN_AARCH64(R"(
    movz w0, #7
    movz w1, #6
    movz w2, #47
    msub w3, w0, w1, w2
  )");
  EXPECT_EQ(getGeneralRegister<uint32_t>(3), 5u);

  // 64-bit
  RUN_AARCH64(R"(
    movz x0, #7
    movz x1, #6
    movz x2, #47
    msub x3, x0, x1, x2
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(3), 5u);
}

TEST_P(InstMul, mulw) {
  RUN_AARCH64(R"(
    movz w0, #7
    movz w1, #6
    mul w2, w0, w1
  )");
  EXPECT_EQ(getGeneralRegister<uint32_t>(2), 42u);

  RUN_AARCH64(R"(
    movz x0, #7
    movz x1, #6
    mul x2, x0, x1
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(2), 42u);

  EXPECT_GROUP(R"(mul w2, w0, w1)", INT_MUL);
  EXPECT_GROUP(R"(mul x2, x0, x1)", INT_MUL);
}

TEST_P(InstMul, smaddl) {
  RUN_AARCH64(R"(
    mov w0, 0x2A
    orr w0, wzr, w0, lsl 24
    movz w1, 0x100
    movz x2, 0x05, lsl 48
    smaddl x3, w0, w1, x2

    mov w4, #-1
    movz w5, 0xFF, lsl 16
    mov x6, 0x100
    smaddl x7, w4, w5, x6
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(3), 0x0005002A00000000);
  EXPECT_EQ(getGeneralRegister<int64_t>(7), -0xFEFF00);
}

TEST_P(InstMul, smulh) {
  RUN_AARCH64(R"(
    movz x0, 0x2AB3
    orr x0, xzr, x0, lsl 48
    movz x1, 0x100
    smulh x2, x0, x1
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(2), 0x000000000000002A);
}

TEST_P(InstMul, smull) {
  RUN_AARCH64(R"(
    mov w0, 0x2A
    orr w0, wzr, w0, lsl 24
    movz w1, 0x100
    smull x3, w0, w1
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(3), 0x0000002A00000000);

  EXPECT_GROUP(R"(smull x3, w0, w1)", INT_MUL);
}

TEST_P(InstMul, umaddl) {
  RUN_AARCH64(R"(
    mov w0, 0x2A
    orr w0, wzr, w0, lsl 24
    movz w1, 0x100
    movz x2, 0x05, lsl 48
    umaddl x3, w0, w1, x2

    # Test umull alias
    umull x4, w0, w1
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(3), 0x0005002A00000000);
  EXPECT_EQ(getGeneralRegister<uint64_t>(4), 0x0000002A00000000);

  EXPECT_GROUP(R"(umull x4, w0, w1)", INT_MUL);
}

INSTANTIATE_TEST_SUITE_P(AArch64, InstMul,
                         ::testing::Values(std::make_tuple(EMULATION, "{}")),
                         paramToString);

}  // namespace
