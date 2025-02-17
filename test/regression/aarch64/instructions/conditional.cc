#include "AArch64RegressionTest.hh"

namespace {

using InstConditional = AArch64RegressionTest;
using namespace simeng::arch::aarch64::InstructionGroups;

TEST_P(InstConditional, ccmn) {
  // 64-bit
  RUN_AARCH64(R"(
    mov x0, 0xff
    mov x1, 0xffffffffffffffff

    # cmp 0x3f, 0x3f; eq = false; nzcv = 8; 
    cmp x0, #0x3f
    ccmn x1, #1, #8, eq
    csetm x3, ne

    # cmp 0xff, 0xfff; mi = true; cmp 0xffffffffffffffff 0; cs = true
    cmp x0, #0xfff
    ccmn x1, #1, #8, mi
    csetm x4, cs
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(3), -1);
  EXPECT_EQ(getGeneralRegister<uint64_t>(4), -1);
}

TEST_P(InstConditional, ccmp) {
  // 32-bit
  RUN_AARCH64(R"(
    mov w0, wzr
    mov w1, 42
    mov w2, 7

    # cmp 0, 0; eq = true; cmp 42, 7; gt = true
    cmp w0, w0
    ccmp w1, w2, 2, eq
    csetm w3, gt

    # cmp 0, 0; ne = false; nzcv = 8; lt = true
    cmp w0, w0
    ccmp w1, w2, 8, ne
    csetm w4, lt

    # cmp 42, 7; gt = true; cmp 42, 31; lt = false
    cmp w1, w2
    ccmp w1, 31, 10, gt
    csetm w5, lt

    # cmp 7, 42; gt = false; nzcv = 8; ne = true
    cmp w2, w1
    ccmp w2, 7, 8, gt
    csetm w6, ne
  )");
  EXPECT_EQ(getGeneralRegister<uint32_t>(3), -1);
  EXPECT_EQ(getGeneralRegister<uint32_t>(4), -1);
  EXPECT_EQ(getGeneralRegister<uint32_t>(5), 0);
  EXPECT_EQ(getGeneralRegister<uint32_t>(6), -1);

  // 64-bit
  RUN_AARCH64(R"(
    mov x0, xzr
    mov x1, 42
    mov x2, 7

    # cmp 0, 0; eq = true; cmp 42, 7; gt = true
    cmp x0, x0
    ccmp x1, x2, 2, eq
    csetm x3, gt

    # cmp 0, 0; ne = false; nzcv = 8; lt = true
    cmp x0, x0
    ccmp x1, x2, 8, ne
    csetm x4, lt

    # cmp 42, 7; gt = true; cmp 42, 31; lt = false
    cmp x1, x2
    ccmp x1, 31, 10, gt
    csetm x5, lt

    # cmp 7, 42; gt = false; nzcv = 8; ne = true
    cmp x2, x1
    ccmp x2, 7, 8, gt
    csetm x6, ne
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(3), -1);
  EXPECT_EQ(getGeneralRegister<uint64_t>(4), -1);
  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), -1);
}

TEST_P(InstConditional, csetm) {
  // 32-bit
  RUN_AARCH64(R"(
    mov w0, wzr
    mov w1, 42
    mov w2, 7
    cmp w0, w0
    csetm w3, eq
    csetm w4, ne
    csetm w5, lt
    csetm w6, le
  )");
  EXPECT_EQ(getGeneralRegister<uint32_t>(3), -1);
  EXPECT_EQ(getGeneralRegister<uint32_t>(4), 0);
  EXPECT_EQ(getGeneralRegister<uint32_t>(5), 0);
  EXPECT_EQ(getGeneralRegister<uint32_t>(6), -1);

  // 64-bit
  RUN_AARCH64(R"(
    mov x0, xzr
    mov x1, 42
    mov x2, 7
    cmp x0, x0
    csetm x3, eq
    csetm x4, ne
    csetm x5, lt
    csetm x6, le
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(3), -1);
  EXPECT_EQ(getGeneralRegister<uint64_t>(4), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 0);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), -1);

  EXPECT_GROUP(R"(csetm w6, le)", INT_SIMPLE_ARTH_NOSHIFT);
  EXPECT_GROUP(R"(csetm x6, le)", INT_SIMPLE_ARTH_NOSHIFT);
}

TEST_P(InstConditional, csinc) {
  // 32-bit
  RUN_AARCH64(R"(
    mov w0, wzr
    mov w1, 42
    mov w2, 7
    cmp w0, w0
    csinc w3, w1, w2, eq
    csinc w4, w1, w2, ne
    csinc w5, w1, w2, lt
    csinc w6, w1, w2, le

    # Check cinc alias as well
    cinc w7, w1, gt
    cinc w8, w1, ge
  )");
  EXPECT_EQ(getGeneralRegister<uint32_t>(3), 42u);
  EXPECT_EQ(getGeneralRegister<uint32_t>(4), 8u);
  EXPECT_EQ(getGeneralRegister<uint32_t>(5), 8u);
  EXPECT_EQ(getGeneralRegister<uint32_t>(6), 42u);
  EXPECT_EQ(getGeneralRegister<uint32_t>(7), 42u);
  EXPECT_EQ(getGeneralRegister<uint32_t>(8), 43u);

  // 64-bit
  RUN_AARCH64(R"(
    mov x0, xzr
    mov x1, 42
    mov x2, 7
    cmp x0, x0
    csinc x3, x1, x2, eq
    csinc x4, x1, x2, ne
    csinc x5, x1, x2, lt
    csinc x6, x1, x2, le

    # Check cinc alias as well
    cinc x7, x1, gt
    cinc x8, x1, ge
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(3), 42u);
  EXPECT_EQ(getGeneralRegister<uint64_t>(4), 8u);
  EXPECT_EQ(getGeneralRegister<uint64_t>(5), 8u);
  EXPECT_EQ(getGeneralRegister<uint64_t>(6), 42u);
  EXPECT_EQ(getGeneralRegister<uint64_t>(7), 42u);
  EXPECT_EQ(getGeneralRegister<uint64_t>(8), 43u);

  EXPECT_GROUP(R"(csinc w6, w1, w2, le)", INT_SIMPLE_ARTH_NOSHIFT);
  EXPECT_GROUP(R"(cinc w8, w1, ge)", INT_SIMPLE_ARTH_NOSHIFT);
  EXPECT_GROUP(R"(csinc x6, x1, x2, le)", INT_SIMPLE_ARTH_NOSHIFT);
  EXPECT_GROUP(R"(cinc x8, x1, ge)", INT_SIMPLE_ARTH_NOSHIFT);
}

TEST_P(InstConditional, csneg) {
  // 32-bit
  RUN_AARCH64(R"(
    mov w0, wzr
    mov w1, 42
    mov w2, 7
    cmp w0, w0
    csneg w3, w1, w2, eq
    csneg w4, w1, w2, ne
    csneg w5, w1, w2, lt
    csneg w6, w1, w2, le

    # Check cneg alias as well
    cneg w7, w1, gt
    cneg w8, w1, ge
  )");
  EXPECT_EQ(getGeneralRegister<int32_t>(3), 42);
  EXPECT_EQ(getGeneralRegister<int32_t>(4), -7);
  EXPECT_EQ(getGeneralRegister<int32_t>(5), -7);
  EXPECT_EQ(getGeneralRegister<int32_t>(6), 42);
  EXPECT_EQ(getGeneralRegister<int32_t>(7), 42);
  EXPECT_EQ(getGeneralRegister<int32_t>(8), -42);

  // 64-bit
  RUN_AARCH64(R"(
    mov x0, xzr
    mov x1, 42
    mov x2, 7
    cmp x0, x0
    csneg x3, x1, x2, eq
    csneg x4, x1, x2, ne
    csneg x5, x1, x2, lt
    csneg x6, x1, x2, le

    # Check cneg alias as well
    cneg x7, x1, gt
    cneg x8, x1, ge
  )");
  EXPECT_EQ(getGeneralRegister<int64_t>(3), 42);
  EXPECT_EQ(getGeneralRegister<int64_t>(4), -7);
  EXPECT_EQ(getGeneralRegister<int64_t>(5), -7);
  EXPECT_EQ(getGeneralRegister<int64_t>(6), 42);
  EXPECT_EQ(getGeneralRegister<int64_t>(7), 42);
  EXPECT_EQ(getGeneralRegister<int64_t>(8), -42);

  EXPECT_GROUP(R"(cneg w8, w1, ge)", INT_SIMPLE_ARTH_NOSHIFT);
  EXPECT_GROUP(R"(cneg x8, x1, ge)", INT_SIMPLE_ARTH_NOSHIFT);
}

TEST_P(InstConditional, tbz) {
  // 32-bit
  RUN_AARCH64(R"(
    mov w1, 42
    mov w2, 7

    movz w0, #0xA005

    tbz w0, 14, .b1
    mov w1, 50
    .b1:

    tbz w0, 2, .b2
    mov w2, 15
    .b2:
  )");
  EXPECT_EQ(getGeneralRegister<uint32_t>(1), 42u);
  EXPECT_EQ(getGeneralRegister<uint32_t>(2), 15u);

  // 64-bit
  RUN_AARCH64(R"(
    mov x1, 42
    mov x2, 7

    movk x0, #0xA005, lsl 48

    tbz x0, 62, .b1
    mov x1, 50
    .b1:

    tbz x0, 50, .b2
    mov x2, 15
    .b2:
  )");
  EXPECT_EQ(getGeneralRegister<uint64_t>(1), 42u);
  EXPECT_EQ(getGeneralRegister<uint64_t>(2), 15u);
}

INSTANTIATE_TEST_SUITE_P(AArch64, InstConditional,
                         ::testing::Values(std::make_tuple(EMULATION, "{}")),
                         paramToString);

}  // namespace
