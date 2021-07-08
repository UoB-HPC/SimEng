#include "RISCVRegressionTest.hh"

namespace {

using InstArithmetic = RISCVRegressionTest;

//TEST_P(InstArithmetic, addi) {
//  RUN_RISCV(R"(
//    addi,x28,x28,3
//  )");
//  EXPECT_EQ(getGeneralRegister<uint64_t>(28), 3u);
//}

//TEST_P(InstArithmetic, add) {
//  RUN_AARCH64(R"(
//    mov w0, wzr
//    add w1, w0, #2
//    add w2, w0, #7, lsl #12
//  )");
//  EXPECT_EQ(getGeneralRegister<uint32_t>(1), 2u);
//  EXPECT_EQ(getGeneralRegister<uint32_t>(2), (7u << 12));
//
//  RUN_AARCH64(R"(
//    mov x0, xzr
//    add x1, x0, #3
//    add x2, x0, #5, lsl #12
//  )");
//  EXPECT_EQ(getGeneralRegister<uint64_t>(1), 3u);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(2), (5u << 12));
//}
//
//// Test that NZCV flags are set correctly by 32-bit adds
//TEST_P(InstArithmetic, addsw) {
//  // 0 + 0 = 0
//  RUN_AARCH64(R"(
//    mov w0, wzr
//    adds w0, w0, #0
//  )");
//  EXPECT_EQ(getNZCV(), 0b0100);
//  EXPECT_EQ(getGeneralRegister<uint32_t>(0), 0u);
//
//  // 2 + 1 = 3
//  RUN_AARCH64(R"(
//    mov w0, #2
//    adds w0, w0, #1
//  )");
//  EXPECT_EQ(getNZCV(), 0b0000);
//  EXPECT_EQ(getGeneralRegister<uint32_t>(0), 3u);
//
//  // -1 + 0 = -1
//  RUN_AARCH64(R"(
//    mov w0, wzr
//    sub w0, w0, #1
//    adds w0, w0, #0
//  )");
//  EXPECT_EQ(getNZCV(), 0b1000);
//  EXPECT_EQ(getGeneralRegister<uint32_t>(0), UINT32_MAX);
//
//  // -1 + 1 = 0
//  RUN_AARCH64(R"(
//    mov w0, wzr
//    sub w0, w0, #1
//    adds w0, w0, #1
//  )");
//  EXPECT_EQ(getNZCV(), 0b0110);
//  EXPECT_EQ(getGeneralRegister<uint32_t>(0), 0);
//
//  // (2^31 -1) + 1 = 2^31
//  RUN_AARCH64(R"(
//    mov w0, wzr
//    mov w1, #1
//    add w1, w0, w1, lsl #31
//    sub w1, w1, #1
//    add w2, w0, #1
//    adds w0, w1, w2
//  )");
//  EXPECT_EQ(getNZCV(), 0b1001);
//  EXPECT_EQ(getGeneralRegister<uint32_t>(0), (1ul << 31));
//
//  // 2^31 + 0 = 2^31
//  RUN_AARCH64(R"(
//    mov w0, wzr
//    mov w1, #1
//    add w1, w0, w1, lsl #31
//    adds w0, w1, #0
//  )");
//  EXPECT_EQ(getNZCV(), 0b1000);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(0), (1u << 31));
//
//  // 2^31 + -1 = 2^31 - 1
//  RUN_AARCH64(R"(
//    mov w0, wzr
//    add w1, w0, #1
//    add w1, w0, w1, lsl #31
//    sub w2, w0, #1
//    adds w0, w1, w2
//  )");
//  EXPECT_EQ(getNZCV(), 0b0011);
//  EXPECT_EQ(getGeneralRegister<uint32_t>(0), (1u << 31) - 1);
//
//  // (7 << 16) + (-1) [8-bit sign-extended]
//  RUN_AARCH64(R"(
//    movz w0, #7, lsl #16
//    # 255 will be -1 when sign-extended from 8-bits
//    mov w2, 255
//    adds w3, w0, w2, sxtb
//  )");
//  EXPECT_EQ(getNZCV(), 0b0010);
//  EXPECT_EQ(getGeneralRegister<uint32_t>(3), (7u << 16) - 1);
//
//  // (7 << 16) + (255 << 4)
//  RUN_AARCH64(R"(
//    movz w0, #7, lsl #16
//    mov w2, 255
//    adds w3, w0, w2, uxtx 4
//  )");
//  EXPECT_EQ(getNZCV(), 0b0000);
//  EXPECT_EQ(getGeneralRegister<uint32_t>(3), (7u << 16) + (255u << 4));
//}
//
//// Test that NZCV flags are set correctly by 64-bit adds
//TEST_P(InstArithmetic, addsx) {
//  // 0 - 0 = 0
//  RUN_AARCH64(R"(
//    mov x0, xzr
//    adds x0, x0, #0
//  )");
//  EXPECT_EQ(getNZCV(), 0b0100);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 0u);
//
//  // 2 + 1 = 3
//  RUN_AARCH64(R"(
//    mov x0, #2
//    adds x0, x0, #1
//  )");
//  EXPECT_EQ(getNZCV(), 0b0000);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 3u);
//
//  // -1 + 0 = -1
//  RUN_AARCH64(R"(
//    mov x0, xzr
//    sub x0, x0, #1
//    adds x0, x0, #0
//  )");
//  EXPECT_EQ(getNZCV(), 0b1000);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(0), UINT64_MAX);
//
//  // -1 + 1 = 0
//  RUN_AARCH64(R"(
//    mov x0, xzr
//    sub x0, x0, #1
//    adds x0, x0, #1
//  )");
//  EXPECT_EQ(getNZCV(), 0b0110);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 0);
//
//  // (2^63 -1) + -1 = 2^63
//  RUN_AARCH64(R"(
//    mov x0, xzr
//    mov x1, #1
//    add x1, x0, x1, lsl #63
//    sub x1, x1, #1
//    add x2, x0, #1
//    adds x0, x1, x2
//  )");
//  EXPECT_EQ(getNZCV(), 0b1001);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(0), (1ul << 63));
//
//  // 2^63 + 0 = 2^63
//  RUN_AARCH64(R"(
//    mov x0, xzr
//    mov x1, #1
//    add x1, x0, x1, lsl #63
//    adds x0, x1, #0
//  )");
//  EXPECT_EQ(getNZCV(), 0b1000);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(0), (1ul << 63));
//
//  // 2^63 + -1 = 2^63 - 1
//  RUN_AARCH64(R"(
//    mov x0, xzr
//    add x1, x0, #1
//    add x1, x0, x1, lsl #63
//    sub x2, x0, #1
//    adds x0, x1, x2
//  )");
//  EXPECT_EQ(getNZCV(), 0b0011);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(0), (1ul << 63) - 1);
//
//  // (7 << 48) + (15 << 33)
//  RUN_AARCH64(R"(
//    movz x0, #7, lsl #48
//    movz x1, #15
//    adds x2, x0, x1, lsl 33
//  )");
//  EXPECT_EQ(getNZCV(), 0b0000);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(2), (7ul << 48) + (15ul << 33));
//
//  // (7 << 48) + (-1) [8-bit sign-extended]
//  RUN_AARCH64(R"(
//    movz x0, #7, lsl #48
//    # 255 will be -1 when sign-extended from 8-bits
//    mov w2, 255
//    adds x3, x0, w2, sxtb
//  )");
//  EXPECT_EQ(getNZCV(), 0b0010);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(3), (7ul << 48) - 1);
//
//  // (7 << 48) + (255 << 4)
//  RUN_AARCH64(R"(
//    movz x0, #7, lsl #48
//    mov w2, 255
//    adds x3, x0, x2, uxtx 4
//  )");
//  EXPECT_EQ(getNZCV(), 0b0000);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(3), (7ul << 48) + (255ul << 4));
//}
//
//TEST_P(InstArithmetic, movk) {
//  // 32-bit
//  RUN_AARCH64(R"(
//    mov w0, wzr
//    sub w0, w0, #1
//    mov w1, w0
//
//    movk w0, #0
//    movk w1, #0, lsl 16
//  )");
//  EXPECT_EQ(getGeneralRegister<uint32_t>(0), 0xFFFF0000);
//  EXPECT_EQ(getGeneralRegister<uint32_t>(1), 0x0000FFFF);
//
//  // 64-bit
//  RUN_AARCH64(R"(
//    mov x0, xzr
//    sub x0, x0, #1
//    mov x1, x0
//    mov x2, x0
//    mov x3, x0
//
//    movk x0, #0
//    movk x1, #0, lsl 16
//    movk x2, #0, lsl 32
//    movk x3, #0, lsl 48
//  )");
//  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 0xFFFFFFFFFFFF0000);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(1), 0xFFFFFFFF0000FFFF);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(2), 0xFFFF0000FFFFFFFF);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(3), 0x0000FFFFFFFFFFFF);
//}
//
//// Test that NZCV flags are set correctly by 32-bit negs
//TEST_P(InstArithmetic, negsw) {
//  // - 0
//  RUN_AARCH64(R"(
//    mov w0, wzr
//    negs w0, w0
//  )");
//  EXPECT_EQ(getNZCV(), 0b0110);
//  EXPECT_EQ(getGeneralRegister<uint32_t>(0), 0u);
//
//  // - 1
//  RUN_AARCH64(R"(
//    mov w0, 1
//    negs w0, w0
//  )");
//  EXPECT_EQ(getNZCV(), 0b1000);
//  EXPECT_EQ(getGeneralRegister<uint32_t>(0), -1);
//
//  // - -1
//  RUN_AARCH64(R"(
//    mov w0, wzr
//    sub w0, w0, #1
//    negs w0, w0
//  )");
//  EXPECT_EQ(getNZCV(), 0b0000);
//  EXPECT_EQ(getGeneralRegister<uint32_t>(0), 1);
//
//  // - (2^31 - 1)
//  RUN_AARCH64(R"(
//    mov w0, wzr
//    mov w1, #1
//    add w1, w0, w1, lsl #31
//    sub w1, w1, #1
//    negs w0, w1
//  )");
//  EXPECT_EQ(getNZCV(), 0b1000);
//  EXPECT_EQ(getGeneralRegister<uint32_t>(0),
//            static_cast<uint32_t>(-((1ul << 31) - 1)));
//
//  // - (2^31)
//  RUN_AARCH64(R"(
//    mov w0, wzr
//    mov w1, #1
//    negs w0, w1, lsl 31
//  )");
//  EXPECT_EQ(getNZCV(), 0b1001);
//  EXPECT_EQ(getGeneralRegister<uint32_t>(0), static_cast<uint32_t>(1ul << 31));
//}
//
//// Test that NZCV flags are set correctly by 64-bit negs
//TEST_P(InstArithmetic, negsx) {
//  // - 0
//  RUN_AARCH64(R"(
//    mov x0, xzr
//    negs x0, x0
//  )");
//  EXPECT_EQ(getNZCV(), 0b0110);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 0u);
//
//  // - 1
//  RUN_AARCH64(R"(
//    mov x0, 1
//    negs x0, x0
//  )");
//  EXPECT_EQ(getNZCV(), 0b1000);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(0), -1);
//
//  // - -1
//  RUN_AARCH64(R"(
//    mov x0, xzr
//    sub x0, x0, #1
//    negs x0, x0
//  )");
//  EXPECT_EQ(getNZCV(), 0b0000);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 1);
//
//  // - (2^63 - 1)
//  RUN_AARCH64(R"(
//    mov x0, xzr
//    mov x1, #1
//    add x1, x0, x1, lsl #63
//    sub x1, x1, #1
//    negs x0, x1
//  )");
//  EXPECT_EQ(getNZCV(), 0b1000);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(0),
//            static_cast<uint64_t>(-((1ul << 63) - 1)));
//
//  // - (2^63)
//  RUN_AARCH64(R"(
//    mov x0, xzr
//    mov x1, #1
//    negs x0, x1, lsl 63
//  )");
//  EXPECT_EQ(getNZCV(), 0b1001);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(0), static_cast<uint64_t>(1ul << 63));
//}
//
//TEST_P(InstArithmetic, sbc) {
//  // 32-bit
//  RUN_AARCH64(R"(
//    mov w0, wzr
//    mov w1, #1
//    sub w2, w0, w1
//    sbc w2, w2, w1
//
//    movz w0, #7, lsl #16
//    movz w1, #15
//    sub w3, w0, w1, lsl 3
//    sbc w3, w3, w1
//  )");
//  EXPECT_EQ(getGeneralRegister<int32_t>(2), -3);
//  EXPECT_EQ(getGeneralRegister<uint32_t>(3),
//            (7u << 16) - (15u << 3) - 15u - 1u);
//
//  // 64-bit
//  RUN_AARCH64(R"(
//    mov x0, xzr
//    mov x1, #1
//    sub x2, x0, x1
//    sbc x2, x2, x1
//
//    movz x0, #7, lsl #48
//    movz x1, #15
//    sub x3, x0, x1, lsl 33
//    sbc x3, x3, x1
//  )");
//  EXPECT_EQ(getGeneralRegister<int64_t>(2), -3);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(3),
//            (7ul << 48) - (15ul << 33) - 15ul - 1ul);
//}
//
//TEST_P(InstArithmetic, sub) {
//  // 32-bit
//  RUN_AARCH64(R"(
//    mov w0, wzr
//    sub w2, w0, #2
//
//    movk w0, #7, lsl #16
//    movz w1, #15
//    sub w3, w0, w1, lsl 3
//  )");
//  EXPECT_EQ(getGeneralRegister<int32_t>(2), -2);
//  EXPECT_EQ(getGeneralRegister<uint32_t>(3), (7u << 16) - (15u << 3));
//
//  // 64-bit
//  RUN_AARCH64(R"(
//    mov x0, xzr
//    sub x2, x0, #2
//
//    movk x0, #7, lsl #48
//    movz x1, #15
//    sub x3, x0, x1, lsl 33
//  )");
//  EXPECT_EQ(getGeneralRegister<int64_t>(2), -2);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(3), (7ul << 48) - (15ul << 33));
//}
//
//// Test that NZCV flags are set correctly by 32-bit subs
//TEST_P(InstArithmetic, subsw) {
//  // 0 - 0 = 0
//  RUN_AARCH64(R"(
//    mov w0, wzr
//    subs w0, w0, #0
//  )");
//  EXPECT_EQ(getNZCV(), 0b0110);
//  EXPECT_EQ(getGeneralRegister<uint32_t>(0), 0u);
//
//  // 2 - 1 = 1
//  RUN_AARCH64(R"(
//    mov w0, #2
//    subs w0, w0, #1
//  )");
//  EXPECT_EQ(getNZCV(), 0b0010);
//  EXPECT_EQ(getGeneralRegister<uint32_t>(0), 1u);
//
//  // 0 - 1 = -1
//  RUN_AARCH64(R"(
//    mov w0, wzr
//    subs w0, w0, #1
//  )");
//  EXPECT_EQ(getNZCV(), 0b1000);
//  EXPECT_EQ(getGeneralRegister<uint32_t>(0), -1);
//
//  // (2^31 -1) - -1 = 2^31
//  RUN_AARCH64(R"(
//    mov w0, wzr
//    mov w1, #1
//    add w1, w0, w1, lsl #31
//    sub w1, w1, #1
//    sub w2, w0, #1
//    subs w0, w1, w2
//  )");
//  EXPECT_EQ(getNZCV(), 0b1001);
//  EXPECT_EQ(getGeneralRegister<uint32_t>(0), (1ul << 31));
//
//  // 2^31 - 0 = 2^31
//  RUN_AARCH64(R"(
//    mov w0, wzr
//    add w1, w0, #1
//    add w1, w0, w1, lsl #31
//    subs w0, w1, #0
//  )");
//  EXPECT_EQ(getNZCV(), 0b1010);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(0), (1u << 31));
//
//  // 2^31 - 1 = 2^31 - 1
//  RUN_AARCH64(R"(
//    mov w0, wzr
//    add w1, w0, #1
//    add w1, w0, w1, lsl #31
//    subs w0, w1, #1
//  )");
//  EXPECT_EQ(getNZCV(), 0b0011);
//  EXPECT_EQ(getGeneralRegister<uint32_t>(0), (1u << 31) - 1);
//
//  // (7 << 16) - (-1) [8-bit sign-extended]
//  RUN_AARCH64(R"(
//    movz w0, #7, lsl #16
//    movz w1, #15
//    # 255 will be -1 when sign-extended from 8-bits
//    mov w2, 255
//    subs w3, w0, w2, sxtb
//  )");
//  EXPECT_EQ(getNZCV(), 0b0000);
//  EXPECT_EQ(getGeneralRegister<uint32_t>(3), (7u << 16) + 1);
//
//  // (7 << 16) - (255 << 4)
//  RUN_AARCH64(R"(
//    movz w0, #7, lsl #16
//    movz w1, #15
//    mov w2, 255
//    subs w3, w0, w2, uxtx 4
//  )");
//  EXPECT_EQ(getNZCV(), 0b0010);
//  EXPECT_EQ(getGeneralRegister<uint32_t>(3), (7u << 16) - (255u << 4));
//}
//
//// Test that NZCV flags are set correctly by 64-bit subs
//TEST_P(InstArithmetic, subsx) {
//  // 0 - 0 = 0
//  RUN_AARCH64(R"(
//    mov x0, xzr
//    subs x0, x0, #0
//  )");
//  EXPECT_EQ(getNZCV(), 0b0110);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 0u);
//
//  // 2 - 1 = 1
//  RUN_AARCH64(R"(
//    mov x0, #2
//    subs x0, x0, #1
//  )");
//  EXPECT_EQ(getNZCV(), 0b0010);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(0), 1u);
//
//  // 0 - 1 = -1
//  RUN_AARCH64(R"(
//    mov x0, xzr
//    subs x0, x0, #1
//  )");
//  EXPECT_EQ(getNZCV(), 0b1000);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(0), -1);
//
//  // (2^63 -1) - -1 = 2^63
//  RUN_AARCH64(R"(
//    mov x0, xzr
//    add x1, x0, #1
//    add x1, x0, x1, lsl #63
//    sub x1, x1, #1
//    sub x2, x0, #1
//    subs x0, x1, x2
//  )");
//  EXPECT_EQ(getNZCV(), 0b1001);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(0), (1ul << 63));
//
//  // 2^63 - 0 = 2^63
//  RUN_AARCH64(R"(
//    mov x0, xzr
//    add x1, x0, #1
//    add x1, x0, x1, lsl #63
//    subs x0, x1, #0
//  )");
//  EXPECT_EQ(getNZCV(), 0b1010);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(0), (1ul << 63));
//
//  // 2^63 - 1 = 2^63 - 1
//  RUN_AARCH64(R"(
//    mov x0, xzr
//    add x1, x0, #1
//    add x1, x0, x1, lsl #63
//    subs x0, x1, #1
//  )");
//  EXPECT_EQ(getNZCV(), 0b0011);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(0), (1ul << 63) - 1);
//
//  // (7 << 48) - (15 << 33)
//  RUN_AARCH64(R"(
//    movz x0, #7, lsl #48
//    movz x1, #15
//    subs x2, x0, x1, lsl 33
//  )");
//  EXPECT_EQ(getNZCV(), 0b0010);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(2), (7ul << 48) - (15ul << 33));
//
//  // (7 << 48) - (-1) [8-bit sign-extended]
//  RUN_AARCH64(R"(
//    movz x0, #7, lsl #48
//    movz x1, #15
//    # 255 will be -1 when sign-extended from 8-bits
//    mov w2, 255
//    subs x3, x0, w2, sxtb
//  )");
//  EXPECT_EQ(getNZCV(), 0b0000);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(3), (7ul << 48) + 1);
//
//  // (7 << 48) - (255 << 4)
//  RUN_AARCH64(R"(
//    movz x0, #7, lsl #48
//    movz x1, #15
//    mov w2, 255
//    subs x3, x0, x2, uxtx 4
//  )");
//  EXPECT_EQ(getNZCV(), 0b0010);
//  EXPECT_EQ(getGeneralRegister<uint64_t>(3), (7ul << 48) - (255ul << 4));
//}
//
//INSTANTIATE_TEST_SUITE_P(AArch64, InstArithmetic, ::testing::Values(EMULATION),
//                         coreTypeToString);

}  // namespace
