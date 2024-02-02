#include "gtest/gtest.h"
#include "simeng/arch/aarch64/helpers/auxiliaryFunctions.hh"

namespace simeng {
namespace arch {
namespace aarch64 {

/** `nzcv` Tests */
TEST(AArch64AuxiliaryFunctionTest, NzcvTest) {
  EXPECT_EQ(nzcv(true, true, true, true), 0b00001111);
  EXPECT_EQ(nzcv(false, false, false, false), 0b00000000);
  EXPECT_EQ(nzcv(true, false, false, true), 0b00001001);
  EXPECT_EQ(nzcv(false, true, false, false), 0b00000100);
}

/** `addWithCarry` Tests */
TEST(AArch64AuxiliaryFunctionTest, AddWithCarry) {
  std::tuple<uint8_t, uint8_t> u8Res = {111, 0b0010};
  EXPECT_EQ(addWithCarry<uint8_t>(123, 244, false), u8Res);

  std::tuple<uint16_t, uint8_t> u16Res = {0xFFFD, 0b1000};
  EXPECT_EQ(addWithCarry<uint16_t>(0xFFF0, 0x000C, true), u16Res);

  std::tuple<uint32_t, uint8_t> u32Res = {2147483649, 0b1001};
  EXPECT_EQ(addWithCarry<uint32_t>(1, 2147483647, true), u32Res);

  std::tuple<uint64_t, uint8_t> u64Res = {0, 0b0110};
  EXPECT_EQ(addWithCarry<uint64_t>(0xFFFFFFFFFFFFFFFF, 1, false), u64Res);
}

/** `bitfieldManipulate` Tests */
TEST(AArch64AuxiliaryFunctionTest, BitfieldManipulate) {
  // uint8
  EXPECT_EQ(bitfieldManipulate<uint8_t>(0xFF, 12, 2, 1, false), 204);
  EXPECT_EQ(bitfieldManipulate<uint8_t>(16, 3, 0xFF, 24, false), 3);
  EXPECT_EQ(bitfieldManipulate<uint8_t>(0, 64, 4, 8, false), 64);
  EXPECT_EQ(bitfieldManipulate<uint8_t>(64, 0, 8, 4, false), 0);

  EXPECT_EQ(bitfieldManipulate<uint8_t>(0xFF, 12, 2, 1, true), 204);
  EXPECT_EQ(bitfieldManipulate<uint8_t>(16, 3, 0xFF, 24, true), 3);
  EXPECT_EQ(bitfieldManipulate<uint8_t>(0, 64, 4, 8, true), 0);
  EXPECT_EQ(bitfieldManipulate<uint8_t>(64, 8, 8, 4, true), 0);

  // uint16
  EXPECT_EQ(bitfieldManipulate<uint16_t>(0xFFFF, 12, 2, 1, false), 49164);
  EXPECT_EQ(bitfieldManipulate<uint16_t>(16, 3, 0xFF, 24, false), 3);
  EXPECT_EQ(bitfieldManipulate<uint16_t>(0, 64, 4, 8, false), 64);
  EXPECT_EQ(bitfieldManipulate<uint16_t>(64, 0, 8, 4, false), 0);

  EXPECT_EQ(bitfieldManipulate<uint16_t>(0xFFFF, 12, 2, 1, true), 49164);
  EXPECT_EQ(bitfieldManipulate<uint16_t>(16, 3, 0xFF, 24, true), 3);
  EXPECT_EQ(bitfieldManipulate<uint16_t>(0, 64, 4, 8, true), 0);
  EXPECT_EQ(bitfieldManipulate<uint16_t>(64, 8, 8, 4, true), 8);

  // uint32
  EXPECT_EQ(bitfieldManipulate<uint32_t>(0xFFFFFFFF, 12, 2, 1, false),
            3221225484);
  EXPECT_EQ(bitfieldManipulate<uint32_t>(16, 3, 0xFF, 24, false), 33);
  EXPECT_EQ(bitfieldManipulate<uint32_t>(0, 64, 4, 8, false), 64);
  EXPECT_EQ(bitfieldManipulate<uint32_t>(64, 0, 8, 4, false), 0);

  EXPECT_EQ(bitfieldManipulate<uint32_t>(0xFFFFFFFF, 12, 2, 1, true),
            3221225484);
  EXPECT_EQ(bitfieldManipulate<uint32_t>(16, 3, 0xFF, 24, true), 33);
  EXPECT_EQ(bitfieldManipulate<uint32_t>(0, 64, 4, 8, true), 0);
  EXPECT_EQ(bitfieldManipulate<uint32_t>(64, 8, 8, 4, true), 8);

  // uint64
  EXPECT_EQ(bitfieldManipulate<uint64_t>(0xFFFFFFFFFFFFFFFF, 12, 2, 1, false),
            13835058055282163724u);
  EXPECT_EQ(bitfieldManipulate<uint64_t>(16, 3, 0xFF, 24, false), 33);
  EXPECT_EQ(bitfieldManipulate<uint64_t>(0, 64, 4, 8, false), 64);
  EXPECT_EQ(bitfieldManipulate<uint64_t>(64, 0, 8, 4, false), 0);

  EXPECT_EQ(bitfieldManipulate<uint64_t>(0xFFFFFFFFFFFFFFFF, 12, 2, 1, true),
            13835058055282163724u);
  EXPECT_EQ(bitfieldManipulate<uint64_t>(16, 3, 0xFF, 24, true), 33);
  EXPECT_EQ(bitfieldManipulate<uint64_t>(0, 64, 4, 8, true), 0);
  EXPECT_EQ(bitfieldManipulate<uint64_t>(64, 8, 8, 4, true), 8);
}

/** `conditionHolds` Tests */
TEST(AArch64AuxiliaryFunctionTest, ConditionHolds) {
  // Run each condition at least twice, one which we expect to be true, one we
  // expect to be false

  // Inverse False
  // EQ/NE
  EXPECT_TRUE(conditionHolds(0b0000, 0b0100));
  EXPECT_FALSE(conditionHolds(0b0000, 0b1011));

  // CS/CC
  EXPECT_TRUE(conditionHolds(0b0010, 0b0010));
  EXPECT_FALSE(conditionHolds(0b0010, 0b1101));

  // MI/PL
  EXPECT_TRUE(conditionHolds(0b0100, 0b1000));
  EXPECT_FALSE(conditionHolds(0b0100, 0b0111));

  // VS/VC
  EXPECT_TRUE(conditionHolds(0b0110, 0b0001));
  EXPECT_FALSE(conditionHolds(0b0110, 0b1110));

  // HI/LS
  EXPECT_TRUE(conditionHolds(0b1000, 0b1010));
  EXPECT_FALSE(conditionHolds(0b1000, 0b1111));
  EXPECT_FALSE(conditionHolds(0b1000, 0b1001));

  // GE/LT
  EXPECT_TRUE(conditionHolds(0b1010, 0b1001));
  EXPECT_TRUE(conditionHolds(0b1010, 0b0000));
  EXPECT_FALSE(conditionHolds(0b1010, 0b1000));

  // GT/LE
  EXPECT_TRUE(conditionHolds(0b1100, 0b1001));
  EXPECT_TRUE(conditionHolds(0b1100, 0b0000));
  EXPECT_FALSE(conditionHolds(0b1100, 0b0001));
  EXPECT_FALSE(conditionHolds(0b1100, 0b1000));
  EXPECT_FALSE(conditionHolds(0b1100, 0b1101));

  // Condition of 0b111 always returns `true`
  // AL
  EXPECT_TRUE(conditionHolds(0b1110, 0b1111));
  EXPECT_TRUE(conditionHolds(0b1110, 0b0000));

  // Inverse True
  // EQ/NE
  EXPECT_FALSE(conditionHolds(0b0001, 0b0100));
  EXPECT_TRUE(conditionHolds(0b0001, 0b1011));

  // CS/CC
  EXPECT_FALSE(conditionHolds(0b0011, 0b0010));
  EXPECT_TRUE(conditionHolds(0b0011, 0b1101));

  // MI/PL
  EXPECT_FALSE(conditionHolds(0b0101, 0b1000));
  EXPECT_TRUE(conditionHolds(0b0101, 0b0111));

  // VS/VC
  EXPECT_FALSE(conditionHolds(0b0111, 0b0001));
  EXPECT_TRUE(conditionHolds(0b0111, 0b1110));

  // HI/LS
  EXPECT_FALSE(conditionHolds(0b1001, 0b1010));
  EXPECT_TRUE(conditionHolds(0b1001, 0b1111));
  EXPECT_TRUE(conditionHolds(0b1001, 0b1001));

  // GE/LT
  EXPECT_FALSE(conditionHolds(0b1011, 0b1001));
  EXPECT_FALSE(conditionHolds(0b1011, 0b0000));
  EXPECT_TRUE(conditionHolds(0b1011, 0b1000));

  // GT/LE
  EXPECT_FALSE(conditionHolds(0b1101, 0b1001));
  EXPECT_FALSE(conditionHolds(0b1101, 0b0000));
  EXPECT_TRUE(conditionHolds(0b1101, 0b0001));
  EXPECT_TRUE(conditionHolds(0b1101, 0b1000));
  EXPECT_TRUE(conditionHolds(0b1101, 0b1101));

  // AL
  // Cond=0b111 and inverse of 1 always returns `true`
  EXPECT_TRUE(conditionHolds(0b1111, 0b1111));
  EXPECT_TRUE(conditionHolds(0b1111, 0b0000));
}

/** `extendValue` Tests */
TEST(AArch64AuxiliaryFunctionTest, ExtendValue) {
  // Test special case
  EXPECT_EQ(extendValue(123, ARM64_EXT_INVALID, 0), 123);

  // Results validated on XCI and A64FX hardware
  EXPECT_EQ(extendValue(270, ARM64_EXT_UXTB, 3), 112);
  EXPECT_EQ(extendValue(65560, ARM64_EXT_UXTH, 3), 192);
  EXPECT_EQ(extendValue(0xFFFFFFFF, ARM64_EXT_UXTW, 3), 34359738360);
  EXPECT_EQ(extendValue(0x0F0F0F0F0F0F0F01, ARM64_EXT_UXTX, 4),
            0xF0F0F0F0F0F0F010);

  EXPECT_EQ(extendValue(133, ARM64_EXT_SXTB, 3), -984);
  EXPECT_EQ(extendValue(32768, ARM64_EXT_SXTH, 3), -262144);
  EXPECT_EQ(extendValue(2147483648, ARM64_EXT_SXTW, 3), -17179869184);
  EXPECT_EQ(extendValue(0x8000000000000000, ARM64_EXT_SXTX, 3), 0);
}

/** `getNZCVfromPred` Tests */
TEST(AArch64AuxiliaryFunctionTest, getNZCVfromPred) {
  uint64_t vl = 128;
  // VL 128 will only use array[0]
  EXPECT_EQ(getNZCVfromPred(
                {0, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF},
                vl, 1),
            0b0110);
  EXPECT_EQ(
      getNZCVfromPred({0xFFFFFFFFFFFFFFFF, 0, 0, 0x300000000000000C}, vl, 2),
      0b1000);
  EXPECT_EQ(getNZCVfromPred(
                {0xE000000000000000, 0xE000000000000000, 0xE000000000000000, 0},
                vl, 4),
            0b0010);
  EXPECT_EQ(getNZCVfromPred({0, 0x8000000000000001, 0, 0}, vl, 8), 0b0110);

  vl = 256;
  // VL 256 will only use array[0]
  EXPECT_EQ(getNZCVfromPred(
                {0, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF},
                vl, 1),
            0b0110);
  EXPECT_EQ(
      getNZCVfromPred({0xFFFFFFFFFFFFFFFF, 0, 0, 0x300000000000000C}, vl, 2),
      0b1000);
  EXPECT_EQ(getNZCVfromPred(
                {0xE000000000000000, 0xE000000000000000, 0xE000000000000000, 0},
                vl, 4),
            0b0010);
  EXPECT_EQ(getNZCVfromPred({0, 0x8000000000000001, 0, 0}, vl, 8), 0b0110);

  vl = 512;
  // VL 512 will only use array[0]
  EXPECT_EQ(getNZCVfromPred(
                {0, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF},
                vl, 1),
            0b0110);
  EXPECT_EQ(
      getNZCVfromPred({0xFFFFFFFFFFFFFFFF, 0, 0, 0x300000000000000C}, vl, 2),
      0b1000);
  EXPECT_EQ(getNZCVfromPred(
                {0xE000000000000000, 0xE000000000000000, 0xE000000000000000, 0},
                vl, 4),
            0b0010);
  EXPECT_EQ(getNZCVfromPred({0, 0x8000000000000001, 0, 0}, vl, 8), 0b0110);

  vl = 1024;
  // VL 1024 will only use array[0, 1]
  EXPECT_EQ(getNZCVfromPred(
                {0, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF},
                vl, 1),
            0b0000);
  EXPECT_EQ(
      getNZCVfromPred({0xFFFFFFFFFFFFFFFF, 0, 0, 0x300000000000000C}, vl, 2),
      0b1010);
  EXPECT_EQ(getNZCVfromPred(
                {0xE000000000000000, 0xE000000000000000, 0xE000000000000000, 0},
                vl, 4),
            0b0010);
  EXPECT_EQ(getNZCVfromPred({0, 0x8000000000000000, 0, 0}, vl, 8), 0b0010);

  vl = 2048;
  // VL 2048 will only use array[0, 1, 2, 3]
  EXPECT_EQ(getNZCVfromPred(
                {0, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF},
                vl, 1),
            0b0000);
  EXPECT_EQ(
      getNZCVfromPred({0xFFFFFFFFFFFFFFFF, 0, 0, 0x300000000000000C}, vl, 2),
      0b1010);
  EXPECT_EQ(getNZCVfromPred(
                {0xE000000000000000, 0xE000000000000000, 0xE000000000000000, 0},
                vl, 4),
            0b0010);
  EXPECT_EQ(getNZCVfromPred({0, 0x8000000000000001, 0, 0}, vl, 8), 0b0010);
}

/** `mulhi` Tests */
TEST(AArch64AuxiliaryFunctionTest, Mulhi) {
  EXPECT_EQ(mulhi(0xFFFFFFFFFFFFFFFF, 2), 1);
  EXPECT_EQ(mulhi(1, 245), 0);

  EXPECT_EQ(mulhi(0xF000000000000000, 4), 3);
  EXPECT_EQ(mulhi(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF), 0xFFFFFFFFFFFFFFFE);
  EXPECT_EQ(mulhi(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF00000000), 0xFFFFFFFEFFFFFFFF);
  EXPECT_EQ(mulhi(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF), 0xFFFFFFFE);
}

/** `sveGetPattern` Tests */
TEST(AArch64AuxiliaryFunctionTest, sveGetPattern) {
  uint16_t vl = 128;
  EXPECT_EQ(sveGetPattern("", 64, vl), 2);
  EXPECT_EQ(sveGetPattern("", 16, vl), 8);
  EXPECT_EQ(sveGetPattern("all", 64, vl), 2);
  EXPECT_EQ(sveGetPattern("all", 16, vl), 8);
  EXPECT_EQ(sveGetPattern("notValid", 64, vl), 2);
  EXPECT_EQ(sveGetPattern("notValid", 16, vl), 8);

  EXPECT_EQ(sveGetPattern("vl1", 64, vl), 1);
  EXPECT_EQ(sveGetPattern("vl2", 64, vl), 2);
  EXPECT_EQ(sveGetPattern("vl3", 64, vl), 0);
  EXPECT_EQ(sveGetPattern("vl4", 64, vl), 0);
  EXPECT_EQ(sveGetPattern("vl5", 64, vl), 0);
  EXPECT_EQ(sveGetPattern("vl6", 64, vl), 0);
  EXPECT_EQ(sveGetPattern("vl7", 64, vl), 0);
  EXPECT_EQ(sveGetPattern("vl8", 64, vl), 0);
  EXPECT_EQ(sveGetPattern("vl16", 64, vl), 0);
  EXPECT_EQ(sveGetPattern("vl32", 64, vl), 0);
  EXPECT_EQ(sveGetPattern("vl64", 64, vl), 0);
  EXPECT_EQ(sveGetPattern("vl128", 64, vl), 0);
  EXPECT_EQ(sveGetPattern("vl256", 64, vl), 0);

  EXPECT_EQ(sveGetPattern("mul4", 8, vl), 16);
  EXPECT_EQ(sveGetPattern("mul3", 8, vl), 15);

  vl = 256;
  EXPECT_EQ(sveGetPattern("", 64, vl), 4);
  EXPECT_EQ(sveGetPattern("", 16, vl), 16);
  EXPECT_EQ(sveGetPattern("all", 64, vl), 4);
  EXPECT_EQ(sveGetPattern("all", 16, vl), 16);
  EXPECT_EQ(sveGetPattern("notValid", 64, vl), 4);
  EXPECT_EQ(sveGetPattern("notValid", 16, vl), 16);

  EXPECT_EQ(sveGetPattern("vl1", 64, vl), 1);
  EXPECT_EQ(sveGetPattern("vl2", 64, vl), 2);
  EXPECT_EQ(sveGetPattern("vl3", 64, vl), 3);
  EXPECT_EQ(sveGetPattern("vl4", 64, vl), 4);
  EXPECT_EQ(sveGetPattern("vl5", 64, vl), 0);
  EXPECT_EQ(sveGetPattern("vl6", 64, vl), 0);
  EXPECT_EQ(sveGetPattern("vl7", 64, vl), 0);
  EXPECT_EQ(sveGetPattern("vl8", 64, vl), 0);
  EXPECT_EQ(sveGetPattern("vl16", 64, vl), 0);
  EXPECT_EQ(sveGetPattern("vl32", 64, vl), 0);
  EXPECT_EQ(sveGetPattern("vl64", 64, vl), 0);
  EXPECT_EQ(sveGetPattern("vl128", 64, vl), 0);
  EXPECT_EQ(sveGetPattern("vl256", 64, vl), 0);

  EXPECT_EQ(sveGetPattern("mul4", 8, vl), 32);
  EXPECT_EQ(sveGetPattern("mul3", 8, vl), 30);

  vl = 512;
  EXPECT_EQ(sveGetPattern("", 64, vl), 8);
  EXPECT_EQ(sveGetPattern("", 16, vl), 32);
  EXPECT_EQ(sveGetPattern("all", 64, vl), 8);
  EXPECT_EQ(sveGetPattern("all", 16, vl), 32);
  EXPECT_EQ(sveGetPattern("notValid", 64, vl), 8);
  EXPECT_EQ(sveGetPattern("notValid", 16, vl), 32);

  EXPECT_EQ(sveGetPattern("vl1", 64, vl), 1);
  EXPECT_EQ(sveGetPattern("vl2", 64, vl), 2);
  EXPECT_EQ(sveGetPattern("vl3", 64, vl), 3);
  EXPECT_EQ(sveGetPattern("vl4", 64, vl), 4);
  EXPECT_EQ(sveGetPattern("vl5", 64, vl), 5);
  EXPECT_EQ(sveGetPattern("vl6", 64, vl), 6);
  EXPECT_EQ(sveGetPattern("vl7", 64, vl), 7);
  EXPECT_EQ(sveGetPattern("vl8", 64, vl), 8);
  EXPECT_EQ(sveGetPattern("vl16", 64, vl), 0);
  EXPECT_EQ(sveGetPattern("vl32", 64, vl), 0);
  EXPECT_EQ(sveGetPattern("vl64", 64, vl), 0);
  EXPECT_EQ(sveGetPattern("vl128", 64, vl), 0);
  EXPECT_EQ(sveGetPattern("vl256", 64, vl), 0);

  EXPECT_EQ(sveGetPattern("mul4", 8, vl), 64);
  EXPECT_EQ(sveGetPattern("mul3", 8, vl), 63);

  vl = 1024;
  EXPECT_EQ(sveGetPattern("", 64, vl), 16);
  EXPECT_EQ(sveGetPattern("", 16, vl), 64);
  EXPECT_EQ(sveGetPattern("all", 64, vl), 16);
  EXPECT_EQ(sveGetPattern("all", 16, vl), 64);
  EXPECT_EQ(sveGetPattern("notValid", 64, vl), 16);
  EXPECT_EQ(sveGetPattern("notValid", 16, vl), 64);

  EXPECT_EQ(sveGetPattern("vl1", 64, vl), 1);
  EXPECT_EQ(sveGetPattern("vl2", 64, vl), 2);
  EXPECT_EQ(sveGetPattern("vl3", 64, vl), 3);
  EXPECT_EQ(sveGetPattern("vl4", 64, vl), 4);
  EXPECT_EQ(sveGetPattern("vl5", 64, vl), 5);
  EXPECT_EQ(sveGetPattern("vl6", 64, vl), 6);
  EXPECT_EQ(sveGetPattern("vl7", 64, vl), 7);
  EXPECT_EQ(sveGetPattern("vl8", 64, vl), 8);
  EXPECT_EQ(sveGetPattern("vl16", 64, vl), 16);
  EXPECT_EQ(sveGetPattern("vl32", 64, vl), 0);
  EXPECT_EQ(sveGetPattern("vl64", 64, vl), 0);
  EXPECT_EQ(sveGetPattern("vl128", 64, vl), 0);
  EXPECT_EQ(sveGetPattern("vl256", 64, vl), 0);

  EXPECT_EQ(sveGetPattern("mul4", 8, vl), 128);
  EXPECT_EQ(sveGetPattern("mul3", 8, vl), 126);

  vl = 2048;
  EXPECT_EQ(sveGetPattern("", 64, vl), 32);
  EXPECT_EQ(sveGetPattern("", 16, vl), 128);
  EXPECT_EQ(sveGetPattern("all", 64, vl), 32);
  EXPECT_EQ(sveGetPattern("all", 16, vl), 128);
  EXPECT_EQ(sveGetPattern("notValid", 64, vl), 32);
  EXPECT_EQ(sveGetPattern("notValid", 16, vl), 128);

  EXPECT_EQ(sveGetPattern("vl1", 64, vl), 1);
  EXPECT_EQ(sveGetPattern("vl2", 64, vl), 2);
  EXPECT_EQ(sveGetPattern("vl3", 64, vl), 3);
  EXPECT_EQ(sveGetPattern("vl4", 64, vl), 4);
  EXPECT_EQ(sveGetPattern("vl5", 64, vl), 5);
  EXPECT_EQ(sveGetPattern("vl6", 64, vl), 6);
  EXPECT_EQ(sveGetPattern("vl7", 64, vl), 7);
  EXPECT_EQ(sveGetPattern("vl8", 64, vl), 8);
  EXPECT_EQ(sveGetPattern("vl16", 64, vl), 16);
  EXPECT_EQ(sveGetPattern("vl32", 64, vl), 32);
  EXPECT_EQ(sveGetPattern("vl64", 64, vl), 0);
  EXPECT_EQ(sveGetPattern("vl128", 64, vl), 0);
  EXPECT_EQ(sveGetPattern("vl256", 64, vl), 0);

  EXPECT_EQ(sveGetPattern("mul4", 8, vl), 256);
  EXPECT_EQ(sveGetPattern("mul3", 8, vl), 255);
}

/** `ShiftValue` Tests */
TEST(AArch64AuxiliaryFunctionTest, ShiftValueTest_LSL) {
  // 8-bit
  const uint8_t a = 0x0F;
  EXPECT_EQ(shiftValue(a, ARM64_SFT_LSL, 4), 0xF0);

  const uint8_t b = 0xF0;
  EXPECT_EQ(shiftValue(b, ARM64_SFT_LSL, 7), 0x00);

  EXPECT_EQ(shiftValue(b, ARM64_SFT_LSL, 0), b);

  // 16-bit
  const uint16_t c = 0x00FF;
  EXPECT_EQ(shiftValue(c, ARM64_SFT_LSL, 8), 0xFF00);

  const uint16_t d = 0xFF00;
  EXPECT_EQ(shiftValue(d, ARM64_SFT_LSL, 15), 0x0000);

  EXPECT_EQ(shiftValue(d, ARM64_SFT_LSL, 0), d);

  // 32-bit
  const uint32_t e = 0x0000FFFF;
  EXPECT_EQ(shiftValue(e, ARM64_SFT_LSL, 16), 0xFFFF0000);

  const uint32_t f = 0xFFFF0000;
  EXPECT_EQ(shiftValue(f, ARM64_SFT_LSL, 31), 0x00000000);

  EXPECT_EQ(shiftValue(f, ARM64_SFT_LSL, 0), f);

  // 64-bit
  const uint64_t g = 0x00000000FFFFFFFF;
  EXPECT_EQ(shiftValue(g, ARM64_SFT_LSL, 32), 0xFFFFFFFF00000000);

  const uint64_t h = 0xFFFFFFFF00000000;
  EXPECT_EQ(shiftValue(h, ARM64_SFT_LSL, 63), 0x0000000000000000);

  EXPECT_EQ(shiftValue(h, ARM64_SFT_LSL, 0), h);
}

TEST(AArch64AuxiliaryFunctionTest, ShiftValueTest_LSR) {
  // 8-bit
  const uint8_t a = 0x0F;
  EXPECT_EQ(shiftValue(a, ARM64_SFT_LSR, 4), 0x00);

  const uint8_t b = 0xF0;
  EXPECT_EQ(shiftValue(b, ARM64_SFT_LSR, 7), 0x01);

  EXPECT_EQ(shiftValue(b, ARM64_SFT_LSR, 0), b);

  // 16-bit
  const uint16_t c = 0x00FF;
  EXPECT_EQ(shiftValue(c, ARM64_SFT_LSR, 8), 0x0);

  const uint16_t d = 0xFF00;
  EXPECT_EQ(shiftValue(d, ARM64_SFT_LSR, 15), 0x0001);

  EXPECT_EQ(shiftValue(d, ARM64_SFT_LSR, 0), d);

  // 32-bit
  const uint32_t e = 0x0000FFFF;
  EXPECT_EQ(shiftValue(e, ARM64_SFT_LSR, 16), 0x00000000);

  const uint32_t f = 0xFFFF0000;
  EXPECT_EQ(shiftValue(f, ARM64_SFT_LSR, 31), 0x00000001);

  EXPECT_EQ(shiftValue(f, ARM64_SFT_LSR, 0), f);

  // 64-bit
  const uint64_t g = 0x00000000FFFFFFFF;
  EXPECT_EQ(shiftValue(g, ARM64_SFT_LSR, 32), 0x0000000000000000);

  const uint64_t h = 0xFFFFFFFF00000000;
  EXPECT_EQ(shiftValue(h, ARM64_SFT_LSR, 63), 0x0000000000000001);

  EXPECT_EQ(shiftValue(h, ARM64_SFT_LSR, 0), h);
}

TEST(AArch64AuxiliaryFunctionTest, ShiftValueTest_ASR) {
  // 8-bit
  const uint8_t a = 0x0F;
  EXPECT_EQ(shiftValue(a, ARM64_SFT_ASR, 4), 0x00);

  const uint8_t b = 0xF0;
  EXPECT_EQ(shiftValue(b, ARM64_SFT_ASR, 7), 0xFF);

  EXPECT_EQ(shiftValue(b, ARM64_SFT_ASR, 0), b);

  // 16-bit
  const uint16_t c = 0x00FF;
  EXPECT_EQ(shiftValue(c, ARM64_SFT_ASR, 8), 0x0000);

  const uint16_t d = 0xFF00;
  EXPECT_EQ(shiftValue(d, ARM64_SFT_ASR, 15), 0xFFFF);

  EXPECT_EQ(shiftValue(d, ARM64_SFT_ASR, 0), d);

  // 32-bit
  const uint32_t e = 0x0000FFFF;
  EXPECT_EQ(shiftValue(e, ARM64_SFT_ASR, 16), 0x00000000);

  const uint32_t f = 0xFFFF0000;
  EXPECT_EQ(shiftValue(f, ARM64_SFT_ASR, 31), 0xFFFFFFFF);

  EXPECT_EQ(shiftValue(f, ARM64_SFT_ASR, 0), f);

  // 64-bit
  const uint64_t g = 0x00000000FFFFFFFF;
  EXPECT_EQ(shiftValue(g, ARM64_SFT_ASR, 32), 0x0000000000000000);

  const uint64_t h = 0xFFFFFFFF00000000;
  EXPECT_EQ(shiftValue(h, ARM64_SFT_ASR, 63), 0xFFFFFFFFFFFFFFFF);

  EXPECT_EQ(shiftValue(h, ARM64_SFT_ASR, 0), h);
}

TEST(AArch64AuxiliaryFunctionTest, ShiftValueTest_ROR) {
  // 8-bit
  const uint8_t a = 0x0F;
  EXPECT_EQ(shiftValue(a, ARM64_SFT_ROR, 4), 0xF0);

  const uint8_t b = 0xF0;
  EXPECT_EQ(shiftValue(b, ARM64_SFT_ROR, 7), 0xE1);

  EXPECT_EQ(shiftValue(b, ARM64_SFT_ROR, 0), b);

  // 16-bit
  const uint16_t c = 0x00FF;
  EXPECT_EQ(shiftValue(c, ARM64_SFT_ROR, 8), 0xFF00);

  const uint16_t d = 0xFF00;
  EXPECT_EQ(shiftValue(d, ARM64_SFT_ROR, 15), 0xFE01);

  EXPECT_EQ(shiftValue(d, ARM64_SFT_ROR, 0), d);

  // 32-bit
  const uint32_t e = 0x0000FFFF;
  EXPECT_EQ(shiftValue(e, ARM64_SFT_ROR, 16), 0xFFFF0000);

  const uint32_t f = 0xFFFF0000;
  EXPECT_EQ(shiftValue(f, ARM64_SFT_ROR, 31), 0xFFFE0001);

  EXPECT_EQ(shiftValue(f, ARM64_SFT_ROR, 0), f);

  // 64-bit
  const uint64_t g = 0x00000000FFFFFFFF;
  EXPECT_EQ(shiftValue(g, ARM64_SFT_ROR, 32), 0xFFFFFFFF00000000);

  const uint64_t h = 0xFFFFFFFF00000000;
  EXPECT_EQ(shiftValue(h, ARM64_SFT_ROR, 63), 0xFFFFFFFE00000001);

  EXPECT_EQ(shiftValue(h, ARM64_SFT_ROR, 0), h);
}

TEST(AArch64AuxiliaryFunctionTest, ShiftValueTest_MSL) {
  // 8-bit
  const uint8_t a = 0x0F;
  EXPECT_EQ(shiftValue(a, ARM64_SFT_MSL, 4), 0xFF);

  const uint8_t b = 0xF0;
  EXPECT_EQ(shiftValue(b, ARM64_SFT_MSL, 7), 0x7F);

  EXPECT_EQ(shiftValue(b, ARM64_SFT_MSL, 0), b);

  // 16-bit
  const uint16_t c = 0x00FF;
  EXPECT_EQ(shiftValue(c, ARM64_SFT_MSL, 8), 0xFFFF);

  const uint16_t d = 0xFF00;
  EXPECT_EQ(shiftValue(d, ARM64_SFT_MSL, 15), 0x7FFF);

  EXPECT_EQ(shiftValue(d, ARM64_SFT_MSL, 0), d);

  // 32-bit
  const uint32_t e = 0x0000FFFF;
  EXPECT_EQ(shiftValue(e, ARM64_SFT_MSL, 16), 0xFFFFFFFF);

  const uint32_t f = 0xFFFF0000;
  EXPECT_EQ(shiftValue(f, ARM64_SFT_MSL, 31), 0x7FFFFFFF);

  EXPECT_EQ(shiftValue(f, ARM64_SFT_MSL, 0), f);

  // 64-bit
  const uint64_t g = 0x00000000FFFFFFFF;
  EXPECT_EQ(shiftValue(g, ARM64_SFT_MSL, 32), 0xFFFFFFFFFFFFFFFF);

  const uint64_t h = 0xFFFFFFFF00000000;
  EXPECT_EQ(shiftValue(h, ARM64_SFT_MSL, 63), 0x7FFFFFFFFFFFFFFF);

  EXPECT_EQ(shiftValue(h, ARM64_SFT_MSL, 0), h);
}

TEST(AArch64AuxiliaryFunctionTest, ShiftValueTest_INVALID) {
  // 8-bit
  const uint8_t a = 0x0F;
  EXPECT_EQ(shiftValue(a, ARM64_SFT_INVALID, 4), a);

  const uint8_t b = 0xF0;
  EXPECT_EQ(shiftValue(b, ARM64_SFT_INVALID, 7), b);

  EXPECT_EQ(shiftValue(b, ARM64_SFT_INVALID, 0), b);

  // 16-bit
  const uint16_t c = 0x00FF;
  EXPECT_EQ(shiftValue(c, ARM64_SFT_INVALID, 8), c);

  const uint16_t d = 0xFF00;
  EXPECT_EQ(shiftValue(d, ARM64_SFT_INVALID, 15), d);

  EXPECT_EQ(shiftValue(d, ARM64_SFT_INVALID, 0), d);

  // 32-bit
  const uint32_t e = 0x0000FFFF;
  EXPECT_EQ(shiftValue(e, ARM64_SFT_INVALID, 16), e);

  const uint32_t f = 0xFFFF0000;
  EXPECT_EQ(shiftValue(f, ARM64_SFT_INVALID, 31), f);

  EXPECT_EQ(shiftValue(f, ARM64_SFT_INVALID, 0), f);

  // 64-bit
  const uint64_t g = 0x00000000FFFFFFFF;
  EXPECT_EQ(shiftValue(g, ARM64_SFT_INVALID, 32), g);

  const uint64_t h = 0xFFFFFFFF00000000;
  EXPECT_EQ(shiftValue(h, ARM64_SFT_INVALID, 63), h);

  EXPECT_EQ(shiftValue(h, ARM64_SFT_INVALID, 0), h);
}

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng