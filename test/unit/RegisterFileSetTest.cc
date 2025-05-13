#include "gtest/gtest.h"
#include "simeng/RegisterFileSet.hh"

namespace simeng {
namespace pipeline {

class RegisterFileSetTest : public ::testing::Test {
 public:
  RegisterFileSetTest() : regFileSet(regFileStruct) {}

 protected:
  const std::vector<RegisterFileStructure> regFileStruct = {
      {8, 10}, {24, 15}, {256, 31}};

  RegisterFileSet regFileSet;
};

// Ensure RegisterFileSet is constructed correctly
TEST_F(RegisterFileSetTest, validConstruction) {
  for (uint8_t i = 0; i < regFileStruct.size(); i++) {
    for (uint16_t j = 0; j < regFileStruct[i].quantity; j++) {
      const Register reg = {i, j};
      EXPECT_EQ(regFileSet.get(reg), RegisterValue(0ull, regFileStruct[i].bytes));
    }
  }
}

// Ensure we can read and write values to the register file
TEST_F(RegisterFileSetTest, readWrite) {
  for (uint8_t i = 0; i < regFileStruct.size(); i++) {
    const uint16_t regSize = regFileStruct[i].bytes;
    const uint16_t maxRegTag = regFileStruct[i].quantity - 1;
    const Register r0 = {i, 0};
    const Register rMax = {i, maxRegTag};

    regFileSet.set(r0, RegisterValue(0ull, regSize));
    regFileSet.set(rMax, RegisterValue(0ull, regSize));

    EXPECT_EQ(regFileSet.get(r0), RegisterValue(0ull, regSize));
    EXPECT_EQ(regFileSet.get(rMax), RegisterValue(0ull, regSize));

    regFileSet.set(r0, RegisterValue(20ull, regSize));
    regFileSet.set(rMax, RegisterValue(40ull, regSize));

    EXPECT_EQ(regFileSet.get(r0), RegisterValue(20ull, regSize));
    EXPECT_EQ(regFileSet.get(rMax), RegisterValue(40ull, regSize));
  }
}

}  // namespace pipeline
}  // namespace simeng