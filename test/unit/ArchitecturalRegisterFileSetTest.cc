#include "gtest/gtest.h"
#include "simeng/ArchitecturalRegisterFileSet.hh"

namespace simeng {
namespace pipeline {

class ArchitecturalRegisterFileSetTest : public ::testing::Test {
 public:
  ArchitecturalRegisterFileSetTest()
      : physRegFileSet(regFileStruct), archRegFileSet(physRegFileSet) {}

 protected:
  const std::vector<RegisterFileStructure> regFileStruct = {
      {8, 10}, {24, 15}, {256, 31}};

  RegisterFileSet physRegFileSet;

  ArchitecturalRegisterFileSet archRegFileSet;
};

// Ensure we can read and write values to the architectural register file
TEST_F(ArchitecturalRegisterFileSetTest, readWrite) {
  for (uint8_t i = 0; i < regFileStruct.size(); i++) {
    const uint16_t regSize = regFileStruct[i].bytes;
    const uint16_t maxRegTag = regFileStruct[i].quantity - 1;
    const Register r0 = {i, 0};
    const Register rMax = {i, maxRegTag};

    EXPECT_EQ(archRegFileSet.get(r0), RegisterValue(0, regSize));
    EXPECT_EQ(archRegFileSet.get(rMax), RegisterValue(0, regSize));

    archRegFileSet.set(r0, RegisterValue(20, regSize));
    archRegFileSet.set(rMax, RegisterValue(40, regSize));

    EXPECT_EQ(archRegFileSet.get(r0), RegisterValue(20, regSize));
    EXPECT_EQ(archRegFileSet.get(rMax), RegisterValue(40, regSize));
  }
}

}  // namespace pipeline
}  // namespace simeng