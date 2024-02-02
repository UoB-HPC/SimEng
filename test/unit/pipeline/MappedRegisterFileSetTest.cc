#include "gtest/gtest.h"
#include "simeng/pipeline/MappedRegisterFileSet.hh"

namespace simeng {
namespace pipeline {

class MappedRegisterFileSetTest : public ::testing::Test {
 public:
  MappedRegisterFileSetTest()
      : regFileSet(physRegFileStruct),
        rat(archRegFileStruct, physRegCounts),
        mappedRegFile(regFileSet, rat) {}

 protected:
  const std::vector<RegisterFileStructure> archRegFileStruct = {
      {8, 10}, {24, 15}, {256, 31}};
  const std::vector<RegisterFileStructure> physRegFileStruct = {
      {8, 20}, {24, 30}, {256, 62}};
  const std::vector<uint16_t> physRegCounts = {20, 30, 62};

  RegisterFileSet regFileSet;
  RegisterAliasTable rat;

  MappedRegisterFileSet mappedRegFile;
};

// Ensure that with continually changing physical-architectural register mapping
// changes, the correct register is being updated with set().
TEST_F(MappedRegisterFileSetTest, getSet) {
  // Loop through all register types
  for (uint8_t i = 0; i < archRegFileStruct.size(); i++) {
    // Keep allocating the same register to a) keep past values and b) more
    // easily verify correct functionality
    const uint16_t maxRegTag = archRegFileStruct[i].quantity - 1;
    const uint16_t regSize = archRegFileStruct[i].bytes;
    const Register rMax = {i, maxRegTag};

    std::vector<Register> physRegs;
    for (int j = 2; j < 12; j++) {
      physRegs.push_back(rat.allocate(rMax));
      RegisterValue regVal = RegisterValue(j, regSize);
      mappedRegFile.set(rMax, regVal);
      EXPECT_EQ(mappedRegFile.get(rMax), regVal);
    }

    for (int k = 0; k < 10; k++) {
      // RAT constructed where Arch-Phys mapping is 1:1. So, first re-mapped
      // value will be to maxArchRegRag + 1
      EXPECT_EQ(physRegs[k].tag, maxRegTag + k + 1);
      EXPECT_EQ(physRegs[k].type, i);
      EXPECT_EQ(regFileSet.get(physRegs[k]), RegisterValue(k + 2, regSize));
    }
  }
}
}  // namespace pipeline
}  // namespace simeng