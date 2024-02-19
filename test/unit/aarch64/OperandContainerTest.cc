#include "gmock/gmock.h"
#include "simeng/RegisterValue.hh"
#include "simeng/arch/aarch64/operandContainer.hh"

namespace simeng {
namespace arch {
namespace aarch64 {

TEST(AArch64OperandContainerTest, correctInit) {
  operandContainer<std::string, MAX_SOURCE_REGISTERS> cont;

  EXPECT_EQ(cont.size(), MAX_SOURCE_REGISTERS);
  for (int i = 0; i < MAX_SOURCE_REGISTERS; i++) {
    EXPECT_EQ(cont[i], "");
  }

  // `resize()` will only work if std::vector is used. std::array should always
  // be used without a call to `makeSME()`
  cont.resize(MAX_SOURCE_REGISTERS * 2);
  EXPECT_EQ(cont.size(), MAX_SOURCE_REGISTERS);
};

TEST(AArch64OperandContainerTest, useVec) {
  operandContainer<std::string, MAX_SOURCE_REGISTERS> cont;
  EXPECT_EQ(cont.size(), MAX_SOURCE_REGISTERS);
  for (int i = 0; i < MAX_SOURCE_REGISTERS; i++) {
    EXPECT_EQ(cont[i], "");
  }

  // Initialise some of the data
  cont[0] = "elem0";
  cont[1] = "elem1";
  cont[2] = "elem2";

  // Convert to Vector
  cont.makeSME(10);
  // Check size is correct after makeSME call
  EXPECT_EQ(cont.size(), MAX_SOURCE_REGISTERS + ADDITIONAL_SME_REGISTERS + 10);
  // Check initialised data was maintained
  for (size_t i = 0; i < cont.size(); i++) {
    if (i == 0 || i == 1 || i == 2) {
      EXPECT_EQ(cont[i], "elem" + std::to_string(i));
    } else {
      EXPECT_EQ(cont[i], "");
    }
  }

  // Ensure re-size works as expected
  cont.resize(2);
  EXPECT_EQ(cont.size(), 2);
  EXPECT_EQ(cont[0], "elem0");
  EXPECT_EQ(cont[1], "elem1");
}

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng