#include "gtest/gtest.h"
#include "simeng/arch/aarch64/ArchInfo.hh"
#include "simeng/config/SimInfo.hh"
#include "simeng/version.hh"

namespace simeng {
namespace arch {
namespace aarch64 {

class AArch64ArchInfoTest : public ::testing::Test {
 public:
  AArch64ArchInfoTest() {
    simeng::config::SimInfo::setConfig(SIMENG_SOURCE_DIR
                                       "/configs/a64fx_SME.yaml");
  }

 protected:
  const std::vector<uint64_t> sysRegisterEnums = {
      arm64_sysreg::ARM64_SYSREG_DCZID_EL0,
      arm64_sysreg::ARM64_SYSREG_FPCR,
      arm64_sysreg::ARM64_SYSREG_FPSR,
      arm64_sysreg::ARM64_SYSREG_TPIDR_EL0,
      arm64_sysreg::ARM64_SYSREG_MIDR_EL1,
      arm64_sysreg::ARM64_SYSREG_CNTVCT_EL0,
      arm64_sysreg::ARM64_SYSREG_PMCCNTR_EL0,
      arm64_sysreg::ARM64_SYSREG_SVCR};

  const std::vector<simeng::RegisterFileStructure> archRegStruct = {
      {8, 32},
      {256, 32},
      {32, 17},
      {1, 1},
      {8, static_cast<uint16_t>(sysRegisterEnums.size())},
      {256, 64}};

  const std::vector<simeng::RegisterFileStructure> physRegStruct = {
      {8, 96},
      {256, 128},
      {32, 48},
      {1, 128},
      {8, static_cast<uint16_t>(sysRegisterEnums.size())},
      {256, 128}};

  const std::vector<uint16_t> physRegQuants = {
      96, 128, 48, 128, static_cast<uint16_t>(sysRegisterEnums.size()), 128};
};

// Test for the getSysRegEnums() function
TEST_F(AArch64ArchInfoTest, getSysRegEnums) {
  ArchInfo info = ArchInfo(config::SimInfo::getConfig());
  EXPECT_EQ(info.getSysRegEnums(), sysRegisterEnums);
}

// Test for the getArchRegStruct() function
TEST_F(AArch64ArchInfoTest, getArchRegStruct) {
  ArchInfo info = ArchInfo(config::SimInfo::getConfig());
  EXPECT_EQ(info.getArchRegStruct(), archRegStruct);
}

// Test for the getPhysRegStruct() function
TEST_F(AArch64ArchInfoTest, getPhysRegStruct) {
  ArchInfo info = ArchInfo(config::SimInfo::getConfig());
  EXPECT_EQ(info.getPhysRegStruct(), physRegStruct);
}

// Test for the getPhysRegQuantities() function
TEST_F(AArch64ArchInfoTest, getPhysRegQuantities) {
  ArchInfo info = ArchInfo(config::SimInfo::getConfig());
  EXPECT_EQ(info.getPhysRegQuantities(), physRegQuants);
}

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng