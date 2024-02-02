#include "gtest/gtest.h"
#include "simeng/arch/riscv/ArchInfo.hh"
#include "simeng/config/SimInfo.hh"
#include "simeng/version.hh"

namespace simeng {
namespace arch {
namespace riscv {

class RiscVArchInfoTest : public ::testing::Test {
 public:
  RiscVArchInfoTest() {
    simeng::config::SimInfo::setConfig(SIMENG_SOURCE_DIR
                                       "/configs/DEMO_RISCV.yaml");
  }

 protected:
  const std::vector<uint64_t> sysRegisterEnums = {
      simeng::arch::riscv::riscv_sysreg::RISCV_SYSREG_FFLAGS,
      simeng::arch::riscv::riscv_sysreg::RISCV_SYSREG_FRM,
      simeng::arch::riscv::riscv_sysreg::RISCV_SYSREG_FCSR,
      simeng::arch::riscv::riscv_sysreg::RISCV_SYSREG_CYCLE,
      simeng::arch::riscv::riscv_sysreg::RISCV_SYSREG_TIME,
      simeng::arch::riscv::riscv_sysreg::RISCV_SYSREG_INSTRET};

  const std::vector<simeng::RegisterFileStructure> archRegStruct = {
      {8, 32}, {8, 32}, {8, static_cast<uint16_t>(sysRegisterEnums.size())}};

  const std::vector<simeng::RegisterFileStructure> physRegStruct = {
      {8, 154}, {8, 90}, {8, static_cast<uint16_t>(sysRegisterEnums.size())}};

  const std::vector<uint16_t> physRegQuants = {
      154, 90, static_cast<uint16_t>(sysRegisterEnums.size())};
};

// Test for the getSysRegEnums() function
TEST_F(RiscVArchInfoTest, getSysRegEnums) {
  ArchInfo info = ArchInfo(config::SimInfo::getConfig());
  EXPECT_EQ(info.getSysRegEnums(), sysRegisterEnums);
}

// Test for the getArchRegStruct() function
TEST_F(RiscVArchInfoTest, getArchRegStruct) {
  ArchInfo info = ArchInfo(config::SimInfo::getConfig());
  EXPECT_EQ(info.getArchRegStruct(), archRegStruct);
}

// Test for the getPhysRegStruct() function
TEST_F(RiscVArchInfoTest, getPhysRegStruct) {
  ArchInfo info = ArchInfo(config::SimInfo::getConfig());
  EXPECT_EQ(info.getPhysRegStruct(), physRegStruct);
}

// Test for the getPhysRegQuantities() function
TEST_F(RiscVArchInfoTest, getPhysRegQuantities) {
  ArchInfo info = ArchInfo(config::SimInfo::getConfig());
  EXPECT_EQ(info.getPhysRegQuantities(), physRegQuants);
}

}  // namespace riscv
}  // namespace arch
}  // namespace simeng