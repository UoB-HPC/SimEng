#pragma once

#include "simeng/arch/ArchInfo.hh"

namespace simeng {
namespace arch {
namespace aarch64 {

/** A class to hold and generate aarch64 specific architecture configuration
 * options. */
class ArchInfo : public simeng::arch::ArchInfo {
 public:
  ArchInfo() {
    // Set the supported aarch64 system register enums
    sysRegisterEnums_ = {arm64_sysreg::ARM64_SYSREG_DCZID_EL0,
                         arm64_sysreg::ARM64_SYSREG_FPCR,
                         arm64_sysreg::ARM64_SYSREG_FPSR,
                         arm64_sysreg::ARM64_SYSREG_TPIDR_EL0,
                         arm64_sysreg::ARM64_SYSREG_MIDR_EL1,
                         arm64_sysreg::ARM64_SYSREG_CNTVCT_EL0,
                         arm64_sysreg::ARM64_SYSREG_PMCCNTR_EL0,
                         arm64_sysreg::ARM64_SYSREG_SVCR};
  }

  /** Get the set of system register enums currently supported. */
  std::vector<uint64_t> getSysRegEnums(ryml::ConstNodeRef config) override {
    return sysRegisterEnums_;
  }

  /** Get the structure of the architecture register fileset(s). */
  std::vector<simeng::RegisterFileStructure> getArchRegStruct(
      ryml::ConstNodeRef config) override {
    // Given some register quantities rely on Config file arguments (SME
    // relies on SVL), it is possible that if the config was to change the
    // register quantities would be incorrect. This function provides a way to
    // reset the Architectural register structure.
    uint16_t ZAbits;
    config["Core"]["Streaming-Vector-Length"] >> ZAbits;
    const uint16_t ZAsize = ZAbits / 8;
    return {
        {8, 32},    // General purpose
        {256, 32},  // Vector
        {32, 17},   // Predicate
        {1, 1},     // NZCV
        {8, static_cast<uint16_t>(sysRegisterEnums_.size())},  // System
        {256, ZAsize}  // Matrix (Each row is a register)
    };
  }

 private:
  /** The vector of all system register Capstone enum values used in the
   * associated Architecture class. */
  std::vector<uint64_t> sysRegisterEnums_;
};

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng