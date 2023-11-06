#pragma once

#include "simeng/arch/ArchInfo.hh"

namespace simeng {
namespace arch {
namespace riscv {

/** A class to hold and generate riscv specific architecture configuration
 * options. */
class ArchInfo : public simeng::arch::ArchInfo {
 public:
  ArchInfo() {
    sysRegisterEnums_ = {
        riscv_sysreg::RISCV_SYSREG_FFLAGS, riscv_sysreg::RISCV_SYSREG_FRM,
        riscv_sysreg::RISCV_SYSREG_FCSR,   riscv_sysreg::RISCV_SYSREG_CYCLE,
        riscv_sysreg::RISCV_SYSREG_TIME,   riscv_sysreg::RISCV_SYSREG_INSTRET};
  }

  /** Get the set of system register enums currently supported. */
  std::vector<uint64_t> getSysRegEnums(ryml::ConstNodeRef config) override {
    return sysRegisterEnums_;
  }

  /** Get the structure of the architecture register fileset(s). */
  std::vector<simeng::RegisterFileStructure> getArchRegStruct(
      ryml::ConstNodeRef config) override {
    return {
        {8, 32},                                              // General purpose
        {8, 32},                                              // Floating Point
        {8, static_cast<uint16_t>(sysRegisterEnums_.size())}  // System
    };
  }

 private:
  /** The vector of all system register Capstone enum values used in the
   * associated Architecture class. */
  std::vector<uint64_t> sysRegisterEnums_;
};

}  // namespace riscv
}  // namespace arch
}  // namespace simeng