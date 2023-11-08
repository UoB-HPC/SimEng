#pragma once

#include "simeng/arch/ArchInfo.hh"

namespace simeng {
namespace arch {
namespace aarch64 {

/** A class to hold and generate aarch64 specific architecture configuration
 * options. */
class ArchInfo : public simeng::arch::ArchInfo {
 public:
  ArchInfo(ryml::ConstNodeRef config)
      : sysRegisterEnums_({arm64_sysreg::ARM64_SYSREG_DCZID_EL0,
                           arm64_sysreg::ARM64_SYSREG_FPCR,
                           arm64_sysreg::ARM64_SYSREG_FPSR,
                           arm64_sysreg::ARM64_SYSREG_TPIDR_EL0,
                           arm64_sysreg::ARM64_SYSREG_MIDR_EL1,
                           arm64_sysreg::ARM64_SYSREG_CNTVCT_EL0,
                           arm64_sysreg::ARM64_SYSREG_PMCCNTR_EL0,
                           arm64_sysreg::ARM64_SYSREG_SVCR}) {
    // Set the size of SME ZA in bytes by dividing the SVL by 8
    config["Core"]["Streaming-Vector-Length"] >> zaSize_;
    zaSize_ = zaSize_ / 8;
    // Generate the architecture-defined architectural register structure
    archRegStruct_ = {
        {8, 32},    // General purpose
        {256, 32},  // Vector
        {32, 17},   // Predicate
        {1, 1},     // NZCV
        {8, static_cast<uint16_t>(sysRegisterEnums_.size())},  // System
        {256, zaSize_}  // Matrix (Each row is a register)
    };

    // Generate the config-defined physical register structure and quantities
    ryml::ConstNodeRef regConfig = config["Register-Set"];
    uint16_t gpCnt;
    regConfig["GeneralPurpose-Count"] >> gpCnt;
    uint16_t fpCnt;
    regConfig["FloatingPoint/SVE-Count"] >> fpCnt;
    uint16_t predCnt;
    regConfig["Predicate-Count"] >> predCnt;
    uint16_t condCnt;
    regConfig["Conditional-Count"] >> condCnt;
    uint16_t matCnt;
    regConfig["Matrix-Count"] >> matCnt;
    // Matrix-Count multiplied by (SVL/8) as internal representation of
    // ZA is a block of row-vector-registers. Therefore we need to
    // convert physical counts from whole-ZA to rows-in-ZA.
    matCnt *= zaSize_;
    physRegStruct_ = {{8, gpCnt},
                      {256, fpCnt},
                      {32, predCnt},
                      {1, condCnt},
                      {8, static_cast<uint16_t>(sysRegisterEnums_.size())},
                      {256, matCnt}};
    physRegQuantities_ = {gpCnt,
                          fpCnt,
                          predCnt,
                          condCnt,
                          static_cast<uint16_t>(sysRegisterEnums_.size()),
                          matCnt};
  }

  /** Get the set of system register enums currently supported. */
  const std::vector<uint64_t>& getSysRegEnums() const override {
    return sysRegisterEnums_;
  }

  /** Get the structure of the architecture register fileset(s). */
  const std::vector<simeng::RegisterFileStructure>& getArchRegStruct()
      const override {
    return archRegStruct_;
  }

  /** Get the structure of the physical register fileset(s) as defined in the
   * simulation configuration. */
  const std::vector<simeng::RegisterFileStructure>& getPhysRegStruct()
      const override {
    return physRegStruct_;
  }

  /** Get the quantities of the physical register in each fileset as defined in
   * the simulation configuration. */
  const std::vector<uint16_t>& getPhysRegQuantities() const override {
    return physRegQuantities_;
  }

 private:
  /** The vector of all system register Capstone enum values used in the
   * associated Architecture class. */
  const std::vector<uint64_t> sysRegisterEnums_;

  /** The structure of the architectural register filesets within the
   * implemented aarch64 architecture. */
  std::vector<simeng::RegisterFileStructure> archRegStruct_;

  /** The structure of the physical register filesets within the
   * implemented aarch64 architecture. */
  std::vector<simeng::RegisterFileStructure> physRegStruct_;

  /** The quantities of the physical register within each filesets of the
   * implemented aarch64 architecture. */
  std::vector<uint16_t> physRegQuantities_;

  /** The size, in bytes, used by the aarch64 SME ZA register. */
  uint16_t zaSize_;
};

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng