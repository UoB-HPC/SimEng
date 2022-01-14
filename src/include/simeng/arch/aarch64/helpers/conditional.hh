#pragma once

#include "auxiliaryFunctions.hh"

namespace simeng {
namespace arch {
namespace aarch64 {
class conditionalHelp {
 public:
  /** Helper function for instructions with the format `cb<z,nz> rn, #imm`.
   */
  template <typename T>
  static std::tuple<bool, uint64_t> condBranch_cmpToZero(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
      const simeng::arch::aarch64::InstructionMetadata& metadata,
      uint64_t instructionAddress, std::function<bool(T)> func) {
    bool branchTaken;
    uint64_t branchAddress;
    if (func(operands[0].get<T>())) {
      branchTaken = true;
      branchAddress = instructionAddress + metadata.operands[1].imm;
    } else {
      branchTaken = false;
      branchAddress = instructionAddress + 4;
    }
    return {branchTaken, branchAddress};
  }

  /** Helper function for instructions with the format `ccmn rn, #imm #nzcv,
   * cc`.
   */
  template <typename T>
  static uint8_t ccmn_imm(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
      const simeng::arch::aarch64::InstructionMetadata& metadata) {
    if (AuxFunc::conditionHolds(metadata.cc, operands[0].get<uint8_t>())) {
      uint8_t nzcv;
      std::tie(std::ignore, nzcv) = AuxFunc::addWithCarry(
          operands[1].get<T>(), static_cast<T>(metadata.operands[1].imm), 0);
      return nzcv;
    }
    return static_cast<uint8_t>(metadata.operands[2].imm);
  }

  /** Helper function for instructions with the format `ccmp rn, #imm #nzcv,
   * cc`.
   */
  template <typename T>
  static uint8_t ccmp_imm(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
      const simeng::arch::aarch64::InstructionMetadata& metadata) {
    if (AuxFunc::conditionHolds(metadata.cc, operands[0].get<uint8_t>())) {
      uint8_t nzcv;
      std::tie(std::ignore, nzcv) = AuxFunc::addWithCarry(
          operands[1].get<T>(), ~static_cast<T>(metadata.operands[1].imm), 1);
      return nzcv;
    }
    return static_cast<uint8_t>(metadata.operands[2].imm);
  }

  /** Helper function for instructions with the format `ccmp rn, rm, #nzcv,
   * cc`.
   */
  template <typename T>
  static uint8_t ccmp_reg(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
      const simeng::arch::aarch64::InstructionMetadata& metadata) {
    if (AuxFunc::conditionHolds(metadata.cc, operands[0].get<uint8_t>())) {
      uint8_t nzcv;
      std::tie(std::ignore, nzcv) =
          AuxFunc::addWithCarry(operands[1].get<T>(), ~operands[2].get<T>(), 1);
      return nzcv;
    }
    return static_cast<uint8_t>(metadata.operands[2].imm);
  }

  /** Helper function for instructions with the format `cs<el, neg, inc, inv>
   * rd, rn, rm, cc`.
   */
  template <typename T>
  static T cs_4ops(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS>& operands,
      const simeng::arch::aarch64::InstructionMetadata& metadata,
      std::function<T(T)> func) {
    if (AuxFunc::conditionHolds(metadata.cc, operands[0].get<uint8_t>())) {
      return operands[1].get<T>();
    }
    return func(operands[2].get<T>());
  }
};
}  // namespace aarch64
}  // namespace arch
}  // namespace simeng