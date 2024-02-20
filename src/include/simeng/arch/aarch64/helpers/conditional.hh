#pragma once

#include "auxiliaryFunctions.hh"

namespace simeng {
namespace arch {
namespace aarch64 {

/** Helper function for instructions with the format `ccmn rn, #imm #nzcv,
 * cc`.
 * T represents the type of sourceValues (e.g. for xn, T = uint64_t).
 * Returns single value of type uint8_t. */
template <typename T>
uint8_t ccmn_imm(srcValContainer& sourceValues,
                 const simeng::arch::aarch64::InstructionMetadata& metadata) {
  if (conditionHolds(metadata.cc, sourceValues[0].get<uint8_t>())) {
    uint8_t nzcv;
    std::tie(std::ignore, nzcv) = addWithCarry(
        sourceValues[1].get<T>(), static_cast<T>(metadata.operands[1].imm), 0);
    return nzcv;
  }
  return static_cast<uint8_t>(metadata.operands[2].imm);
}

/** Helper function for instructions with the format `ccmp rn, #imm #nzcv,
 * cc`.
 * T represents the type of sourceValues (e.g. for xn, T = uint64_t).
 * Returns single value of type uint8_t. */
template <typename T>
uint8_t ccmp_imm(srcValContainer& sourceValues,
                 const simeng::arch::aarch64::InstructionMetadata& metadata) {
  if (conditionHolds(metadata.cc, sourceValues[0].get<uint8_t>())) {
    uint8_t nzcv;
    std::tie(std::ignore, nzcv) = addWithCarry(
        sourceValues[1].get<T>(), ~static_cast<T>(metadata.operands[1].imm), 1);
    return nzcv;
  }
  return static_cast<uint8_t>(metadata.operands[2].imm);
}

/** Helper function for instructions with the format `ccmp rn, rm, #nzcv,
 * cc`.
 * T represents the type of sourceValues (e.g. for xn, T = uint64_t).
 * Returns single value of type uint8_t. */
template <typename T>
uint8_t ccmp_reg(srcValContainer& sourceValues,
                 const simeng::arch::aarch64::InstructionMetadata& metadata) {
  if (conditionHolds(metadata.cc, sourceValues[0].get<uint8_t>())) {
    uint8_t nzcv;
    std::tie(std::ignore, nzcv) =
        addWithCarry(sourceValues[1].get<T>(), ~sourceValues[2].get<T>(), 1);
    return nzcv;
  }
  return static_cast<uint8_t>(metadata.operands[2].imm);
}

/** Helper function for instructions with the format `cb<z,nz> rn, #imm`.
 * T represents the type of sourceValues (e.g. for xn, T = uint64_t).
 * Returns tuple of type [bool branch taken, uint64_t address]. */
template <typename T>
std::tuple<bool, uint64_t> condBranch_cmpToZero(
    srcValContainer& sourceValues,
    const simeng::arch::aarch64::InstructionMetadata& metadata,
    uint64_t instructionAddress, std::function<bool(T)> func) {
  bool branchTaken;
  uint64_t branchAddress;
  if (func(sourceValues[0].get<T>())) {
    branchTaken = true;
    branchAddress = instructionAddress + metadata.operands[1].imm;
  } else {
    branchTaken = false;
    branchAddress = instructionAddress + 4;
  }
  return {branchTaken, branchAddress};
}

/** Helper function for instructions with the format `cs<el, neg, inc, inv>
 * rd, rn, rm, cc`.
 * T represents the type of sourceValues (e.g. for xd, T = uint64_t).
 * Returns single value of type T. */
template <typename T>
T cs_4ops(srcValContainer& sourceValues,
          const simeng::arch::aarch64::InstructionMetadata& metadata,
          std::function<T(T)> func) {
  if (conditionHolds(metadata.cc, sourceValues[0].get<uint8_t>())) {
    return sourceValues[1].get<T>();
  }
  return func(sourceValues[2].get<T>());
}

/** Helper function for instructions with the format `tb<z,nz> rn, #imm,
 * label`.
 * T represents the type of sourceValues (e.g. for xn, T = uint64_t).
 * Returns tuple of type [bool branch taken, uint64_t address]. */
template <typename T>
std::tuple<bool, uint64_t> tbnz_tbz(
    srcValContainer& sourceValues,
    const simeng::arch::aarch64::InstructionMetadata& metadata,
    uint64_t instructionAddress, bool isNZ) {
  bool branchTaken;
  uint64_t branchAddress = instructionAddress;
  if (sourceValues[0].get<T>() &
      (static_cast<T>(1) << metadata.operands[1].imm)) {
    branchTaken = isNZ;
  } else {
    branchTaken = !isNZ;
  }
  branchAddress += branchTaken ? metadata.operands[2].imm : 4;
  return {branchTaken, branchAddress};
}

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng