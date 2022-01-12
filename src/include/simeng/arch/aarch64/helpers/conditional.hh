#pragma once

#include <cmath>
#include <limits>
#include <tuple>

#include "ExecuteHelperFunctions.hh"
#include "arch/aarch64/InstructionMetadata.hh"

namespace simeng {
namespace arch {
namespace aarch64 {
class conditionalHelp {
 public:
  /** Helper function for instructions with the format `cb{z, nz} rn, #imm`.
   */
  template <typename T>
  static std::tuple<bool, uint64_t> condBranch_zORnz(
      std::array<RegisterValue, Instruction::MAX_SOURCE_REGISTERS> operands,
      struct simeng::arch::aarch64::InstructionMetadata metadata,
      uint64_t instructionAddress, bool nonZero) {
    bool branchTaken;
    uint64_t branchAddress;
    if (nonZero ? (operands[0].get<T>() != 0) : (operands[0].get<T>() == 0)) {
      branchTaken = true;
      branchAddress = instructionAddress + metadata.operands[1].imm;
    } else {
      branchTaken = false;
      branchAddress = instructionAddress + 4;
    }
    return {branchTaken, branchAddress};
  }
};
}  // namespace aarch64
}  // namespace arch
}  // namespace simeng