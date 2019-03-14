#include "A64Instruction.hh"

namespace simeng {

std::vector<std::pair<uint64_t, uint8_t>> A64Instruction::generateAddresses() {
  assert((isLoad() || isStore()) &&
         "generateAddresses called on non-load-or-store instruction");

  switch (metadata.id) {
    case ARM64_INS_LDR: {
      switch (getRegisterSize(metadata.operands[0].reg)) {
        case A64RegisterSize::W: {
          setMemoryAddresses(
              {{operands[0].get<uint64_t>() + metadata.operands[1].mem.disp,
                4}});
          break;
        }
        case A64RegisterSize::X: {
          setMemoryAddresses(
              {{operands[0].get<uint64_t>() + metadata.operands[1].mem.disp,
                8}});
          break;
        }
        default: {
          exception = A64InstructionException::ExecutionNotYetImplemented;
          return {};
        }
      }
      break;
    }
    case ARM64_INS_STR: {
      switch (getRegisterSize(metadata.operands[0].reg)) {
        case A64RegisterSize::W: {
          setMemoryAddresses(
              {{operands[1].get<uint64_t>() + metadata.operands[1].mem.disp,
                4}});
          break;
        }
        case A64RegisterSize::X: {
          setMemoryAddresses(
              {{operands[1].get<uint64_t>() + metadata.operands[1].mem.disp,
                8}});
          break;
        }
        default: {
          exception = A64InstructionException::ExecutionNotYetImplemented;
          return {};
        }
      }
      break;
    }
    default:
      exception = A64InstructionException::ExecutionNotYetImplemented;
      return {};
  }
  return memoryAddresses;
}

}  // namespace simeng
