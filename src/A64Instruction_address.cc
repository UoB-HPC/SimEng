#include "A64Instruction.hh"

namespace simeng {

std::vector<std::pair<uint64_t, uint8_t>> A64Instruction::generateAddresses() {
  assert((isLoad() || isStore()) &&
         "generateAddresses called on non-load-or-store instruction");

  switch (metadata.id) {
    // case A64Opcode::STR_I:
    // case A64Opcode::LDR_I: {
    //   if (metadata.wback) {
    //     exception = A64InstructionException::ExecutionNotYetImplemented;
    //     return {};
    //   }

    //   int baseOpIndex = 0;
    //   if (opcode == A64Opcode::STR_I) {
    //     baseOpIndex = 1;
    //   }

    //   auto address = operands[baseOpIndex].get<uint64_t>() + metadata.offset;
    //   setMemoryAddresses({{address, 1 << metadata.scale}});
    //   return memoryAddresses;
    // }
    default:
      exception = A64InstructionException::ExecutionNotYetImplemented;
      return {};
  }
}

}  // namespace simeng
