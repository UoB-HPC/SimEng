#include "A64Instruction.hh"
#include "A64InstructionMetadata.hh"

#include <iostream>

namespace simeng {

/** Extend `value` according to `extendType`, and left-shift the result by
 * `shift` */
uint64_t extendValue(uint64_t value, uint8_t extendType, uint8_t shift) {
  uint64_t extended;
  switch (extendType) {
    case ARM64_EXT_UXTB:
      extended = static_cast<uint8_t>(value);
      break;
    case ARM64_EXT_UXTH:
      extended = static_cast<uint16_t>(value);
      break;
    case ARM64_EXT_UXTW:
      extended = static_cast<uint32_t>(value);
      break;
    case ARM64_EXT_UXTX:
      extended = value;
      break;
    case ARM64_EXT_SXTB:
      extended = static_cast<int8_t>(value);
      break;
    case ARM64_EXT_SXTH:
      extended = static_cast<int16_t>(value);
      break;
    case ARM64_EXT_SXTW:
      extended = static_cast<int32_t>(value);
      break;
    case ARM64_EXT_SXTX:
      extended = value;
      break;
    default:
      assert(false && "Invalid extension type");
      return 0;
  }

  return extended << shift;
}

span<const std::pair<uint64_t, uint8_t>> A64Instruction::generateAddresses() {
  assert((isLoad() || isStore()) &&
         "generateAddresses called on non-load-or-store instruction");

  switch (metadata.opcode) {
    case A64Opcode::AArch64_LDRBBpre: {  // ldrb wt, [xn, #imm]!
      setMemoryAddresses(
          {{operands[0].get<uint64_t>() + metadata.operands[1].mem.disp, 1}});
      break;
    }
    case A64Opcode::AArch64_LDRBBui: {  // ldrb wt, [xn, #imm]
      setMemoryAddresses(
          {{operands[0].get<uint64_t>() + metadata.operands[1].mem.disp, 1}});
      break;
    }
    case A64Opcode::AArch64_LDRDroX: {  // ldr dt, [xn, xm{, extend {amount}}]
      if (metadata.operands[1].shift.type != 0) {
        executionNYI();
        return getGeneratedAddresses();
      }
      setMemoryAddresses(
          {{operands[0].get<uint64_t>() + operands[1].get<uint64_t>(), 8}});
      break;
    }
    case A64Opcode::AArch64_LDRWui: {  // ldr wt, [xn, #imm]
      setMemoryAddresses(
          {{operands[0].get<uint64_t>() + metadata.operands[1].mem.disp, 4}});
      break;
    }
    case A64Opcode::AArch64_LDRXl: {  // ldr xt, #imm
      setMemoryAddresses({{metadata.operands[1].imm + instructionAddress_, 8}});
      break;
    }
    case A64Opcode::AArch64_LDRXpost: {  // ldr xt, [xn], #imm
      setMemoryAddresses({{operands[0].get<uint64_t>(), 8}});
      break;
    }
    case A64Opcode::AArch64_LDRXui: {  // ldr xt, [xn, #imm]
      setMemoryAddresses(
          {{operands[0].get<uint64_t>() + metadata.operands[1].mem.disp, 8}});
      break;
    }
    case A64Opcode::AArch64_LDPQi: {  // ldp qt1, qt2, [xn, #imm]
      uint64_t base =
          operands[0].get<uint64_t>() + metadata.operands[0].mem.disp;
      setMemoryAddresses({{base, 16}, {base + 16, 16}});
      break;
    }
    case A64Opcode::AArch64_LDPXi: {  // ldp xt1, xt2, [xn, #imm]
      uint64_t base =
          operands[0].get<uint64_t>() + metadata.operands[2].mem.disp;
      setMemoryAddresses({{base, 8}, {base + 8, 8}});
      break;
    }
    case A64Opcode::AArch64_LDPXpost: {  // ldp xt1, xt2, [xn], #imm
      uint64_t base = operands[0].get<uint64_t>();
      setMemoryAddresses({{base, 8}, {base + 8, 8}});
      break;
    }
    case A64Opcode::AArch64_LDURWi: {  // ldur wt, [xn, #imm]
      setMemoryAddresses(
          {{operands[0].get<uint64_t>() + metadata.operands[1].mem.disp, 4}});
      break;
    }
    case A64Opcode::AArch64_LDURXi: {  // ldur xt, [xn, #imm]
      setMemoryAddresses(
          {{operands[0].get<uint64_t>() + metadata.operands[1].mem.disp, 8}});
      break;
    }
    case A64Opcode::AArch64_PRFMui: {  // prfm op, [xn, xm{, extend{, #amount}}]
      // TODO: Implement prefetching
      break;
    }
    case A64Opcode::AArch64_STPXi: {  // stp xt1, xt2, [xn, #imm]

      uint64_t base =
          operands[2].get<uint64_t>() + metadata.operands[2].mem.disp;
      setMemoryAddresses({{base, 8}, {base + 8, 8}});
      break;
    }
    case A64Opcode::AArch64_STPXpre: {  // stp xt1, xt2, [xn, #imm]!
      uint64_t base =
          operands[2].get<uint64_t>() + metadata.operands[2].mem.disp;
      setMemoryAddresses({{base, 8}, {base + 8, 8}});
      break;
    }
    case A64Opcode::AArch64_STPQi: {  // stp qt1, qt2, [xn, #imm]
      uint64_t base =
          operands[2].get<uint64_t>() + metadata.operands[2].mem.disp;
      setMemoryAddresses({{base, 16}, {base + 16, 16}});
      break;
    }
    case A64Opcode::AArch64_STRWroX: {  // str wt, [xn, xm{, extend, {#amount}}]
      uint64_t offset =
          extendValue(operands[2].get<uint64_t>(), metadata.operands[1].ext,
                      metadata.operands[1].shift.type);
      setMemoryAddresses({{operands[1].get<uint64_t>() + offset, 4}});
      break;
    }
    case A64Opcode::AArch64_STRWui: {  // str wt, [xn, #imm]
      setMemoryAddresses(
          {{operands[1].get<uint64_t>() + metadata.operands[1].mem.disp, 4}});
      break;
    }
    case A64Opcode::AArch64_STRXui: {  // str xt, [xn, #imm]
      setMemoryAddresses(
          {{operands[1].get<uint64_t>() + metadata.operands[1].mem.disp, 8}});
      break;
    }
    case A64Opcode::AArch64_STURWi: {  // stur wt, [xn, #imm]
      setMemoryAddresses(
          {{operands[1].get<uint64_t>() + metadata.operands[1].mem.disp, 4}});
      break;
    }
    default:
      exception = A64InstructionException::ExecutionNotYetImplemented;
  }
  return getGeneratedAddresses();
}

}  // namespace simeng
