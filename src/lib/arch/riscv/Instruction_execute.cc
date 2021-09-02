#include <cmath>
#include <tuple>

#include "InstructionMetadata.hh"
#include "simeng/arch/riscv/Instruction.hh"

namespace simeng {
namespace arch {
namespace riscv {

/** Multiply `a` and `b`, and return the high 64 bits of the result.
 * https://stackoverflow.com/a/28904636 */
uint64_t mulhi(uint64_t a, uint64_t b) {
  uint64_t a_lo = (uint32_t)a;
  uint64_t a_hi = a >> 32;
  uint64_t b_lo = (uint32_t)b;
  uint64_t b_hi = b >> 32;

  uint64_t a_x_b_hi = a_hi * b_hi;
  uint64_t a_x_b_mid = a_hi * b_lo;
  uint64_t b_x_a_mid = b_hi * a_lo;
  uint64_t a_x_b_lo = a_lo * b_lo;

  uint64_t carry_bit = ((uint64_t)(uint32_t)a_x_b_mid +
                        (uint64_t)(uint32_t)b_x_a_mid + (a_x_b_lo >> 32)) >>
                       32;

  uint64_t multhi =
      a_x_b_hi + (a_x_b_mid >> 32) + (b_x_a_mid >> 32) + carry_bit;

  return multhi;
}

/** Extend 'bits' by value in position 'msb' of 'bits' (1 indexed) */
uint64_t bitExtend(uint64_t bits, uint64_t msb) {
  int64_t leftShift = bits << (64 - msb);
  int64_t rightShift = leftShift >> (64 - msb);
  return rightShift;
}

uint64_t signExtendW(uint64_t bits) { return bitExtend(bits, 32); }

uint64_t zeroExtend(uint64_t bits, uint64_t msb) {
  uint64_t leftShift = bits << (64 - msb);
  uint64_t rightShift = leftShift >> (64 - msb);
  return rightShift;
}

void Instruction::executionNYI() {
  exceptionEncountered_ = true;
  exception_ = InstructionException::ExecutionNotYetImplemented;
  return;
}

void Instruction::execute() {
  assert(!executed_ && "Attempted to execute an instruction more than once");
  assert(
      canExecute() &&
      "Attempted to execute an instruction before all operands were provided");

  executed_ = true;
  switch (metadata.opcode) {
    case Opcode::RISCV_LB: {
      results[0] = bitExtend(memoryData[0].get<uint8_t>(), 8);
      break;
    }
    case Opcode::RISCV_LBU: {
      results[0] = zeroExtend(memoryData[0].get<uint8_t>(), 8);
      break;
    }
    case Opcode::RISCV_LH: {
      results[0] = bitExtend(memoryData[0].get<uint16_t>(), 16);
      break;
    }
    case Opcode::RISCV_LHU: {
      results[0] = zeroExtend(memoryData[0].get<uint16_t>(), 16);
      break;
    }
    case Opcode::RISCV_LW: {
      results[0] = bitExtend(memoryData[0].get<uint32_t>(), 32);
      break;
    }
    case Opcode::RISCV_LWU: {
      results[0] = zeroExtend(memoryData[0].get<uint32_t>(), 32);
      break;
    }
    case Opcode::RISCV_LD: {
      results[0] = memoryData[0];
      break;
    }
    case Opcode::RISCV_SB:
      [[fallthrough]];
    case Opcode::RISCV_SH:
      [[fallthrough]];
    case Opcode::RISCV_SW:
      [[fallthrough]];
    case Opcode::RISCV_SD: {
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::RISCV_SLL: {
      const int64_t rs1 = operands[0].get<int64_t>();
      const int64_t rs2 =
          operands[1].get<int64_t>() & 63;  // Only use lowest 6 bits
      int64_t out = static_cast<int64_t>(rs1 << rs2);
      results[0] = out;
      break;
    }
    case Opcode::RISCV_SLLI: {
      const int64_t rs1 = operands[0].get<int64_t>();
      const int64_t rs2 =
          metadata.operands[2].imm & 63;  // Only use lowest 6 bits
      int64_t out = static_cast<int64_t>(rs1 << rs2);
      results[0] = out;
      break;
    }
    case Opcode::RISCV_SLLW: {
      const int32_t rs1 = operands[0].get<int32_t>();
      const int32_t rs2 =
          operands[1].get<int32_t>() & 63;  // Only use lowest 6 bits
      int64_t out = signExtendW(static_cast<int32_t>(rs1 << rs2));
      results[0] = out;
      break;
    }
    case Opcode::RISCV_SLLIW: {
      const int32_t rs1 = operands[0].get<uint32_t>();
      const int32_t rs2 =
          metadata.operands[2].imm & 63;  // Only use lowest 6 bits
      uint64_t out = signExtendW(static_cast<uint32_t>(rs1 << rs2));
      results[0] = out;
      break;
    }
    case Opcode::RISCV_SRL: {
      const uint64_t rs1 = operands[0].get<uint64_t>();
      const uint64_t rs2 =
          operands[1].get<uint64_t>() & 63;  // Only use lowest 6 bits
      uint64_t out = static_cast<uint64_t>(rs1 >> rs2);
      results[0] = out;
      break;
    }
    case Opcode::RISCV_SRLI: {
      const uint64_t rs1 = operands[0].get<uint64_t>();
      const uint64_t rs2 =
          metadata.operands[2].imm & 63;  // Only use lowest 6 bits
      uint64_t out = static_cast<uint64_t>(rs1 >> rs2);
      results[0] = out;
      break;
    }
    case Opcode::RISCV_SRLW: {
      const uint32_t rs1 = operands[0].get<uint32_t>();
      const uint32_t rs2 =
          operands[1].get<uint32_t>() & 63;  // Only use lowest 6 bits
      uint64_t out = signExtendW(static_cast<uint64_t>(rs1 >> rs2));
      results[0] = out;
      break;
    }
    case Opcode::RISCV_SRLIW: {
      const uint32_t rs1 = operands[0].get<uint32_t>();
      const uint32_t rs2 =
          metadata.operands[2].imm & 63;  // Only use lowest 6 bits
      uint64_t out = signExtendW(static_cast<uint32_t>(rs1 >> rs2));
      results[0] = out;
      break;
    }
    case Opcode::RISCV_SRA: {
      const int64_t rs1 = operands[0].get<int64_t>();
      const int64_t rs2 =
          operands[1].get<int64_t>() & 63;  // Only use lowest 6 bits
      int64_t out = static_cast<int64_t>(rs1 >> rs2);
      results[0] = out;
      break;
    }
    case Opcode::RISCV_SRAI: {
      const int64_t rs1 = operands[0].get<int64_t>();
      const int64_t rs2 =
          metadata.operands[2].imm & 63;  // Only use lowest 6 bits
      int64_t out = static_cast<int64_t>(rs1 >> rs2);
      results[0] = out;
      break;
    }
    case Opcode::RISCV_SRAW: {
      const int32_t rs1 = operands[0].get<int32_t>();
      const int32_t rs2 =
          operands[1].get<int32_t>() & 63;  // Only use lowest 6 bits
      int64_t out = static_cast<int32_t>(rs1 >> rs2);
      results[0] = out;
      break;
    }
    case Opcode::RISCV_SRAIW: {
      const int32_t rs1 = operands[0].get<int32_t>();
      const int32_t rs2 =
          metadata.operands[2].imm & 63;  // Only use lowest 6 bits
      int64_t out = static_cast<int32_t>(rs1 >> rs2);
      results[0] = out;
      break;
    }
    case Opcode::RISCV_ADD: {
      const uint64_t n = operands[0].get<uint64_t>();
      const uint64_t m = operands[1].get<uint64_t>();
      uint64_t out = static_cast<uint64_t>(n + m);
      results[0] = out;
      break;
    }
    case Opcode::RISCV_ADDW: {
      const int32_t n = operands[0].get<int32_t>();
      const int32_t m = operands[1].get<int32_t>();
      int64_t out = static_cast<int64_t>(static_cast<int32_t>(n + m));
      results[0] = out;
      break;
    }
    case Opcode::RISCV_ADDI: {  // addi ad, an, #imm
      const uint64_t rs1 = operands[0].get<uint64_t>();
      const uint64_t rs2 = metadata.operands[2].imm;
      uint64_t out = static_cast<uint64_t>(rs1 + rs2);
      results[0] = out;
      break;
    }
    case Opcode::RISCV_ADDIW: {  // addi ad, an, #imm
      const int32_t rs1 = operands[0].get<int32_t>();
      const int32_t rs2 = metadata.operands[2].imm;
      uint64_t out = signExtendW(rs1 + rs2);
      results[0] = out;
      break;
    }
    case Opcode::RISCV_SUB: {
      const uint64_t rs1 = operands[0].get<uint64_t>();
      const uint64_t rs2 = operands[1].get<uint64_t>();
      uint64_t out = static_cast<uint64_t>(rs1 - rs2);
      results[0] = out;
      break;
    }
    case Opcode::RISCV_SUBW: {
      const int32_t rs1 = operands[0].get<int32_t>();
      const int32_t rs2 = operands[1].get<int32_t>();
      int64_t out = static_cast<int64_t>(static_cast<int32_t>(rs1 - rs2));
      results[0] = out;
      break;
    }
    case Opcode::RISCV_LUI: {
      uint64_t out = signExtendW(metadata.operands[1].imm
                                 << 12);  // Shift into upper 20 bits
      results[0] = out;
      break;
    }
    case Opcode::RISCV_AUIPC: {
      const int64_t pc = instructionAddress_;
      const int64_t uimm = signExtendW(metadata.operands[1].imm
                                       << 12);  // Shift into upper 20 bits
      uint64_t out = static_cast<uint64_t>(pc + uimm);
      results[0] = out;
      break;
    }
    case Opcode::RISCV_XOR: {
      const uint64_t n = operands[0].get<uint64_t>();
      const uint64_t m = operands[1].get<uint64_t>();
      uint64_t out = static_cast<uint64_t>(m ^ n);
      results[0] = out;
      break;
    }
    case Opcode::RISCV_XORI: {
      const uint64_t n = operands[0].get<uint64_t>();
      const uint64_t m = metadata.operands[2].imm;
      uint64_t out = static_cast<uint64_t>(n ^ m);
      results[0] = out;
      break;
    }
    case Opcode::RISCV_OR: {
      const uint64_t n = operands[0].get<uint64_t>();
      const uint64_t m = operands[1].get<uint64_t>();
      uint64_t out = static_cast<uint64_t>(m | n);
      results[0] = out;
      break;
    }
    case Opcode::RISCV_ORI: {
      const uint64_t n = operands[0].get<uint64_t>();
      const uint64_t m = metadata.operands[2].imm;
      uint64_t out = static_cast<uint64_t>(n | m);
      results[0] = out;
      break;
    }
    case Opcode::RISCV_AND: {
      const uint64_t n = operands[0].get<uint64_t>();
      const uint64_t m = operands[1].get<uint64_t>();
      uint64_t out = static_cast<uint64_t>(m & n);
      results[0] = out;
      break;
    }
    case Opcode::RISCV_ANDI: {
      const uint64_t n = operands[0].get<uint64_t>();
      const uint64_t m = metadata.operands[2].imm;
      uint64_t out = static_cast<uint64_t>(n & m);
      results[0] = out;
      break;
    }
    case Opcode::RISCV_SLT: {
      const int64_t rs1 = operands[0].get<int64_t>();
      const int64_t rs2 = operands[1].get<int64_t>();
      if (rs1 < rs2) {
        results[0] = static_cast<uint64_t>(1);
      } else {
        results[0] = static_cast<uint64_t>(0);
      }
      break;
    }
    case Opcode::RISCV_SLTU: {
      const uint64_t rs1 = operands[0].get<uint64_t>();
      const uint64_t rs2 = operands[1].get<uint64_t>();
      if (rs1 < rs2) {
        results[0] = static_cast<uint64_t>(1);
      } else {
        results[0] = static_cast<uint64_t>(0);
      }
      break;
    }
    case Opcode::RISCV_SLTI: {
      const int64_t rs1 = operands[0].get<int64_t>();
      const int64_t imm = metadata.operands[2].imm;
      if (rs1 < imm) {
        results[0] = static_cast<uint64_t>(1);
      } else {
        results[0] = static_cast<uint64_t>(0);
      }
      break;
    }
    case Opcode::RISCV_SLTIU: {
      const uint64_t rs1 = operands[0].get<uint64_t>();
      const uint64_t imm = static_cast<int64_t>(metadata.operands[2].imm);
      if (rs1 < imm) {
        results[0] = static_cast<uint64_t>(1);
      } else {
        results[0] = static_cast<uint64_t>(0);
      }
      break;
    }
    case Opcode::RISCV_BEQ: {
      const uint64_t rs1 = operands[0].get<uint64_t>();
      const uint64_t rs2 = operands[1].get<uint64_t>();
      if (rs1 == rs2) {
        branchAddress_ = instructionAddress_ +
                         metadata.operands[2].imm;  // Set LSB of result to 0
        branchTaken_ = true;
      } else {
        branchAddress_ = instructionAddress_ + 4;
        branchTaken_ = false;
      }
      break;
    }
    case Opcode::RISCV_BNE: {
      const uint64_t rs1 = operands[0].get<uint64_t>();
      const uint64_t rs2 = operands[1].get<uint64_t>();
      if (rs1 != rs2) {
        branchAddress_ = instructionAddress_ +
                         metadata.operands[2].imm;  // Set LSB of result to 0
        branchTaken_ = true;
      } else {
        branchAddress_ = instructionAddress_ + 4;
        branchTaken_ = false;
      }
      break;
    }
    case Opcode::RISCV_BLT: {
      const int64_t rs1 = operands[0].get<int64_t>();
      const int64_t rs2 = operands[1].get<int64_t>();
      if (rs1 < rs2) {
        branchAddress_ = instructionAddress_ +
                         metadata.operands[2].imm;  // Set LSB of result to 0
        branchTaken_ = true;
      } else {
        branchAddress_ = instructionAddress_ + 4;
        branchTaken_ = false;
      }
      break;
    }
    case Opcode::RISCV_BLTU: {
      const uint64_t rs1 = operands[0].get<uint64_t>();
      const uint64_t rs2 = operands[1].get<uint64_t>();
      if (rs1 < rs2) {
        branchAddress_ = instructionAddress_ +
                         metadata.operands[2].imm;  // Set LSB of result to 0
        branchTaken_ = true;
      } else {
        branchAddress_ = instructionAddress_ + 4;
        branchTaken_ = false;
      }
      break;
    }
    case Opcode::RISCV_BGE: {
      const int64_t rs1 = operands[0].get<int64_t>();
      const int64_t rs2 = operands[1].get<int64_t>();
      if (rs1 >= rs2) {
        branchAddress_ = instructionAddress_ +
                         metadata.operands[2].imm;  // Set LSB of result to 0
        branchTaken_ = true;
      } else {
        branchAddress_ = instructionAddress_ + 4;
        branchTaken_ = false;
      }
      break;
    }
    case Opcode::RISCV_BGEU: {
      const uint64_t rs1 = operands[0].get<uint64_t>();
      const uint64_t rs2 = operands[1].get<uint64_t>();
      if (rs1 >= rs2) {
        branchAddress_ = instructionAddress_ +
                         metadata.operands[2].imm;  // Set LSB of result to 0
        branchTaken_ = true;
      } else {
        branchAddress_ = instructionAddress_ + 4;
        branchTaken_ = false;
      }
      break;
    }
    case Opcode::RISCV_JAL: {
      branchAddress_ = instructionAddress_ +
                       metadata.operands[1].imm;  // Set LSB of result to 0
      branchTaken_ = true;
      results[0] = instructionAddress_ + 4;
      break;
    }
    case Opcode::RISCV_JALR: {
      branchAddress_ =
          (operands[0].get<uint64_t>() + metadata.operands[2].imm) &
          ~1;  // Set LSB of result to 0
      branchTaken_ = true;
      results[0] = instructionAddress_ + 4;
      break;
    }
    case Opcode::RISCV_ECALL: {
      exceptionEncountered_ = true;
      exception_ = InstructionException::SupervisorCall;
      break;
    }
    case Opcode::RISCV_FENCE: {
      // TODO currently modelled as a NOP as all codes are currently single
      // threaded "Informally, no other RISC-V hart or external device can
      // observe any operation in the successor set following a FENCE before any
      // operation in the predecessor set preceding the FENCE."
      // https://msyksphinz-self.github.io/riscv-isadoc/html/rvi.html#fence
      break;
    }

      // Atomic Extension
      // TODO not implemented atomically
    case Opcode::RISCV_LR_W:
    case Opcode::RISCV_LR_W_AQ:
    case Opcode::RISCV_LR_W_RL:
    case Opcode::RISCV_LR_W_AQ_RL: {
      // TODO set "reservation set" in memory, currently not needed as all codes
      //  are single threaded
      // TODO check that address is naturally aligned to operand size,
      //  if not raise address-misaligned/access-fault exception
      // TODO use aq and rl bits to prevent reordering with other memory
      // operations
      results[0] = bitExtend(memoryData[0].get<uint32_t>(), 32);
      break;
    }
    case Opcode::RISCV_LR_D:
    case Opcode::RISCV_LR_D_AQ:
    case Opcode::RISCV_LR_D_RL:
    case Opcode::RISCV_LR_D_AQ_RL: {
      results[0] = memoryData[0].get<uint64_t>();
      break;
    }
    case Opcode::RISCV_SC_W:
    case Opcode::RISCV_SC_W_AQ:
    case Opcode::RISCV_SC_W_RL:
    case Opcode::RISCV_SC_W_AQ_RL:
    case Opcode::RISCV_SC_D:
    case Opcode::RISCV_SC_D_AQ:
    case Opcode::RISCV_SC_D_RL:
    case Opcode::RISCV_SC_D_AQ_RL: {
      // TODO check "reservation set" hasn't been written to before performing
      // store
      // TODO write rd correctly based on whether sc succeeds
      // TODO check that address is naturally aligned to operand size,
      //  if not raise address-misaligned/access-fault exception
      // TODO use aq and rl bits to prevent reordering with other memory
      // operations
      memoryData[0] = operands[0];
      results[0] = static_cast<uint64_t>(0);
      break;
    }
    case Opcode::RISCV_AMOSWAP_W:
    case Opcode::RISCV_AMOSWAP_W_AQ:
    case Opcode::RISCV_AMOSWAP_W_RL:
    case Opcode::RISCV_AMOSWAP_W_AQ_RL: {
      // Load memory at address rs1 into rd
      // Swap rd and rs2
      // Store rd to memory at address rs1
      // TODO raise address misaligned or access-fault errors
      // TODO account for AQ and RL bits
      int64_t rd = signExtendW(memoryData[0].get<uint32_t>());
      int32_t rs2 = operands[0].get<int32_t>();
      results[0] = rd;
      memoryData[0] = rs2;
      break;
    }
    case Opcode::RISCV_AMOSWAP_D:
    case Opcode::RISCV_AMOSWAP_D_AQ:
    case Opcode::RISCV_AMOSWAP_D_RL:
    case Opcode::RISCV_AMOSWAP_D_AQ_RL: {
      uint64_t rd = memoryData[0].get<uint64_t>();
      uint64_t rs2 = operands[0].get<uint64_t>();
      results[0] = rd;
      memoryData[0] = rs2;
      break;
    }
    case Opcode::RISCV_AMOADD_W:
    case Opcode::RISCV_AMOADD_W_AQ:
    case Opcode::RISCV_AMOADD_W_RL:
    case Opcode::RISCV_AMOADD_W_AQ_RL: {
      int64_t rd = signExtendW(memoryData[0].get<uint32_t>());
      results[0] = rd;
      memoryData[0] = static_cast<int32_t>(rd + operands[0].get<int64_t>());
      break;
    }
    case Opcode::RISCV_AMOADD_D:
    case Opcode::RISCV_AMOADD_D_AQ:
    case Opcode::RISCV_AMOADD_D_RL:
    case Opcode::RISCV_AMOADD_D_AQ_RL: {
      int64_t rd = memoryData[0].get<uint64_t>();
      results[0] = rd;
      memoryData[0] = static_cast<int64_t>(rd + operands[0].get<int64_t>());
      break;
    }
    case Opcode::RISCV_AMOAND_W:
    case Opcode::RISCV_AMOAND_W_AQ:
    case Opcode::RISCV_AMOAND_W_RL:
    case Opcode::RISCV_AMOAND_W_AQ_RL: {
      int64_t rd = signExtendW(memoryData[0].get<uint32_t>());
      results[0] = rd;
      memoryData[0] = static_cast<int32_t>(rd & operands[0].get<int64_t>());
      break;
    }
    case Opcode::RISCV_AMOAND_D:
    case Opcode::RISCV_AMOAND_D_AQ:
    case Opcode::RISCV_AMOAND_D_RL:
    case Opcode::RISCV_AMOAND_D_AQ_RL: {
      int64_t rd = memoryData[0].get<uint64_t>();
      results[0] = rd;
      memoryData[0] = static_cast<int64_t>(rd & operands[0].get<int64_t>());
      break;
    }
    case Opcode::RISCV_AMOOR_W:
    case Opcode::RISCV_AMOOR_W_AQ:
    case Opcode::RISCV_AMOOR_W_RL:
    case Opcode::RISCV_AMOOR_W_AQ_RL: {
      int64_t rd = signExtendW(memoryData[0].get<uint32_t>());
      results[0] = rd;
      memoryData[0] = static_cast<int32_t>(rd | operands[0].get<int64_t>());
      break;
    }
    case Opcode::RISCV_AMOOR_D:
    case Opcode::RISCV_AMOOR_D_AQ:
    case Opcode::RISCV_AMOOR_D_RL:
    case Opcode::RISCV_AMOOR_D_AQ_RL: {
      int64_t rd = memoryData[0].get<uint64_t>();
      results[0] = rd;
      memoryData[0] = static_cast<int64_t>(rd | operands[0].get<int64_t>());
      break;
    }
    case Opcode::RISCV_AMOXOR_W:
    case Opcode::RISCV_AMOXOR_W_AQ:
    case Opcode::RISCV_AMOXOR_W_RL:
    case Opcode::RISCV_AMOXOR_W_AQ_RL: {
      int64_t rd = signExtendW(memoryData[0].get<uint32_t>());
      results[0] = rd;
      memoryData[0] = static_cast<int32_t>(rd ^ operands[0].get<int64_t>());
      break;
    }
    case Opcode::RISCV_AMOXOR_D:
    case Opcode::RISCV_AMOXOR_D_AQ:
    case Opcode::RISCV_AMOXOR_D_RL:
    case Opcode::RISCV_AMOXOR_D_AQ_RL: {
      int64_t rd = memoryData[0].get<uint64_t>();
      results[0] = rd;
      memoryData[0] = static_cast<int64_t>(rd ^ operands[0].get<int64_t>());
      break;
    }

    case Opcode::RISCV_AMOMIN_W:
    case Opcode::RISCV_AMOMIN_W_AQ:
    case Opcode::RISCV_AMOMIN_W_RL:
    case Opcode::RISCV_AMOMIN_W_AQ_RL: {
      results[0] = signExtendW(memoryData[0].get<int32_t>());
      memoryData[0] =
          std::min(memoryData[0].get<int32_t>(), operands[0].get<int32_t>());
      break;
    }
    case Opcode::RISCV_AMOMIN_D:
    case Opcode::RISCV_AMOMIN_D_AQ:
    case Opcode::RISCV_AMOMIN_D_RL:
    case Opcode::RISCV_AMOMIN_D_AQ_RL: {
      int64_t rd = memoryData[0].get<int64_t>();
      results[0] = rd;
      memoryData[0] =
          static_cast<int64_t>(std::min(rd, operands[0].get<int64_t>()));
      break;
    }
    case Opcode::RISCV_AMOMINU_W:
    case Opcode::RISCV_AMOMINU_W_AQ:
    case Opcode::RISCV_AMOMINU_W_RL:
    case Opcode::RISCV_AMOMINU_W_AQ_RL: {
      results[0] = signExtendW(memoryData[0].get<uint32_t>());
      memoryData[0] =
          std::min(memoryData[0].get<uint32_t>(), operands[0].get<uint32_t>());
      break;
    }
    case Opcode::RISCV_AMOMINU_D:
    case Opcode::RISCV_AMOMINU_D_AQ:
    case Opcode::RISCV_AMOMINU_D_RL:
    case Opcode::RISCV_AMOMINU_D_AQ_RL: {
      uint64_t rd = memoryData[0].get<uint64_t>();
      results[0] = rd;
      memoryData[0] =
          static_cast<uint64_t>(std::min(rd, operands[0].get<uint64_t>()));
      break;
    }

    case Opcode::RISCV_AMOMAX_W:
    case Opcode::RISCV_AMOMAX_W_AQ:
    case Opcode::RISCV_AMOMAX_W_RL:
    case Opcode::RISCV_AMOMAX_W_AQ_RL: {
      results[0] = signExtendW(memoryData[0].get<int32_t>());
      memoryData[0] =
          std::max(memoryData[0].get<int32_t>(), operands[0].get<int32_t>());
      break;
    }
    case Opcode::RISCV_AMOMAX_D:
    case Opcode::RISCV_AMOMAX_D_AQ:
    case Opcode::RISCV_AMOMAX_D_RL:
    case Opcode::RISCV_AMOMAX_D_AQ_RL: {
      int64_t rd = memoryData[0].get<int64_t>();
      results[0] = rd;
      memoryData[0] =
          static_cast<int64_t>(std::max(rd, operands[0].get<int64_t>()));
      break;
    }
    case Opcode::RISCV_AMOMAXU_W:
    case Opcode::RISCV_AMOMAXU_W_AQ:
    case Opcode::RISCV_AMOMAXU_W_RL:
    case Opcode::RISCV_AMOMAXU_W_AQ_RL: {
      results[0] = signExtendW(memoryData[0].get<uint32_t>());
      memoryData[0] =
          std::max(memoryData[0].get<uint32_t>(), operands[0].get<uint32_t>());
      break;
    }
    case Opcode::RISCV_AMOMAXU_D:
    case Opcode::RISCV_AMOMAXU_D_AQ:
    case Opcode::RISCV_AMOMAXU_D_RL:
    case Opcode::RISCV_AMOMAXU_D_AQ_RL: {
      uint64_t rd = memoryData[0].get<uint64_t>();
      results[0] = rd;
      memoryData[0] =
          static_cast<uint64_t>(std::max(rd, operands[0].get<uint64_t>()));
      break;
    }
    default:
      return executionNYI();
  }
}

}  // namespace riscv
}  // namespace arch
}  // namespace simeng