
#include <cfenv>
#include <cmath>
#include <iostream>
#include <tuple>

#include "InstructionMetadata.hh"
#include "simeng/arch/riscv/Architecture.hh"
#include "simeng/arch/riscv/Instruction.hh"

namespace simeng {
namespace arch {
namespace riscv {

/** NaN box single precision floating point values as defined in
 * riscv-spec-20191213 page 73 */
uint64_t NanBoxFloat(float f) {
  static_assert(sizeof(float) == 4 && "Float not of size 4 bytes");

  uint64_t box = 0xffffffff00000000;
  std::memcpy(reinterpret_cast<char*>(&box), reinterpret_cast<char*>(&f),
              sizeof(float));

  return box;
}

float checkNanBox(RegisterValue operand) {
  // Ensure NaN box is correct
  if ((operand.get<uint64_t>() & 0xffffffff00000000) == 0xffffffff00000000) {
    // Correct
    return operand.get<float>();
  } else {
    // Not correct
    return std::nanf("");
  }
}

/** Multiply unsigned `a` and unsigned `b`, and return the high 64 bits of the
 * result. https://stackoverflow.com/a/28904636 */
uint64_t mulhiuu(uint64_t a, uint64_t b) {
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

/** Multiply signed `a` and signed `b`, and return the high 64 bits of the
 * result. */
uint64_t mulhiss(int64_t a, int64_t b) {
  // TODO NYI
  return a;
}

/** Multiply signed `a` and unsigned `b`, and return the high 64 bits of the
 * result. */
uint64_t mulhisu(int64_t a, uint64_t b) {
  // TODO NYI
  return a;
}

/** Extend 'bits' by value in position 'msb' of 'bits' (1 indexed) */
uint64_t bitExtend(uint64_t bits, uint64_t msb) {
  assert(msb != 0 && "Attempted to bit extend 0th bit");
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

void Instruction::setStaticRoundingModeThen(
    std::function<void(void)> operation) {
  // Extract rounding mode (rm) from raw bytes
  // The 3 relevant bits are always in positions 12-14. Take second byte from
  // encoding and mask with 01110000. Shift right by 4 to remove trailing 0's
  // and improve readability
  uint8_t rm = (metadata_.encoding[1] & 0x70) >> 4;

  /** A variable to hold the current fenv rounding mode/architectural dynamic
   * rounding mode. Used to restore the rounding mode after the architecturally
   * static rounding mode is used. */
  int currRM_ = fegetround();

  switch (rm) {
    case 0x00:  // RNE, Round to nearest, ties to even
      fesetround(FE_TONEAREST);
      break;
    case 0x01:  // RTZ Round towards zero
      fesetround(FE_TOWARDZERO);
      break;
    case 0x02:  // RDN Round down (-infinity)
      fesetround(FE_DOWNWARD);
      break;
    case 0x03:  // RUP Round up (+infinity)
      fesetround(FE_UPWARD);
      break;
    case 0x04:  // RMM Round to nearest, ties to max magnitude
      // FE_TONEAREST ties towards even but no other options available in fenv
      fesetround(FE_TONEAREST);
      break;
    case 0x05:
      // If frm is set to an invalid value (101–111), any subsequent attempt to
      // execute a floating-point operation with a dynamic rounding mode will
      // raise an illegal instruction exception.
      // Reserved
      std::cout << "[SimEng:Instruction_execute] Invalid static rounding mode "
                   "5 used, "
                   "instruction address:"
                << instructionAddress_ << std::endl;
      exceptionEncountered_ = true;
      exception_ = InstructionException::IllegalInstruction;
      break;
    case 0x06:
      // Reserved
      std::cout << "[SimEng:Instruction_execute] Invalid static rounding mode "
                   "6 used, "
                   "instruction address:"
                << instructionAddress_ << std::endl;
      exceptionEncountered_ = true;
      exception_ = InstructionException::IllegalInstruction;
      break;
    case 0x07:
      // Use dynamic rounding mode e.g. that which is already set
      // TODO check the dynamic rounding mode value in the CSR here. If set to
      // invalid value raise an illegal instruction exception. From spec "any
      // subsequent attempt to execute a floating-point operation with a dynamic
      // rounding mode will raise an illegal instruction exception". Requires
      // full Zicsr implementation
      break;
    default:
      std::cout
          << "[SimEng:Instruction_execute] Invalid static rounding mode out of "
             "range, instruction address:"
          << instructionAddress_ << std::endl;
      exceptionEncountered_ = true;
      exception_ = InstructionException::IllegalInstruction;
  }

  operation();

  fesetround(currRM_);

  // TODO if it appears that repeated rounding mode changes are slow, could
  // set target rounding mode variable and only update if different to currentRM
  return;
}

void Instruction::executionNYI() {
  exceptionEncountered_ = true;
  exception_ = InstructionException::ExecutionNotYetImplemented;
  return;
}

void Instruction::execute() {
  assert(!executed_ && "Attempted to execute an instruction more than once");
  assert(canExecute() &&
         "Attempted to execute an instruction before all source operands were "
         "provided");

  // Implementation of rv64imafdc according to the v. 20191213 unprivileged spec

  executed_ = true;
  switch (metadata_.opcode) {
    case Opcode::RISCV_LB: {  // LB rd,rs1,imm
      results_[0] =
          RegisterValue(bitExtend(memoryData_[0].get<uint8_t>(), 8), 8);
      break;
    }
    case Opcode::RISCV_LBU: {  // LBU rd,rs1,imm
      results_[0] =
          RegisterValue(zeroExtend(memoryData_[0].get<uint8_t>(), 8), 8);
      break;
    }
    case Opcode::RISCV_LH: {  // LH rd,rs1,imm
      results_[0] =
          RegisterValue(bitExtend(memoryData_[0].get<uint16_t>(), 16), 8);
      break;
    }
    case Opcode::RISCV_LHU: {  // LHU rd,rs1,imm
      results_[0] =
          RegisterValue(zeroExtend(memoryData_[0].get<uint16_t>(), 16), 8);
      break;
    }
    case Opcode::RISCV_LW: {  // LW rd,rs1,imm
      results_[0] =
          RegisterValue(bitExtend(memoryData_[0].get<uint32_t>(), 32), 8);
      break;
    }
    case Opcode::RISCV_LWU: {  // LWU rd,rs1,imm
      results_[0] =
          RegisterValue(zeroExtend(memoryData_[0].get<uint32_t>(), 32), 8);
      break;
    }
    case Opcode::RISCV_LD: {  // LD rd,rs1,imm
      results_[0] = RegisterValue(memoryData_[0].get<uint64_t>(), 8);
      break;
    }
    case Opcode::RISCV_SB:  // SB rs1,rs2,imm
      [[fallthrough]];
    case Opcode::RISCV_SH:  // SH rs1,rs2,imm
      [[fallthrough]];
    case Opcode::RISCV_SW:  // SW rs1,rs2,imm
      [[fallthrough]];
    case Opcode::RISCV_SD: {  // SD rs1,rs2,imm
      memoryData_[0] = sourceValues_[0];
      break;
    }
    case Opcode::RISCV_SLL: {  // SLL rd,rs1,rs2
      const int64_t rs1 = sourceValues_[0].get<int64_t>();
      const int64_t rs2 =
          sourceValues_[1].get<int64_t>() & 63;  // Only use lowest 6 bits
      int64_t out = static_cast<int64_t>(rs1 << rs2);
      results_[0] = RegisterValue(out, 8);
      break;
    }
    case Opcode::RISCV_SLLI: {  // SLLI rd,rs1,shamt
      const int64_t rs1 = sourceValues_[0].get<int64_t>();
      const int64_t shamt = sourceImm_ & 63;  // Only use lowest 6 bits
      int64_t out = static_cast<int64_t>(rs1 << shamt);
      results_[0] = RegisterValue(out, 8);
      break;
    }
    case Opcode::RISCV_SLLW: {  // SLLW rd,rs1,rs2
      const int32_t rs1 = sourceValues_[0].get<int32_t>();
      const int32_t rs2 =
          sourceValues_[1].get<int32_t>() & 31;  // Only use lowest 5 bits
      int64_t out = signExtendW(static_cast<int32_t>(rs1 << rs2));
      results_[0] = RegisterValue(out, 8);
      break;
    }
    case Opcode::RISCV_SLLIW: {  // SLLIW rd,rs1,shamt
      const int32_t rs1 = sourceValues_[0].get<uint32_t>();
      const int32_t shamt = sourceImm_ & 31;  // Only use lowest 5 bits
      uint64_t out = signExtendW(static_cast<uint32_t>(rs1 << shamt));
      results_[0] = RegisterValue(out, 8);
      break;
    }
    case Opcode::RISCV_SRL: {  // SRL rd,rs1,rs2
      const uint64_t rs1 = sourceValues_[0].get<uint64_t>();
      const uint64_t rs2 =
          sourceValues_[1].get<uint64_t>() & 63;  // Only use lowest 6 bits
      uint64_t out = static_cast<uint64_t>(rs1 >> rs2);
      results_[0] = RegisterValue(out, 8);
      break;
    }
    case Opcode::RISCV_SRLI: {  // SRLI rd,rs1,shamt
      const uint64_t rs1 = sourceValues_[0].get<uint64_t>();
      const uint64_t shamt = sourceImm_ & 63;  // Only use lowest 6 bits
      uint64_t out = static_cast<uint64_t>(rs1 >> shamt);
      results_[0] = RegisterValue(out, 8);
      break;
    }
    case Opcode::RISCV_SRLW: {  // SRLW rd,rs1,rs2
      const uint32_t rs1 = sourceValues_[0].get<uint32_t>();
      const uint32_t rs2 =
          sourceValues_[1].get<uint32_t>() & 31;  // Only use lowest 5 bits
      uint64_t out = signExtendW(static_cast<uint64_t>(rs1 >> rs2));
      results_[0] = RegisterValue(out, 8);
      break;
    }
    case Opcode::RISCV_SRLIW: {  // SRLIW rd,rs1,shamt
      const uint32_t rs1 = sourceValues_[0].get<uint32_t>();
      const uint32_t shamt = sourceImm_ & 31;  // Only use lowest 5 bits
      uint64_t out = signExtendW(static_cast<uint32_t>(rs1 >> shamt));
      results_[0] = RegisterValue(out, 8);
      break;
    }
    case Opcode::RISCV_SRA: {  // SRA rd,rs1,rs2
      const int64_t rs1 = sourceValues_[0].get<int64_t>();
      const int64_t rs2 =
          sourceValues_[1].get<int64_t>() & 63;  // Only use lowest 6 bits
      int64_t out = static_cast<int64_t>(rs1 >> rs2);
      results_[0] = RegisterValue(out, 8);
      break;
    }
    case Opcode::RISCV_SRAI: {  // SRAI rd,rs1,shamt
      const int64_t rs1 = sourceValues_[0].get<int64_t>();
      const int64_t shamt = sourceImm_ & 63;  // Only use lowest 6 bits
      int64_t out = static_cast<int64_t>(rs1 >> shamt);
      results_[0] = RegisterValue(out, 8);
      break;
    }
    case Opcode::RISCV_SRAW: {  // SRAW rd,rs1,rs2
      const int32_t rs1 = sourceValues_[0].get<int32_t>();
      const int32_t rs2 =
          sourceValues_[1].get<int32_t>() & 31;  // Only use lowest 5 bits
      int64_t out = static_cast<int32_t>(rs1 >> rs2);
      results_[0] = RegisterValue(out, 8);
      break;
    }
    case Opcode::RISCV_SRAIW: {  // SRAIW rd,rs1,shamt
      const int32_t rs1 = sourceValues_[0].get<int32_t>();
      const int32_t shamt = sourceImm_ & 31;  // Only use lowest 5 bits
      int64_t out = static_cast<int32_t>(rs1 >> shamt);
      results_[0] = RegisterValue(out, 8);
      break;
    }
    case Opcode::RISCV_ADD: {  // ADD rd,rs1,rs2
      const uint64_t rs1 = sourceValues_[0].get<uint64_t>();
      const uint64_t rs2 = sourceValues_[1].get<uint64_t>();
      uint64_t out = static_cast<uint64_t>(rs1 + rs2);
      results_[0] = RegisterValue(out, 8);
      break;
    }
    case Opcode::RISCV_ADDW: {  // ADDW rd,rs1,rs2
      const int32_t rs1 = sourceValues_[0].get<int32_t>();
      const int32_t rs2 = sourceValues_[1].get<int32_t>();
      int64_t out = static_cast<int64_t>(static_cast<int32_t>(rs1 + rs2));
      results_[0] = RegisterValue(out, 8);
      break;
    }
    case Opcode::RISCV_ADDI: {  // ADDI rd,rs1,imm
      const uint64_t rs1 = sourceValues_[0].get<uint64_t>();
      uint64_t out = static_cast<uint64_t>(rs1 + sourceImm_);
      results_[0] = RegisterValue(out, 8);
      break;
    }
    case Opcode::RISCV_ADDIW: {  // ADDIW rd,rs1,imm
      const int32_t rs1 = sourceValues_[0].get<int32_t>();
      uint64_t out = signExtendW(rs1 + sourceImm_);
      results_[0] = RegisterValue(out, 8);
      break;
    }
    case Opcode::RISCV_SUB: {  // SUB rd,rs1,rs2
      const uint64_t rs1 = sourceValues_[0].get<uint64_t>();
      const uint64_t rs2 = sourceValues_[1].get<uint64_t>();
      uint64_t out = static_cast<uint64_t>(rs1 - rs2);
      results_[0] = RegisterValue(out, 8);
      break;
    }
    case Opcode::RISCV_SUBW: {  // SUBW rd,rs1,rs2
      const int32_t rs1 = sourceValues_[0].get<int32_t>();
      const int32_t rs2 = sourceValues_[1].get<int32_t>();
      int64_t out = static_cast<int64_t>(static_cast<int32_t>(rs1 - rs2));
      results_[0] = RegisterValue(out, 8);
      break;
    }
    case Opcode::RISCV_LUI: {                        // LUI rd,imm
      uint64_t out = signExtendW(sourceImm_ << 12);  // Shift into upper 20 bits
      results_[0] = RegisterValue(out, 8);
      break;
    }
    case Opcode::RISCV_AUIPC: {  // AUIPC rd,imm
      const int64_t pc = instructionAddress_;
      const int64_t uimm =
          signExtendW(sourceImm_ << 12);  // Shift into upper 20 bits
      uint64_t out = static_cast<uint64_t>(pc + uimm);
      results_[0] = RegisterValue(out, 8);
      break;
    }
    case Opcode::RISCV_XOR: {  // XOR rd,rs1,rs2
      const uint64_t rs1 = sourceValues_[0].get<uint64_t>();
      const uint64_t rs2 = sourceValues_[1].get<uint64_t>();
      uint64_t out = static_cast<uint64_t>(rs1 ^ rs2);
      results_[0] = RegisterValue(out, 8);
      break;
    }
    case Opcode::RISCV_XORI: {  // XORI rd,rs1,imm
      const uint64_t rs1 = sourceValues_[0].get<uint64_t>();
      uint64_t out = static_cast<uint64_t>(rs1 ^ sourceImm_);
      results_[0] = RegisterValue(out, 8);
      break;
    }
    case Opcode::RISCV_OR: {  // OR rd,rs1,rs2
      const uint64_t rs1 = sourceValues_[0].get<uint64_t>();
      const uint64_t rs2 = sourceValues_[1].get<uint64_t>();
      uint64_t out = static_cast<uint64_t>(rs1 | rs2);
      results_[0] = RegisterValue(out, 8);
      break;
    }
    case Opcode::RISCV_ORI: {  // ORI rd,rs1,imm
      const uint64_t rs1 = sourceValues_[0].get<uint64_t>();
      uint64_t out = static_cast<uint64_t>(rs1 | sourceImm_);
      results_[0] = RegisterValue(out, 8);
      break;
    }
    case Opcode::RISCV_AND: {  // AND rd,rs1,rs2
      const uint64_t rs1 = sourceValues_[0].get<uint64_t>();
      const uint64_t rs2 = sourceValues_[1].get<uint64_t>();
      uint64_t out = static_cast<uint64_t>(rs1 & rs2);
      results_[0] = RegisterValue(out, 8);
      break;
    }
    case Opcode::RISCV_ANDI: {  // ANDI rd,rs1,imm
      const uint64_t rs1 = sourceValues_[0].get<uint64_t>();
      uint64_t out = static_cast<uint64_t>(rs1 & sourceImm_);
      results_[0] = RegisterValue(out, 8);
      break;
    }
    case Opcode::RISCV_SLT: {  // SLT rd,rs1,rs2
      const int64_t rs1 = sourceValues_[0].get<int64_t>();
      const int64_t rs2 = sourceValues_[1].get<int64_t>();
      if (rs1 < rs2) {
        results_[0] = RegisterValue(static_cast<uint64_t>(1), 8);
      } else {
        results_[0] = RegisterValue(static_cast<uint64_t>(0), 8);
      }
      break;
    }
    case Opcode::RISCV_SLTU: {  // SLTU rd,rs1,rs2
      const uint64_t rs1 = sourceValues_[0].get<uint64_t>();
      const uint64_t rs2 = sourceValues_[1].get<uint64_t>();
      if (rs1 < rs2) {
        results_[0] = RegisterValue(static_cast<uint64_t>(1), 8);
      } else {
        results_[0] = RegisterValue(static_cast<uint64_t>(0), 8);
      }
      break;
    }
    case Opcode::RISCV_SLTI: {  // SLTI rd,rs1,imm
      const int64_t rs1 = sourceValues_[0].get<int64_t>();
      if (rs1 < sourceImm_) {
        results_[0] = RegisterValue(static_cast<uint64_t>(1), 8);
      } else {
        results_[0] = RegisterValue(static_cast<uint64_t>(0), 8);
      }
      break;
    }
    case Opcode::RISCV_SLTIU: {  // SLTIU rd,rs1,imm
      const uint64_t rs1 = sourceValues_[0].get<uint64_t>();
      if (rs1 < static_cast<uint64_t>(sourceImm_)) {
        results_[0] = RegisterValue(static_cast<uint64_t>(1), 8);
      } else {
        results_[0] = RegisterValue(static_cast<uint64_t>(0), 8);
      }
      break;
    }
    case Opcode::RISCV_BEQ: {  // BEQ rs1,rs2,imm
      const uint64_t rs1 = sourceValues_[0].get<uint64_t>();
      const uint64_t rs2 = sourceValues_[1].get<uint64_t>();
      if (rs1 == rs2) {
        branchAddress_ =
            instructionAddress_ + sourceImm_;  // Set LSB of result to 0
        branchTaken_ = true;
      } else {
        branchAddress_ = instructionAddress_ + metadata_.getInsnLength();
        branchTaken_ = false;
      }
      break;
    }
    case Opcode::RISCV_BNE: {  // BNE rs1,rs2,imm
      const uint64_t rs1 = sourceValues_[0].get<uint64_t>();
      const uint64_t rs2 = sourceValues_[1].get<uint64_t>();
      if (rs1 != rs2) {
        branchAddress_ =
            instructionAddress_ + sourceImm_;  // Set LSB of result to 0
        branchTaken_ = true;
      } else {
        // Increase by instruction size to account for compressed instructions
        branchAddress_ = instructionAddress_ + metadata_.getInsnLength();
        branchTaken_ = false;
      }
      break;
    }
    case Opcode::RISCV_BLT: {  // BLT rs1,rs2,imm
      const int64_t rs1 = sourceValues_[0].get<int64_t>();
      const int64_t rs2 = sourceValues_[1].get<int64_t>();
      if (rs1 < rs2) {
        branchAddress_ =
            instructionAddress_ + sourceImm_;  // Set LSB of result to 0
        branchTaken_ = true;
      } else {
        branchAddress_ = instructionAddress_ + metadata_.getInsnLength();
        branchTaken_ = false;
      }
      break;
    }
    case Opcode::RISCV_BLTU: {  // BLTU rs1,rs2,imm
      const uint64_t rs1 = sourceValues_[0].get<uint64_t>();
      const uint64_t rs2 = sourceValues_[1].get<uint64_t>();
      if (rs1 < rs2) {
        branchAddress_ =
            instructionAddress_ + sourceImm_;  // Set LSB of result to 0
        branchTaken_ = true;
      } else {
        branchAddress_ = instructionAddress_ + metadata_.getInsnLength();
        branchTaken_ = false;
      }
      break;
    }
    case Opcode::RISCV_BGE: {  // BGE rs1,rs2,imm
      const int64_t rs1 = sourceValues_[0].get<int64_t>();
      const int64_t rs2 = sourceValues_[1].get<int64_t>();
      if (rs1 >= rs2) {
        branchAddress_ =
            instructionAddress_ + sourceImm_;  // Set LSB of result to 0
        branchTaken_ = true;
      } else {
        branchAddress_ = instructionAddress_ + metadata_.getInsnLength();
        branchTaken_ = false;
      }
      break;
    }
    case Opcode::RISCV_BGEU: {  // BGEU rs1,rs2,imm
      const uint64_t rs1 = sourceValues_[0].get<uint64_t>();
      const uint64_t rs2 = sourceValues_[1].get<uint64_t>();
      if (rs1 >= rs2) {
        branchAddress_ =
            instructionAddress_ + sourceImm_;  // Set LSB of result to 0
        branchTaken_ = true;
      } else {
        branchAddress_ = instructionAddress_ + metadata_.getInsnLength();
        branchTaken_ = false;
      }
      break;
    }
    case Opcode::RISCV_JAL: {  // JAL rd,imm
      branchAddress_ =
          instructionAddress_ + sourceImm_;  // Set LSB of result to 0
      branchTaken_ = true;
      results_[0] =
          RegisterValue(instructionAddress_ + metadata_.getInsnLength(), 8);
      break;
    }
    case Opcode::RISCV_JALR: {  // JALR rd,rs1,imm
      branchAddress_ = (sourceValues_[0].get<uint64_t>() + sourceImm_) &
                       ~1;  // Set LSB of result to 0
      branchTaken_ = true;
      results_[0] =
          RegisterValue(instructionAddress_ + metadata_.getInsnLength(), 8);
      break;
    }
      // TODO EBREAK
      // used to return control to a debugging environment pg27 20191213
    case Opcode::RISCV_ECALL: {  // ECALL
      exceptionEncountered_ = true;
      exception_ = InstructionException::SupervisorCall;
      break;
    }
    case Opcode::RISCV_FENCE: {  // FENCE
      // TODO currently modelled as a NOP as all codes are currently single
      // threaded "Informally, no other RISC-V hart or external device can
      // observe any operation in the successor set following a FENCE before
      // any operation in the predecessor set preceding the FENCE."
      // https://msyksphinz-self.github.io/riscv-isadoc/html/rvi.html#fence

      /* "a simple implementation ... might be able to implement the FENCE
       * instruction as a NOP", pg13 20191213 spec */
      break;
    }

      // Atomic Extension (A)
      // TODO not implemented atomically
    case Opcode::RISCV_LR_W:  // LR.W rd,rs1
    case Opcode::RISCV_LR_W_AQ:
    case Opcode::RISCV_LR_W_RL:
    case Opcode::RISCV_LR_W_AQ_RL: {
      // TODO set "reservation set" in memory, currently not needed as all
      // codes are single threaded
      // TODO check that address is naturally aligned to operand size,
      //  if not raise address-misaligned/access-fault exception
      // TODO use aq and rl bits to prevent reordering with other memory
      // operations
      results_[0] =
          RegisterValue(bitExtend(memoryData_[0].get<uint32_t>(), 32), 8);
      break;
    }
    case Opcode::RISCV_LR_D:  // LR.D rd,rs1
    case Opcode::RISCV_LR_D_AQ:
    case Opcode::RISCV_LR_D_RL:
    case Opcode::RISCV_LR_D_AQ_RL: {
      results_[0] = RegisterValue(memoryData_[0].get<uint64_t>(), 8);
      break;
    }
    case Opcode::RISCV_SC_W:  // SC.W rd,rs1,rs2
    case Opcode::RISCV_SC_W_AQ:
    case Opcode::RISCV_SC_W_RL:
    case Opcode::RISCV_SC_W_AQ_RL:
    case Opcode::RISCV_SC_D:  // SC.D rd,rs1,rs2
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
      memoryData_[0] = sourceValues_[0];
      results_[0] = RegisterValue(static_cast<uint64_t>(0), 8);
      break;
    }
    case Opcode::RISCV_AMOSWAP_W:  // AMOSWAP.W rd,rs1,rs2
    case Opcode::RISCV_AMOSWAP_W_AQ:
    case Opcode::RISCV_AMOSWAP_W_RL:
    case Opcode::RISCV_AMOSWAP_W_AQ_RL: {
      // Load memory at address rs1 into rd
      // Swap rd and rs2
      // Store rd to memory at address rs1
      // TODO raise address misaligned or access-fault errors
      // TODO account for AQ and RL bits
      int64_t rd = signExtendW(memoryData_[0].get<uint32_t>());
      int32_t rs2 = sourceValues_[0].get<int32_t>();
      results_[0] = RegisterValue(rd, 8);
      memoryData_[0] = rs2;
      break;
    }
    case Opcode::RISCV_AMOSWAP_D:  // AMOSWAP.D rd,rs1,rs2
    case Opcode::RISCV_AMOSWAP_D_AQ:
    case Opcode::RISCV_AMOSWAP_D_RL:
    case Opcode::RISCV_AMOSWAP_D_AQ_RL: {
      uint64_t rd = memoryData_[0].get<uint64_t>();
      uint64_t rs2 = sourceValues_[0].get<uint64_t>();
      results_[0] = RegisterValue(rd, 8);
      memoryData_[0] = rs2;
      break;
    }
    case Opcode::RISCV_AMOADD_W:  // AMOADD.W rd,rs1,rs2
    case Opcode::RISCV_AMOADD_W_AQ:
    case Opcode::RISCV_AMOADD_W_RL:
    case Opcode::RISCV_AMOADD_W_AQ_RL: {
      int64_t rd = signExtendW(memoryData_[0].get<uint32_t>());
      results_[0] = RegisterValue(rd, 8);
      memoryData_[0] =
          static_cast<int32_t>(rd + sourceValues_[0].get<int64_t>());
      break;
    }
    case Opcode::RISCV_AMOADD_D:  // AMOADD.D rd,rs1,rs2
    case Opcode::RISCV_AMOADD_D_AQ:
    case Opcode::RISCV_AMOADD_D_RL:
    case Opcode::RISCV_AMOADD_D_AQ_RL: {
      int64_t rd = memoryData_[0].get<uint64_t>();
      results_[0] = RegisterValue(rd, 8);
      memoryData_[0] =
          static_cast<int64_t>(rd + sourceValues_[0].get<int64_t>());
      break;
    }
    case Opcode::RISCV_AMOAND_W:  // AMOAND.W rd,rs1,rs2
    case Opcode::RISCV_AMOAND_W_AQ:
    case Opcode::RISCV_AMOAND_W_RL:
    case Opcode::RISCV_AMOAND_W_AQ_RL: {
      int64_t rd = signExtendW(memoryData_[0].get<uint32_t>());
      results_[0] = RegisterValue(rd, 8);
      memoryData_[0] =
          static_cast<int32_t>(rd & sourceValues_[0].get<int64_t>());
      break;
    }
    case Opcode::RISCV_AMOAND_D:  // AMOAND.D rd,rs1,rs2
    case Opcode::RISCV_AMOAND_D_AQ:
    case Opcode::RISCV_AMOAND_D_RL:
    case Opcode::RISCV_AMOAND_D_AQ_RL: {
      int64_t rd = memoryData_[0].get<uint64_t>();
      results_[0] = RegisterValue(rd, 8);
      memoryData_[0] =
          static_cast<int64_t>(rd & sourceValues_[0].get<int64_t>());
      break;
    }
    case Opcode::RISCV_AMOOR_W:  // AMOOR.W rd,rs1,rs2
    case Opcode::RISCV_AMOOR_W_AQ:
    case Opcode::RISCV_AMOOR_W_RL:
    case Opcode::RISCV_AMOOR_W_AQ_RL: {
      int64_t rd = signExtendW(memoryData_[0].get<uint32_t>());
      results_[0] = RegisterValue(rd, 8);
      memoryData_[0] =
          static_cast<int32_t>(rd | sourceValues_[0].get<int64_t>());
      break;
    }
    case Opcode::RISCV_AMOOR_D:  // AMOOR.D rd,rs1,rs2
    case Opcode::RISCV_AMOOR_D_AQ:
    case Opcode::RISCV_AMOOR_D_RL:
    case Opcode::RISCV_AMOOR_D_AQ_RL: {
      int64_t rd = memoryData_[0].get<uint64_t>();
      results_[0] = RegisterValue(rd, 8);
      memoryData_[0] =
          static_cast<int64_t>(rd | sourceValues_[0].get<int64_t>());
      break;
    }
    case Opcode::RISCV_AMOXOR_W:  // AMOXOR.W rd,rs1,rs2
    case Opcode::RISCV_AMOXOR_W_AQ:
    case Opcode::RISCV_AMOXOR_W_RL:
    case Opcode::RISCV_AMOXOR_W_AQ_RL: {
      int64_t rd = signExtendW(memoryData_[0].get<uint32_t>());
      results_[0] = RegisterValue(rd, 8);
      memoryData_[0] =
          static_cast<int32_t>(rd ^ sourceValues_[0].get<int64_t>());
      break;
    }
    case Opcode::RISCV_AMOXOR_D:  // AMOXOR.D rd,rs1,rs2
    case Opcode::RISCV_AMOXOR_D_AQ:
    case Opcode::RISCV_AMOXOR_D_RL:
    case Opcode::RISCV_AMOXOR_D_AQ_RL: {
      int64_t rd = memoryData_[0].get<uint64_t>();
      results_[0] = RegisterValue(rd, 8);
      memoryData_[0] =
          static_cast<int64_t>(rd ^ sourceValues_[0].get<int64_t>());
      break;
    }

    case Opcode::RISCV_AMOMIN_W:  // AMOMIN.W rd,rs1,rs2
    case Opcode::RISCV_AMOMIN_W_AQ:
    case Opcode::RISCV_AMOMIN_W_RL:
    case Opcode::RISCV_AMOMIN_W_AQ_RL: {
      results_[0] =
          RegisterValue(signExtendW(memoryData_[0].get<int32_t>()), 8);
      memoryData_[0] = std::min(memoryData_[0].get<int32_t>(),
                                sourceValues_[0].get<int32_t>());
      break;
    }
    case Opcode::RISCV_AMOMIN_D:  // AMOMIN.D rd,rs1,rs2
    case Opcode::RISCV_AMOMIN_D_AQ:
    case Opcode::RISCV_AMOMIN_D_RL:
    case Opcode::RISCV_AMOMIN_D_AQ_RL: {
      int64_t rd = memoryData_[0].get<int64_t>();
      results_[0] = RegisterValue(rd, 8);
      memoryData_[0] =
          static_cast<int64_t>(std::min(rd, sourceValues_[0].get<int64_t>()));
      break;
    }
    case Opcode::RISCV_AMOMINU_W:  // AMOMINU.W rd,rs1,rs2
    case Opcode::RISCV_AMOMINU_W_AQ:
    case Opcode::RISCV_AMOMINU_W_RL:
    case Opcode::RISCV_AMOMINU_W_AQ_RL: {
      results_[0] =
          RegisterValue(signExtendW(memoryData_[0].get<uint32_t>()), 8);
      memoryData_[0] = std::min(memoryData_[0].get<uint32_t>(),
                                sourceValues_[0].get<uint32_t>());
      break;
    }
    case Opcode::RISCV_AMOMINU_D:  // AMOMINU.D rd,rs1,rs2
    case Opcode::RISCV_AMOMINU_D_AQ:
    case Opcode::RISCV_AMOMINU_D_RL:
    case Opcode::RISCV_AMOMINU_D_AQ_RL: {
      uint64_t rd = memoryData_[0].get<uint64_t>();
      results_[0] = RegisterValue(rd, 8);
      memoryData_[0] =
          static_cast<uint64_t>(std::min(rd, sourceValues_[0].get<uint64_t>()));
      break;
    }

    case Opcode::RISCV_AMOMAX_W:  // AMOMAX.W rd,rs1,rs2
    case Opcode::RISCV_AMOMAX_W_AQ:
    case Opcode::RISCV_AMOMAX_W_RL:
    case Opcode::RISCV_AMOMAX_W_AQ_RL: {
      results_[0] =
          RegisterValue(signExtendW(memoryData_[0].get<int32_t>()), 8);
      memoryData_[0] = std::max(memoryData_[0].get<int32_t>(),
                                sourceValues_[0].get<int32_t>());
      break;
    }
    case Opcode::RISCV_AMOMAX_D:  // AMOMAX.D rd,rs1,rs2
    case Opcode::RISCV_AMOMAX_D_AQ:
    case Opcode::RISCV_AMOMAX_D_RL:
    case Opcode::RISCV_AMOMAX_D_AQ_RL: {
      int64_t rd = memoryData_[0].get<int64_t>();
      results_[0] = RegisterValue(rd, 8);
      memoryData_[0] =
          static_cast<int64_t>(std::max(rd, sourceValues_[0].get<int64_t>()));
      break;
    }
    case Opcode::RISCV_AMOMAXU_W:  // AMOMAXU.W rd,rs1,rs2
    case Opcode::RISCV_AMOMAXU_W_AQ:
    case Opcode::RISCV_AMOMAXU_W_RL:
    case Opcode::RISCV_AMOMAXU_W_AQ_RL: {
      results_[0] =
          RegisterValue(signExtendW(memoryData_[0].get<uint32_t>()), 8);
      memoryData_[0] = std::max(memoryData_[0].get<uint32_t>(),
                                sourceValues_[0].get<uint32_t>());
      break;
    }
    case Opcode::RISCV_AMOMAXU_D:  // AMOMAXU.D rd,rs1,rs2
    case Opcode::RISCV_AMOMAXU_D_AQ:
    case Opcode::RISCV_AMOMAXU_D_RL:
    case Opcode::RISCV_AMOMAXU_D_AQ_RL: {
      uint64_t rd = memoryData_[0].get<uint64_t>();
      results_[0] = RegisterValue(rd, 8);
      memoryData_[0] =
          static_cast<uint64_t>(std::max(rd, sourceValues_[0].get<uint64_t>()));
      break;
    }

      // Integer multiplication division extension (M)
    case Opcode::RISCV_MUL: {  // MUL rd,rs1,rs2
      const int64_t rs1 = sourceValues_[0].get<int64_t>();
      const int64_t rs2 = sourceValues_[1].get<int64_t>();
      results_[0] = RegisterValue(static_cast<int64_t>(rs1 * rs2), 8);
      break;
    }
      //    case Opcode::RISCV_MULH: {//MULH rd,rs1,rs2
      //      return executionNYI();
      //
      //      const int64_t rs1 = operands[0].get<int64_t>();
      //      const int64_t rs2 = operands[1].get<int64_t>();
      //      results[0] = RegisterValue(mulhiss(rs1, rs2);
      //      break;
      //    }
    case Opcode::RISCV_MULHU: {  // MULHU rd,rs1,rs2
      const uint64_t rs1 = sourceValues_[0].get<uint64_t>();
      const uint64_t rs2 = sourceValues_[1].get<uint64_t>();
      results_[0] = RegisterValue(mulhiuu(rs1, rs2), 8);
      break;
    }
      //    case Opcode::RISCV_MULHSU: {//MULHSU rd,rs1,rs2
      //      return executionNYI();
      //
      //      const int64_t rs1 = operands[0].get<int64_t>();
      //      const uint64_t rs2 = operands[1].get<uint64_t>();
      //      results[0] = RegisterValue(mulhisu(rs1, rs2);
      //      break;
      //    }
    case Opcode::RISCV_MULW: {  // MULW rd,rs1,rs2
      const uint32_t rs1 = sourceValues_[0].get<uint32_t>();
      const uint32_t rs2 = sourceValues_[1].get<uint32_t>();
      results_[0] = RegisterValue(signExtendW(rs1 * rs2), 8);
      break;
    }

    case Opcode::RISCV_DIV: {  // DIV rd,rs1,rs2
      const int64_t rs1 = sourceValues_[0].get<int64_t>();
      const int64_t rs2 = sourceValues_[1].get<int64_t>();
      if (rs2 == 0) {
        // divide by zero
        results_[0] = RegisterValue(static_cast<uint64_t>(-1), 8);
      } else if (rs1 == static_cast<int64_t>(0x8000000000000000) && rs2 == -1) {
        // division overflow
        results_[0] = RegisterValue(rs1, 8);
      } else {
        results_[0] = RegisterValue(static_cast<int64_t>(rs1 / rs2), 8);
      }
      break;
    }
    case Opcode::RISCV_DIVW: {  // DIVW rd,rs1,rs2
      const int32_t rs1 = sourceValues_[0].get<int32_t>();
      const int32_t rs2 = sourceValues_[1].get<int32_t>();
      if (rs2 == 0) {
        // divide by zero
        results_[0] = RegisterValue(static_cast<uint64_t>(-1), 8);
      } else if (rs1 == static_cast<int32_t>(0x80000000) && rs2 == -1) {
        // division overflow
        results_[0] = RegisterValue(static_cast<int64_t>(signExtendW(rs1)), 8);
      } else {
        results_[0] =
            RegisterValue(static_cast<int64_t>(signExtendW(rs1 / rs2)), 8);
      }
      break;
    }
    case Opcode::RISCV_DIVU: {  // DIVU rd,rs1,rs2
      const uint64_t rs1 = sourceValues_[0].get<uint64_t>();
      const uint64_t rs2 = sourceValues_[1].get<uint64_t>();
      if (rs2 == 0) {
        // divide by zero
        results_[0] = RegisterValue(static_cast<uint64_t>(-1), 8);
      } else {
        results_[0] = RegisterValue(static_cast<uint64_t>(rs1 / rs2), 8);
      }
      break;
    }
    case Opcode::RISCV_DIVUW: {  // DIVUW rd,rs1,rs2
      const uint32_t rs1 = sourceValues_[0].get<uint32_t>();
      const uint32_t rs2 = sourceValues_[1].get<uint32_t>();
      if (rs2 == 0) {
        // divide by zero
        results_[0] = RegisterValue(static_cast<uint64_t>(-1), 8);
      } else {
        results_[0] =
            RegisterValue(static_cast<uint64_t>(signExtendW(rs1 / rs2)), 8);
      }
      break;
    }
    case Opcode::RISCV_REM: {  // REM rd,rs1,rs2
      const int64_t rs1 = sourceValues_[0].get<int64_t>();
      const int64_t rs2 = sourceValues_[1].get<int64_t>();
      if (rs2 == 0) {
        // divide by zero
        results_[0] = RegisterValue(static_cast<uint64_t>(rs1), 8);
      } else if (rs1 == static_cast<int64_t>(0x8000000000000000) && rs2 == -1) {
        // division overflow
        results_[0] = RegisterValue(static_cast<int64_t>(0), 8);
      } else {
        results_[0] = RegisterValue(static_cast<int64_t>(rs1 % rs2), 8);
      }
      break;
    }
    case Opcode::RISCV_REMW: {  // REMW rd,rs1,rs2
      const int32_t rs1 = sourceValues_[0].get<int32_t>();
      const int32_t rs2 = sourceValues_[1].get<int32_t>();
      if (rs2 == 0) {
        // divide by zero
        results_[0] = RegisterValue(static_cast<int64_t>(signExtendW(rs1)), 8);
      } else if (rs1 == static_cast<int32_t>(0x80000000) && rs2 == -1) {
        // division overflow
        results_[0] = RegisterValue(static_cast<int64_t>(0), 8);
      } else {
        results_[0] =
            RegisterValue(static_cast<int64_t>(signExtendW(rs1 % rs2)), 8);
      }
      break;
    }
    case Opcode::RISCV_REMU: {  // REMU rd,rs1,rs2
      const uint64_t rs1 = sourceValues_[0].get<uint64_t>();
      const uint64_t rs2 = sourceValues_[1].get<uint64_t>();
      if (rs2 == 0) {
        // divide by zero
        results_[0] = RegisterValue(rs1, 8);
      } else {
        results_[0] = RegisterValue(static_cast<uint64_t>(rs1 % rs2), 8);
      }
      break;
    }
    case Opcode::RISCV_REMUW: {  // REMUW rd,rs1,rs2
      const uint32_t rs1 = sourceValues_[0].get<uint32_t>();
      const uint32_t rs2 = sourceValues_[1].get<uint32_t>();
      if (rs2 == 0) {
        // divide by zero
        results_[0] = RegisterValue(static_cast<int64_t>(signExtendW(rs1)), 8);
      } else {
        results_[0] =
            RegisterValue(static_cast<uint64_t>(signExtendW(rs1 % rs2)), 8);
      }
      break;
    }

      // Control and Status Register extension (Zicsr)

      // Currently do not read-modify-write ATOMICALLY
      // Left mostly unimplemented due to Capstone being unable to disassemble
      // CSR addresses. Some partial functionality is implemented for
      // correctness of other extensions
    case Opcode::RISCV_CSRRW: {  // CSRRW rd,csr,rs1
      // TODO dummy implementation to allow progression and correct setting of
      // floating point rounding modes. Full functionality to be implemented
      // with Zicsr implementation

      // Raise exception to force pipeline flush and commit of all older
      // instructions in program order before execution. Execution
      // logic in ExceptionHandler.cc
      exceptionEncountered_ = true;
      exception_ = InstructionException::PipelineFlush;

      break;
    }
    case Opcode::RISCV_CSRRWI: {  // CSRRWI rd,csr,imm
      executionNYI();
      break;
    }
    case Opcode::RISCV_CSRRS: {  // CSRRS rd,csr,rs1
      // dummy implementation to allow progression
      // TODO implement fully when Zicsr extension is supported
      results_[0] = RegisterValue(static_cast<uint64_t>(0), 8);
      break;
    }
    case Opcode::RISCV_CSRRSI: {  // CSRRSI rd,csr,imm
      executionNYI();
      break;
    }
    case Opcode::RISCV_CSRRC: {  // CSRRC rd,csr,rs1
      executionNYI();
      break;
    }
    case Opcode::RISCV_CSRRCI: {  // CSRRCI rd,csr,imm
      executionNYI();
      break;
    }

      // Single-Precision Floating-Point (F)
      // Double-Precision Floating-Point (D)
    case Opcode::RISCV_FSD: {  // FSD rs1,rs2,imm
      memoryData_[0] = sourceValues_[0];
      break;
    }
    case Opcode::RISCV_FSW: {  // FSW rs1,rs2,imm
      memoryData_[0] = sourceValues_[0];
      break;
    }
    case Opcode::RISCV_FLD: {  // FLD rd,rs1,imm
      results_[0] = memoryData_[0].get<double>();
      break;
    }
    case Opcode::RISCV_FLW: {  // FLW rd,rs1,imm
      const float memSingle = memoryData_[0].get<float>();

      results_[0] = RegisterValue(NanBoxFloat(memSingle), 8);
      break;
    }

    case Opcode::RISCV_FADD_D: {  // FADD.D rd,rs1,rs2
      setStaticRoundingModeThen([&] {
        const double rs1 = sourceValues_[0].get<double>();
        const double rs2 = sourceValues_[1].get<double>();

        results_[0] = RegisterValue(rs1 + rs2, 8);
      });
      break;
    }
    case Opcode::RISCV_FADD_S: {  // FADD.S rd,rs1,rs2

      setStaticRoundingModeThen([&] {
        const float rs1 = checkNanBox(sourceValues_[0]);
        const float rs2 = checkNanBox(sourceValues_[1]);

        results_[0] = RegisterValue(NanBoxFloat(rs1 + rs2), 8);
      });
      break;
    }
    case Opcode::RISCV_FSUB_D: {  // FSUB.D rd,rs1,rs2

      setStaticRoundingModeThen([&] {
        const double rs1 = sourceValues_[0].get<double>();
        const double rs2 = sourceValues_[1].get<double>();

        results_[0] = RegisterValue(rs1 - rs2, 8);
      });

      break;
    }
    case Opcode::RISCV_FSUB_S: {  // FSUB.S rd,rs1,rs2

      setStaticRoundingModeThen([&] {
        const float rs1 = checkNanBox(sourceValues_[0]);
        const float rs2 = checkNanBox(sourceValues_[1]);

        results_[0] = RegisterValue(NanBoxFloat(rs1 - rs2), 8);
      });

      break;
    }
    case Opcode::RISCV_FDIV_D: {  // FDIV.D rd,rs1,rs2

      setStaticRoundingModeThen([&] {
        const double rs1 = sourceValues_[0].get<double>();
        const double rs2 = sourceValues_[1].get<double>();

        results_[0] = RegisterValue(rs1 / rs2, 8);
      });

      break;
    }
    case Opcode::RISCV_FDIV_S: {  // FDIV.S rd,rs1,rs2

      setStaticRoundingModeThen([&] {
        const float rs1 = checkNanBox(sourceValues_[0]);
        const float rs2 = checkNanBox(sourceValues_[1]);

        results_[0] = RegisterValue(NanBoxFloat(rs1 / rs2), 8);
      });

      break;
    }
    case Opcode::RISCV_FMUL_D: {  // FMUL.D rd,rs1,rs2

      setStaticRoundingModeThen([&] {
        const double rs1 = sourceValues_[0].get<double>();
        const double rs2 = sourceValues_[1].get<double>();

        results_[0] = RegisterValue(rs1 * rs2, 8);
      });

      break;
    }
    case Opcode::RISCV_FMUL_S: {  // FMUL.S rd,rs1,rs2

      setStaticRoundingModeThen([&] {
        const float rs1 = checkNanBox(sourceValues_[0]);
        const float rs2 = checkNanBox(sourceValues_[1]);

        results_[0] = RegisterValue(NanBoxFloat(rs1 * rs2), 8);
      });

      break;
    }
    case Opcode::RISCV_FSQRT_D: {  // FSQRT.D rd,rs1

      setStaticRoundingModeThen([&] {
        const double rs1 = sourceValues_[0].get<double>();

        const double sqrtAns = sqrt(rs1);

        // With -ve rs1, sqrt = -NaN, but qemu returns canonical (+)NaN. Adjust
        // for this here
        const double res = std::isnan(sqrtAns) ? nanf("0") : sqrtAns;

        results_[0] = RegisterValue(res, 8);
      });

      break;
    }
    case Opcode::RISCV_FSQRT_S: {  // FSQRT.S rd,rs1

      setStaticRoundingModeThen([&] {
        const float rs1 = checkNanBox(sourceValues_[0]);

        const float sqrtAns = sqrtf(rs1);

        // With -ve rs1, sqrt = -NaN, but qemu returns canonical (+)NaN. Adjust
        // for this here
        const float res = std::isnan(sqrtAns) ? nanf("0") : sqrtAns;

        results_[0] = RegisterValue(NanBoxFloat(res), 8);
      });

      break;
    }

    case Opcode::RISCV_FMIN_D: {  // FMIN.D rd,rs1,rs2
      const double rs1 = sourceValues_[0].get<double>();
      const double rs2 = sourceValues_[1].get<double>();

      // cpp fmin reference: This function is not required to be sensitive to
      // the sign of zero, although some implementations additionally enforce
      // that if one argument is +0 and the other is -0, then +0 is returned.
      // But RISC-V spec requires -0.0 to be considered < +0.0
      if (rs1 == 0 && rs2 == 0) {
        results_[0] = RegisterValue(0x8000000000000000, 8);
      } else {
        results_[0] = RegisterValue(fmin(rs1, rs2), 8);
      }

      break;
    }
    case Opcode::RISCV_FMIN_S: {  // FMIN.S rd,rs1,rs2
      const float rs1 = checkNanBox(sourceValues_[0]);
      const float rs2 = checkNanBox(sourceValues_[1]);

      // Comments regarding fminf similar to RISCV_FMIN_D
      if (rs1 == 0 && rs2 == 0) {
        results_[0] = RegisterValue(0xffffffff80000000, 8);
      } else {
        results_[0] = RegisterValue(NanBoxFloat(fminf(rs1, rs2)), 8);
      }

      break;
    }
    case Opcode::RISCV_FMAX_D: {  // FMAX.D rd,rs1,rs2

      const double rs1 = sourceValues_[0].get<double>();
      const double rs2 = sourceValues_[1].get<double>();

      // cpp fmax reference: This function is not required to be sensitive to
      // the sign of zero, although some implementations additionally enforce
      // that if one argument is +0 and the other is -0, then +0 is returned.
      // But RISC-V spec requires this to be the case
      if (rs1 == 0 && rs2 == 0) {
        results_[0] = RegisterValue(0x0000000000000000, 8);
      } else {
        results_[0] = RegisterValue(fmax(rs1, rs2), 8);
      }
      break;
    }
    case Opcode::RISCV_FMAX_S: {  // FMAX.S rd,rs1,rs2
      const float rs1 = checkNanBox(sourceValues_[0]);
      const float rs2 = checkNanBox(sourceValues_[1]);

      // Comments regarding fmaxf similar to RISCV_FMAX_D
      if (rs1 == 0 && rs2 == 0) {
        results_[0] = RegisterValue(0xffffffff00000000, 8);
      } else {
        results_[0] = RegisterValue(NanBoxFloat(fmaxf(rs1, rs2)), 8);
      }
      break;
    }

      // TODO "The fused multiply-add instructions must set the invalid
      // operation exception flag when the multiplicands are ∞ and zero, even
      // when the addend is a quiet NaN." pg69, require Zicsr extension
    case Opcode::RISCV_FMADD_D: {  // FMADD.D rd,rs1,rs2,rs3
      // The fused multiply-add instructions must set the invalid operation
      // exception flag when the multiplicands are infinity and zero, even when
      // the addend is a quiet NaN.

      setStaticRoundingModeThen([&] {
        const double rs1 = sourceValues_[0].get<double>();
        const double rs2 = sourceValues_[1].get<double>();
        const double rs3 = sourceValues_[2].get<double>();

        results_[0] = RegisterValue(fma(rs1, rs2, rs3), 8);
      });

      break;
    }
    case Opcode::RISCV_FMADD_S: {  // FMADD.S rd,rs1,rs2,rs3

      setStaticRoundingModeThen([&] {
        const float rs1 = checkNanBox(sourceValues_[0]);
        const float rs2 = checkNanBox(sourceValues_[1]);
        const float rs3 = checkNanBox(sourceValues_[2]);

        if (std::isnan(rs1) || std::isnan(rs2) || std::isnan(rs3)) {
          results_[0] = RegisterValue(NanBoxFloat(std::nanf("")), 8);
        } else {
          results_[0] = RegisterValue(NanBoxFloat(fmaf(rs1, rs2, rs3)), 8);
        }
      });

      break;
    }
    case Opcode::RISCV_FNMSUB_D: {  // FNMSUB.D rd,rs1,rs2,rs3

      setStaticRoundingModeThen([&] {
        const double rs1 = sourceValues_[0].get<double>();
        const double rs2 = sourceValues_[1].get<double>();
        const double rs3 = sourceValues_[2].get<double>();

        results_[0] = RegisterValue(-(rs1 * rs2) + rs3, 8);
      });

      break;
    }
    case Opcode::RISCV_FNMSUB_S: {  // FNMSUB.S rd,rs1,rs2,rs3

      setStaticRoundingModeThen([&] {
        const float rs1 = checkNanBox(sourceValues_[0]);
        const float rs2 = checkNanBox(sourceValues_[1]);
        const float rs3 = checkNanBox(sourceValues_[2]);

        if (std::isnan(rs1) || std::isnan(rs2) || std::isnan(rs3)) {
          results_[0] = RegisterValue(NanBoxFloat(std::nanf("")), 8);
        } else {
          results_[0] = RegisterValue(NanBoxFloat(-(rs1 * rs2) + rs3), 8);
        }
      });

      break;
    }
    case Opcode::RISCV_FMSUB_D: {  // FMSUB.D rd,rs1,rs2,rs3

      setStaticRoundingModeThen([&] {
        const double rs1 = sourceValues_[0].get<double>();
        const double rs2 = sourceValues_[1].get<double>();
        const double rs3 = sourceValues_[2].get<double>();

        results_[0] = RegisterValue((rs1 * rs2) - rs3, 8);
      });

      break;
    }
    case Opcode::RISCV_FMSUB_S: {  // FMSUB.S rd,rs1,rs2,rs3

      setStaticRoundingModeThen([&] {
        const float rs1 = checkNanBox(sourceValues_[0]);
        const float rs2 = checkNanBox(sourceValues_[1]);
        const float rs3 = checkNanBox(sourceValues_[2]);

        if (std::isnan(rs1) || std::isnan(rs2) || std::isnan(rs3)) {
          results_[0] = RegisterValue(NanBoxFloat(std::nanf("")), 8);
        } else {
          results_[0] = RegisterValue(NanBoxFloat((rs1 * rs2) - rs3), 8);
        }
      });

      break;
    }
    case Opcode::RISCV_FNMADD_D: {  // FNMADD.D rd,rs1,rs2,rs3

      setStaticRoundingModeThen([&] {
        const double rs1 = sourceValues_[0].get<double>();
        const double rs2 = sourceValues_[1].get<double>();
        const double rs3 = sourceValues_[2].get<double>();

        results_[0] = RegisterValue(-(rs1 * rs2) - rs3, 8);
      });

      break;
    }
    case Opcode::RISCV_FNMADD_S: {  // FNMADD.S rd,rs1,rs2,rs3

      setStaticRoundingModeThen([&] {
        const float rs1 = checkNanBox(sourceValues_[0]);
        const float rs2 = checkNanBox(sourceValues_[1]);
        const float rs3 = checkNanBox(sourceValues_[2]);

        // Some implementations return -NaN if certain inputs are NaN but spec
        // requires +NaN. Ensure this happens
        if (std::isnan(rs1) || std::isnan(rs2) || std::isnan(rs3)) {
          results_[0] = RegisterValue(NanBoxFloat(std::nanf("")), 8);
        } else {
          results_[0] = RegisterValue(NanBoxFloat(-(rs1 * rs2) - rs3), 8);
        }
      });

      break;
    }
    case Opcode::RISCV_FCVT_D_L: {  // FCVT.D.L rd,rs1

      setStaticRoundingModeThen([&] {
        const int64_t rs1 = sourceValues_[0].get<int64_t>();

        results_[0] = RegisterValue((double)rs1, 8);
      });

      break;
    }
    case Opcode::RISCV_FCVT_D_W: {  // FCVT.D.W rd,rs1

      setStaticRoundingModeThen([&] {
        const int32_t rs1 = sourceValues_[0].get<int32_t>();

        results_[0] = RegisterValue((double)rs1, 8);
      });

      break;
    }
    case Opcode::RISCV_FCVT_S_L: {  // FCVT.S.L rd,rs1

      setStaticRoundingModeThen([&] {
        const int64_t rs1 = sourceValues_[0].get<int64_t>();

        results_[0] = RegisterValue(NanBoxFloat((float)rs1), 8);
      });

      break;
    }
    case Opcode::RISCV_FCVT_S_W: {  // FCVT.S.W rd,rs1

      setStaticRoundingModeThen([&] {
        const int32_t rs1 = sourceValues_[0].get<int32_t>();

        results_[0] = RegisterValue(NanBoxFloat((float)rs1), 8);
      });

      break;
    }
    case Opcode::RISCV_FCVT_W_D: {  // FCVT.W.D rd,rs1

      setStaticRoundingModeThen([&] {
        const double rs1 = sourceValues_[0].get<double>();

        if (std::isnan(rs1)) {
          results_[0] = RegisterValue(0x7FFFFFFF, 8);
        } else {
          results_[0] = RegisterValue(signExtendW((int32_t)rint(rs1)), 8);
        }
      });

      break;
    }
    case Opcode::RISCV_FCVT_W_S: {  // FCVT.W.S rd,rs1

      setStaticRoundingModeThen([&] {
        const float rs1 = checkNanBox(sourceValues_[0]);

        if (std::isnan(rs1)) {
          results_[0] = RegisterValue(0x7FFFFFFF, 8);
        } else {
          results_[0] = RegisterValue(signExtendW((int32_t)rintf(rs1)), 8);
        }
      });

      break;
    }
    case Opcode::RISCV_FCVT_L_D: {  // FCVT.L.D rd,rs1

      setStaticRoundingModeThen([&] {
        const double rs1 = sourceValues_[0].get<double>();

        if (std::isnan(rs1)) {
          results_[0] = RegisterValue(0x7FFFFFFFFFFFFFFF, 8);
        } else {
          results_[0] = RegisterValue((int64_t)rint(rs1), 8);
        }
      });

      break;
    }
    case Opcode::RISCV_FCVT_L_S: {  // FCVT.L.S rd,rs1

      setStaticRoundingModeThen([&] {
        const float rs1 = checkNanBox(sourceValues_[0]);

        if (std::isnan(rs1)) {
          results_[0] = RegisterValue(0x7FFFFFFFFFFFFFFF, 8);
        } else {
          results_[0] = RegisterValue((int64_t)rintf(rs1), 8);
        }
      });

      break;
    }
    case Opcode::RISCV_FCVT_WU_D: {  // FCVT.WU.D rd,rs1

      setStaticRoundingModeThen([&] {
        const double rs1 = sourceValues_[0].get<double>();

        if (std::isnan(rs1) || rs1 >= pow(2, 32) - 1) {
          results_[0] = RegisterValue(0xFFFFFFFFFFFFFFFF, 8);
        } else {
          if (rs1 < 0) {
            // TODO: set csr flag when Zicsr implementation is complete
            results_[0] = RegisterValue((uint64_t)0, 8);
          } else {
            results_[0] = RegisterValue(signExtendW((uint32_t)rint(rs1)), 8);
          }
        }
      });

      break;
    }
    case Opcode::RISCV_FCVT_WU_S: {  // FCVT.WU.S rd,rs1

      setStaticRoundingModeThen([&] {
        const float rs1 = checkNanBox(sourceValues_[0]);

        if (std::isnan(rs1) || rs1 >= pow(2, 32) - 1) {
          results_[0] = RegisterValue(0xFFFFFFFFFFFFFFFF, 8);
        } else {
          if (rs1 < 0) {
            // TODO: set csr flag when Zicsr implementation is complete
            results_[0] = RegisterValue((uint64_t)0, 8);
          } else {
            results_[0] = RegisterValue(signExtendW((uint32_t)rintf(rs1)), 8);
          }
        }
      });

      break;
    }
    case Opcode::RISCV_FCVT_LU_D: {  // FCVT.LU.D rd,rs1

      setStaticRoundingModeThen([&] {
        const double rs1 = sourceValues_[0].get<double>();

        if (std::isnan(rs1) || rs1 >= pow(2, 64) - 1) {
          results_[0] = RegisterValue(0xFFFFFFFFFFFFFFFF, 8);
        } else {
          if (rs1 < 0) {
            // TODO: set csr flag when Zicsr implementation is complete
            results_[0] = RegisterValue((uint64_t)0, 8);
          } else {
            results_[0] = RegisterValue((uint64_t)rint(rs1), 8);
          }
        }
      });

      break;
    }
    case Opcode::RISCV_FCVT_LU_S: {  // FCVT.LU.S rd,rs1

      setStaticRoundingModeThen([&] {
        const float rs1 = checkNanBox(sourceValues_[0]);

        if (std::isnan(rs1) || rs1 >= pow(2, 64) - 1) {
          results_[0] = RegisterValue(0xFFFFFFFFFFFFFFFF, 8);
        } else {
          if (rs1 < 0) {
            // TODO: set csr flag when Zicsr implementation is complete
            results_[0] = RegisterValue((uint64_t)0, 8);
          } else {
            results_[0] = RegisterValue((uint64_t)rintf(rs1), 8);
          }
        }
      });

      break;
    }
    case Opcode::RISCV_FCVT_D_LU: {  // FCVT.D.LU rd,rs1

      setStaticRoundingModeThen([&] {
        const uint64_t rs1 = sourceValues_[0].get<uint64_t>();

        results_[0] = RegisterValue((double)rs1, 8);
      });

      break;
    }
    case Opcode::RISCV_FCVT_D_WU: {  // FCVT.D.WU rd,rs1

      setStaticRoundingModeThen([&] {
        const uint32_t rs1 = sourceValues_[0].get<uint32_t>();

        results_[0] = RegisterValue((double)rs1, 8);
      });

      break;
    }
    case Opcode::RISCV_FCVT_S_LU: {  // FCVT.S.LU rd,rs1

      setStaticRoundingModeThen([&] {
        const uint64_t rs1 = sourceValues_[0].get<uint64_t>();

        results_[0] = RegisterValue(NanBoxFloat((float)rs1), 8);
      });

      break;
    }
    case Opcode::RISCV_FCVT_S_WU: {  // FCVT.S.WU rd,rs1

      setStaticRoundingModeThen([&] {
        const uint32_t rs1 = sourceValues_[0].get<uint32_t>();

        results_[0] = RegisterValue(NanBoxFloat((float)rs1), 8);
      });

      break;
    }

    case Opcode::RISCV_FCVT_D_S: {  // FCVT.D.S rd,rs1
      const float rs1 = checkNanBox(sourceValues_[0]);

      results_[0] = RegisterValue((double)rs1, 8);
      break;
    }
    case Opcode::RISCV_FCVT_S_D: {  // FCVT.S.D rd,rs1
      const double rs1 = sourceValues_[0].get<double>();

      results_[0] = RegisterValue(NanBoxFloat((float)rs1), 8);
      break;
    }

    case Opcode::RISCV_FSGNJ_D: {  // FSGNJ.D rd,rs1,rs2
      const double rs1 = sourceValues_[0].get<double>();
      const double rs2 = sourceValues_[1].get<double>();

      results_[0] = RegisterValue(std::copysign(rs1, rs2), 8);
      break;
    }
    case Opcode::RISCV_FSGNJ_S: {  // FSGNJ.S rd,rs1,rs2
      const float rs1 = checkNanBox(sourceValues_[0]);
      const float rs2 = checkNanBox(sourceValues_[1]);

      results_[0] = RegisterValue(NanBoxFloat(std::copysign(rs1, rs2)), 8);
      break;
    }
    case Opcode::RISCV_FSGNJN_D: {  // FSGNJN.D rd,rs1,rs2
      const double rs1 = sourceValues_[0].get<double>();
      const double rs2 = sourceValues_[1].get<double>();

      results_[0] = RegisterValue(std::copysign(rs1, -rs2), 8);
      break;
    }

    case Opcode::RISCV_FSGNJN_S: {  // FSGNJN.S rd,rs1,rs2
      const float rs1 = checkNanBox(sourceValues_[0]);
      const float rs2 = checkNanBox(sourceValues_[1]);

      results_[0] = RegisterValue(NanBoxFloat(std::copysign(rs1, -rs2)), 8);
      break;
    }
    case Opcode::RISCV_FSGNJX_D: {  // FSGNJX.D rd,rs1,rs2
      const double rs1 = sourceValues_[0].get<double>();
      const double rs2 = sourceValues_[1].get<double>();

      const double xorSign = pow(-1, std::signbit(rs1) ^ std::signbit(rs2));

      results_[0] = RegisterValue(std::copysign(rs1, xorSign), 8);
      break;
    }
    case Opcode::RISCV_FSGNJX_S: {  // FSGNJX.S rd,rs1,rs2
      const float rs1 = checkNanBox(sourceValues_[0]);
      const float rs2 = checkNanBox(sourceValues_[1]);

      const float xorSign = pow(-1, std::signbit(rs1) ^ std::signbit(rs2));

      results_[0] = RegisterValue(NanBoxFloat(std::copysign(rs1, xorSign)), 8);
      break;
    }

    case Opcode::RISCV_FMV_D_X: {  // FMV.D.X rd,rs1
      const double rs1 = sourceValues_[0].get<double>();

      results_[0] = RegisterValue(rs1, 8);
      break;
    }
    case Opcode::RISCV_FMV_X_D: {  // FMV.X.D rd,rs1
      const double rs1 = sourceValues_[0].get<double>();

      results_[0] = RegisterValue(rs1, 8);
      break;
    }
    case Opcode::RISCV_FMV_W_X: {  // FMV.W.X rd,rs1
      const float rs1 = sourceValues_[0].get<float>();

      results_[0] = RegisterValue(NanBoxFloat(rs1), 8);
      break;
    }
    case Opcode::RISCV_FMV_X_W: {  // FMV.X.W rd,rs1
      const uint64_t rs1 = sourceValues_[0].get<uint64_t>();

      results_[0] = RegisterValue(signExtendW(rs1), 8);
      break;
    }

      // TODO FLT.S and FLE.S perform what the IEEE 754-2008 standard refers
      // to as signaling comparisons: that is, they set the invalid operation
      // exception flag if either input is NaN. FEQ.S performs a quiet
      // comparison: it only sets the invalid operation exception flag if
      // either input is a signaling NaN. For all three instructions, the
      // result is 0 if either operand is NaN. This requires a proper
      // implementation of the Zicsr extension
    case Opcode::RISCV_FEQ_D: {  // FEQ.D rd,rs1,rs2
      // TODO FEQ.S performs a quiet
      // comparison: it only sets the invalid operation exception flag if
      // either input is a signaling NaN. Qemu doesn't seem to set CSR flags
      // with sNANs so unsure of correct implementation. Also require proper
      // Zicsr implementation
      const double rs1 = sourceValues_[0].get<double>();
      const double rs2 = sourceValues_[1].get<double>();

      if (rs1 == rs2 && !std::isnan(rs1) && !std::isnan(rs2)) {
        results_[0] = RegisterValue(static_cast<uint64_t>(1), 8);
      } else {
        results_[0] = RegisterValue(static_cast<uint64_t>(0), 8);
      }
      break;
    }
    case Opcode::RISCV_FEQ_S: {  // FEQ.S rd,rs1,rs2
      const float rs1 = checkNanBox(sourceValues_[0]);
      const float rs2 = checkNanBox(sourceValues_[1]);

      if (rs1 == rs2 && !std::isnan(rs1) && !std::isnan(rs2)) {
        results_[0] = RegisterValue(static_cast<uint64_t>(1), 8);
      } else {
        results_[0] = RegisterValue(static_cast<uint64_t>(0), 8);
      }
      break;
    }
    case Opcode::RISCV_FLT_D: {  // FLT.D rd,rs1,rs2
      const double rs1 = sourceValues_[0].get<double>();
      const double rs2 = sourceValues_[1].get<double>();

      if (std::isnan(rs1) || std::isnan(rs2)) {
        // TODO: set csr flag when Zicsr implementation is complete
      }
      if (rs1 < rs2 && !std::isnan(rs1) && !std::isnan(rs2)) {
        results_[0] = RegisterValue(static_cast<uint64_t>(1), 8);
      } else {
        results_[0] = RegisterValue(static_cast<uint64_t>(0), 8);
      }
      break;
    }
    case Opcode::RISCV_FLT_S: {  // FLT.S rd,rs1,rs2
      const float rs1 = checkNanBox(sourceValues_[0]);
      const float rs2 = checkNanBox(sourceValues_[1]);

      if (std::isnan(rs1) || std::isnan(rs2)) {
        // TODO: set csr flag when Zicsr implementation is complete
      }
      if (rs1 < rs2 && !std::isnan(rs1) && !std::isnan(rs2)) {
        results_[0] = RegisterValue(static_cast<uint64_t>(1), 8);
      } else {
        results_[0] = RegisterValue(static_cast<uint64_t>(0), 8);
      }
      break;
    }
    case Opcode::RISCV_FLE_D: {  // FLE.D rd,rs1,rs2
      const double rs1 = sourceValues_[0].get<double>();
      const double rs2 = sourceValues_[1].get<double>();

      if (std::isnan(rs1) || std::isnan(rs2)) {
        // TODO: set csr flag when Zicsr implementation is complete
      }
      if (rs1 <= rs2 && !std::isnan(rs1) && !std::isnan(rs2)) {
        results_[0] = RegisterValue(static_cast<uint64_t>(1), 8);
      } else {
        results_[0] = RegisterValue(static_cast<uint64_t>(0), 8);
      }
      break;
    }
    case Opcode::RISCV_FLE_S: {  // FLE.S rd,rs1,rs2
      const float rs1 = checkNanBox(sourceValues_[0]);
      const float rs2 = checkNanBox(sourceValues_[1]);

      if (std::isnan(rs1) || std::isnan(rs2)) {
        // TODO: set csr flag when Zicsr implementation is complete
      }
      if (rs1 <= rs2 && !std::isnan(rs1) && !std::isnan(rs2)) {
        results_[0] = RegisterValue(static_cast<uint64_t>(1), 8);
      } else {
        results_[0] = RegisterValue(static_cast<uint64_t>(0), 8);
      }
      break;
    }
    case Opcode::RISCV_FCLASS_S: {
      executionNYI();
      break;
    }
    case Opcode::RISCV_FCLASS_D: {
      executionNYI();
      break;
    }

    default:
      return executionNYI();
  }
}

}  // namespace riscv
}  // namespace arch
}  // namespace simeng