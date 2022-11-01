#pragma once

#include <string>

#include "capstone/capstone.h"

namespace simeng {
namespace arch {
namespace riscv {

/** RISC-V opcodes. Each opcode represents a unique RISC-V operation. */
namespace Opcode {
#define GET_INSTRINFO_ENUM
#include "RISCVGenInstrInfo.inc"
}  // namespace Opcode

/** A simplified RISC-V-only version of the Capstone instruction structure. */
struct InstructionMetadata {
 public:
  /** Constructs a metadata object from a Capstone instruction representation.
   */
  InstructionMetadata(const cs_insn& insn);

  /** Constructs an invalid metadata object containing the invalid encoding. */
  InstructionMetadata(const uint8_t* invalidEncoding, uint8_t bytes = 4);

  /** The maximum operand string length as defined in Capstone */
  static const size_t MAX_OPERAND_STR_LENGTH =
      sizeof(cs_insn::op_str) / sizeof(char);
  /** The maximum number of implicit source register as defined in Capstone */
  static const size_t MAX_IMPLICIT_SOURCES =
      sizeof(cs_detail::regs_read) / sizeof(uint16_t);
  /** The maximum number of implicit destination register as defined in Capstone
   */
  static const size_t MAX_IMPLICIT_DESTINATIONS =
      sizeof(cs_detail::regs_write) / sizeof(uint16_t);
  /** The maximum number of groups and instruction can belong to as defined in
   * Capstone */
  static const size_t MAX_GROUPS = sizeof(cs_detail::groups) / sizeof(uint8_t);
  /** The maximum number of operands as defined in Capstone */
  static const size_t MAX_OPERANDS =
      sizeof(cs_riscv::operands) / sizeof(cs_riscv_op);

  /** The instruction's mnemonic ID. */
  unsigned int id;

  /** The instruction's opcode. */
  unsigned int opcode;

  /** The instruction's encoding. */
  uint8_t encoding[4];

  /** The instruction's mnemonic. */
  char mnemonic[CS_MNEMONIC_SIZE];
  /** The remainder of the instruction's assembly representation. */
  std::string operandStr;

  /** The implicitly referenced registers. */
  uint16_t implicitSources[MAX_IMPLICIT_SOURCES];
  /** The number of implicitly referenced registers. */
  uint8_t implicitSourceCount;

  /** The implicitly referenced destination registers. */
  uint16_t implicitDestinations[MAX_IMPLICIT_DESTINATIONS];
  /** The number of implicitly referenced destination registers. */
  uint8_t implicitDestinationCount;

  /** The explicit operands. */
  cs_riscv_op operands[MAX_OPERANDS];
  /** The number of explicit operands. */
  uint8_t operandCount;

 private:
  /** Detect instruction aliases and update metadata to match the de-aliased
   * instruction. */
  void alterPseudoInstructions(const cs_insn& insn);

  /** Flag the instruction as invalid due to a detected unsupported alias. */
  void aliasNYI();

  /** RISC-V helper function
   * Use register zero as operands[1] and immediate value as operands[2] */
  void includeZeroRegisterPosOne();

  /** RISC-V helper function
   * Use register zero as operands[0] and immediate value as operands[2] */
  void includeZeroRegisterPosZero();
};

}  // namespace riscv
}  // namespace arch
}  // namespace simeng
