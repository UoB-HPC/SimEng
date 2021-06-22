#pragma once

#include <string>

#include "capstone/capstone.h"

namespace simeng {
namespace arch {
namespace riscv {

/** AArch64 opcodes. Each opcode represents a unique AArch64 operation. */
namespace Opcode {
#define GET_INSTRINFO_ENUM
#include "RISCVGenInstrInfo.inc"
}  // namespace Opcode

/** A simplified AArch64-only version of the Capstone instruction structure. */
struct InstructionMetadata {
 public:
  /** Constructs a metadata object from a Capstone instruction representation.
   */
  InstructionMetadata(const cs_insn& insn);

  /** Constructs an invalid metadata object containing the invalid encoding. */
  InstructionMetadata(const uint8_t* invalidEncoding, uint8_t bytes = 4);

  static const size_t MAX_OPERAND_STR_LENGTH =
      sizeof(cs_insn::op_str) / sizeof(char);
  static const size_t MAX_IMPLICIT_SOURCES =
      sizeof(cs_detail::regs_read) / sizeof(uint16_t);
  static const size_t MAX_IMPLICIT_DESTINATIONS =
      sizeof(cs_detail::regs_write) / sizeof(uint16_t);
  static const size_t MAX_GROUPS = sizeof(cs_detail::groups) / sizeof(uint8_t);
  static const size_t MAX_OPERANDS =
      sizeof(cs_arm64::operands) / sizeof(cs_arm64_op);

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

  /** The instruction groups this instruction belongs to. Non-exhaustive. */
  uint8_t groups[MAX_GROUPS];
  /** The number of instruction groups this instruction belongs to. */
  uint8_t groupCount;

  /** The condition code of the instruction. */
  uint8_t cc;
  /** Whether this instruction sets the condition flags. */
  bool setsFlags;
  /** Whether this instruction performs a base-address register writeback
   * operation. */
  bool writeback;

  /** The explicit operands. */
  cs_arm64_op operands[MAX_OPERANDS];
  /** The number of explicit operands. */
  uint8_t operandCount;

 private:
  /** Detect instruction aliases and update metadata to match the de-aliased
   * instruction. */
  void revertAliasing();

  /** Flag the instruction as invalid due to a detected unsupported alias. */
  void aliasNYI();
};

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng
