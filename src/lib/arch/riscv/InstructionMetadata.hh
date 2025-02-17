#pragma once

#include <string>

#include "simeng/arch/riscv/Architecture.hh"
#include "simeng/arch/riscv/Instruction.hh"

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

  /* Returns the current exception state of the metadata */
  InstructionException getMetadataException() const {
    return metadataException_;
  }

  /* Returns a bool stating whether an exception has been encountered. */
  bool getMetadataExceptionEncountered() const {
    return metadataExceptionEncountered_;
  }

  /* Return extra information about the exception */
  std::string getExceptionString() const { return exceptionString_; }

  /* Returns the length of the instruction in bytes. */
  uint8_t getInsnLength() const { return insnLengthBytes_; }

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

  /** Detect compressed instructions and update metadata to match the
   * non-compressed instruction expansion. */
  void convertCompressedInstruction(const cs_insn& insn);

  /** Flag the instruction as aliasNYI due to a detected unsupported alias. */
  void aliasNYI();

  /** Flag the instruction as illegal and provide some extra information via a
   * string */
  void illegalAlias(std::string info);

  /** RISC-V helper function
   * Use register zero as operands[1] and immediate value as operands[2] */
  void includeZeroRegisterPosOne();

  /** RISC-V helper function
   * Use register zero as operands[0] and immediate value as operands[2] */
  void includeZeroRegisterPosZero();

  /** RISC-V helper function
   * Duplicate operands[0] and move operands[1] to operands[2] */
  void duplicateFirstOp();

  /** RISC-V helper function
   * Combine operands[1] and operands[2] which are of type imm and reg
   * respectively into a single mem type operand */
  void createMemOpPosOne();

  /** The current exception state of this instruction. */
  InstructionException metadataException_ = InstructionException::None;

  /** Whether an exception has been encountered. */
  bool metadataExceptionEncountered_ = false;

  /** Additional information to print to the user */
  std::string exceptionString_ = "";

  /** The length of the instruction encoding in bytes. */
  uint8_t insnLengthBytes_;
};

}  // namespace riscv
}  // namespace arch
}  // namespace simeng
