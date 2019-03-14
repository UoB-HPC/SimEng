#pragma once

#include <cstring>

#include "capstone/capstone.h"

namespace simeng {

/** A simplified A64-only version of the Capstone instruction structure. */
struct A64InstructionMetadata {
 public:
  A64InstructionMetadata(){};

  /** Constructs a metadata object from a Capstone instruction representation.
   */
  A64InstructionMetadata(const cs_insn& insn);

  /** The instruction's mnemonic ID. */
  unsigned int id;

  /** The instruction's mnemonic. */
  char mnemonic[CS_MNEMONIC_SIZE];
  /** The remainder of the instruction's assembly representation. */
  char operandStr[160];

  /** The implicitly referenced registers. */
  uint16_t implicitSources[16];
  /** The number of implicitly referenced registers. */
  uint8_t implicitSourceCount;

  /** The implicitly referenced destination registers. */
  uint16_t implicitDestinations[20];
  /** The number of implicitly referenced destination registers. */
  uint8_t implicitDestinationCount;

  /** The instruction groups this instruction belongs to. Non-exhaustive. */
  uint8_t groups[8];
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
  cs_arm64_op operands[8];
  /** The number of explicit operands. */
  uint8_t operandCount;
};

}  // namespace simeng
