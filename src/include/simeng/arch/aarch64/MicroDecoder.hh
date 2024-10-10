#pragma once

#include <forward_list>

#include "simeng/arch/Architecture.hh"
#include "simeng/arch/aarch64/Instruction.hh"

namespace simeng {
namespace arch {
namespace aarch64 {

/** A struct to hold information to construct a default cs_aarch64_op from. */
struct OpType {
  aarch64_op_type type;
  bool isDestination = false;
};

/** A aarch64 custom decoder for splitting appropriate macro-ops into micro-ops.
 */
class MicroDecoder {
 public:
  /** Construct a micro decoder for splitting relevant instructions. */
  MicroDecoder(ryml::ConstNodeRef config = config::SimInfo::getConfig());

  ~MicroDecoder();

  /** From a macro-op, split into one or more micro-ops and populate passed
   * vector. Return the number of micro-ops generated. */
  uint8_t decode(const Architecture& architecture, uint32_t word,
                 const Instruction& macroOp, MacroOp& output,
                 csh capstoneHandle);

 private:
  /** Detect if there's an overlap between the underlying hardware registers
   * (e.g. z5, v5, q5, d5, s5, h5, and b5). */
  bool detectOverlap(aarch64_reg registerA, aarch64_reg registerB);

  /** Create a default cs_detail object from a vector of operand types. */
  cs_detail createDefaultDetail(std::vector<OpType> opTypes);

  /** Create an address offset uop from a base register and an immediate. */
  Instruction createImmOffsetUop(const Architecture& architecture,
                                 aarch64_reg base, int64_t offset,
                                 csh capstoneHandle, bool lastMicroOp = false,
                                 int microOpIndex = 0);

  /** Create an address offset uop from a base register and a register. */
  Instruction createRegOffsetUop(const Architecture& architecture,
                                 aarch64_reg base, aarch64_reg offset,
                                 csh capstoneHandle, bool lastMicroOp = false,
                                 int microOpIndex = 0);

  /** Create a load uop from a destination register and a capstone memory
   * operand. */
  Instruction createLdrUop(const Architecture& architecture, aarch64_reg dest,
                           aarch64_op_mem mem, csh capstoneHandle,
                           bool lastMicroOp = false, int microOpIndex = 0,
                           uint8_t dataSize = 0);

  /** Create a store data uop from a source register. */
  Instruction createSDUop(const Architecture& architecture, aarch64_reg src,
                          csh capstoneHandle, bool lastMicroOp = false,
                          int microOpIndex = 0);

  /** Create a store address uop from a capstone memory
   * operand. */
  Instruction createStrUop(const Architecture& architecture, aarch64_op_mem mem,
                           csh capstoneHandle, bool lastMicroOp = false,
                           int microOpIndex = 0, uint8_t dataSize = 0);

  /** Flag to determine whether instruction splitting is enabled. */
  const bool instructionSplit_;

  /** A micro-decoding cache, mapping an instruction word to a previously split
   * instruction. Instructions are added to the cache as they're split into
   * their respective micro-operations, to reduce the overhead of future
   * splitting. */
  static std::unordered_map<uint32_t, std::vector<Instruction>>
      microDecodeCache_;

  /** A cache for newly created instruction metadata. Ensures metadata values
   * persist for a micro-operations' life cycle. */
  static std::forward_list<InstructionMetadata> microMetadataCache_;

  // Default objects
  /** Default capstone instruction structure. */
  cs_aarch64 default_info = {AArch64CC_Invalid, false, false, 0, {}};

  /** Default register. */
  cs_aarch64_op default_op = {0,
                              AARCH64LAYOUT_INVALID,
                              {AARCH64_SFT_INVALID, 0},
                              AARCH64_EXT_INVALID,
                              AARCH64_OP_INVALID,
                              false,
                              {},
                              {},
                              CS_AC_READ,
                              false};

  /** Default capstone instruction detail. */
  cs_detail default_detail = {{}, 0, {}, 0, {}, 0, {}};
};

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng
