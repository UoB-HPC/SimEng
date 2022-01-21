#pragma once

#include <forward_list>

#include "simeng/arch/Architecture.hh"
#include "simeng/arch/aarch64/Instruction.hh"
#include "yaml-cpp/yaml.h"

namespace simeng {
namespace arch {
namespace aarch64 {

/** A struct to hold an information to constract a default cs_arm64_op from . */
struct OpType {
  arm64_op_type type;
  bool isDestination = false;
};

/** A aarch64 custom decoder for splitting appropriate macro-ops into micro-ops.
 */
class MicroDecoder {
 public:
  /** Construct a micro decoder for splitting relevant instructons. */
  MicroDecoder(YAML::Node config);
  ~MicroDecoder();

  /** From a macro-op, split into one or more micro-ops and populate passed
   * vector. Return the number of micro-ops generated. */
  uint8_t decode(const Architecture& architecture, uint32_t word,
                 Instruction macroOp, MacroOp& output, csh capstoneHandle);

  /** Create a default cs_detail object from a vector of operand types. */
  cs_detail createDefaultDetail(std::vector<OpType> opTypes);

  /** Create an address offset uop from a base register and an immediate. */
  cs_insn createImmOffsetUop(arm64_reg base, int64_t offset);

  /** Create a load uop from a destination register and a capstone memory
   * operand. */
  cs_insn createLdrUop(arm64_reg dest, arm64_op_mem mem);

  /** Create a store data uop from a source register. */
  cs_insn createSDUop(arm64_reg src);

  /** Create a store address uop from a capstone memory
   * operand. */
  cs_insn createStrUop(arm64_op_mem mem);

 private:
  /** Flag to determine whether instruction splitting is enabled. */
  bool instructionSplit_;

  /** A micro-decoding cache, mapping an instruction word to a previously split
   * instruction. Instructions are added to the cache as they're split into
   * their repsective micro-operations, to reduce the overhead of future
   * splitting. */
  static std::unordered_map<uint32_t, std::vector<Instruction>>
      microDecodeCache;

  /** A cache for newly created instruction metadata. Ensures metadata values
   * persist for a micro-operations' life cycle. */
  static std::forward_list<InstructionMetadata> microMetadataCache;

  // Default objects
  /** Default capstone instruction structure. */
  cs_arm64 default_info = {ARM64_CC_INVALID, false, false, 0, {}};

  /** Default register. */
  cs_arm64_op default_op = {0,
                            ARM64_VAS_INVALID,
                            {ARM64_SFT_INVALID, 0},
                            ARM64_EXT_INVALID,
                            ARM64_OP_INVALID,
                            {},
                            CS_AC_READ};

  /** Default capstone instruction detail. */
  cs_detail default_detail = {{}, 0, {}, 0, {}, 0, {}};
};

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng
