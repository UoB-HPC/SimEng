#pragma once

#include "simeng/arch/Architecture.hh"
#include "simeng/arch/aarch64/Instruction.hh"
#include "yaml-cpp/yaml.h"

namespace simeng {
namespace arch {
namespace aarch64 {

/** A aarch64 custom decoder for splitting appropriate macro-ops into micro-ops.
 */
class MicroDecoder {
 public:
  /** Construct a micro decoder for splitting relevant instructons. */
  MicroDecoder(YAML::Node config);

  /** From a macro-op, split into one or more micro-ops and populate passed
   * vector. Return the number of micro-ops generated. */
  uint8_t decode(const Architecture& architecture, Instruction macroOp,
                 MacroOp& output, csh capstoneHandle);

 private:
  /** Flag to determine whether instruction splitting is enabled. */
  bool instructionSplit_;
};

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng
