#pragma once

#include <tuple>
#include <vector>

#include "simeng/BranchPredictor.hh"
#include "simeng/Core.hh"
#include "simeng/Instruction.hh"
#include "simeng/MemoryInterface.hh"

namespace simeng {

using MacroOp = std::vector<std::shared_ptr<Instruction>>;

namespace arch {

/** An abstract Instruction Set Architecture (ISA) definition. Each supported
 * ISA should provide a derived implementation of this class. */
class Architecture {
 public:
  virtual ~Architecture(){};

  /** Attempt to pre-decode from `bytesAvailable` bytes of instruction memory.
   * Writes into the supplied macro-op vector, and returns the number of bytes
   * consumed to produce it; a value of 0 indicates too few bytes were present
   * for a valid decoding. */
  virtual uint8_t predecode(const void* ptr, uint8_t bytesAvailable,
                            uint64_t instructionAddress,
                            MacroOp& output) const = 0;

  /** Returns a vector of {size, number} pairs describing the available
   * registers. */
  virtual std::vector<RegisterFileStructure> getRegisterFileStructures()
      const = 0;

  /** Returns a zero-indexed register tag for a system register encoding. */
  virtual int32_t getSystemRegisterTag(uint16_t reg) const = 0;

  /** Returns the number of system registers that have a mapping. */
  virtual uint16_t getNumSystemRegisters() const = 0;

  /** Returns the maximum size of a valid instruction in bytes. */
  virtual uint8_t getMaxInstructionSize() const = 0;

  /** Returns the physical register structure as defined within the config
   * file
   */
  virtual std::vector<RegisterFileStructure>
  getConfigPhysicalRegisterStructure() const = 0;

  /** Returns the physical register quantities as defined within the config file
   */
  virtual std::vector<uint16_t> getConfigPhysicalRegisterQuantities() const = 0;

  /** Updates System registers of any system-based timers. */
  virtual void updateSystemTimerRegisters(RegisterFileSet* regFile,
                                          const uint64_t iterations) const = 0;

  /** After a context switch, update any required variables. */
  virtual void updateAfterContextSwitch(
      const simeng::OS::cpuContext& context) const = 0;
};

}  // namespace arch
}  // namespace simeng
