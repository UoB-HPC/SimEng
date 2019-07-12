#pragma once

#include "../../Core.hh"

#include <map>
#include <string>

#include "../../MemoryInterface.hh"
#include "../../RegisterFileSet.hh"
#include "../../span.hh"
#include "arch/Architecture.hh"

namespace simeng {
namespace models {
namespace emulation {

/** An emulation-style core model. Executes each instruction in turn. */
class Core : public simeng::Core {
 public:
  /** Construct an emulation-style core, providing memory interfaces for
   * instructions and data, along with the instruction entry point and an ISA to
   * use. */
  Core(MemoryInterface& instructionMemory, MemoryInterface& dataMemory,
       uint64_t entryPoint, uint64_t programByteLength,
       const arch::Architecture& isa);

  /** Tick the core. */
  void tick() override;

  /** Check whether the program has halted. */
  bool hasHalted() const override;

  /** Retrieve the architectural register file set. */
  const ArchitecturalRegisterFileSet& getArchitecturalRegisterFileSet()
      const override;

  /** Retrieve a map of statistics to report. */
  std::map<std::string, std::string> getStats() const override;

 private:
  /** Execute an instruction. */
  void execute(std::shared_ptr<Instruction>& uop);

  /** Handle an encountered exception. */
  void handleException(const std::shared_ptr<Instruction>& instruction);

  /** Process an active exception handler. */
  void processExceptionHandler();

  /** Apply changes to the process state. */
  void applyStateChange(const arch::ProcessStateChange& change);

  /** A memory interface to access instructions. */
  MemoryInterface& instructionMemory_;

  /** A memory interface to access data. */
  MemoryInterface& dataMemory_;

  /** The length of the available instruction memory. */
  uint64_t programByteLength_;

  /** The currently used ISA. */
  const arch::Architecture& isa_;

  /** The current program counter. */
  uint64_t pc_ = 0;

  /** The core's register file set. */
  RegisterFileSet registerFileSet_;

  /** An architectural register file set, serving as a simple wrapper around the
   * register file set. */
  ArchitecturalRegisterFileSet architecturalRegisterFileSet_;

  /** Whether or not the core has halted. */
  bool hasHalted_ = false;

  /** A reusable macro-op vector to fill with uops. */
  MacroOp macroOp_;

  /** The active exception handler. */
  std::shared_ptr<arch::ExceptionHandler> exceptionHandler_;

  /** Is the core waiting on a data read? */
  unsigned int pendingReads_ = 0;

  /** The number of instructions executed. */
  uint64_t instructionsExecuted_ = 0;
};

}  // namespace emulation
}  // namespace models
}  // namespace simeng
