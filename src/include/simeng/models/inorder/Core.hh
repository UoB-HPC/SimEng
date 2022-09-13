#pragma once

#include <vector>

#include "simeng/ArchitecturalRegisterFileSet.hh"
#include "simeng/Core.hh"
#include "simeng/FlatMemoryInterface.hh"
#include "simeng/pipeline/DecodeUnit.hh"
#include "simeng/pipeline/ExecuteUnit.hh"
#include "simeng/pipeline/FetchUnit.hh"
#include "simeng/pipeline/WritebackUnit.hh"

namespace simeng {
namespace models {
namespace inorder {

/** A simple scalar in-order pipelined core model. */
class Core : public simeng::Core {
 public:
  /** Construct a core model, providing an ISA and branch predictor to use,
   * along with a pointer and size of instruction memory, and a pointer to
   * process memory. */
  Core(FlatMemoryInterface& instructionMemory, FlatMemoryInterface& dataMemory,
       uint64_t processMemorySize, uint64_t entryPoint,
       const arch::Architecture& isa, BranchPredictor& branchPredictor);

  /** Tick the core. Ticks each of the pipeline stages sequentially, then ticks
   * the buffers between them. Checks for and executes pipeline flushes at the
   * end of each cycle. */
  void tick() override;

  /** Check whether the program has halted. */
  bool hasHalted() const override;

  /** Retrieve the architectural register file set. */
  const ArchitecturalRegisterFileSet& getArchitecturalRegisterFileSet()
      const override;

  /** Retrieve the number of instructions retired. */
  uint64_t getInstructionsRetiredCount() const override;

  /** Retrieve the simulated nanoseconds elapsed since the core started. */
  uint64_t getSystemTimer() const override;

  /** Generate a map of statistics to report. */
  std::map<std::string, std::string> getStats() const override;

 private:
  /** Raise an exception to the core, providing the generating instruction. */
  void raiseException(const std::shared_ptr<Instruction>& instruction);

  /** Handle an exception raised during the cycle. */
  void handleException();

  /** Load and supply memory data requested by an instruction. */
  void loadData(const std::shared_ptr<Instruction>& instruction);
  /** Store data supplied by an instruction to memory. */
  void storeData(const std::shared_ptr<Instruction>& instruction);

  /** Forward operands to the most recently decoded instruction. */
  void forwardOperands(const span<Register>& destinations,
                       const span<RegisterValue>& values);

  /** Read pending registers for the most recently decoded instruction. */
  void readRegisters();

  /** Process the active exception handler. */
  void processExceptionHandler();

  /** Apply changes to the process state. */
  void applyStateChange(const arch::ProcessStateChange& change);

  /** Handle requesting/execution of a load instruction. */
  void handleLoad(const std::shared_ptr<Instruction>& instruction);

  /** The process memory. */
  MemoryInterface& dataMemory_;

  /** A reference to the core's architecture. */
  const arch::Architecture& isa_;

  /** The core's register file set. */
  RegisterFileSet registerFileSet_;

  /** An architectural register file set, serving as a simple wrapper around the
   * register file set. */
  ArchitecturalRegisterFileSet architecturalRegisterFileSet_;

  /** The process memory. */
  span<char> processMemory;

  /** The buffer between fetch and decode. */
  pipeline::PipelineBuffer<MacroOp> fetchToDecodeBuffer_;

  /** The buffer between decode and execute. */
  pipeline::PipelineBuffer<std::shared_ptr<Instruction>> decodeToExecuteBuffer_;

  /** The buffer between execute and writeback. */
  std::vector<pipeline::PipelineBuffer<std::shared_ptr<Instruction>>>
      completionSlots_;

  /** The previously generated addresses. */
  std::queue<simeng::MemoryAccessTarget> previousAddresses_;

  /** The fetch unit; fetches instructions from memory. */
  pipeline::FetchUnit fetchUnit_;

  /** The decode unit; decodes instructions into uops and reads operands. */
  pipeline::DecodeUnit decodeUnit_;

  /** The execute unit; executes uops and sends to writeback, also forwarding
   * results. */
  pipeline::ExecuteUnit executeUnit_;

  /** The writeback unit; writes uop results to the register files. */
  pipeline::WritebackUnit writebackUnit_;

  /** The number of times the pipeline has been flushed. */
  uint64_t flushes_ = 0;

  /** The number of times this core has been ticked. */
  uint64_t ticks_ = 0;

  /** Whether an exception was generated during the cycle. */
  bool exceptionGenerated_ = false;

  /** A pointer to the instruction responsible for generating the exception. */
  std::shared_ptr<Instruction> exceptionGeneratingInstruction_;

  /** Whether the core has halted. */
  bool hasHalted_ = false;

  /** The active exception handler. */
  std::shared_ptr<arch::ExceptionHandler> exceptionHandler_;
};

}  // namespace inorder
}  // namespace models
}  // namespace simeng
