#pragma once

#include "../Core.hh"

#include <iostream>
#include <vector>

#include "../pipeline/DecodeUnit.hh"
#include "../pipeline/ExecuteUnit.hh"
#include "../pipeline/FetchUnit.hh"
#include "../pipeline/WritebackUnit.hh"

namespace simeng {
namespace inorder {

/** A simple scalar in-order pipelined core model. */
class Core : public simeng::Core {
 public:
  /** Construct a core model, providing an ISA and branch predictor to use,
   * along with a pointer and size of instruction memory, and a pointer to
   * process memory. */
  Core(const span<char> processMemory, uint64_t entryPoint,
       const Architecture& isa, BranchPredictor& branchPredictor);

  /** Tick the core. Ticks each of the pipeline stages sequentially, then ticks
   * the buffers between them. Checks for and executes pipeline flushes at the
   * end of each cycle. */
  void tick() override;

  /** Check whether the program has halted. */
  bool hasHalted() const override;

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

  /** The process memory. */
  const span<char> processMemory_;

  /** A reference to the core's architecture. */
  const Architecture& isa;

  /** The core's register file set. */
  RegisterFileSet registerFileSet;

  /** The buffer between fetch and decode. */
  PipelineBuffer<MacroOp> fetchToDecodeBuffer;

  /** The buffer between decode and execute. */
  PipelineBuffer<std::shared_ptr<Instruction>> decodeToExecuteBuffer;

  /** The buffer between execute and writeback. */
  std::vector<PipelineBuffer<std::shared_ptr<Instruction>>> completionSlots;

  /** The fetch unit; fetches instructions from memory. */
  pipeline::FetchUnit fetchUnit;

  /** The decode unit; decodes instructions into uops and reads operands. */
  pipeline::DecodeUnit decodeUnit;

  /** The execute unit; executes uops and sends to writeback, also forwarding
   * results. */
  pipeline::ExecuteUnit executeUnit;

  /** The writeback unit; writes uop results to the register files. */
  pipeline::WritebackUnit writebackUnit;

  /** The number of times the pipeline has been flushed. */
  uint64_t flushes = 0;

  /** The number of times this core has been ticked. */
  uint64_t ticks = 0;

  /** Whether an exception was generated during the cycle. */
  bool exceptionGenerated_ = false;

  /** A pointer to the instruction responsible for generating the exception. */
  std::shared_ptr<Instruction> exceptionGeneratingInstruction_;

  /** Whether the core has halted. */
  bool hasHalted_ = false;
};

}  // namespace inorder
}  // namespace simeng
