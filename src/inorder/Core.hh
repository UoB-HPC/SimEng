#pragma once

#include "../Core.hh"

#include <vector>

#include "DecodeUnit.hh"
#include "ExecuteUnit.hh"
#include "FetchUnit.hh"
#include "WritebackUnit.hh"

namespace simeng {
namespace inorder {

/** A simple scalar in-order pipelined core model. */
class Core : public simeng::Core {
 public:
  /** Construct a core model, providing an ISA and branch predictor to use,
   * along with a pointer and size of instruction memory, and a pointer to
   * process memory. */
  Core(const char* insnPtr, unsigned int programByteLength,
       const Architecture& isa, BranchPredictor& branchPredictor, char* memory);

  /** Tick the core. Ticks each of the pipeline stages sequentially, then ticks
   * the buffers between them. Checks for and executes pipeline flushes at the
   * end of each cycle. */
  void tick() override;

  /** Check whether the program has halted. */
  bool hasHalted() const override;

  /** Generate a map of statistics to report. */
  std::map<std::string, std::string> getStats() const override;

 private:
  /** The core's register file set. */
  RegisterFileSet registerFileSet;

  /** The buffer between fetch and decode. */
  PipelineBuffer<MacroOp> fetchToDecodeBuffer;

  /** The buffer between decode and execute. */
  PipelineBuffer<std::shared_ptr<Instruction>> decodeToExecuteBuffer;

  /** The buffer between execute and writeback. */
  PipelineBuffer<std::shared_ptr<Instruction>> executeToWritebackBuffer;

  /** The fetch unit; fetches instructions from memory. */
  FetchUnit fetchUnit;

  /** The decode unit; decodes instructions into uops and reads operands. */
  DecodeUnit decodeUnit;

  /** The execute unit; executes uops and sends to writeback, also forwarding
   * results. */
  ExecuteUnit executeUnit;

  /** The writeback unit; writes uop results to the register files. */
  WritebackUnit writebackUnit;

  /** The number of times the pipeline has been flushed. */
  uint64_t flushes = 0;

  /** The number of times this core has been ticked. */
  uint64_t ticks = 0;
};

}  // namespace inorder
}  // namespace simeng
