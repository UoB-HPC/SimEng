#pragma once

#include <vector>

#include "FetchUnit.hh"
#include "DecodeUnit.hh"
#include "ExecuteUnit.hh"
#include "WritebackUnit.hh"

namespace simeng {

/** A simple scalar in-order pipelined core model. */
class Core {
 public:
  /** Construct a core model, providing an ISA and branch predictor to use, along with a pointer and size of instruction memory. */
  Core(char* insnPtr, unsigned int programByteLength, Architecture& isa, BranchPredictor& branchPredictor);

  /** Tick the core. Ticks each of the pipeline stages sequentially, then ticks the buffers between them. Checks for and executes pipeline flushes at the end of each cycle. */
  void tick();

  /** Check whether the program has halted. */
  bool hasHalted() const;

  /** Retrieve the number of flushes that have occurred. */
  int getFlushesCount() const;

  /** Retrieve the number of instructions that retired. */
  int getInstructionsRetiredCount() const;
 private:
  /** A pointer to process memory. */
  char* memory;

  /** The core's register file. */
  RegisterFile registerFile;

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

  /** The execute unit; executes uops and forwards results to decode. */
  ExecuteUnit executeUnit;

  /** The writeback unit; writes uop results to the register file. */
  WritebackUnit writebackUnit;

  /** The number of times the pipeline has been flushed. */
  int flushes = 0;
};

} // namespace simeng
