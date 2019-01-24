#pragma once

#include "PipelineBuffer.hh"
#include "Instruction.hh"

namespace simeng {

/** An in-order pipeline writeback unit. Responsible for handling writing instruction results to the register file. */
class WritebackUnit {
 public:
  /** Constructs a writeback unit with references to an input buffer and register file to write to. */
  WritebackUnit(PipelineBuffer<std::shared_ptr<Instruction>>& fromExecute, RegisterFile& registerFile);
  
  /** Tick the writeback unit to perform its operation for this cycle. */
  void tick();
 private:
  /** A buffer of instructions to process, coming from the execute unit. */
  PipelineBuffer<std::shared_ptr<Instruction>>& fromExecuteBuffer;

  /** The register file to write results into. */
  RegisterFile& registerFile;
};

} // namespace simeng
