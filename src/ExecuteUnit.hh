#pragma once

#include "PipelineBuffer.hh"
#include "Instruction.hh"
#include "DecodeUnit.hh"

namespace simeng {

class ExecuteUnit {
 public:
  ExecuteUnit(PipelineBuffer<std::shared_ptr<Instruction>>& fromDecode, PipelineBuffer<std::shared_ptr<Instruction>>& toWriteback, DecodeUnit& decodeUnit, BranchPredictor& predictor, char* memory);

  void tick();
  bool shouldFlush() const;
  uint64_t getFlushAddress() const;
 private:
  PipelineBuffer<std::shared_ptr<Instruction>>& fromDecodeBuffer;
  PipelineBuffer<std::shared_ptr<Instruction>>& toWritebackBuffer;
  
  DecodeUnit& decodeUnit;
  BranchPredictor& predictor;

  char* memory;

  bool shouldFlush_;
  uint64_t pc;
  uint64_t flushedInstructionAddress;
};

} // namespace simeng
