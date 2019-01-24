#pragma once

#include "PipelineBuffer.hh"
#include "Instruction.hh"
#include "DecodeUnit.hh"

namespace simeng {

class ExecuteUnit {
 public:
  ExecuteUnit(PipelineBuffer<std::shared_ptr<Instruction>>& fromDecode, PipelineBuffer<std::shared_ptr<Instruction>>& toWriteback, DecodeUnit& decodeUnit, char* memory);

  void tick();
  std::tuple<bool, uint64_t> shouldFlush() const;
 private:
  PipelineBuffer<std::shared_ptr<Instruction>>& fromDecodeBuffer;
  PipelineBuffer<std::shared_ptr<Instruction>>& toWritebackBuffer;
  
  DecodeUnit& decodeUnit;
  char* memory;

  bool shouldFlush_;
  uint64_t pc;
};

} // namespace simeng
