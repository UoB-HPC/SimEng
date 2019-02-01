#pragma once

#include <deque>

#include "../Instruction.hh"

namespace simeng {
namespace outoforder {

class ReorderBuffer {
 public:
  ReorderBuffer(unsigned int maxSize);

  void reserve(std::shared_ptr<Instruction> insn);

  unsigned int commit(unsigned int maxCommitSize);

  void flush(uint64_t afterSeqId);

  unsigned int size() const;

 private:
  unsigned int maxSize;
  std::deque<std::shared_ptr<Instruction>> buffer;
  uint64_t seqId = 0;
};

}  // namespace outoforder
}  // namespace simeng
