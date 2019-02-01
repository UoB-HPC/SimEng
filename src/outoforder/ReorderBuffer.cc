#include "ReorderBuffer.hh"

#include <algorithm>
#include <cassert>
#include <iostream>

namespace simeng {
namespace outoforder {

ReorderBuffer::ReorderBuffer(unsigned int maxSize) : maxSize(maxSize) {}

void ReorderBuffer::reserve(std::shared_ptr<Instruction> insn) {
  assert(buffer.size() + 1 < maxSize &&
         "Attempted to reserve entry in reorder buffer when already full");
  insn->setSequenceId(seqId);
  seqId++;
  buffer.push_back(insn);
}

unsigned int ReorderBuffer::commit(unsigned int maxCommitSize) {
  size_t maxCommits =
      std::min(static_cast<size_t>(maxCommitSize), buffer.size());

  unsigned int n;
  for (n = 0; n < maxCommits; n++) {
    // if (buffer[0] != nullptr && !buffer[0]->canCommit()) {
    //   break;
    // }
    buffer.pop_front();
  }

  return n;
}

// TODO: Implement
void ReorderBuffer::flush(uint64_t afterSeqId) {}

unsigned int ReorderBuffer::size() const { return buffer.size(); }

}  // namespace outoforder
}  // namespace simeng
