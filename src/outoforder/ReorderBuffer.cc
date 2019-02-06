#include "ReorderBuffer.hh"

#include <algorithm>
#include <cassert>

namespace simeng {
namespace outoforder {

ReorderBuffer::ReorderBuffer(unsigned int maxSize, RegisterAliasTable& rat)
    : rat(rat), maxSize(maxSize) {}

void ReorderBuffer::reserve(std::shared_ptr<Instruction> insn) {
  assert(buffer.size() < maxSize &&
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
    auto& uop = buffer[0];
    if (uop != nullptr) {
      if (!uop->canCommit()) {
        break;
      }
      const auto& destinations = uop->getDestinationRegisters();
      for (const auto& reg : destinations) {
        rat.commit(reg);
      }
    }
    buffer.pop_front();
  }

  return n;
}

void ReorderBuffer::flush(uint64_t afterSeqId) {
  for (size_t i = 0; i < buffer.size(); i++) {
    auto& uop = buffer[i];
    if (uop->getSequenceId() > afterSeqId) {
      for (const auto& reg : uop->getDestinationRegisters()) {
        rat.rewind(reg);
      }
      uop->setFlushed();
      buffer[i] = nullptr;
    }
  }
}

unsigned int ReorderBuffer::size() const { return buffer.size(); }

}  // namespace outoforder
}  // namespace simeng
