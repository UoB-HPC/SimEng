#include "ReorderBuffer.hh"

#include <algorithm>
#include <cassert>

namespace simeng {
namespace outoforder {

ReorderBuffer::ReorderBuffer(unsigned int maxSize, RegisterAliasTable& rat,
                             LoadStoreQueue& lsq)
    : rat(rat), lsq(lsq), maxSize(maxSize) {}

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
    if (!uop->canCommit()) {
      break;
    }

    const auto& destinations = uop->getDestinationRegisters();
    for (const auto& reg : destinations) {
      rat.commit(reg);
    }

    // If it's a memory op, commit the entry at the head of the respective queue
    if (uop->isStore()) {
      lsq.commitStore();
    } else if (uop->isLoad()) {
      lsq.commitLoad();
    }
    buffer.pop_front();
  }

  return n;
}

void ReorderBuffer::flush(uint64_t afterSeqId) {
  // Iterate backwards from the tail of the queue to find and remove ops newer
  // than `afterSeqId`
  for (size_t i = buffer.size() - 1; i >= 0; i--) {
    auto& uop = buffer[i];
    if (uop->getSequenceId() <= afterSeqId) {
      break;
    }

    for (const auto& reg : uop->getDestinationRegisters()) {
      rat.rewind(reg);
    }
    uop->setFlushed();
    buffer.pop_back();
  }
}

unsigned int ReorderBuffer::size() const { return buffer.size(); }

unsigned int ReorderBuffer::getFreeSpace() const {
  return maxSize - buffer.size();
}

}  // namespace outoforder
}  // namespace simeng
