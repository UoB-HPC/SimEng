#include "simeng/pipeline/ReorderBuffer.hh"

#include <algorithm>
#include <cassert>

namespace simeng {
namespace pipeline {

ReorderBuffer::ReorderBuffer(
    unsigned int maxSize, RegisterAliasTable& rat, LoadStoreQueue& lsq,
    std::function<void(const std::shared_ptr<Instruction>&)> raiseException)
    : rat_(rat),
      lsq_(lsq),
      maxSize_(maxSize),
      raiseException_(raiseException) {}

void ReorderBuffer::reserve(const std::shared_ptr<Instruction>& insn) {
  assert(buffer_.size() < maxSize_ &&
         "Attempted to reserve entry in reorder buffer when already full");
  insn->setSequenceId(seqId_);
  seqId_++;
  insn->setInstructionId(insnId_);
  if (insn->isLastMicroOp()) insnId_++;

  buffer_.push_back(insn);
}

void ReorderBuffer::commitMicroOps(uint64_t insnId) {
  size_t index = 0;
  int firstOp = -1;

  // Find first instance of uop belonging to macro-op instruction
  auto& uop = buffer_[index];
  while (uop->getInstructionId() <= insnId) {
    if (uop->getInstructionId() == insnId) {
      firstOp = index;
      break;
    }
    index++;
    uop = buffer_[index];
  }

  // If found, see if all uops are committable
  if (firstOp) {
    while (uop->getInstructionId() == insnId) {
      if (!uop->isWaitingCommit()) return;
      index++;
      uop = buffer_[index];
    }
    // No early return thus all uops are committable
    uop = buffer_[firstOp];
    while (uop->getInstructionId() == insnId) {
      uop->setCommitReady();
      firstOp++;
      uop = buffer_[firstOp];
    }
  }
  return;
}

unsigned int ReorderBuffer::commit(unsigned int maxCommitSize) {
  shouldFlush_ = false;
  size_t maxCommits =
      std::min(static_cast<size_t>(maxCommitSize), buffer_.size());

  unsigned int n;
  for (n = 0; n < maxCommits; n++) {
    auto& uop = buffer_[0];
    if (!uop->canCommit()) {
      break;
    }

    if (uop->isLastMicroOp()) instructionsCommitted_++;

    if (uop->exceptionEncountered()) {
      raiseException_(uop);
      buffer_.pop_front();
      return n + 1;
    }

    const auto& destinations = uop->getDestinationRegisters();
    for (const auto& reg : destinations) {
      rat_.commit(reg);
    }

    // If it's a memory op, commit the entry at the head of the respective queue
    if (uop->isLoad()) {
      lsq_.commitLoad(uop);
    }
    if (uop->isStore()) {
      bool violationFound = lsq_.commitStore(uop);
      if (violationFound) {
        loadViolations_++;
        // Memory order violation found; aborting commits and flushing
        auto load = lsq_.getViolatingLoad();
        shouldFlush_ = true;
        flushAfter_ = load->getSequenceId() - 1;
        pc_ = load->getInstructionAddress();

        buffer_.pop_front();
        return n + 1;
      }
    }
    buffer_.pop_front();
  }

  return n;
}

void ReorderBuffer::flush(uint64_t afterSeqId) {
  // Iterate backwards from the tail of the queue to find and remove ops newer
  // than `afterSeqId`
  while (!buffer_.empty()) {
    auto& uop = buffer_.back();
    if (uop->getSequenceId() <= afterSeqId) {
      break;
    }

    // To rewind destination registers in correct history order, rewinding of
    // register renaming is done backwards
    auto destinations = uop->getDestinationRegisters();
    for (int i = destinations.size() - 1; i >= 0; i--) {
      const auto& reg = destinations[i];
      rat_.rewind(reg);
    }
    uop->setFlushed();
    buffer_.pop_back();
  }
}

unsigned int ReorderBuffer::size() const { return buffer_.size(); }

unsigned int ReorderBuffer::getFreeSpace() const {
  return maxSize_ - buffer_.size();
}

bool ReorderBuffer::shouldFlush() const { return shouldFlush_; }
uint64_t ReorderBuffer::getFlushAddress() const { return pc_; }
uint64_t ReorderBuffer::getFlushSeqId() const { return flushAfter_; }

uint64_t ReorderBuffer::getInstructionsCommittedCount() const {
  return instructionsCommitted_;
}

uint64_t ReorderBuffer::getViolatingLoadsCount() const {
  return loadViolations_;
}

}  // namespace pipeline
}  // namespace simeng
