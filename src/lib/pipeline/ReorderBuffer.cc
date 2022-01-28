#include "simeng/pipeline/ReorderBuffer.hh"

#include <algorithm>
#include <cassert>
#include <iostream>

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
  if (buffer_.size()) {
    size_t index = 0;
    int firstOp = -1;

    // Find first instance of uop belonging to macro-op instruction
    for (; index < buffer_.size(); index++) {
      if (buffer_[index]->getInstructionId() == insnId) {
        firstOp = index;
        break;
      }
    }

    if (firstOp > -1) {
      // If found, see if all uops are committable
      for (; index < buffer_.size(); index++) {
        if (buffer_[index]->getInstructionId() != insnId) break;
        if (!buffer_[index]->isWaitingCommit()) {
          return;
        }
      }
      // No early return thus all uops are committable
      for (; firstOp < buffer_.size(); firstOp++) {
        if (buffer_[firstOp]->getInstructionId() != insnId) break;
        buffer_[firstOp]->setCommitReady();
      }
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
      // std::cout << "ROB stalled on: " << uop->getSequenceId() << ":"
      //           << uop->getInstructionId() << ":0x" << std::hex
      //           << uop->getInstructionAddress() << std::dec << ":"
      //           << uop->getMicroOpIndex() << std::endl;
      break;
    }

    if (uop->isLastMicroOp()) instructionsCommitted_++;

    if (uop->exceptionEncountered()) {
      raiseException_(uop);
      buffer_.pop_front();
      return n + 1;
    }

    const auto& destinations = uop->getDestinationRegisters();
    const auto& results = uop->getResults();
    // std::cout << "ROB: " << uop->getInstructionId() << ":0x" << std::hex
    //           << uop->getInstructionAddress() << std::dec << std::endl;
    for (int i = 0; i < destinations.size(); i++) {
      rat_.commit(destinations[i]);
      // std::cout << "\t" << unsigned(destinations[i].type) << ":"
      //           << unsigned(destinations[i].tag) << " <- ";
      // if (results[i].size() == 1)
      //   std::cout << unsigned(results[i].get<uint8_t>());
      // else if (results[i].size() == 2)
      //   std::cout << results[i].get<uint16_t>();
      // else if (results[i].size() == 4)
      //   std::cout << results[i].get<uint32_t>();
      // else if (results[i].size() == 8)
      //   std::cout << results[i].get<uint64_t>();
      // else if (results[i].size() == 256)
      //   std::cout << results[i].getAsVector<uint64_t>()[0] << ":"
      //             << results[i].getAsVector<uint64_t>()[1];
      // else
      //   std::cout << "N/A";
      // std::cout << std::endl;
    }

    // If it's a memory op, commit the entry at the head of the respective queue
    if (uop->isLoad()) {
      lsq_.commitLoad(uop);
    }
    if (uop->isStoreAddress()) {
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
    // std::cout << "\tFlushing: " << uop->getSequenceId() << ":"
    //           << uop->getInstructionId() << ":0x" << std::hex
    //           << uop->getInstructionAddress() << std::dec << ":"
    //           << uop->getMicroOpIndex() << ":" << std::endl;
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
