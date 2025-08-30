#include "simeng/pipeline/ReorderBuffer.hh"

#include <algorithm>
#include <cassert>
#include <iostream>
#include <utility>

namespace simeng {
namespace pipeline {

ReorderBuffer::ReorderBuffer(
    uint32_t maxSize, RegisterAliasTable& rat, LoadStoreQueue& lsq,
    std::function<void(const std::shared_ptr<Instruction>&)> raiseException,
    std::function<void(uint64_t branchAddress)> sendLoopBoundary,
    BranchPredictor& predictor, uint16_t loopBufSize,
    uint16_t loopDetectionThreshold)
    : rat_(rat),
      lsq_(lsq),
      maxSize_(maxSize),
      raiseException_(std::move(raiseException)),
      sendLoopBoundary_(std::move(sendLoopBoundary)),
      predictor_(predictor),
      loopBufSize_(loopBufSize),
      loopDetectionThreshold_(loopDetectionThreshold) {}

void ReorderBuffer::reserve(const std::shared_ptr<Instruction>& insn) {
  assert(buffer_.size() < maxSize_ &&
         "Attempted to reserve entry in reorder buffer when already full");
  insn->setSequenceId(seqId_);
  seqId_++;
  insn->setInstructionId(insnId_);
  if (insn->isLastMicroOp()) insnId_++;

  buffer_.push_back(insn);
}

void ReorderBuffer::commitMicroOps(const uint64_t insnId) {
  if (!buffer_.empty()) {
    size_t index = 0;
    uint64_t firstOp = UINT64_MAX;
    bool foundFirstInstance = false;

    // Find first instance of uop belonging to macro-op instruction
    for (; index < buffer_.size(); index++) {
      if (buffer_[index]->getInstructionId() == insnId) {
        firstOp = index;
        foundFirstInstance = true;
        break;
      }
    }

    if (foundFirstInstance) {
      bool validForCommit = false;
      // If found, see if all uops are committable
      for (; index < buffer_.size(); index++) {
        if (buffer_[index]->getInstructionId() != insnId) break;
        if (!buffer_[index]->isWaitingCommit()) {
          return;
        }
        if (buffer_[index]->isLastMicroOp()) {
          // all microOps must be in ROB for the commit to be valid
          validForCommit = true;
        }
      }
      if (!validForCommit) return;

      assert(firstOp != UINT64_MAX && "firstOp hasn't been populated");
      // No early return thus all uops are committable
      for (; firstOp < buffer_.size(); firstOp++) {
        if (buffer_[firstOp]->getInstructionId() != insnId) break;
        buffer_[firstOp]->setCommitReady();
      }
    }
  }
}

unsigned int ReorderBuffer::commit(const uint64_t maxCommitSize) {
  shouldFlush_ = false;
  const size_t maxCommits =
      // ReSharper disable once CppRedundantCastExpression
      std::min(static_cast<size_t>(maxCommitSize), buffer_.size());

  unsigned int n = 0;
  std::shared_ptr<Instruction> offloadedBatch = nullptr;
  for (; n < maxCommits; n++) {
    auto& uop = buffer_.front();
    if (!uop->canCommit()) {
      if (uop->isOffloaded()) {
        // Mark a batch of offloaded instructions as waiting commit
        // (i.e. non-speculative, can be sent to the accelerator)
        for (size_t i = 0; i < maxCommits - n; i++) {
          const auto& insn = buffer_[i];
          if (!insn->isOffloaded()) break;
          insn->setWaitingAcceleratorCommit();
        }
      }

      break;
    }

    // Aggregate offloaded instructions into batches
    if (uop->isOffloaded()) {
      offloadedBatch = uop;
    } else if (offloadedBatch != nullptr) {
      // Finished commiting offloaded instruction batch
      break;
    }

    if (uop->isLastMicroOp()) instructionsCommitted_++;

    if (uop->exceptionEncountered()) {
      raiseException_(uop);
      buffer_.pop_front();
      return n + 1;
    }

    const auto& destinations = uop->getDestinationRegisters();
    for (const auto destination : destinations) {
      rat_.commit(destination);
    }

    // If it's a memory op, commit the entry at the head of the respective queue
    if (!uop->isOffloaded()) {
      if (uop->isLoad()) {
        lsq_.commitLoad(uop);
      }
      if (uop->isStoreAddress()) {
        if (lsq_.commitStore(uop)) {
          loadViolations_++;
          // Memory order violation found; aborting commits and flushing
          const auto load = lsq_.getViolatingLoad();
          shouldFlush_ = true;
          flushAfter_ = load->getInstructionId() - 1;
          pc_ = load->getInstructionAddress();

          buffer_.pop_front();
          return n + 1;
        }
      }
    }

    // Increment or swap out branch counter for loop detection
    if (uop->isBranch() && !loopDetected_) {
      bool increment = true;
      if (branchCounter_.first.address != uop->getInstructionAddress()) {
        // Mismatch on instruction address, reset
        increment = false;
      } else if (branchCounter_.first.outcome != uop->getBranchPrediction()) {
        // Mismatch on branch outcome, reset
        increment = false;
      } else if (instructionsCommitted_ - branchCounter_.first.commitNumber >
                 loopBufSize_) {
        // Loop too big to fit in loop buffer, reset
        increment = false;
      }

      if (increment) {
        // Reset commitNumber value
        branchCounter_.first.commitNumber = instructionsCommitted_;
        // Increment counter
        branchCounter_.second++;

        if (branchCounter_.second > loopDetectionThreshold_) {
          // If the same branch with the same outcome is sequentially retired
          // more times than the loopDetectionThreshold_ value, identify as a
          // loop boundary
          loopDetected_ = true;
          sendLoopBoundary_(uop->getInstructionAddress());
        }
      } else {
        // Swap out latest branch
        branchCounter_ = {{uop->getInstructionAddress(),
                           uop->getBranchPrediction(), instructionsCommitted_},
                          0};
      }
    }

    // If it is a branch, now update the predictor (here to ensure order of
    // updates is correct)
    if (uop->isBranch()) {
      predictor_.update(uop->getInstructionAddress(), uop->wasBranchTaken(),
                        uop->getBranchAddress(), uop->getBranchType(),
                        uop->getInstructionId());
      // Update the branches retired and mispredicted counters
      retiredBranches_++;
      if (uop->wasBranchMispredicted()) branchMispredicts_++;
    }

    buffer_.pop_front();
  }

  // Flush after commiting the whole batch of offloaded instructions to prevent
  // memory ordering issues
  if (offloadedBatch != nullptr && !buffer_.empty() &&
      !buffer_.front()->isOffloaded()) {
    shouldFlush_ = true;
    flushAfter_ = offloadedBatch->getInstructionId();
    pc_ = buffer_.front()->getInstructionAddress();
  }

  return n;
}

void ReorderBuffer::flush(const uint64_t afterInsnId) {
  // Iterate backwards from the tail of the queue to find and remove ops newer
  // than `afterInsnId`
  while (!buffer_.empty()) {
    const auto& uop = buffer_.back();
    if (uop->getInstructionId() <= afterInsnId &&
        afterInsnId != static_cast<uint64_t>(-1)) {
      break;
    }

    // To rewind destination registers in correct history order, rewinding of
    // register renaming is done backwards
    auto destinations = uop->getDestinationRegisters();
    for (int i = static_cast<int>(destinations.size()) - 1; i >= 0; i--) {
      const auto& reg = destinations[i];
      // Only rewind the register if it was renamed
      if (reg.renamed) rat_.rewind(reg);
    }
    uop->setFlushed();
    // If the instruction is a branch, supply address to branch flushing logic
    if (uop->isBranch()) {
      predictor_.flush(uop->getInstructionAddress());
    }
    buffer_.pop_back();
  }

  // Reset branch counter and loop detection
  branchCounter_ = {{0, {false, 0}, 0}, 0};
  loopDetected_ = false;
}

unsigned int ReorderBuffer::size() const { return buffer_.size(); }

unsigned int ReorderBuffer::getFreeSpace() const {
  return maxSize_ - buffer_.size();
}

bool ReorderBuffer::shouldFlush() const { return shouldFlush_; }
uint64_t ReorderBuffer::getFlushAddress() const { return pc_; }
uint64_t ReorderBuffer::getFlushInsnId() const { return flushAfter_; }

uint64_t ReorderBuffer::getInstructionsCommittedCount() const {
  return instructionsCommitted_;
}

uint64_t ReorderBuffer::getViolatingLoadsCount() const {
  return loadViolations_;
}

uint64_t ReorderBuffer::getBranchMispredictedCount() const {
  return branchMispredicts_;
}

uint64_t ReorderBuffer::getRetiredBranchesCount() const {
  return retiredBranches_;
}

std::shared_ptr<Instruction> ReorderBuffer::findInstructionAfter(
    const std::shared_ptr<Instruction>& insn) const {
  auto it = buffer_.begin();
  while (it != buffer_.end()) {
    if (it->get() == insn.get()) {
      ++it;
      break;
    }
    ++it;
  }
  return it != buffer_.end() ? *it : nullptr;
}

}  // namespace pipeline
}  // namespace simeng
