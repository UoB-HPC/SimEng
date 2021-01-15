#include "simeng/pipeline/ReorderBuffer.hh"

#include <algorithm>
#include <cassert>
#include <iostream>

namespace simeng {
namespace pipeline {

ReorderBuffer::ReorderBuffer(
    unsigned int maxSize, RegisterAliasTable& rat, LoadStoreQueue& lsq,
    std::function<void(const std::shared_ptr<Instruction>&)> raiseException,
    std::function<void(uint64_t branchAddress)> sendLoopBoundary,
    BranchPredictor& predictor, uint16_t loopBufSize,
    uint16_t loopDetectionThreshold)
    : rat_(rat),
      lsq_(lsq),
      maxSize_(maxSize),
      raiseException_(raiseException),
      sendLoopBoundary_(sendLoopBoundary),
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

void ReorderBuffer::commitMicroOps(uint64_t insnId) {
  if (buffer_.size()) {
    size_t index = 0;
    int firstOp = -1;
    bool validForCommit = false;

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
        } else if (buffer_[index]->isLastMicroOp()) {
          // all microOps must be in ROB for the commit to be valid
          validForCommit = true;
        }
      }
      if (!validForCommit) return;

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
      break;
    }

    if (uop->isLastMicroOp()) instructionsCommitted_++;

    bool tracePrintable = false;
    std::map<uint64_t, Trace*>::iterator it;
    cycleTrace tr;
    if (uop->getTraceId() != 0) {
      it = traceMap.find(uop->getTraceId());
      if (it != traceMap.end()) {
        tracePrintable = true;
        tr = it->second->getCycleTraces();
      }
    }

    if (tracePrintable) {
      if (tr.finished != 1) {
        tr.retire = trace_cycle;
        tr.finished = 1;
        it->second->setCycleTraces(tr);
      }
    }

    if (uop->exceptionEncountered()) {
      if (tracePrintable) {
        tr.finished = 1;
        it->second->setCycleTraces(tr);
      }
      // Exception.rob.robCommit
      probeTrace newProbe = {17, trace_cycle, uop->getTraceId()};
      Trace* newTrace = new Trace;
      newTrace->setProbeTraces(newProbe);
      probeList.push_back(newTrace);

      raiseException_(uop);
      buffer_.pop_front();
      return n + 1;
    }

    const auto& destinations = uop->getDestinationRegisters();
    for (int i = 0; i < destinations.size(); i++) {
      rat_.commit(destinations[i]);
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
        flushAfter_ = load->getInstructionId() - 1;
        pc_ = load->getInstructionAddress();

        if (tracePrintable) {
          tr.finished = 1;
          it->second->setCycleTraces(tr);
        }
        // Flush.rob.storeViolation
        probeTrace newProbe = {15, trace_cycle, uop->getTraceId()};
        Trace* newTrace = new Trace;
        newTrace->setProbeTraces(newProbe);
        probeList.push_back(newTrace);

        buffer_.pop_front();
        return n + 1;
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
      } else if ((instructionsCommitted_ - branchCounter_.first.commitNumber) >
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
    buffer_.pop_front();
  }

  return n;
}

void ReorderBuffer::flush(uint64_t afterSeqId) {
  // Iterate backwards from the tail of the queue to find and remove ops newer
  // than `afterSeqId`
  while (!buffer_.empty()) {
    auto& uop = buffer_.back();
    if (uop->getInstructionId() <= afterSeqId) {
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
    // If the instruction is a branch, supply address to branch flushing logic
    if (uop->isBranch()) {
      predictor_.flush(uop->getInstructionAddress());
    }

    if (uop->getTraceId() != 0) {
      std::map<uint64_t, Trace*>::iterator it =
          traceMap.find(uop->getTraceId());
      if (it != traceMap.end()) {
        cycleTrace tr = it->second->getCycleTraces();
        tr.finished = 1;
        it->second->setCycleTraces(tr);
      }
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
uint64_t ReorderBuffer::getFlushSeqId() const { return flushAfter_; }

uint64_t ReorderBuffer::getInstructionsCommittedCount() const {
  return instructionsCommitted_;
}

uint64_t ReorderBuffer::getViolatingLoadsCount() const {
  return loadViolations_;
}

}  // namespace pipeline
}  // namespace simeng
