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
  buffer_.push_back(insn);
  if(insn->isSVC()) {
    svc_insns.push_back(insn);
  }
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

    instructionsCommitted_++;

    if (uop->exceptionEncountered()) {
      raiseException_(uop);
      if(uop->isSVC()) {
        svc_insns.pop_front();
      }
      buffer_.pop_front();
      return n + 1;
    }

    const auto& destinations = uop->getDestinationRegisters();
    for (const auto& reg : destinations) {
      rat_.commit(reg);
    }

    // If it's a memory op, commit the entry at the head of the respective queue
    if (uop->isStore()) {
      bool violationFound = lsq_.commitStore(uop);
      bool svcViolation = false;
      std::shared_ptr<Instruction> violatingSvc;
      const auto& storeAddresses = uop->getGeneratedAddresses();
      for (const auto& svc : svc_insns) {
        const auto& loadAddresses = svc->getGeneratedAddresses();
        for (const auto& storeReq : storeAddresses) {
          // Iterate over load addresses
          for (const auto& loadReq : loadAddresses) {
            // Check for overlapping requests, and flush if discovered
            if (!(storeReq.address + storeReq.size <= loadReq.address || 
                  loadReq.address + loadReq.size <= storeReq.address)) {
              violatingSvc = svc;
              svcViolation = true;
              break;
            }
          }
          if(svcViolation) break;
        }
        if(svcViolation) break;
      }
      if (violationFound || svcViolation) {
        if(violationFound) {
          // Memory order violation found; aborting commits and flushing
          auto load = lsq_.getViolatingLoad();
          shouldFlush_ = true;
          flushAfter_ = load->getSequenceId() - 1;
          pc_ = load->getInstructionAddress();
        }
        if(svcViolation) {
          // Memory order violation found; aborting commits and flushing
          if(shouldFlush_) {
            if(flushAfter_ > violatingSvc->getSequenceId()) {
              flushAfter_ = violatingSvc->getSequenceId() - 1;
              pc_ = violatingSvc->getInstructionAddress();
            }
          } else {
            shouldFlush_ = true;
            flushAfter_ = violatingSvc->getSequenceId() - 1;
            pc_ = violatingSvc->getInstructionAddress();
          }
        }
        buffer_.pop_front();
        return n + 1;
      }
    } else if (uop->isLoad()) {
      lsq_.commitLoad(uop);
    }
    if(uop->isSVC()) {
      svc_insns.pop_front();
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

    for (const auto& reg : uop->getDestinationRegisters()) {
      rat_.rewind(reg);
    }
    uop->setFlushed();
    buffer_.pop_back();
  }

  while (!svc_insns.empty()) {
    auto& uop = svc_insns.back();
    if(uop->isFlushed()) {
      svc_insns.pop_back();
    }
    else {
      break;
    }    
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

}  // namespace pipeline
}  // namespace simeng
