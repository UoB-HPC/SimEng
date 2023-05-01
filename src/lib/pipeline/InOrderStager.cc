#include "simeng/pipeline/InOrderStager.hh"

#include <algorithm>
#include <cassert>
#include <iostream>

namespace simeng {
namespace pipeline {

InOrderStager::InOrderStager() {}

void InOrderStager::recordIssue(const std::shared_ptr<Instruction>& insn) {
  // Add instruction to buffer
  issueOrderQueue_.push_back(insn);
}

bool InOrderStager::canWriteback(uint64_t seqId) const {
  // The associated instruction is considered to be ready for writeback if its
  // sequence ID is at the front of the tracking queue
  if (issueOrderQueue_.size() &&
      issueOrderQueue_.front()->getSequenceId() == seqId)
    return true;
  return false;
}

uint64_t InOrderStager::getNextId() const {
  // Return the next sequence ID that can undergo writeback logic, return -1 if
  // none exist
  if (issueOrderQueue_.size()) return issueOrderQueue_.front()->getSequenceId();
  return -1;
}

void InOrderStager::recordRetired(uint64_t seqId) {
  assert(issueOrderQueue_.front()->getSequenceId() == seqId &&
         "Tried to record a retirement out of program order");
  // Remove sequence ID from the tracking queue
  issueOrderQueue_.pop_front();
}

void InOrderStager::flush(uint64_t afterSeqId) {
  // Iterate backwards from the tail of the queue to find and remove entires
  // newer than `afterInsnId`
  while (!issueOrderQueue_.empty()) {
    if (issueOrderQueue_.back()->getSequenceId() <= afterSeqId) {
      break;
    }
    issueOrderQueue_.back()->setFlushed();
    issueOrderQueue_.pop_back();
  }
}

void InOrderStager::flush() {
  // Clear tracking queue in response to pipeline flush
  while (!issueOrderQueue_.empty()) {
    issueOrderQueue_.front()->setFlushed();
    issueOrderQueue_.pop_front();
  }
}

bool InOrderStager::isEmpty() const { return issueOrderQueue_.empty(); }

}  // namespace pipeline
}  // namespace simeng
