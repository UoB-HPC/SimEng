#include "simeng/Instruction.hh"

#include <iostream>

namespace simeng {

bool Instruction::exceptionEncountered() const { return exceptionEncountered_; }

void Instruction::setInstructionAddress(uint64_t address) {
  instructionAddress_ = address;
}
uint64_t Instruction::getInstructionAddress() const {
  return instructionAddress_;
}

void Instruction::setBranchPrediction(BranchPrediction prediction) {
  prediction_ = prediction;
}

uint64_t Instruction::getBranchAddress() const { return branchAddress_; }
bool Instruction::wasBranchTaken() const { return branchTaken_; }

bool Instruction::wasBranchMispredicted() const {
  assert(executed_ &&
         "Branch misprediction check requires instruction to have executed");

  // Flag as mispredicted if taken state was wrongly predicted, or taken and
  // predicted target is wrong
  
  return (branchTaken_ != prediction_.taken ||
          (branchTaken_ && prediction_.target != branchAddress_));
}

void Instruction::setSequenceId(uint64_t seqId) { sequenceId_ = seqId; };
uint64_t Instruction::getSequenceId() const { return sequenceId_; };

void Instruction::setFlushed() { flushed_ = true; }
bool Instruction::isFlushed() const { return flushed_; }

bool Instruction::hasExecuted() const { return executed_; }

void Instruction::setCommitReady() { canCommit_ = true; }
bool Instruction::canCommit() const { return canCommit_; }

bool Instruction::hasAllData() const { return (dataPending_ == 0); }

uint16_t Instruction::getLatency() const { return latency_; }
uint16_t Instruction::getStallCycles() const { return stallCycles_; }

void Instruction::setDispatchStalled(bool stalled) { dispatchStalled_ = stalled; }
bool Instruction::isDispatchStalled() const { return dispatchStalled_; }

}  // namespace simeng
