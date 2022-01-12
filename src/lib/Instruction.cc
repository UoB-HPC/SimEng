#include "simeng/Instruction.hh"

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

void Instruction::setInstructionId(uint64_t insnId) { instructionId_ = insnId; }
uint64_t Instruction::getInstructionId() const { return instructionId_; }

void Instruction::setFlushed() { flushed_ = true; }
bool Instruction::isFlushed() const { return flushed_; }

bool Instruction::hasExecuted() const { return executed_; }

void Instruction::setCommitReady() { canCommit_ = true; }
bool Instruction::canCommit() const { return canCommit_; }

bool Instruction::hasAllData() const { return (dataPending_ == 0); }

uint16_t Instruction::getLatency() const { return latency_; }
uint16_t Instruction::getLSQLatency() const { return lsqExecutionLatency_; }
uint16_t Instruction::getStallCycles() const { return stallCycles_; }

bool Instruction::shouldSplitRequests() const { return splitMemoryRequests_; }

bool Instruction::isMicroOp() const { return isMicroOp_; }
bool Instruction::isLastMicroOp() const { return isLastMicroOp_; }
void Instruction::setWaitingCommit() { waitingCommit_ = true; }
bool Instruction::isWaitingCommit() const { return waitingCommit_; }
int Instruction::getMicroOpIndex() const { return microOpIndex_; }

}  // namespace simeng
