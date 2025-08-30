#include "simeng/Instruction.hh"

#include "simeng/Accelerator.hh"
#include "simeng/config/SimInfo.hh"
#include "simeng/serialization.hh"

namespace simeng {

Instruction::Instruction(span<uint8_t>& serialized) {
  deserialize_field(serialized, instructionId_);
  deserialize_field(serialized, sequenceId_);
  deserialize_field(serialized, instructionAddress_);
  deserialize_field(serialized, offloaded_);
  deserialize_field(serialized, waitingAcceleratorCommit_);
  deserialize_field(serialized, executed_);
  deserialize_field(serialized, latency_);
  deserialize_field(serialized, lsqExecutionLatency_);
  deserialize_field(serialized, stallCycles_);
  deserialize_vector(serialized, supportedPorts_);
  deserialize_field(serialized, canCommit_);
  deserialize_vector(serialized, memoryAddresses_);
  deserialize_regval_vector(serialized, memoryData_);
  deserialize_field(serialized, dataPending_);
  deserialize_field(serialized, prediction_);
  deserialize_field(serialized, branchAddress_);
  deserialize_field(serialized, branchTaken_);
  deserialize_field(serialized, branchType_);
  deserialize_field(serialized, knownOffset_);
  deserialize_field(serialized, flushed_);
  deserialize_field(serialized, exceptionEncountered_);
  deserialize_field(serialized, isMicroOp_);
  deserialize_field(serialized, isLastMicroOp_);
  deserialize_field(serialized, waitingCommit_);
  deserialize_field(serialized, microOpIndex_);
}

void Instruction::serializeInto(std::vector<uint8_t>& buffer) const {
  serialize_field(buffer, instructionId_);
  serialize_field(buffer, sequenceId_);
  serialize_field(buffer, instructionAddress_);
  serialize_field(buffer, offloaded_);
  serialize_field(buffer, waitingAcceleratorCommit_);
  serialize_field(buffer, executed_);
  serialize_field(buffer, latency_);
  serialize_field(buffer, lsqExecutionLatency_);
  serialize_field(buffer, stallCycles_);
  serialize_vector(buffer, supportedPorts_);
  serialize_field(buffer, canCommit_);
  serialize_vector(buffer, memoryAddresses_);
  serialize_regval_vector(buffer, memoryData_);
  serialize_field(buffer, dataPending_);
  serialize_field(buffer, prediction_);
  serialize_field(buffer, branchAddress_);
  serialize_field(buffer, branchTaken_);
  serialize_field(buffer, branchType_);
  serialize_field(buffer, knownOffset_);
  serialize_field(buffer, flushed_);
  serialize_field(buffer, exceptionEncountered_);
  serialize_field(buffer, isMicroOp_);
  serialize_field(buffer, isLastMicroOp_);
  serialize_field(buffer, waitingCommit_);
  serialize_field(buffer, microOpIndex_);
  serializeIntoImpl(buffer);
}

void Instruction::setSequenceId(const uint64_t seqId) { sequenceId_ = seqId; }

uint64_t Instruction::getSequenceId() const { return sequenceId_.value_or(0); }

bool Instruction::isSequenceIdValid() const { return sequenceId_.has_value(); }

void Instruction::setInstructionId(const uint64_t insnId) {
  instructionId_ = insnId;
}

uint64_t Instruction::getInstructionId() const { return instructionId_; }

void Instruction::setInstructionAddress(const uint64_t address) {
  instructionAddress_ = address;
}

uint64_t Instruction::getInstructionAddress() const {
  return instructionAddress_;
}

void Instruction::setBranchPrediction(const BranchPrediction prediction) {
  prediction_ = prediction;
}

BranchPrediction Instruction::getBranchPrediction() const {
  return prediction_;
}

uint64_t Instruction::getBranchAddress() const { return branchAddress_; }

bool Instruction::wasBranchTaken() const { return branchTaken_; }

bool Instruction::wasBranchMispredicted() const {
  assert(executed_ &&
         "Branch misprediction check requires instruction to have executed");
  // Flag as mispredicted if taken state was wrongly predicted, or taken
  // and predicted target is wrong
  return branchTaken_ != prediction_.isTaken ||
         prediction_.target != branchAddress_;
}

bool Instruction::exceptionEncountered() const { return exceptionEncountered_; }

bool Instruction::hasAllData() const { return dataPending_ == 0; }

bool Instruction::hasExecuted() const { return executed_; }

uint16_t Instruction::getLatency() const { return latency_; }

uint16_t Instruction::getStallCycles() const { return stallCycles_; }

uint16_t Instruction::getLSQLatency() const { return lsqExecutionLatency_; }

void Instruction::markOffloaded(const accelerator_id_t accelerator) {
  assert(accelerator != Accelerator::NO_ACCELERATOR &&
         "Cannot mark instruction as offloaded with no accelerator specified.");
  offloaded_ = accelerator;
}

void Instruction::markAccelerated() {
  offloaded_ = Accelerator::NO_ACCELERATOR;
  sequenceId_.reset();
  waitingAcceleratorCommit_ = false;
}

bool Instruction::canBeOffloaded() const {
  if (!isOffloaded()) return false;

  // Wait until not speculative
  if (!isWaitingAcceleratorCommit()) return false;

  const auto& logic = config::SimInfo::getOffloadingLogic();
  return logic.isInstructionReady(offloaded_, *this);
}

bool Instruction::isOffloaded() const noexcept {
  return offloaded_ != Accelerator::NO_ACCELERATOR;
}

void Instruction::setWaitingAcceleratorCommit() noexcept {
  waitingAcceleratorCommit_ = true;
}

void Instruction::setAcceleratorCommited() noexcept {
  waitingAcceleratorCommit_ = false;
}

bool Instruction::isWaitingAcceleratorCommit() const noexcept {
  return waitingAcceleratorCommit_;
}

bool Instruction::isRegisterOffloaded(const Register& reg) const {
  if (offloaded_ == Accelerator::NO_ACCELERATOR) return false;

  const auto& logic = config::SimInfo::getOffloadingLogic();
  return logic.isRegisterOffloaded(offloaded_, reg);
}

void Instruction::moveOffloadedResults(
    std::shared_ptr<Instruction>& offloadedSrc) {
  executed_ = offloadedSrc->executed_;
  memoryAddresses_ = offloadedSrc->memoryAddresses_;
  memoryData_ = offloadedSrc->memoryData_;
  dataPending_ = offloadedSrc->dataPending_;
  branchAddress_ = offloadedSrc->branchAddress_;
  branchTaken_ = offloadedSrc->branchTaken_;
  exceptionEncountered_ = offloadedSrc->exceptionEncountered_;
  moveOffloadedResultsImpl(offloadedSrc);
  offloadedSrc = nullptr;
}

void Instruction::setWaitingCommit() { waitingCommit_ = true; }

bool Instruction::isWaitingCommit() const { return waitingCommit_; }

void Instruction::setCommitReady() { canCommit_ = true; }

bool Instruction::canCommit() const { return canCommit_; }

void Instruction::setFlushed() { flushed_ = true; }

bool Instruction::isFlushed() const { return flushed_; }

bool Instruction::isMicroOp() const { return isMicroOp_; }

bool Instruction::isLastMicroOp() const { return isLastMicroOp_; }

int Instruction::getMicroOpIndex() const { return microOpIndex_; }

void Instruction::baseCloneInto(Instruction* dest) const {
  dest->instructionId_ = instructionId_;
  dest->sequenceId_ = sequenceId_;
  dest->instructionAddress_ = instructionAddress_;
  dest->offloaded_ = offloaded_;
  dest->waitingAcceleratorCommit_ = waitingAcceleratorCommit_;
  dest->executed_ = executed_;
  dest->latency_ = latency_;
  dest->lsqExecutionLatency_ = lsqExecutionLatency_;
  dest->stallCycles_ = stallCycles_;
  dest->supportedPorts_ = supportedPorts_;
  dest->canCommit_ = canCommit_;
  dest->memoryAddresses_ = memoryAddresses_;
  dest->memoryData_ = memoryData_;
  dest->dataPending_ = dataPending_;
  dest->prediction_ = prediction_;
  dest->branchAddress_ = branchAddress_;
  dest->branchTaken_ = branchTaken_;
  dest->branchType_ = branchType_;
  dest->knownOffset_ = knownOffset_;
  dest->flushed_ = flushed_;
  dest->exceptionEncountered_ = exceptionEncountered_;
  dest->isMicroOp_ = isMicroOp_;
  dest->isLastMicroOp_ = isLastMicroOp_;
  dest->waitingCommit_ = waitingCommit_;
  dest->microOpIndex_ = microOpIndex_;
}

void Instruction::setMemoryAddresses(
    const std::vector<memory::MemoryAccessTarget>& addresses) {
  memoryData_.resize(addresses.size());
  memoryAddresses_ = addresses;
  dataPending_ = addresses.size();
}

void Instruction::setMemoryAddresses(
    std::vector<memory::MemoryAccessTarget>&& addresses) {
  dataPending_ = addresses.size();
  memoryData_.resize(addresses.size());
  memoryAddresses_ = std::move(addresses);
}

void Instruction::setMemoryAddresses(const memory::MemoryAccessTarget address) {
  dataPending_ = 1;
  memoryData_.resize(1);
  memoryAddresses_.push_back(address);
}

}  // namespace simeng
