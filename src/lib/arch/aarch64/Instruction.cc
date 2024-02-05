#include <algorithm>
#include <cassert>
#include <vector>

#include "InstructionMetadata.hh"

namespace simeng {
namespace arch {
namespace aarch64 {

Instruction::Instruction(const Architecture& architecture,
                         const InstructionMetadata& metadata,
                         MicroOpInfo microOpInfo)
    : architecture_(architecture),
      metadata_(metadata),
      exception_(metadata.getMetadataException()) {
  exceptionEncountered_ = metadata.getMetadataExceptionEncountered();
  isMicroOp_ = microOpInfo.isMicroOp;
  microOpcode_ = microOpInfo.microOpcode;
  dataSize_ = microOpInfo.dataSize;
  isLastMicroOp_ = microOpInfo.isLastMicroOp;
  microOpIndex_ = microOpInfo.microOpIndex;
  decode();
}

Instruction::Instruction(const Architecture& architecture,
                         const InstructionMetadata& metadata,
                         InstructionException exception)
    : architecture_(architecture), metadata_(metadata) {
  exception_ = exception;
  exceptionEncountered_ = true;
}

InstructionException Instruction::getException() const { return exception_; }

const span<Register> Instruction::getSourceRegisters() const {
  return {const_cast<Register*>(sourceRegisters_.data()),
          sourceRegisters_.size()};
}

const span<RegisterValue> Instruction::getSourceOperands() const {
  return {const_cast<RegisterValue*>(sourceValues_.data()),
          sourceValues_.size()};
}

const span<Register> Instruction::getDestinationRegisters() const {
  // The `destinationRegisterCount` is used here as the span count value because
  // there may be n number of zero registers in the latter indexes of the
  // `destinationRegisters` vector. These cannot be written to and hence
  // shouldn't be included in the returned span.
  return {const_cast<Register*>(destinationRegisters_.data()),
          destinationRegisterCount_};
}
bool Instruction::isOperandReady(int index) const {
  return static_cast<bool>(sourceValues_[index]);
}

void Instruction::renameSource(uint16_t i, Register renamed) {
  sourceRegisters_[i] = renamed;
}

void Instruction::renameDestination(uint16_t i, Register renamed) {
  destinationRegisters_[i] = renamed;
}

void Instruction::supplyOperand(uint16_t i, const RegisterValue& value) {
  assert(!canExecute() &&
         "Attempted to provide an operand to a ready-to-execute instruction");
  assert(value.size() > 0 &&
         "Attempted to provide an uninitialised RegisterValue");

  sourceValues_[i] = value;
  sourceOperandsPending_--;
}

void Instruction::supplyData(uint64_t address, const RegisterValue& data) {
  for (size_t i = 0; i < memoryAddresses_.size(); i++) {
    if (memoryAddresses_[i].address == address && !memoryData_[i]) {
      if (!data) {
        // Raise exception for failed read
        // TODO: Move this logic to caller and distinguish between different
        // memory faults (e.g. bus error, page fault, seg fault)
        exception_ = InstructionException::DataAbort;
        exceptionEncountered_ = true;
        memoryData_[i] = RegisterValue(0, memoryAddresses_[i].size);
      } else {
        memoryData_[i] = data;
      }
      dataPending_--;
      return;
    }
  }
}

span<const RegisterValue> Instruction::getData() const {
  return {memoryData_.data(), memoryData_.size()};
}

bool Instruction::canExecute() const { return (sourceOperandsPending_ == 0); }

const span<RegisterValue> Instruction::getResults() const {
  // The `destinationRegisterCount` is used here as the span count value because
  // there may be n number of values attributed to zero registers in the latter
  // indexes of the `results` vector. Zero registers cannot be written to and
  // hence shouldn't be included in the returned span.
  return {const_cast<RegisterValue*>(results_.data()),
          destinationRegisterCount_};
}

bool Instruction::isStoreAddress() const { return isStoreAddress_; }
bool Instruction::isStoreData() const { return isStoreData_; }
bool Instruction::isLoad() const { return isLoad_; }
bool Instruction::isBranch() const { return isBranch_; }

void Instruction::setMemoryAddresses(
    const std::vector<MemoryAccessTarget>& addresses) {
  memoryData_.resize(addresses.size());
  memoryAddresses_ = addresses;
  dataPending_ = addresses.size();
}

void Instruction::setMemoryAddresses(
    std::vector<MemoryAccessTarget>&& addresses) {
  dataPending_ = addresses.size();
  memoryData_.resize(addresses.size());
  memoryAddresses_ = std::move(addresses);
}

void Instruction::setMemoryAddresses(MemoryAccessTarget address) {
  dataPending_ = 1;
  memoryData_.resize(1);
  memoryAddresses_.push_back(address);
}

span<const MemoryAccessTarget> Instruction::getGeneratedAddresses() const {
  return {memoryAddresses_.data(), memoryAddresses_.size()};
}

std::tuple<bool, uint64_t> Instruction::checkEarlyBranchMisprediction() const {
  assert(
      !executed_ &&
      "Early branch misprediction check shouldn't be called after execution");

  if (!isBranch()) {
    // Instruction isn't a branch; if predicted as taken, it will require a
    // flush
    return {prediction_.taken, instructionAddress_ + 4};
  }

  // Not enough information to determine this was a misprediction
  return {false, 0};
}

BranchType Instruction::getBranchType() const { return branchType_; }

int64_t Instruction::getKnownOffset() const { return knownOffset_; }

uint16_t Instruction::getGroup() const {
  // Use identifiers to decide instruction group
  // Set base
  uint16_t base = InstructionGroups::INT;
  if (isScalarData_)
    base = InstructionGroups::SCALAR;
  else if (isVectorData_)
    base = InstructionGroups::VECTOR;
  else if (isSVEData_)
    base = InstructionGroups::SVE;
  else if (isSMEData_)
    base = InstructionGroups::SME;

  if (isLoad_) return base + 10;
  if (isStoreAddress_) return base + 11;
  if (isStoreData_) return base + 12;
  if (isBranch_) return InstructionGroups::BRANCH;
  if (isPredicate_) return InstructionGroups::PREDICATE;
  if (isDivideOrSqrt_) return base + 9;
  if (isMultiply_) return base + 8;
  if (isConvert_) return base + 7;
  if (isCompare_) return base + 6;
  if (isLogical_) {
    if (isNoShift_) return base + 5;
    return base + 4;
  }
  if (isNoShift_) return base + 3;
  return base + 2;  // Default return is {Data type}_SIMPLE_ARTH
}

void Instruction::setExecutionInfo(const ExecutionInfo& info) {
  if (isLoad_ || isStoreAddress_) {
    lsqExecutionLatency_ = info.latency;
  } else {
    latency_ = info.latency;
  }
  stallCycles_ = info.stallCycles;
  supportedPorts_ = info.ports;
}

const std::vector<uint16_t>& Instruction::getSupportedPorts() {
  if (supportedPorts_.size() == 0) {
    exception_ = InstructionException::NoAvailablePort;
    exceptionEncountered_ = true;
  }
  return supportedPorts_;
}

const InstructionMetadata& Instruction::getMetadata() const {
  return metadata_;
}

const Architecture& Instruction::getArchitecture() const {
  return architecture_;
}

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng
