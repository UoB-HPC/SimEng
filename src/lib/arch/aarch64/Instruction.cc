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

const span<Register> Instruction::getSourceRegisters() const {
  return {const_cast<Register*>(sourceRegisters_.data()), sourceRegisterCount_};
}

const span<RegisterValue> Instruction::getSourceOperands() const {
  return {const_cast<RegisterValue*>(sourceValues_.data()),
          sourceRegisterCount_};
}

const span<Register> Instruction::getDestinationRegisters() const {
  return {const_cast<Register*>(destinationRegisters_.data()),
          destinationRegisterCount_};
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

bool Instruction::isOperandReady(int index) const {
  return static_cast<bool>(sourceValues_[index]);
}

const span<RegisterValue> Instruction::getResults() const {
  return {const_cast<RegisterValue*>(results_.data()),
          destinationRegisterCount_};
}

span<const memory::MemoryAccessTarget> Instruction::getGeneratedAddresses()
    const {
  return {memoryAddresses_.data(), memoryAddresses_.size()};
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

std::tuple<bool, uint64_t> Instruction::checkEarlyBranchMisprediction() const {
  assert(
      !executed_ &&
      "Early branch misprediction check shouldn't be called after execution");

  if (!isBranch()) {
    // Instruction isn't a branch; if predicted as taken, it will require a
    // flush
    return {prediction_.isTaken, instructionAddress_ + 4};
  }

  // Not enough information to determine this was a misprediction
  return {false, 0};
}

BranchType Instruction::getBranchType() const { return branchType_; }

int64_t Instruction::getKnownOffset() const { return knownOffset_; }

bool Instruction::isStoreAddress() const {
  return isInstruction(InsnType::isStoreAddress);
}

bool Instruction::isStoreData() const {
  return isInstruction(InsnType::isStoreData);
}

bool Instruction::isLoad() const { return isInstruction(InsnType::isLoad); }

bool Instruction::isBranch() const { return isInstruction(InsnType::isBranch); }

uint16_t Instruction::getGroup() const {
  // Use identifiers to decide instruction group
  // Set base
  uint16_t base = InstructionGroups::INT;
  if (isInstruction(InsnType::isScalarData))
    base = InstructionGroups::SCALAR;
  else if (isInstruction(InsnType::isVectorData))
    base = InstructionGroups::VECTOR;
  else if (isInstruction(InsnType::isSVEData))
    base = InstructionGroups::SVE;
  else if (isInstruction(InsnType::isSMEData))
    base = InstructionGroups::SME;

  if (isInstruction(InsnType::isLoad)) return base + 10;
  if (isInstruction(InsnType::isStoreAddress)) return base + 11;
  if (isInstruction(InsnType::isStoreData)) return base + 12;
  if (isInstruction(InsnType::isBranch)) return InstructionGroups::BRANCH;
  if (isInstruction(InsnType::isPredicate)) return InstructionGroups::PREDICATE;
  if (isInstruction(InsnType::isDivideOrSqrt)) return base + 9;
  if (isInstruction(InsnType::isMultiply)) return base + 8;
  if (isInstruction(InsnType::isConvert)) return base + 7;
  if (isInstruction(InsnType::isCompare)) return base + 6;
  if (isInstruction(InsnType::isLogical)) {
    if (isInstruction(InsnType::isShift)) return base + 4;
    return base + 5;
  }
  if (isInstruction(InsnType::isShift)) return base + 2;
  return base + 3;  // Default return is {Data type}_SIMPLE_ARTH
}

bool Instruction::canExecute() const { return (sourceOperandsPending_ == 0); }

const std::vector<uint16_t>& Instruction::getSupportedPorts() {
  if (supportedPorts_.size() == 0) {
    exception_ = InstructionException::NoAvailablePort;
    exceptionEncountered_ = true;
  }
  return supportedPorts_;
}

void Instruction::setExecutionInfo(const ExecutionInfo& info) {
  if (isInstruction(InsnType::isLoad) ||
      isInstruction(InsnType::isStoreAddress)) {
    lsqExecutionLatency_ = info.latency;
  } else {
    latency_ = info.latency;
  }
  stallCycles_ = info.stallCycles;
  supportedPorts_ = info.ports;
}

const InstructionMetadata& Instruction::getMetadata() const {
  return metadata_;
}

const Architecture& Instruction::getArchitecture() const {
  return architecture_;
}

InstructionException Instruction::getException() const { return exception_; }

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng
