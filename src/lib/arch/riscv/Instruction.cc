#include "simeng/arch/riscv/Instruction.hh"

#include <algorithm>
#include <cassert>
#include <vector>

#include "InstructionMetadata.hh"

namespace simeng {
namespace arch {
namespace riscv {

Instruction::Instruction(const Architecture& architecture,
                         const InstructionMetadata& metadata)
    : architecture_(architecture),
      metadata_(metadata),
      exception_(metadata.getMetadataException()) {
  exceptionEncountered_ = metadata.getMetadataExceptionEncountered();
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
  return {const_cast<RegisterValue*>(results_.data()),
          destinationRegisterCount_};
}

bool Instruction::isStoreAddress() const {
  return isInstruction(InsnIdentifier::isStoreMask);
}
bool Instruction::isStoreData() const {
  return isInstruction(InsnIdentifier::isStoreMask);
}
bool Instruction::isLoad() const {
  return isInstruction(InsnIdentifier::isLoadMask);
}
bool Instruction::isBranch() const {
  return isInstruction(InsnIdentifier::isBranchMask);
}
bool Instruction::isAtomic() const {
  return isInstruction(InsnIdentifier::isAtomicMask);
}
bool Instruction::isFloat() const {
  return isInstruction(InsnIdentifier::isFloatMask);
}

span<const memory::MemoryAccessTarget> Instruction::getGeneratedAddresses()
    const {
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
  uint16_t base = InstructionGroups::INT;

  if (isFloat()) {
    base = InstructionGroups::FLOAT;
  }

  if (isBranch()) return InstructionGroups::BRANCH;
  if (isLoad()) return base + 8;
  if (isStoreAddress()) return base + 9;
  if (isInstruction(InsnIdentifier::isDivideMask)) return base + 7;
  if (isInstruction(InsnIdentifier::isMultiplyMask)) return base + 6;
  if (isInstruction(InsnIdentifier::isShiftMask) ||
      isInstruction(InsnIdentifier::isConvertMask))
    return base + 5;
  if (isInstruction(InsnIdentifier::isLogicalMask)) return base + 4;
  if (isInstruction(InsnIdentifier::isCompareMask)) return base + 3;
  return base + 2;  // Default return is {Data type}_SIMPLE_ARTH
}

void Instruction::setExecutionInfo(const ExecutionInfo& info) {
  if (isInstruction(InsnIdentifier::isLoadMask) ||
      isInstruction(InsnIdentifier::isStoreMask)) {
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

}  // namespace riscv
}  // namespace arch
}  // namespace simeng
