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
                         const InstructionException exception)
    : architecture_(architecture), metadata_(metadata), exception_(exception) {
  exceptionEncountered_ = true;
}

std::unique_ptr<simeng::Instruction> Instruction::clone() const {
  // TODO: If at any point the Instruction's copy constructor stops being
  //       equivalent to performing a deep copy, this method need to be updated
  auto clone = std::make_unique<Instruction>(*this);
  baseCloneInto(clone.get());
  return clone;
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

void Instruction::renameSource(const uint16_t i, const Register renamed) {
  sourceRegisters_[i] = renamed;
}
void Instruction::renameDestination(const uint16_t i, const Register renamed) {
  destinationRegisters_[i] = renamed;
}

void Instruction::supplyOperand(const uint16_t i, const RegisterValue& value) {
  assert(!canExecute() &&
         "Attempted to provide an operand to a ready-to-execute instruction");
  assert(value.size() > 0 &&
         "Attempted to provide an uninitialised RegisterValue");

  sourceValues_[i] = value;
  sourceOperandsPending_--;
}

bool Instruction::isOperandReady(const int index) const {
  // ReSharper disable once CppRedundantCastExpression
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

void Instruction::supplyData(const uint64_t address,
                             const RegisterValue& data) {
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

BranchType Instruction::getBranchType() const { return branchType_; }

int64_t Instruction::getKnownOffset() const { return knownOffset_; }

bool Instruction::isStoreAddress() const {
  return isInstruction(InsnType::isStore);
}

bool Instruction::isStoreData() const {
  return isInstruction(InsnType::isStore);
}

bool Instruction::isLoad() const { return isInstruction(InsnType::isLoad); }

bool Instruction::isBranch() const { return isInstruction(InsnType::isBranch); }

uint16_t Instruction::getGroup() const {
  uint16_t base = InstructionGroups::INT;

  if (isInstruction(InsnType::isFloat)) {
    base = InstructionGroups::FLOAT;
  }

  if (isInstruction(InsnType::isBranch)) return InstructionGroups::BRANCH;
  if (isInstruction(InsnType::isLoad)) return base + 8;
  if (isInstruction(InsnType::isStore)) return base + 9;
  if (isInstruction(InsnType::isDivide)) return base + 7;
  if (isInstruction(InsnType::isMultiply)) return base + 6;
  if (isInstruction(InsnType::isShift) || isInstruction(InsnType::isConvert))
    return base + 5;
  if (isInstruction(InsnType::isLogical)) return base + 4;
  if (isInstruction(InsnType::isCompare)) return base + 3;
  return base + 2;  // Default return is {Data type}_SIMPLE_ARTH
}

bool Instruction::canExecute() const { return sourceOperandsPending_ == 0; }

bool Instruction::canBeOffloaded() const { return false; }

const std::vector<uint16_t>& Instruction::getSupportedPorts() {
  if (supportedPorts_.empty()) {
    exception_ = InstructionException::NoAvailablePort;
    exceptionEncountered_ = true;
  }
  return supportedPorts_;
}

void Instruction::setExecutionInfo(const ExecutionInfo& info) {
  if (isInstruction(InsnType::isLoad) || isInstruction(InsnType::isStore)) {
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

}  // namespace riscv
}  // namespace arch
}  // namespace simeng
