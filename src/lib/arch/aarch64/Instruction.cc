#include <algorithm>
#include <cassert>
#include <vector>

#include "InstructionMetadata.hh"
#include "simeng/serialization.hh"

namespace simeng {
namespace arch {
namespace aarch64 {

Instruction::Instruction(const Architecture& architecture,
                         std::shared_ptr<const InstructionMetadata> metadata,
                         const MicroOpInfo microOpInfo)
    : architecture_(architecture),
      metadata_(std::move(metadata)),
      exception_(metadata_->getMetadataException()) {
  exceptionEncountered_ = metadata_->getMetadataExceptionEncountered();
  isMicroOp_ = microOpInfo.isMicroOp;
  microOpcode_ = microOpInfo.microOpcode;
  dataSize_ = microOpInfo.dataSize;
  isLastMicroOp_ = microOpInfo.isLastMicroOp;
  microOpIndex_ = microOpInfo.microOpIndex;
  decode();
}

Instruction::Instruction(const Architecture& architecture,
                         std::shared_ptr<const InstructionMetadata> metadata,
                         const InstructionException exception)
    : architecture_(architecture),
      metadata_(std::move(metadata)),
      exception_(exception) {
  exceptionEncountered_ = true;
}

Instruction::Instruction(const Architecture& architecture,
                         span<uint8_t>& serialized)
    : simeng::Instruction(serialized), architecture_(architecture) {
  metadata_ = std::make_shared<InstructionMetadata>(serialized);
  sourceRegisters_ = srcRegContainer(serialized);
  deserialize_field(serialized, sourceRegisterCount_);
  destinationRegisters_ = destRegContainer(serialized);
  deserialize_field(serialized, destinationRegisterCount_);
  sourceValues_ = srcValContainer(serialized);
  results_ = destValContainer(serialized);
  deserialize_field(serialized, exception_);
  deserialize_field(serialized, sourceOperandsPending_);
  deserialize_field(serialized, microOpcode_);
  deserialize_field(serialized, dataSize_);
  deserialize_field(serialized, instructionIdentifier_);
}

std::unique_ptr<simeng::Instruction> Instruction::clone() const {
  // TODO: If at any point the Instruction's copy constructor stops being
  //       equivalent to performing a deep copy, this method needs to be updated
  auto clone = std::make_unique<Instruction>(*this);
  baseCloneInto(clone.get());
  return clone;
}

void Instruction::serializeIntoImpl(std::vector<uint8_t>& buffer) const {
  metadata_->serializeInto(buffer);
  serialize_vector(buffer, sourceRegisters_);
  serialize_field(buffer, sourceRegisterCount_);
  serialize_vector(buffer, destinationRegisters_);
  serialize_field(buffer, destinationRegisterCount_);
  serialize_regval_vector(buffer, sourceValues_);
  serialize_regval_vector(buffer, results_);
  serialize_field(buffer, exception_);
  serialize_field(buffer, sourceOperandsPending_);
  serialize_field(buffer, microOpcode_);
  serialize_field(buffer, dataSize_);
  serialize_field(buffer, instructionIdentifier_);
}

void Instruction::moveOffloadedResultsImpl(
    std::shared_ptr<simeng::Instruction>& offloadedSrc) {
  // NOLINTBEGIN(*-pro-type-static-cast-downcast)
  const auto& src = *static_cast<Instruction*>(offloadedSrc.get());
  // NOLINTEND(*-pro-type-static-cast-downcast)
  sourceValues_ = src.sourceValues_;
  results_ = src.results_;
  exception_ = src.exception_;
  sourceOperandsPending_ = src.sourceOperandsPending_;
  dataSize_ = src.dataSize_;
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

bool Instruction::canExecute() const {
  return sourceOperandsPending_ == 0 && !isOffloaded();
}

const std::vector<uint16_t>& Instruction::getSupportedPorts() {
  if (supportedPorts_.empty() && !isOffloaded()) {
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
  return *metadata_;
}

const Architecture& Instruction::getArchitecture() const {
  return architecture_;
}

InstructionException Instruction::getException() const { return exception_; }

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng
