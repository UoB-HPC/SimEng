#include <algorithm>
#include <cassert>
#include <vector>

#include "InstructionMetadata.hh"

namespace simeng {
namespace arch {
namespace aarch64 {

const Register Instruction::ZERO_REGISTER = {RegisterType::GENERAL,
                                             (uint16_t)-1};

Instruction::Instruction(const Architecture& architecture,
                         const InstructionMetadata& metadata,
                         MicroOpInfo microOpInfo)
    : architecture_(architecture), metadata(metadata) {
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
    : architecture_(architecture), metadata(metadata) {
  exception_ = exception;
  exceptionEncountered_ = true;
}

InstructionException Instruction::getException() const { return exception_; }

const span<Register> Instruction::getOperandRegisters() const {
  return {const_cast<Register*>(sourceRegisters.data()), sourceRegisterCount};
}

const span<Register> Instruction::getDestinationRegisters() const {
  return {const_cast<Register*>(destinationRegisters.data()),
          destinationRegisterCount};
}

bool Instruction::isOperandReady(int index) const {
  return static_cast<bool>(operands[index]);
}

void Instruction::renameSource(uint8_t i, Register renamed) {
  sourceRegisters[i] = renamed;
}

void Instruction::renameDestination(uint8_t i, Register renamed) {
  destinationRegisters[i] = renamed;
}

void Instruction::supplyOperand(uint8_t i, const RegisterValue& value) {
  assert(!canExecute() &&
         "Attempted to provide an operand to a ready-to-execute instruction");
  assert(value.size() > 0 &&
         "Attempted to provide an uninitialised RegisterValue");

  operands[i] = value;
  operandsPending--;
}

bool Instruction::canExecute() const { return (operandsPending == 0); }

const span<RegisterValue> Instruction::getResults() const {
  return {const_cast<RegisterValue*>(results.data()), destinationRegisterCount};
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

void Instruction::supplyData(uint64_t address, const RegisterValue& data) {
  for (size_t i = 0; i < memoryAddresses_.size(); i++) {
    if (memoryAddresses_[i].vaddr == address && !memoryData_[i]) {
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

bool Instruction::isStoreAddress() const {
  return insnTypeMetadata & isStoreAddrMask;
}

bool Instruction::isStoreData() const {
  return insnTypeMetadata & isStoreDataMask;
}

bool Instruction::isLoad() const { return insnTypeMetadata & isLoadMask; }

bool Instruction::isBranch() const { return insnTypeMetadata & isBranchMask; }

bool Instruction::isAtomic() const { return insnTypeMetadata & isAtomicMask; }

bool Instruction::isAcquire() const { return insnTypeMetadata & isAcquireMask; }

bool Instruction::isRelease() const { return insnTypeMetadata & isReleaseMask; }

bool Instruction::isLoadReserved() const {
  return insnTypeMetadata & isLoadRsrvdMask;
}

bool Instruction::isStoreCond() const {
  return insnTypeMetadata & isStoreCondMask;
}

uint16_t Instruction::getGroup() const {
  // Use identifiers to decide instruction group
  // Set base
  uint16_t base = InstructionGroups::INT;
  if (insnTypeMetadata & isScalarDataMask)
    base = InstructionGroups::SCALAR;
  else if (insnTypeMetadata & isVectorDataMask)
    base = InstructionGroups::VECTOR;
  else if (insnTypeMetadata & isSVEDataMask)
    base = InstructionGroups::SVE;
  else if (insnTypeMetadata & isSMEDataMask)
    base = InstructionGroups::SME;

  if (isLoad()) return base + 10;
  if (isStoreAddress()) return base + 11;
  if (isStoreData()) return base + 12;
  if (isBranch()) return InstructionGroups::BRANCH;
  if (insnTypeMetadata & isPredicateMask) return InstructionGroups::PREDICATE;
  if (insnTypeMetadata & isDivOrSqrtMask) return base + 9;
  if (insnTypeMetadata & isMultiplyMask) return base + 8;
  if (insnTypeMetadata & isConvertMask) return base + 7;
  if (insnTypeMetadata & isCompareMask) return base + 6;
  if (insnTypeMetadata & isLogicalMask) {
    if (insnTypeMetadata & isNoShiftMask) return base + 5;
    return base + 4;
  }
  if (insnTypeMetadata & isNoShiftMask) return base + 3;
  return base + 2;  // Default return is {Data type}_SIMPLE_ARTH
}

void Instruction::setExecutionInfo(const ExecutionInfo& info) {
  if (isLoad() || isStoreAddress()) {
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

const InstructionMetadata& Instruction::getMetadata() const { return metadata; }

const Architecture& Instruction::getArchitecture() const {
  return architecture_;
}

void Instruction::updateCondStoreResult(const bool success) {
  assert((insnTypeMetadata & isStoreCondMask) &&
         "[SimEng:Instruction] Attempted to update the result register of a "
         "non-conditional-store instruction.");
  RegisterValue result = {(uint64_t)0 | !success, 8};
  results[0] = result;
}

/** Extend `value` according to `extendType`, and left-shift the result by
 * `shift` */
uint64_t Instruction::extendValue(uint64_t value, uint8_t extendType,
                                  uint8_t shift) const {
  if (extendType == ARM64_EXT_INVALID && shift == 0) {
    // Special case: an invalid shift type with a shift amount of 0 implies an
    // identity operation
    return value;
  }

  uint64_t extended;
  switch (extendType) {
    case ARM64_EXT_UXTB:
      extended = static_cast<uint8_t>(value);
      break;
    case ARM64_EXT_UXTH:
      extended = static_cast<uint16_t>(value);
      break;
    case ARM64_EXT_UXTW:
      extended = static_cast<uint32_t>(value);
      break;
    case ARM64_EXT_UXTX:
      extended = value;
      break;
    case ARM64_EXT_SXTB:
      extended = static_cast<int8_t>(value);
      break;
    case ARM64_EXT_SXTH:
      extended = static_cast<int16_t>(value);
      break;
    case ARM64_EXT_SXTW:
      extended = static_cast<int32_t>(value);
      break;
    case ARM64_EXT_SXTX:
      extended = value;
      break;
    default:
      assert(false && "Invalid extension type");
      return 0;
  }

  return extended << shift;
}

/** Extend `value` using extension/shifting rules defined in `op`. */
uint64_t Instruction::extendOffset(uint64_t value,
                                   const cs_arm64_op& op) const {
  if (op.ext == 0) {
    if (op.shift.value == 0) {
      return value;
    }
    if (op.shift.type == 1) {
      return extendValue(value, ARM64_EXT_UXTX, op.shift.value);
    }
  }
  return extendValue(value, op.ext, op.shift.value);
}

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng
