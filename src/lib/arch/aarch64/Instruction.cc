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

void Instruction::setSourceRegisters(const std::vector<Register>& registers) {
  assert(registers.size() <= MAX_SOURCE_REGISTERS &&
         "Exceeded maximum source registers for an AArch64 instruction");

  sourceRegisterCount = registers.size();
  operandsPending = registers.size();

  for (size_t i = 0; i < registers.size(); i++) {
    auto reg = registers[i];
    if (reg == Instruction::ZERO_REGISTER) {
      // Any zero-register references should be marked as ready, and
      //  the corresponding operand value zeroed
      operands[i] = RegisterValue(0, 8);
      operandsPending--;
    }
    sourceRegisters[i] = reg;
  }
}
void Instruction::setDestinationRegisters(
    const std::vector<Register>& registers) {
  assert(registers.size() <= MAX_DESTINATION_REGISTERS &&
         "Exceeded maximum destination registers for an AArch64 instruction");
  destinationRegisterCount = registers.size();
  std::copy(registers.begin(), registers.end(), destinationRegisters.begin());
}

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

void Instruction::supplyData(uint64_t address, const RegisterValue& data) {
  for (size_t i = 0; i < memoryAddresses.size(); i++) {
    if (memoryAddresses[i].address == address && !memoryData[i]) {
      if (!data) {
        // Raise exception for failed read
        // TODO: Move this logic to caller and distinguish between different
        // memory faults (e.g. bus error, page fault, seg fault)
        exception_ = InstructionException::DataAbort;
        exceptionEncountered_ = true;
        memoryData[i] = RegisterValue(0, memoryAddresses[i].size);
      } else {
        memoryData[i] = data;
      }
      dataPending_--;
      return;
    }
  }
}

span<const RegisterValue> Instruction::getData() const {
  return {memoryData.data(), memoryData.size()};
}

bool Instruction::canExecute() const { return (operandsPending == 0); }

const span<RegisterValue> Instruction::getResults() const {
  return {const_cast<RegisterValue*>(results.data()), destinationRegisterCount};
}

bool Instruction::isStoreAddress() const { return isStoreAddress_; }
bool Instruction::isStoreData() const { return isStoreData_; }
bool Instruction::isLoad() const { return isLoad_; }
bool Instruction::isBranch() const { return isBranch_; }

void Instruction::setMemoryAddresses(
    const std::vector<MemoryAccessTarget>& addresses) {
  memoryData.resize(addresses.size());
  memoryAddresses = addresses;
  dataPending_ = addresses.size();
}

void Instruction::setMemoryAddresses(
    std::vector<MemoryAccessTarget>&& addresses) {
  dataPending_ = addresses.size();
  memoryData.resize(addresses.size());
  memoryAddresses = std::move(addresses);
}

span<const MemoryAccessTarget> Instruction::getGeneratedAddresses() const {
  return {memoryAddresses.data(), memoryAddresses.size()};
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

uint64_t Instruction::getKnownTarget() const { return knownTarget_; }

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

  if (isPredicate_) return InstructionGroups::PREDICATE;
  if (isLoad_) return base + 10;
  if (isStoreAddress_) return base + 11;
  if (isStoreData_) return base + 12;
  if (isBranch_) return InstructionGroups::BRANCH;
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
const std::vector<uint8_t>& Instruction::getSupportedPorts() {
  if (supportedPorts_.size() == 0) {
    exception_ = InstructionException::NoAvailablePort;
    exceptionEncountered_ = true;
  }
  return supportedPorts_;
}

const InstructionMetadata& Instruction::getMetadata() const { return metadata; }

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

/** Retrieve the producer group this instruction belongs to. */
uint16_t Instruction::getProducerGroup() const {
  if (isPredicate_) {
    if (isLoad_)
      return ProducerGroups::PRED_LOAD;
    else if (isStoreAddress_ || isStoreData_)
      return ProducerGroups::PRED_STORE;
    else
      return ProducerGroups::PRED_OP;
  } else if (isScalarData_ || isVectorData_ || isSVEData_) {
    if (isLoad_)
      return ProducerGroups::SIMD_FP_SVE_LOAD;
    else if (isStoreAddress_ || isStoreData_)
      return ProducerGroups::SIMD_FP_SVE_STORE;
    else
      return ProducerGroups::SIMD_FP_SVE_OP;
  } else {
    // Is INT
    if (isLoad_)
      return ProducerGroups::INT_LOAD;
    else if (isStoreAddress_ || isStoreData_)
      return ProducerGroups::INT_STORE;
    else
      return ProducerGroups::INT_OP;
  }

  return ProducerGroups::DEFAULT;
}

/** Retrieve the consumer group this instruction belongs to. */
uint16_t Instruction::getConsumerGroup() const {
  const span<Register>& registers = Instruction::getDestinationRegisters();

  if (isPredicate_) {
    if (isLoad_)
      return ConsumerGroups::PRED_LOAD;
    else if (isStoreAddress_ || isStoreData_)
      return ConsumerGroups::PRED_STORE;
    else {
      for (int i = 0; i < registers.size(); i++) {
        if (registers[i].type == RegisterType::NZCV)
          return ConsumerGroups::PRED_OP_NZCV;
      }
      return ConsumerGroups::PRED_OP;
    }
  } else if (isScalarData_ || isVectorData_ || isSVEData_) {
    if (isLoad_)
      return ConsumerGroups::SIMD_FP_SVE_LOAD;
    else if (isStoreAddress_ || isStoreData_)
      return ConsumerGroups::SIMD_FP_SVE_STORE;
    else if (isSVEData_ && isCompare_) {
      for (int i = 0; i < registers.size(); i++) {
        if (registers[i].type == RegisterType::NZCV)
          return ConsumerGroups::SVE_CMP_NZCV;
        if (registers[i].type == RegisterType::PREDICATE)
          return ConsumerGroups::SVE_CMP_PR;
      }
    } else {
      for (int i = 0; i < registers.size(); i++) {
        if (registers[i].type == RegisterType::NZCV)
          return ConsumerGroups::SIMD_FP_SVE_OP_NZCV;
      }
      return ConsumerGroups::SIMD_FP_SVE_OP;
    }
  } else {
    // Is INT
    if (isLoad_)
      return ConsumerGroups::INT_LOAD;
    else if (isStoreAddress_ || isStoreData_)
      return ConsumerGroups::INT_STORE;
    else {
      for (int i = 0; i < registers.size(); i++) {
        if (registers[i].type == RegisterType::NZCV)
          return ConsumerGroups::INT_OP_NZCV;
      }
      return ConsumerGroups::INT_OP;
    }
  }

  return ConsumerGroups::DEFAULT;
}

/** Check if producer is allowed to forward its result to the consumer. */
int8_t Instruction::canForward(uint16_t producer, uint16_t consumer) const {
  std::vector<std::pair<uint16_t, uint8_t>> forwardings =
      groupForwardings_.at(producer);
  for (int i = 0; i < forwardings.size(); i++) {
    if (std::get<0>(forwardings[i]) == consumer)
      return std::get<1>(forwardings[i]);
  }
  // As result is typically latency, a result of -1 means that a forwarding is
  // not permitted. DEAFULT falls into this catagory.
  return -1;
}

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng
