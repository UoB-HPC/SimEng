#include "A64Instruction.hh"

#include <algorithm>
#include <cassert>
#include <vector>

#include "A64InstructionMetadata.hh"

namespace simeng {

const Register A64Instruction::ZERO_REGISTER = {A64RegisterType::GENERAL,
                                                (uint16_t)-1};

A64Instruction::A64Instruction(const A64InstructionMetadata& metadata)
    : metadata(metadata) {
  decode();
}

A64InstructionException A64Instruction::getException() const {
  return exception;
}

void A64Instruction::setSourceRegisters(
    const std::vector<Register>& registers) {
  assert(registers.size() <= MAX_SOURCE_REGISTERS &&
         "Exceeded maximum source registers for an A64 instruction");

  sourceRegisterCount = registers.size();
  operandsPending = registers.size();

  for (size_t i = 0; i < registers.size(); i++) {
    auto reg = registers[i];
    if (reg == A64Instruction::ZERO_REGISTER) {
      // Any zero-register references should be marked as ready, and
      //  the corresponding operand value zeroed
      operands[i] = RegisterValue(0, 8);
      operandsPending--;
    }
    sourceRegisters[i] = reg;
  }
}
void A64Instruction::setDestinationRegisters(
    const std::vector<Register>& registers) {
  assert(registers.size() <= MAX_DESTINATION_REGISTERS &&
         "Exceeded maximum destination registers for an A64 instruction");
  destinationRegisterCount = registers.size();
  std::copy(registers.begin(), registers.end(), destinationRegisters.begin());
}

const span<Register> A64Instruction::getOperandRegisters() const {
  return {const_cast<Register*>(sourceRegisters.data()), sourceRegisterCount};
}
const span<Register> A64Instruction::getDestinationRegisters() const {
  return {const_cast<Register*>(destinationRegisters.data()),
          destinationRegisterCount};
}
bool A64Instruction::isOperandReady(int index) const {
  return static_cast<bool>(operands[index]);
}

void A64Instruction::renameSource(uint8_t i, Register renamed) {
  sourceRegisters[i] = renamed;
}
void A64Instruction::renameDestination(uint8_t i, Register renamed) {
  destinationRegisters[i] = renamed;
}

void A64Instruction::supplyOperand(const Register& reg,
                                   const RegisterValue& value) {
  assert(!canExecute() &&
         "Attempted to provide an operand to a ready-to-execute instruction");
  assert(value.size() > 0 &&
         "Attempted to provide an uninitialised RegisterValue");

  // Iterate over operand registers, and copy value if the provided register
  // matches
  for (size_t i = 0; i < sourceRegisterCount; i++) {
    if (sourceRegisters[i] == reg && !isOperandReady(i)) {
      operands[i] = value;
      operandsPending--;
      break;
    }
  }
}

void A64Instruction::supplyData(uint64_t address, const RegisterValue& data) {
  for (size_t i = 0; i < memoryAddresses.size(); i++) {
    if (memoryAddresses[i].first == address && !memoryData[i]) {
      memoryData[i] = data;
      dataPending_--;
      return;
    }
  }
}

span<const RegisterValue> A64Instruction::getData() const {
  return {memoryData.data(), memoryData.size()};
}

bool A64Instruction::canExecute() const { return (operandsPending == 0); }

const span<RegisterValue> A64Instruction::getResults() const {
  return {const_cast<RegisterValue*>(results.data()), destinationRegisterCount};
}

bool A64Instruction::isStore() const { return isStore_; }
bool A64Instruction::isLoad() const { return isLoad_; }
bool A64Instruction::isBranch() const { return isBranch_; }

void A64Instruction::setMemoryAddresses(
    const std::initializer_list<std::pair<uint64_t, uint8_t>>& addresses) {
  memoryData = std::vector<RegisterValue>(addresses.size());
  memoryAddresses = addresses;
  dataPending_ = addresses.size();
}

span<const std::pair<uint64_t, uint8_t>> A64Instruction::getGeneratedAddresses()
    const {
  return {memoryAddresses.data(), memoryAddresses.size()};
}

std::tuple<bool, uint64_t> A64Instruction::checkEarlyBranchMisprediction()
    const {
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

uint16_t A64Instruction::getGroup() const {
  if (isBranch()) {
    return A64InstructionGroups::BRANCH;
  }
  if (isLoad()) {
    return A64InstructionGroups::LOAD;
  }
  if (isStore()) {
    return A64InstructionGroups::STORE;
  }

  return A64InstructionGroups::ARITHMETIC;
}

const A64InstructionMetadata& A64Instruction::getMetadata() const {
  return metadata;
}

/** Extend `value` according to `extendType`, and left-shift the result by
 * `shift` */
uint64_t A64Instruction::extendValue(uint64_t value, uint8_t extendType,
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
uint64_t A64Instruction::extendOffset(uint64_t value,
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

}  // namespace simeng
