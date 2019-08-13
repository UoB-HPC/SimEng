#include "simeng/arch/aarch64/Instruction.hh"

#include <algorithm>
#include <cassert>
#include <vector>

#include "InstructionMetadata.hh"

namespace simeng {
namespace arch {
namespace aarch64 {

const Register Instruction::ZERO_REGISTER = {RegisterType::GENERAL,
                                             (uint16_t)-1};

Instruction::Instruction(const InstructionMetadata& metadata, uint8_t latency,
                         uint8_t stallCycles)
    : metadata(metadata) {
  latency_ = latency;
  stallCycles_ = stallCycles;

  decode();
}

InstructionException Instruction::getException() const { return exception; }

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

void Instruction::supplyOperand(const Register& reg,
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

void Instruction::supplyData(uint64_t address, const RegisterValue& data) {
  for (size_t i = 0; i < memoryAddresses.size(); i++) {
    if (memoryAddresses[i].address == address && !memoryData[i]) {
      if (!data) {
        // Raise exception for failed read
        // TODO: Move this logic to caller and distinguish between different
        // memory faults (e.g. bus error, page fault, seg fault)
        exception = InstructionException::DataAbort;
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

bool Instruction::isStore() const { return isStore_; }
bool Instruction::isLoad() const { return isLoad_; }
bool Instruction::isBranch() const { return isBranch_; }

void Instruction::setMemoryAddresses(
    const std::initializer_list<MemoryAccessTarget>& addresses) {
  // memoryData = std::vector<RegisterValue>(addresses.size());
  memoryData.set(addresses.size(), {});
  memoryAddresses = addresses;
  dataPending_ = addresses.size();
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

uint16_t Instruction::getGroup() const {
  if (isBranch()) {
    return InstructionGroups::BRANCH;
  }
  if (isLoad()) {
    return InstructionGroups::LOAD;
  }
  if (isStore()) {
    return InstructionGroups::STORE;
  }

  if (isASIMD_) {
    return InstructionGroups::ASIMD;
  }
  return InstructionGroups::ARITHMETIC;
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

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng
