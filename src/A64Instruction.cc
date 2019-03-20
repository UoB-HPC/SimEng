#include "A64Instruction.hh"

#include <algorithm>
#include <cassert>
#include <vector>

namespace simeng {

const Register A64Instruction::ZERO_REGISTER = {A64RegisterType::GENERAL,
                                                (uint16_t)-1};

A64Instruction::A64Instruction(const A64InstructionMetadata& metadata)
    : metadata(metadata) {
  decode();
}

InstructionException A64Instruction::getException() const {
  return static_cast<InstructionException>(exception);
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

  // Iterate over operand registers, and copy value if the provided register
  // matches
  for (size_t i = 0; i < sourceRegisterCount; i++) {
    if (sourceRegisters[i] == reg) {
      operands[i] = value;
      operandsPending--;
      break;
    }
  }
}

void A64Instruction::supplyData(uint64_t address, const RegisterValue& data) {
  for (size_t i = 0; i < memoryAddresses.size(); i++) {
    if (memoryAddresses[i].first == address) {
      memoryData[i] = data;
      return;
    }
  }
}

std::vector<RegisterValue> A64Instruction::getData() const {
  return memoryData;
}

bool A64Instruction::canExecute() const { return (operandsPending == 0); }

const span<RegisterValue> A64Instruction::getResults() const {
  return {const_cast<RegisterValue*>(results.data()), destinationRegisterCount};
}

bool A64Instruction::isStore() const { return isStore_; }
bool A64Instruction::isLoad() const { return isLoad_; }
bool A64Instruction::isBranch() const { return isBranch_; }

void A64Instruction::setMemoryAddresses(
    const std::vector<std::pair<uint64_t, uint8_t>>& addresses) {
  memoryData = std::vector<RegisterValue>(addresses.size());
  memoryAddresses = addresses;
}

std::vector<std::pair<uint64_t, uint8_t>>
A64Instruction::getGeneratedAddresses() const {
  return memoryAddresses;
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

}  // namespace simeng
