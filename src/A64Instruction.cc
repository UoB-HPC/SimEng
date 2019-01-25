#include "A64Instruction.hh"

#include <algorithm>
#include <iostream>
#include <vector>

namespace simeng {

const Register A64Instruction::ZERO_REGISTER = {A64RegisterType::GENERAL,
                                                (uint16_t)-1};

A64Instruction::A64Instruction(uint32_t insn) { decodeA64(insn); }

void A64Instruction::setInstructionAddress(uint64_t address) {
  instructionAddress = address;
}
void A64Instruction::setBranchPrediction(BranchPrediction prediction) {
  this->prediction = prediction;
}

InstructionException A64Instruction::getException() const {
  return static_cast<InstructionException>(exception);
}

void A64Instruction::setSourceRegisters(
    const std::vector<Register>& registers) {
  operands = std::vector<RegisterValue>(registers.size());
  operandsPending = registers.size();

  for (size_t i = 0; i < registers.size(); i++) {
    auto reg = registers[i];
    if (reg == A64Instruction::ZERO_REGISTER) {
      // Any zero-register references should be marked as ready, and
      //  the corresponding operand value zeroed
      operands[i] = RegisterValue(0, 8);
      operandsPending--;
    }
  }
  sourceRegisters = registers;
}
void A64Instruction::setDestinationRegisters(
    const std::vector<Register>& registers) {
  destinationRegisters = registers;
  results = std::vector<A64Result>(destinationRegisters.size());
}

const std::vector<Register>& A64Instruction::getOperandRegisters() const {
  return sourceRegisters;
}
const std::vector<Register>& A64Instruction::getDestinationRegisters() const {
  return destinationRegisters;
}
bool A64Instruction::isOperandReady(int index) const {
  return static_cast<bool>(operands[index]);
}

void A64Instruction::rename(const std::vector<Register>& destinations,
                            const std::vector<Register>& operands) {
  destinationRegisters = destinations;
  sourceRegisters = operands;
}

void A64Instruction::supplyOperand(const Register& reg,
                                   const RegisterValue& value) {
  assert(!canExecute() &&
         "Attempted to provide an operand to a ready-to-execute instruction");

  // Iterate over operand registers, and copy value if the provided register
  // matches
  for (size_t i = 0; i < sourceRegisters.size(); i++) {
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

bool A64Instruction::canCommit() const { return executed; }

std::vector<RegisterValue> A64Instruction::getResults() const {
  // Map from internal result format to RegisterValue vector
  auto out = std::vector<RegisterValue>(results.size());
  std::transform(results.begin(), results.end(), out.begin(),
                 [](const A64Result& item) { return item.value; });
  return out;
}

bool A64Instruction::isStore() const { return isStore_; }
bool A64Instruction::isLoad() const { return isLoad_; }
bool A64Instruction::isBranch() const { return isBranch_; }

uint64_t A64Instruction::getInstructionAddress() const { return instructionAddress; }

void A64Instruction::setMemoryAddresses(
    const std::vector<std::pair<uint64_t, uint8_t>>& addresses) {
  memoryData = std::vector<RegisterValue>(addresses.size());
  memoryAddresses = addresses;
}

std::vector<std::pair<uint64_t, uint8_t>>
A64Instruction::getGeneratedAddresses() const {
  return memoryAddresses;
}

std::tuple<bool, uint64_t> A64Instruction::checkEarlyBranchMisprediction() const {
  assert(!executed && "Early branch misprediction check shouldn't be called after execution");

  if (!isBranch()) {
    // Instruction isn't a branch; if predicted as taken, it will require a flush
    return {prediction.taken, instructionAddress + 4};
  }

  // Not enough information to determine this was a misprediction
  return {false, 0};
}

bool A64Instruction::wasBranchMispredicted() const {
  assert(executed && "Branch misprediction check requires instruction to have executed");

  // Flag as mispredicted if taken state was wrongly predicted, or taken and predicted target is wrong
  return (branchTaken != prediction.taken || (branchTaken && prediction.target != branchAddress));
}
uint64_t A64Instruction::getBranchAddress() const { return branchAddress; }
bool A64Instruction::wasBranchTaken() const { return branchTaken; }

}  // namespace simeng
