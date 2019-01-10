#include "A64Instruction.hh"

#include <algorithm>
#include <iostream>
#include <vector>

namespace simeng {

const Register A64Instruction::ZERO_REGISTER = {A64RegisterType::GENERAL,
                                                (uint16_t)-1};
std::unordered_map<uint32_t, A64Instruction> A64Instruction::decodeCache;

std::vector<std::shared_ptr<Instruction>> A64Instruction::decode(
    void *insnPtr, uint64_t instructionAddress) {
  // Dereference the instruction pointer and to obtain the instruction word
  uint32_t insn = *static_cast<uint32_t *>(insnPtr);

  std::shared_ptr<A64Instruction> uop;
  if (decodeCache.count(insn)) {
    // A decoding for this already exists, duplicate and return that
    uop = std::make_shared<A64Instruction>(decodeCache[insn]);
  } else {
    // Generate a fresh decoding, and add to cache
    auto decoded = A64Instruction(insn, instructionAddress);
    decodeCache[insn] = decoded;
    uop = std::make_shared<A64Instruction>(decoded);
  }

  // Bundle into a macro-op
  return {uop};
}

A64Instruction::A64Instruction(uint32_t insn, uint64_t instructionAddress)
    : instructionAddress(instructionAddress) {
  decodeA64(insn);
}

InstructionException A64Instruction::getException() { return exception; }

void A64Instruction::setSourceRegisters(
    const std::vector<Register> &registers) {
  operands = std::vector<A64Operand>(registers.size());
  operandsPending = registers.size();

  for (auto i = 0; i < registers.size(); i++) {
    auto reg = registers[i];
    if (reg == A64Instruction::ZERO_REGISTER) {
      // Any zero-register references should be marked as ready, and
      //  the corresponding operand value zeroed
      operands[i].value = RegisterValue(0, 8);
      operands[i].ready = true;
      operandsPending--;
    }
  }
  sourceRegisters = registers;
}
void A64Instruction::setDestinationRegisters(
    const std::vector<Register> &registers) {
  destinationRegisters = registers;
  results = std::vector<A64Result>(destinationRegisters.size());
}

const std::vector<Register> &A64Instruction::getOperandRegisters() {
  return sourceRegisters;
}
const std::vector<Register> &A64Instruction::getDestinationRegisters() {
  return destinationRegisters;
}
bool A64Instruction::isOperandReady(int index) { return operands[index].ready; }

void A64Instruction::rename(const std::vector<Register> &destinations,
                            const std::vector<Register> &operands) {
  destinationRegisters = destinations;
  sourceRegisters = operands;
}

void A64Instruction::supplyOperand(const Register &reg,
                                   const RegisterValue &value) {
  if (canExecute()) {
    // All source operands are already present
    return;
  }

  // Iterate over operand registers, and copy value if the provided register
  // matches
  for (auto i = 0; i < sourceRegisters.size(); i++) {
    if (sourceRegisters[i] == reg) {
      if (!operands[i].ready) {
        operands[i].value = value;
        operands[i].ready = true;
        operandsPending--;
      }
      break;
    }
  }
}

void A64Instruction::supplyData(uint64_t address, const RegisterValue &data) {
  for (int i = 0; i < memoryAddresses.size(); i++) {
    if (memoryAddresses[i].first != address) {
      continue;
    }

    memoryData[i] = data;
    return;
  }
}

std::vector<RegisterValue> A64Instruction::getData() { return memoryData; }

bool A64Instruction::canExecute() { return (operandsPending == 0); }

bool A64Instruction::canCommit() { return executed; }

std::vector<RegisterValue> A64Instruction::getResults() {
  // Map from internal result format to RegisterValue vector
  auto out = std::vector<RegisterValue>(results.size());
  std::transform(results.begin(), results.end(), out.begin(),
                 [](const A64Result &item) { return item.value; });
  return out;
}

bool A64Instruction::isStore() { return isStore_; }
bool A64Instruction::isLoad() { return isLoad_; }
bool A64Instruction::isBranch() { return isBranch_; }

void A64Instruction::setMemoryAddresses(
    const std::vector<std::pair<uint64_t, uint8_t>> &addresses) {
  memoryData = std::vector<RegisterValue>(addresses.size());
  memoryAddresses = addresses;
}

std::vector<std::pair<uint64_t, uint8_t>>
A64Instruction::getGeneratedAddresses() {
  return memoryAddresses;
}

bool A64Instruction::wasBranchMispredicted() {
  // TEMPORARY
  // Needs replacing once branch prediction is implemented
  return false;
}
uint64_t A64Instruction::getBranchAddress() { return branchAddress; }

}  // namespace simeng
