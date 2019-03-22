#include "A64IllegalInstruction.hh"

namespace simeng {
A64IllegalInstruction::A64IllegalInstruction(uint64_t encoding)
    : encoding_(encoding) {
  exceptionEncountered_ = true;
}

A64InstructionException A64IllegalInstruction::getException() const {
  return A64InstructionException::EncodingUnallocated;
}

const span<Register> A64IllegalInstruction::getOperandRegisters() const {
  return {nullptr, 0};
}
const span<Register> A64IllegalInstruction::getDestinationRegisters() const {
  return {nullptr, 0};
}
bool A64IllegalInstruction::isOperandReady(int index) const { return true; }
void A64IllegalInstruction::renameSource(uint8_t i, Register renamed) {}
void A64IllegalInstruction::renameDestination(uint8_t i, Register renamed) {}
void A64IllegalInstruction::supplyOperand(const Register& reg,
                                          const RegisterValue& value) {}
bool A64IllegalInstruction::canExecute() const { return true; }
void A64IllegalInstruction::execute() {}

const span<RegisterValue> A64IllegalInstruction::getResults() const {
  return {nullptr, 0};
}

std::vector<std::pair<uint64_t, uint8_t>>
A64IllegalInstruction::generateAddresses() {
  return {};
}

std::vector<std::pair<uint64_t, uint8_t>>
A64IllegalInstruction::getGeneratedAddresses() const {
  return {};
}

void A64IllegalInstruction::supplyData(uint64_t address,
                                       const RegisterValue& data) {}

std::vector<RegisterValue> A64IllegalInstruction::getData() const { return {}; }

std::tuple<bool, uint64_t>
A64IllegalInstruction::checkEarlyBranchMisprediction() const {
  return {false, 0};
}

bool A64IllegalInstruction::isStore() const { return false; }
bool A64IllegalInstruction::isLoad() const { return false; }
bool A64IllegalInstruction::isBranch() const { return false; }

uint16_t A64IllegalInstruction::getGroup() const { return 0; }

}  // namespace simeng
