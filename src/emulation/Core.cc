#include "Core.hh"

#include <cstring>

namespace simeng {
namespace emulation {

Core::Core(const char* insnPtr, uint64_t programByteLength,
           const Architecture& isa, char* memory)
    : memory(memory),
      insnPtr(insnPtr),
      programByteLength(programByteLength),
      isa(isa),
      registerFileSet(isa.getRegisterFileStructures()) {}

void Core::tick() {
  if (pc >= programByteLength) {
    hasHalted_ = true;
    return;
  }

  // Fetch
  auto bytesRead = isa.predecode(insnPtr + pc, 4, pc, {false, 0}, macroOp);

  pc += bytesRead;

  // Decode
  auto uop = macroOp[0];

  // Issue
  auto registers = uop->getOperandRegisters();
  for (size_t i = 0; i < registers.size(); i++) {
    auto reg = registers[i];
    if (!uop->isOperandReady(i)) {
      uop->supplyOperand(reg, registerFileSet.get(reg));
    }
  }

  // Execute
  if (uop->isLoad()) {
    auto addresses = uop->generateAddresses();
    for (auto const& request : addresses) {
      // Copy the data at the requested memory address into a RegisterValue
      auto data = simeng::RegisterValue(memory + request.first, request.second);

      uop->supplyData(request.first, data);
    }
  } else if (uop->isStore()) {
    uop->generateAddresses();
  }
  uop->execute();

  if (uop->isStore()) {
    auto addresses = uop->getGeneratedAddresses();
    auto data = uop->getData();
    for (size_t i = 0; i < addresses.size(); i++) {
      auto request = addresses[i];

      // Copy data to memory
      auto address = memory + request.first;
      memcpy(address, data[i].getAsVector<char>(), request.second);
    }
  } else if (uop->isBranch()) {
    pc = uop->getBranchAddress();
  }

  // Writeback
  auto results = uop->getResults();
  auto destinations = uop->getDestinationRegisters();
  for (size_t i = 0; i < results.size(); i++) {
    auto reg = destinations[i];
    registerFileSet.set(reg, results[i]);
  }
}

bool Core::hasHalted() const { return hasHalted_; }

std::map<std::string, std::string> Core::getStats() const { return {}; };

}  // namespace emulation
}  // namespace simeng
