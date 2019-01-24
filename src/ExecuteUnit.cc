#include "ExecuteUnit.hh"

#include <iostream>
#include <cstring>

namespace simeng {

ExecuteUnit::ExecuteUnit(PipelineBuffer<std::shared_ptr<Instruction>>& fromDecode, PipelineBuffer<std::shared_ptr<Instruction>>& toWriteback, DecodeUnit& decodeUnit, char* memory) : fromDecodeBuffer(fromDecode), toWritebackBuffer(toWriteback), decodeUnit(decodeUnit), memory(memory) {}

void ExecuteUnit::tick() {

  shouldFlush_ = false;

  auto uop = fromDecodeBuffer.getHeadSlots()[0];
  if (uop == nullptr) {
    decodeUnit.forwardOperands({}, {});

    auto out = toWritebackBuffer.getTailSlots();
    out[0] = nullptr;

    return;
  }
  // std::cout << "Execute: continuing" << std::endl;
  
  if (uop->isLoad()) {
    auto addresses = uop->generateAddresses();
    for (auto const& request : addresses) {
      // Pointer manipulation to generate a RegisterValue from an arbitrary
      // memory address
      auto buffer = malloc(request.second);
      memcpy(buffer, memory + request.first, request.second);

      auto ptr = std::shared_ptr<uint8_t>((uint8_t*)buffer, free);
      auto data = RegisterValue(ptr);

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
      memcpy(address, data[i].getAsVector<void>(), request.second);
    }
  } else if (uop->isBranch() && uop->wasBranchMispredicted()) {
    pc = uop->getBranchAddress();
    shouldFlush_ = true;
  }

  // Operand forwarding; allows a dependent uop to execute next cycle
  decodeUnit.forwardOperands(uop->getDestinationRegisters(), uop->getResults());

  auto out = toWritebackBuffer.getTailSlots();
  out[0] = uop;

  fromDecodeBuffer.getHeadSlots()[0] = nullptr;
}

std::tuple<bool, uint64_t> ExecuteUnit::shouldFlush() const {
  return {shouldFlush_, pc};
}

} // namespace simeng
