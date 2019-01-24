#include "WritebackUnit.hh"

#include <iostream>

namespace simeng {

WritebackUnit::WritebackUnit(PipelineBuffer<std::shared_ptr<Instruction>>& fromExecute, RegisterFile& registerFile) : fromExecuteBuffer(fromExecute), registerFile(registerFile) {}

void WritebackUnit::tick() {
    
  std::cout << "Writeback: tick()" << std::endl;

  auto uop = fromExecuteBuffer.getHeadSlots()[0];
  if (uop == nullptr) {
    std::cout << "Writeback: nop" << std::endl;
    return;
  }
  std::cout << "Writeback: continuing" << std::endl;

  auto results = uop->getResults();
  auto destinations = uop->getDestinationRegisters();
  for (size_t i = 0; i < results.size(); i++) {
    auto reg = destinations[i];
    registerFile.set(reg, results[i]);
  }

  fromExecuteBuffer.getHeadSlots()[0] = nullptr;
}

} // namespace simeng
