#include "ExecuteUnit.hh"

#include <cstring>

namespace simeng {
namespace inorder {

ExecuteUnit::ExecuteUnit(
    PipelineBuffer<std::shared_ptr<Instruction>>& fromDecode,
    PipelineBuffer<std::shared_ptr<Instruction>>& toWriteback,
    std::function<void(span<Register>, span<RegisterValue>)> forwardOperands,
    BranchPredictor& predictor, char* memory)
    : fromDecodeBuffer(fromDecode),
      toWritebackBuffer(toWriteback),
      forwardOperands(forwardOperands),
      predictor(predictor),
      memory(memory) {}

void ExecuteUnit::tick() {
  shouldFlush_ = false;

  auto uop = fromDecodeBuffer.getHeadSlots()[0];
  if (uop == nullptr) {
    // NOP
    // Forward a lack of results to trigger reading other operands.
    forwardOperands({}, {});
    return;
  }

  if (uop->isLoad()) {
    auto addresses = uop->generateAddresses();
    for (auto const& request : addresses) {
      // Copy the data at the requested memory address into a RegisterValue
      auto data = RegisterValue(memory + request.first, request.second);

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

    // Update branch predictor with branch results
    predictor.update(uop->getInstructionAddress(), uop->wasBranchTaken(), pc);

    if (uop->wasBranchMispredicted()) {
      // Misprediction; flush the pipeline
      shouldFlush_ = true;
    }
  }

  // Operand forwarding; allows a dependent uop to execute next cycle
  forwardOperands(uop->getDestinationRegisters(), uop->getResults());

  auto out = toWritebackBuffer.getTailSlots();
  out[0] = uop;

  fromDecodeBuffer.getHeadSlots()[0] = nullptr;
}

bool ExecuteUnit::shouldFlush() const { return shouldFlush_; }
uint64_t ExecuteUnit::getFlushAddress() const { return pc; }

}  // namespace inorder
}  // namespace simeng
