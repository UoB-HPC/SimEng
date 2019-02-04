#include "ExecuteUnit.hh"

#include <cstring>

namespace simeng {
namespace outoforder {

ExecuteUnit::ExecuteUnit(
    PipelineBuffer<std::shared_ptr<Instruction>>& fromDecode,
    PipelineBuffer<std::shared_ptr<Instruction>>& toWriteback,
    DispatchIssueUnit& dispatchIssueUnit, BranchPredictor& predictor,
    char* memory)
    : fromDecodeBuffer(fromDecode),
      toWritebackBuffer(toWriteback),
      dispatchIssueUnit(dispatchIssueUnit),
      predictor(predictor),
      memory(memory) {}

void ExecuteUnit::tick() {
  shouldFlush_ = false;

  auto uop = fromDecodeBuffer.getHeadSlots()[0];
  if (uop == nullptr) {
    // NOP
    // Forward a lack of results to trigger reading other operands.
    dispatchIssueUnit.forwardOperands({}, {});
    return;
  }

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
  } else if (uop->isBranch()) {
    pc = uop->getBranchAddress();

    // Update branch predictor with branch results
    predictor.update(uop->getInstructionAddress(), uop->wasBranchTaken(), pc);

    if (uop->wasBranchMispredicted()) {
      // Misprediction; flush the pipeline
      shouldFlush_ = true;
      flushAfter = uop->getSequenceId();
    }
  }

  // Operand forwarding; allows a dependent uop to execute next cycle
  dispatchIssueUnit.forwardOperands(uop->getDestinationRegisters(),
                                    uop->getResults());

  auto out = toWritebackBuffer.getTailSlots();
  out[0] = uop;

  fromDecodeBuffer.getHeadSlots()[0] = nullptr;
}

bool ExecuteUnit::shouldFlush() const { return shouldFlush_; }
uint64_t ExecuteUnit::getFlushAddress() const { return pc; }
uint64_t ExecuteUnit::getFlushSeqId() const { return flushAfter; }

}  // namespace outoforder
}  // namespace simeng
