#include "ExecuteUnit.hh"

#include <cstring>

namespace simeng {
namespace outoforder {

ExecuteUnit::ExecuteUnit(
    PipelineBuffer<std::shared_ptr<Instruction>>& fromIssue,
    PipelineBuffer<std::shared_ptr<Instruction>>& toWriteback,
    DispatchIssueUnit& dispatchIssueUnit, LoadStoreQueue& lsq,
    BranchPredictor& predictor)
    : fromIssueBuffer(fromIssue),
      toWritebackBuffer(toWriteback),
      dispatchIssueUnit(dispatchIssueUnit),
      lsq(lsq),
      predictor(predictor) {}

void ExecuteUnit::tick() {
  tickCounter++;
  shouldFlush_ = false;

  auto& uop = fromIssueBuffer.getHeadSlots()[0];
  if (uop != nullptr) {
    if (!uop->isFlushed()) {
      // TODO: Retrieve latency from the instruction
      const unsigned int latency = 2;

      if (latency == 1 && pipeline.size() == 0) {
        // Pipeline is empty and insn will execute this cycle; bypass
        execute(uop);
      } else {
        // Add insn to pipeline
        pipeline.push({uop, tickCounter + latency - 1});
      }
    }
    fromIssueBuffer.getHeadSlots()[0] = nullptr;
  }

  if (pipeline.size() == 0) {
    return;
  }

  // Pop flushed instructions from the pipeline until a non-flushed instruction
  // is found. If the pipeline ends up empty, return early.
  while (pipeline.front().insn->isFlushed()) {
    pipeline.pop();
    if (pipeline.size() == 0) {
      return;
    }
  }

  auto& head = pipeline.front();
  if (head.readyAt <= tickCounter) {
    execute(head.insn);
    pipeline.pop();
  }
}

void ExecuteUnit::execute(std::shared_ptr<Instruction>& uop) {
  if (uop->isLoad()) {
    uop->generateAddresses();
    lsq.startLoad(uop);
  } else if (uop->isStore()) {
    uop->generateAddresses();
  }

  uop->execute();
  if (uop->exceptionEncountered()) {
    // Exception; don't forward results, don't pass uop forward
    return;
  }

  if (uop->isBranch()) {
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

  toWritebackBuffer.getTailSlots()[0] = uop;
}

bool ExecuteUnit::shouldFlush() const { return shouldFlush_; }
uint64_t ExecuteUnit::getFlushAddress() const { return pc; }
uint64_t ExecuteUnit::getFlushSeqId() const { return flushAfter; }

}  // namespace outoforder
}  // namespace simeng
