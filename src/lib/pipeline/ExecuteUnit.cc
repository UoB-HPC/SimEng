#include "ExecuteUnit.hh"

#include <cstring>

namespace simeng {
namespace pipeline {

ExecuteUnit::ExecuteUnit(
    PipelineBuffer<std::shared_ptr<Instruction>>& input,
    PipelineBuffer<std::shared_ptr<Instruction>>& output,
    std::function<void(span<Register>, span<RegisterValue>)> forwardOperands,
    std::function<void(const std::shared_ptr<Instruction>&)> handleLoad,
    std::function<void(const std::shared_ptr<Instruction>&)> handleStore,
    std::function<void(const std::shared_ptr<Instruction>&)> raiseException,
    BranchPredictor& predictor, bool pipelined)
    : input_(input),
      output_(output),
      forwardOperands_(forwardOperands),
      handleLoad_(handleLoad),
      handleStore_(handleStore),
      raiseException_(raiseException),
      predictor_(predictor),
      pipelined_(pipelined) {}

void ExecuteUnit::tick() {
  tickCounter_++;
  shouldFlush_ = false;

  if (stallUntil_ <= tickCounter_) {
    input_.stall(false);
    // Input isn't stalled; process instruction and add to pipeline

    auto& uop = input_.getHeadSlots()[0];
    if (uop != nullptr) {
      if (!uop->isFlushed()) {
        // Retrieve execution latency from the instruction
        auto latency = uop->getLatency();

        if (latency == 1 && pipeline_.size() == 0) {
          // Pipeline is empty and insn will execute this cycle; bypass
          execute(uop);
        } else {
          // Add insn to pipeline
          pipeline_.push({uop, tickCounter_ + latency - 1});

          // This instruction may take more than a single cycle; check for a
          // stall. For unpipelined units, the unit will stall for the full
          // instruction duration.
          auto stallCycles =
              pipelined_ ? uop->getStallCycles() : uop->getLatency();
          if (stallCycles > 1) {
            stallUntil_ = tickCounter_ + stallCycles - 1;
            input_.stall(true);
          }
        }
      }
      input_.getHeadSlots()[0] = nullptr;
    }
  }

  if (pipeline_.size() == 0) {
    return;
  }

  // Pop flushed instructions from the pipeline until a non-flushed instruction
  // is found. If the pipeline ends up empty, return early.
  while (pipeline_.front().insn->isFlushed()) {
    pipeline_.pop();
    if (pipeline_.size() == 0) {
      return;
    }
  }

  auto& head = pipeline_.front();
  if (head.readyAt <= tickCounter_) {
    execute(head.insn);
    pipeline_.pop();
  }
}

void ExecuteUnit::execute(std::shared_ptr<Instruction>& uop) {
  assert(uop->canExecute() &&
         "Attempted to execute an instruction before it was ready");

  if (uop->exceptionEncountered()) {
    // Exception encountered prior to execution
    // TODO: Identify whether this can be removed; executing an
    // exception-encountered uop would have to be guaranteed to be safe
    raiseException_(uop);
    return;
  }

  if (uop->isLoad()) {
    uop->generateAddresses();
    handleLoad_(uop);
    return;
  } else if (uop->isStore()) {
    uop->generateAddresses();
  }

  uop->execute();
  if (uop->exceptionEncountered()) {
    // Exception; don't forward results, don't pass uop forward
    raiseException_(uop);
    return;
  }

  if (uop->isStore()) {
    handleStore_(uop);
  } else if (uop->isBranch()) {
    pc_ = uop->getBranchAddress();

    // Update branch predictor with branch results
    predictor_.update(uop->getInstructionAddress(), uop->wasBranchTaken(), pc_);

    if (uop->wasBranchMispredicted()) {
      // Misprediction; flush the pipeline
      shouldFlush_ = true;
      flushAfter_ = uop->getSequenceId();
    }
  }

  // Operand forwarding; allows a dependent uop to execute next cycle
  forwardOperands_(uop->getDestinationRegisters(), uop->getResults());

  output_.getTailSlots()[0] = uop;
}

bool ExecuteUnit::shouldFlush() const { return shouldFlush_; }
uint64_t ExecuteUnit::getFlushAddress() const { return pc_; }
uint64_t ExecuteUnit::getFlushSeqId() const { return flushAfter_; }

}  // namespace pipeline
}  // namespace simeng
