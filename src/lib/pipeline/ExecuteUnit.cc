#include "simeng/pipeline/ExecuteUnit.hh"

#include <cstring>
#include <iostream>

namespace simeng {
namespace pipeline {

ExecuteUnit::ExecuteUnit(
    PipelineBuffer<std::shared_ptr<Instruction>>& input,
    PipelineBuffer<std::shared_ptr<Instruction>>& output,
    std::function<void(span<Register>, span<RegisterValue>)> forwardOperands,
    std::function<void(const std::shared_ptr<Instruction>&)> handleLoad,
    std::function<void(const std::shared_ptr<Instruction>&)> handleStore,
    std::function<void(const std::shared_ptr<Instruction>&)> raiseException,
    BranchPredictor& predictor, bool pipelined,
    const std::vector<uint16_t>& blockingGroups)
    : input_(input),
      output_(output),
      forwardOperands_(forwardOperands),
      handleLoad_(handleLoad),
      handleStore_(handleStore),
      raiseException_(raiseException),
      predictor_(predictor),
      pipelined_(pipelined),
      blockingGroups_(blockingGroups) {}

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
        cycles_++;
        // Block uop execution if appropriate
        if (std::find(blockingGroups_.begin(), blockingGroups_.end(),
                      uop->getGroup()) != blockingGroups_.end()) {
          if (operationsStalled_.size() == 0) {
            // Add uop to pipeline
            pipeline_.push_back({nullptr, tickCounter_ + latency - 1});
            pipeline_.back().insn = std::move(uop);
            operationsStalled_.push_back(pipeline_.back().insn);
          } else {
            // Stall execution start cycle
            operationsStalled_.push_back(nullptr);
            operationsStalled_.back() = std::move(uop);
          }
        } else if (latency == 1 && pipeline_.size() == 0) {
          // Pipeline is empty and insn will execute this cycle; bypass
          execute(uop);
        } else {
          // This instruction may take more than a single cycle; check for a
          // stall. For unpipelined units, the unit will stall for the full
          // instruction duration.
          auto stallCycles =
              pipelined_ ? uop->getStallCycles() : uop->getLatency();
          if (stallCycles > 1) {
            stallUntil_ = tickCounter_ + stallCycles - 1;
            input_.stall(true);
          }

          // Add insn to pipeline
          pipeline_.push_back({nullptr, tickCounter_ + latency - 1});
          pipeline_.back().insn = std::move(uop);
        }
      }
      input_.getHeadSlots()[0] = nullptr;
    }
  }

  if (pipeline_.size() == 0) {
    return;
  }

  auto& head = pipeline_.front();
  if (head.readyAt <= tickCounter_) {
    // Check if the completion of an operation would unblock
    // another stalled operation.
    if (std::find(blockingGroups_.begin(), blockingGroups_.end(),
                  head.insn->getGroup()) != blockingGroups_.end()) {
      operationsStalled_.pop_front();
      if (operationsStalled_.size() > 0) {
        // Add uop to pipeline
        auto& uop = operationsStalled_.front();
        pipeline_.push_back({nullptr, tickCounter_ + uop->getLatency() - 1});
        pipeline_.back().insn = std::move(uop);
        operationsStalled_.front() = pipeline_.back().insn;
      }
    }
    execute(head.insn);
    pipeline_.pop_front();
  }
}

void ExecuteUnit::execute(std::shared_ptr<Instruction>& uop) {
  assert(uop->canExecute() &&
         "Attempted to execute an instruction before it was ready");
  // std::cout << "Execute: " << uop->getSequenceId()
  //           << ":"
  // << uop->getInstructionId() << ":0x" << std::hex
  // << uop->getInstructionAddress() << std::dec << ":"
  // << uop->getMicroOpIndex() << std::endl;

  if (uop->exceptionEncountered()) {
    // Exception encountered prior to execution
    // TODO: Identify whether this can be removed; executing an
    // exception-encountered uop would have to be guaranteed to be safe
    raiseException_(uop);
    return;
  }
  // std::cout << "Execute 0x" << std::hex << uop->getInstructionAddress()
  //           << std::dec << std::endl;

  if (uop->isLoad()) {
    // std::cout << "\tinto load" << std::endl;
    uop->generateAddresses();
    if (uop->exceptionEncountered()) {
      // Exception; don't pass handle load function
      raiseException_(uop);
      return;
    }
    handleLoad_(uop);
    return;
  } else if (uop->isStoreAddress() || uop->isStoreData()) {
    if (uop->isStoreAddress()) {
      // std::cout << "\tinto str addr" << std::endl;
      uop->generateAddresses();
    }
    if (uop->isStoreData()) {
      // std::cout << "\tinto str data" << std::endl;
      uop->execute();
    }
    handleStore_(uop);
  } else {
    uop->execute();
  }

  if (uop->exceptionEncountered()) {
    // Exception; don't forward results, don't pass uop forward
    raiseException_(uop);
    return;
  }

  if (uop->isBranch()) {
    // std::cout << "\tinto branch: 0x" << std::hex << uop->getBranchAddress()
    //           << std::dec << std::endl;
    pc_ = uop->getBranchAddress();

    // Update branch predictor with branch results
    predictor_.update(uop, uop->wasBranchTaken(), pc_);

    // Update the branch instruction counter
    branchesExecuted_++;

    if (uop->wasBranchMispredicted()) {
      // Misprediction; flush the pipeline
      shouldFlush_ = true;
      // std::cout << "FLUSHED AT EXECUTE: 0x" << std::hex
      //           << uop->getInstructionAddress() << std::dec << std::endl;
      flushAfter_ = uop->getSequenceId();
      // Update the branch misprediction counter
      branchMispredicts_++;
    }
  }

  // Operand forwarding; allows a dependent uop to execute next cycle
  forwardOperands_(uop->getDestinationRegisters(), uop->getResults());

  output_.getTailSlots()[0] = std::move(uop);
}

bool ExecuteUnit::shouldFlush() const { return shouldFlush_; }
uint64_t ExecuteUnit::getFlushAddress() const { return pc_; }
uint64_t ExecuteUnit::getFlushSeqId() const { return flushAfter_; }

void ExecuteUnit::purgeFlushed() {
  if (pipeline_.size() == 0) {
    return;
  }

  // If the newest instruction has been flushed, clear any stalls.
  if (pipeline_.back().insn->isFlushed()) {
    stallUntil_ = tickCounter_;
  }

  // Iterate over the pipeline and remove flushed instructions
  auto it = pipeline_.begin();
  while (it != pipeline_.end()) {
    auto& entry = *it;
    if (entry.insn->isFlushed()) {
      it = pipeline_.erase(it);
    } else {
      it++;
    }
  }

  // If first blocking in-flight instruction is flushed, ensure another
  // non-flushed stalled instruction takes it place in the pipeline if
  // available.
  bool replace = false;
  if (operationsStalled_.size() > 0 &&
      operationsStalled_.front()->isFlushed()) {
    replace = true;
  }
  auto itStall = operationsStalled_.begin();
  while (itStall != operationsStalled_.end()) {
    auto& entry = *itStall;
    if (entry->isFlushed()) {
      itStall = operationsStalled_.erase(itStall);
    } else {
      itStall++;
    }
  }

  if (replace && operationsStalled_.size() > 0) {
    // Add uop to pipeline
    auto& uop = operationsStalled_.front();
    pipeline_.push_back({nullptr, tickCounter_ + uop->getLatency() - 1});
    pipeline_.back().insn = std::move(uop);
    operationsStalled_.front() = pipeline_.back().insn;
  }
}

uint64_t ExecuteUnit::getBranchExecutedCount() const {
  return branchesExecuted_;
}
uint64_t ExecuteUnit::getBranchMispredictedCount() const {
  return branchMispredicts_;
}

uint64_t ExecuteUnit::getCycles() const { return cycles_; }

}  // namespace pipeline
}  // namespace simeng
