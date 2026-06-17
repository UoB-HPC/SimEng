#include "simeng/pipeline/ExecuteUnit.hh"

#include <cstring>
#include <iostream>

bool euPrint = false;

namespace simeng {
namespace pipeline {

ExecuteUnit::ExecuteUnit(
    uint16_t id, PipelineBuffer<std::shared_ptr<Instruction>>& input,
    PipelineBuffer<std::shared_ptr<Instruction>>& output,
    std::function<void(span<Register>, span<RegisterValue>, const uint16_t)>
        forwardOperands,
    std::function<void(const std::shared_ptr<Instruction>&)> handleLoad,
    std::function<void(const std::shared_ptr<Instruction>&)> handleStore,
    std::function<void(const std::shared_ptr<Instruction>&)> raiseException,
    bool pipelined, const std::vector<uint16_t>& blockingGroups,
    bool enableLLSC)
    : id_(id),
      input_(input),
      output_(output),
      forwardOperands_(forwardOperands),
      handleLoad_(handleLoad),
      handleStore_(handleStore),
      raiseException_(raiseException),
      pipelined_(pipelined),
      blockingGroups_(blockingGroups),
      enableLLSC_(enableLLSC) {
  if (id_ == 0 || id_ == 3) outputRestriction_ = false;
}

void ExecuteUnit::tick() {
  tickCounter_++;
  shouldFlush_ = false;

  // If the output is stalled, stall input
  if (output_.isStalled()) {
    input_.stall(true);
    return;
  }
  if (euPrint && pipeline_.size()) {
    std::cerr << "[SimEng:EU" << id_ << "]\tPipeline at head of tick = [";
    for (const auto& e : pipeline_) {
      std::cerr << e.insn->getSequenceId() << ":" << std::hex
                << e.insn->getInstructionAddress() << std::dec << ":"
                << e.readyAt - e.insn->getLatency() + 1 << " - " << e.readyAt
                << " | ";
    }
    if (pipeline_.size()) std::cerr << "\b\b\b";
    std::cerr << "]" << std::endl;
  }

  if (pipeline_.size() != 0) cycles_++;

  if (stallUntil_ <= tickCounter_) {
    input_.stall(false);
    // Input isn't stalled; process instruction and add to pipeline

    auto& uop = input_.getHeadSlots()[0];
    if (uop != nullptr) {
      if (!uop->isFlushed()) {
        // Retrieve execution latency from the instruction
        auto latency = uop->getLatency();
        // cycles_++;
        if (pipeline_.size() == 0) cycles_++;

        uint64_t readyAt = tickCounter_ + latency - 1;

        // Block uop execution if appropriate
        if (std::find(blockingGroups_.begin(), blockingGroups_.end(),
                      uop->getGroup()) != blockingGroups_.end()) {
          if (euPrint)
            std::cerr << "[SimEng:EU" << id_ << "]\t\tNew insn "
                      << uop->getSequenceId() << ":" << std::hex
                      << uop->getInstructionAddress() << std::dec
                      << " with latency " << latency << " will be ready at "
                      << readyAt << std::endl;
          if (operationsStalled_.size() == 0) {
            // Add uop to pipeline
            auto pipeItr = pipeline_.begin();
            while (pipeItr != pipeline_.end()) {
              if (readyAt < pipeItr->readyAt) break;
              pipeItr++;
            }
            pipeItr = pipeline_.insert(pipeItr, {std::move(uop), readyAt});
            operationsStalled_.push_back(pipeItr->insn);
          } else {
            // Stall execution start cycle
            operationsStalled_.push_back(std::move(uop));
          }
        } else if (latency == 1 && pipeline_.size() == 0) {
          // Pipeline is empty and insn will execute this cycle; bypass=
          execute(uop);
        } else {
          if (euPrint)
            std::cerr << "[SimEng:EU" << id_ << "]\t\tNew insn "
                      << uop->getSequenceId() << ":" << std::hex
                      << uop->getInstructionAddress() << std::dec
                      << " with latency " << latency << " will be ready at "
                      << readyAt << std::endl;
          // This instruction may take more than a single cycle; check for a
          // stall. For unpipelined units, the unit will stall for the full
          // instruction duration.
          auto stallCycles =
              pipelined_ ? uop->getStallCycles() : uop->getLatency();
          if (stallCycles > 1) {
            stallUntil_ = tickCounter_ + stallCycles - 1;
            input_.stall(true);
          }

          // Add uop to pipeline
          auto pipeItr = pipeline_.begin();
          while (pipeItr != pipeline_.end()) {
            if (readyAt < pipeItr->readyAt) break;
            pipeItr++;
          }
          pipeItr = pipeline_.insert(pipeItr, {std::move(uop), readyAt});
        }
      }
      // else if (pipeline_.size()) {
      //   cycles_++;
      // }
      input_.getHeadSlots()[0] = nullptr;
    }
    // else if (pipeline_.size()) {
    //   cycles_++;
    // }
  }
  if (euPrint && pipeline_.size()) {
    std::cerr << "[SimEng:EU" << id_ << "]\tPipeline at middle of tick = [";
    for (const auto& e : pipeline_) {
      std::cerr << e.insn->getSequenceId() << ":" << std::hex
                << e.insn->getInstructionAddress() << std::dec << ":"
                << e.readyAt - e.insn->getLatency() + 1 << " - " << e.readyAt
                << " | ";
    }
    if (pipeline_.size()) std::cerr << "\b\b\b";
    std::cerr << "]" << std::endl;
  }

  if (pipeline_.size() == 0) {
    return;
  }

  // auto& head = pipeline_.front();
  bool releaseOpBlock = false;
  auto pipelineItr = pipeline_.begin();
  while (pipelineItr != pipeline_.end()) {
    if (pipelineItr->readyAt <= tickCounter_) {
      if (outputRestriction_ &&
          pipelineItr->insn->getDestinationRegisters().size()) {
        if (tickCounter_ <= outputCooldown_) {
          pipelineItr++;
          continue;
        }
      }
      // Check if the completion of an operation would unblock
      // another stalled operation.
      if (std::find(blockingGroups_.begin(), blockingGroups_.end(),
                    pipelineItr->insn->getGroup()) != blockingGroups_.end()) {
        releaseOpBlock = true;
      }
      // if (pipeline_.size() > 1 &&
      //     (head.insn->getSupportedPorts()[0] == 0 ||
      //      head.insn->getSupportedPorts()[0] == 3) &&
      //     pipeline_[1].insn->getLatency() < 9 &&
      //     pipeline_[1].insn->getLatency() > 2 &&
      //     ((pipeline_[1].readyAt - pipeline_[0].readyAt) < 3)) {
      //   std::cerr << "EU overlap between " << std::hex
      //             << head.insn->getInstructionAddress() << std::dec << "("
      //             << head.insn->getOpcode() << ") and " << std::hex
      //             << pipeline_[1].insn->getInstructionAddress() << std::dec
      //             <<
      //             "("
      //             << pipeline_[1].insn->getOpcode() << ")" << std::endl;
      // }
      execute(pipelineItr->insn);
      pipeline_.erase(pipelineItr);
      // pipeline_.pop_front();

      // if (pipeline_.size()) {
      //   if (pipeline_.front().insn->getLatency() >= 4 &&
      //       pipeline_.front().insn->getLatency() <= 9) {
      //     pipeline_.front().readyAt = tickCounter_ + 5;
      //   }
      // }
      break;
    } else {
      break;
    }
    pipelineItr++;
  }

  if (releaseOpBlock) {
    // Remove uop copy from operationsStalled_
    operationsStalled_.pop_front();
    // Start any blocked talled uops
    if (operationsStalled_.size() > 0) {
      uint64_t readyAt =
          tickCounter_ + operationsStalled_.front()->getLatency() - 1;
      // Add uop to pipeline
      auto pipeItr = pipeline_.begin();
      while (pipeItr != pipeline_.end()) {
        if (readyAt < pipeItr->readyAt) break;
        pipeItr++;
      }
      pipeItr = pipeline_.insert(
          pipeItr, {std::move(operationsStalled_.front()), readyAt});
      operationsStalled_.front() = pipeItr->insn;
    }
  }

  if (euPrint && pipeline_.size()) {
    std::cerr << "[SimEng:EU" << id_ << "]\tPipeline at end of tick = [";
    for (const auto& e : pipeline_) {
      std::cerr << e.insn->getSequenceId() << ":" << std::hex
                << e.insn->getInstructionAddress() << std::dec << ":"
                << e.readyAt - e.insn->getLatency() + 1 << " - " << e.readyAt
                << " | ";
    }
    if (pipeline_.size()) std::cerr << "\b\b\b";
    std::cerr << "]" << std::endl;
  }
}

void ExecuteUnit::execute(std::shared_ptr<Instruction>& uop) {
  if (outputRestriction_ && outputCooldown_ <= tickCounter_) {
    if (uop->getDestinationRegisters().size()) {
      outputCooldown_ = tickCounter_ + 2;
    }
  }

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
    if (uop->exceptionEncountered()) {
      // Exception; don't pass handle load function
      raiseException_(uop);
      return;
    }
    // For Load-Reserved and Atomics, don't start load until at head of ROB
    if (!(enableLLSC_ && (uop->isLoadReserved() || uop->isAtomic())))
      handleLoad_(uop);
    return;
  } else if (uop->isStoreAddress() || uop->isStoreData()) {
    if (uop->isStoreAddress()) {
      uop->generateAddresses();
      if (uop->exceptionEncountered()) {
        // Exception; don't pass handle load function
        raiseException_(uop);
        return;
      }
      if (uop->isStoreData()) {
        uop->execute();
      }
      handleStore_(uop);
      return;
    }
    if (uop->isStoreData()) {
      uop->execute();
      handleStore_(uop);
    }
    // if (uop->isStoreCond()) {
    //   if (enableLLSC_) {
    //     // If the store is marked Exclusive then it isn't sent to writeback
    //     // straight away.
    //     // Set commit ready and return early.
    //     uop->setCommitReady();
    //     return;
    //   } else {
    //     uop->updateCondStoreResult(true);
    //   }
    // }
  } else if (uop->isPrefetch()) {
    uop->generateAddresses();
    if (uop->exceptionEncountered()) {
      // Exception; don't pass handle load function
      raiseException_(uop);
      return;
    }
    handleLoad_(uop);
    uop->execute();
  } else {
    uop->execute();
  }

  if (uop->exceptionEncountered()) {
    // Exception; don't forward results, don't pass uop forward
    raiseException_(uop);
    return;
  }

  if (uop->isBranch()) {
    pc_ = uop->getBranchAddress();

    if (uop->wasBranchMispredicted()) {
      // Misprediction; flush the pipeline
      shouldFlush_ = true;
      flushAfterInsnId_ = uop->getInstructionId();
    }
  }

  // Operand forwarding; allows a dependent uop to execute next cycle
  // std::cerr << "[SimEng] Execute " << std::hex <<
  // uop->getInstructionAddress()
  //           << std::dec << " - " << uop->getSequenceId() << " - "
  //           << uop->getGroup() << std::endl;
  // std::cerr << "Forwarding from " << std::hex <<
  // uop->getInstructionAddress()
  //           << std::dec << " to" << std::endl;
  forwardOperands_(uop->getDestinationRegisters(), uop->getResults(),
                   uop->getGroup());

  output_.getTailSlots()[0] = std::move(uop);
}

bool ExecuteUnit::shouldFlush() const { return shouldFlush_; }
uint64_t ExecuteUnit::getFlushAddress() const { return pc_; }
uint64_t ExecuteUnit::getFlushInsnId() const { return flushAfterInsnId_; }

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

void ExecuteUnit::flush() {
  pipeline_.clear();
  operationsStalled_.clear();
}

bool ExecuteUnit::isEmpty() {
  // Execution unit is considered empty if no instructions are present in the
  // pipeline_ and operationsStalled_ queues
  return !(pipeline_.size() != 0 || operationsStalled_.size() != 0);
}

uint64_t ExecuteUnit::getCycles() const { return cycles_; }

bool ExecuteUnit::isEmpty() const {
  // Execution unit is considered empty if no instructions are present in the
  // pipeline_ and operationsStalled_ queues
  if (pipeline_.size() != 0 || operationsStalled_.size() != 0) {
    return false;
  }
  return true;
}

}  // namespace pipeline
}  // namespace simeng
