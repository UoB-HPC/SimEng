#include "simeng/pipeline/DecodeUnit.hh"

#include <cassert>

namespace simeng {
namespace pipeline {

DecodeUnit::DecodeUnit(PipelineBuffer<MacroOp>& input,
                       PipelineBuffer<std::shared_ptr<Instruction>>& output,
                       BranchPredictor& predictor)
    : input_(input), output_(output), predictor_(predictor){};

void DecodeUnit::tick() {
  // Stall if output buffer is stalled
  if (output_.isStalled()) {
    input_.stall(true);
    return;
  }

  shouldFlush_ = false;
  input_.stall(false);

  // Stall if internal uop is overpopulated, otherwise add uops from input to
  // internal buffer
  if (microOps_.size() >= output_.getWidth()) {
    input_.stall(true);
  } else {
    // Populate uop buffer with newly fetched macro-ops
    for (size_t slot = 0; slot < input_.getWidth(); slot++) {
      auto& macroOp = input_.getHeadSlots()[slot];

      if (macroOp.size() == 0) {
        // Nothing to process for this macro-op
        continue;
      }

      for (uint8_t index = 0; index < macroOp.size(); index++) {
        // std::cout << "Pushing 0x" << std::hex
        //           << macroOp[index]->getInstructionAddress() << std::dec
        //           << " to microOps_" << std::endl;
        microOps_.push_back(std::move(macroOp[index]));
      }

      input_.getHeadSlots()[slot].clear();
    }
  }

  // Process uops in buffer
  for (size_t slot = 0; slot < output_.getWidth(); slot++) {
    // If there's no more uops to decode, exit loop early
    if (!microOps_.size()) break;

    // Move uop to output buffer and remove from internal buffer
    auto& uop = (output_.getTailSlots()[slot] = std::move(microOps_.front()));
    // std::cout << "Decode 0x" << std::hex << uop->getInstructionAddress()
    //           << std::dec << std::endl;
    microOps_.pop_front();

    // Check preliminary branch prediction results now that the instruction is
    // decoded. Identifies:
    // - Non-branch instructions mistakenly predicted as branches
    // - Incorrect targets for immediate branches
    auto [misprediction, correctAddress] = uop->checkEarlyBranchMisprediction();
    if (misprediction) {
      earlyFlushes_++;
      shouldFlush_ = true;
      pc_ = correctAddress;

      if (!uop->isBranch()) {
        // Non-branch incorrectly predicted as a branch; let the predictor know
        predictor_.update(uop, false, pc_);
        // Remove macro-operations in microOps_ buffer after macro-operation
        // decoded in this cycle
        // std::cout << "FLUSHED AT DECODE: 0x" << std::hex
        //           << uop->getInstructionAddress() << std::dec
        //           << " which microOps_.size() = " << microOps_.size()
        //           << std::endl;
        auto uopIt = microOps_.begin();
        // Find first microOps_ entry not belonging to same address as flushing
        // instruction
        while (uopIt != microOps_.end()) {
          if ((*uopIt)->getInstructionAddress() !=
              uop->getInstructionAddress()) {
            break;
          } else {
            uopIt++;
          }
        }
        // Remove all entries after first macro-operation in buffer
        while (uopIt != microOps_.end()) {
          // std::cout << "\tRemoving 0x" << std::hex
          //           << (*uopIt)->getInstructionAddress() << std::dec
          //           << std::endl;
          uopIt = microOps_.erase(uopIt);
        }
      }

      // Skip processing remaining uops, as they need to be flushed
      break;
    }
  }
}

bool DecodeUnit::shouldFlush() const { return shouldFlush_; }
uint64_t DecodeUnit::getFlushAddress() const { return pc_; }
uint64_t DecodeUnit::getEarlyFlushes() const { return earlyFlushes_; };
void DecodeUnit::purgeFlushed() {
  // std::cout << "Clearing " << microOps_.size() << " from microOps_"
  //           << std::endl;
  // std::cout << "Clearing MicroOps_ with microOps_.size() = " <<
  // microOps_.size()
  //           << std::endl;
  // auto uopIt = microOps_.begin();
  // while (uopIt != microOps_.end()) {
  //   std::cout << "\tRemoving 0x" << std::hex
  //             << (*uopIt)->getInstructionAddress() << std::dec << std::endl;
  //   uopIt++;
  // }
  microOps_.clear();
}

}  // namespace pipeline
}  // namespace simeng
