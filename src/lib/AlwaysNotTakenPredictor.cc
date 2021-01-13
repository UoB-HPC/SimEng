#include "simeng/AlwaysNotTakenPredictor.hh"

namespace simeng {

BranchPrediction AlwaysNotTakenPredictor::predict(
    std::shared_ptr<Instruction> uop) {
  return {false, 0};
}

void AlwaysNotTakenPredictor::update(std::shared_ptr<Instruction> uop,
                                     bool taken, uint64_t targetAddress) {}

}  // namespace simeng
