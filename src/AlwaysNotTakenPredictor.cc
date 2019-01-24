#include "AlwaysNotTakenPredictor.hh"

namespace simeng {

BranchPrediction AlwaysNotTakenPredictor::predict(uint64_t instructionAddress) {
  return {false, 0};
}

void AlwaysNotTakenPredictor::update(uint64_t instructionAddress, bool taken, uint64_t targetAddress) {}

} // namespace simeng
