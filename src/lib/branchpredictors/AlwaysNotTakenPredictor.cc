#include "simeng/branchpredictors/AlwaysNotTakenPredictor.hh"

namespace simeng {
BranchPrediction AlwaysNotTakenPredictor::predict(
    [[maybe_unused]] uint64_t address, BranchType type, int64_t knownOffset) {
  return {false, 0};
}

void AlwaysNotTakenPredictor::update(uint64_t address, bool taken,
                                     uint64_t targetAddress, BranchType type,
                                     uint64_t instructionId) {}

void AlwaysNotTakenPredictor::flush(uint64_t address) {}
}  // namespace simeng
