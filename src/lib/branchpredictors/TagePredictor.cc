#include "simeng/branchpredictors/TagePredictor"

namespace simeng {
TagePredictor::TagePredictor(ryml::ConstNodeRef config)
  : rasSize_(config["Branch-Predictor"]["RAS-entries"].as<uint64_t>()) {
  // Initialise the predictor tables to be weakly taken and not useful


}

TagePredictor::~TagePredictor() {
  ras_.clear();
}

BranchPrediction TagePredictor::predict(uint64_t address, BranchType type,
                                        int64_t knownOffset, bool isLoop) {


}

void TagePredictor::update(uint64_t address, bool isTaken, uint64_t
                                                              targetAddress,
                           simeng::BranchType type, uint64_t instructionId) {


}

void TagePredictor::flush(uint64_t address) {


}


} // namespace simeng