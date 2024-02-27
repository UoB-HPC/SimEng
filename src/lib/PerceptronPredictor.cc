#include "simeng/PerceptronPredictor.hh"

namespace simeng {

PerceptronPredictor::PerceptronPredictor(ryml::ConstNodeRef config)
    : btbBits_(config["Branch-Predictor"]["BTB-Tag-Bits"].as<uint64_t>()),
      globalHistoryLength_(
          config["Branch-Predictor"]["Global-History-Length"].as<uint64_t>()),
      rasSize_(config["Branch-Predictor"]["RAS-entries"].as<uint64_t>()) {
  // Build BTB based on config options
  uint32_t btbSize = (1 << btbBits_);
  btb_.resize(btbSize);
  // Initialise perceptron values with 0 for the global history weights, and 1
  // for the bias weight; and initialise the target with 0 (i.e., unknown)
  for (uint32_t i = 0; i < btbSize; i++) {
    btb_[i].first.assign(globalHistoryLength_, 0);
    btb_[i].first.push_back(1);
    btb_[i].second = 0;
  }

  // Set up training threshold according to empirically determined formula
  trainingThreshold_ = (uint64_t)((1.93 * globalHistoryLength_) + 14);
}

PerceptronPredictor::~PerceptronPredictor() {
  ras_.clear();
  rasHistory_.clear();
}

BranchPrediction PerceptronPredictor::predict(uint64_t address, BranchType type,
                                              int64_t knownOffset) {
  // Get the hashed index for the prediction table.  XOR the global history with
  // the non-zero bits of the address, and then keep only the btbBits_ bits of
  // the output to keep it in bounds of the prediction table.
  uint64_t hashedIndex =
      ((address >> 2) ^ globalHistory_) & ((1 << btbBits_) - 1);

  // Store the global history for correct hashing in update() --
  // needs to be global history and not the hashed index as hashing loses
  // information at longer global history lengths
  btbHistory_[address] = globalHistory_;

  // Retrieve the perceptron from the BTB
  std::vector<int8_t> perceptron = btb_[hashedIndex].first;

  // Get dot product of perceptron and history
  int64_t Pout = getDotProduct(perceptron, globalHistory_);
  // Determine direction prediction based on its sign
  bool direction = (Pout >= 0);

  // Retrieve target prediction
  uint64_t target =
      (knownOffset != 0) ? address + knownOffset : btb_[hashedIndex].second;

  BranchPrediction prediction = {direction, target};

  // Amend prediction based on branch type
  if (type == BranchType::Unconditional) {
    prediction.taken = true;
  } else if (type == BranchType::Return) {
    prediction.taken = true;
    // Return branches can use the RAS if an entry is available
    if (ras_.size() > 0) {
      prediction.target = ras_.back();
      // Record top of RAS used for target prediction
      rasHistory_[address] = ras_.back();
      ras_.pop_back();
    }
  } else if (type == BranchType::SubroutineCall) {
    prediction.taken = true;
    // Subroutine call branches must push their associated return address to RAS
    if (ras_.size() >= rasSize_) {
      ras_.pop_front();
    }
    ras_.push_back(address + 4);
    // Record that this address is a branch-and-link instruction
    rasHistory_[address] = 0;
  } else if (type == BranchType::Conditional) {
    if (!prediction.taken) prediction.target = address + 4;
  }
  return prediction;
}

void PerceptronPredictor::update(uint64_t address, bool taken,
                                 uint64_t targetAddress, BranchType type) {
  // Work out hash index
  uint64_t prevGlobalHistory = btbHistory_[address];
  uint64_t hashedIndex =
      ((address >> 2) ^ prevGlobalHistory) & ((1 << btbBits_) - 1);

  std::vector<int8_t> perceptron = btb_[hashedIndex].first;

  // Work out the most recent prediction
  int64_t Pout = getDotProduct(perceptron, prevGlobalHistory);
  bool directionPrediction = (Pout >= 0);

  // Update the perceptron if the prediction was wrong, or the dot product's
  // magnitude was not greater than the training threshold
  if ((directionPrediction != taken) ||
      ((uint64_t)abs(Pout) < trainingThreshold_)) {
    int8_t t = (taken) ? 1 : -1;

    for (uint64_t i = 0; i < globalHistoryLength_; i++) {
      int8_t xi =
          ((prevGlobalHistory & (1 << ((globalHistoryLength_ - 1) - i))) == 0)
              ? -1
              : 1;
      int8_t product_xi_t = xi * t;
      // Make sure no overflow (+-127)
      if (!(perceptron[i] == 127 && product_xi_t == 1) &&
          !(perceptron[i] == -127 && product_xi_t == -1)) {
        perceptron[i] += product_xi_t;
      }
    }
    perceptron[globalHistoryLength_] += t;
  }

  btb_[hashedIndex].first = perceptron;
  btb_[hashedIndex].second = targetAddress;

  globalHistory_ =
      ((globalHistory_ << 1) | taken) & ((1 << globalHistoryLength_) - 1);
  return;
}

void PerceptronPredictor::flush(uint64_t address) {
  // If address interacted with RAS, rewind entry
  auto it = rasHistory_.find(address);
  if (it != rasHistory_.end()) {
    uint64_t target = it->second;
    if (target != 0) {
      // If history entry belongs to a return instruction, push target back onto
      // stack
      if (ras_.size() >= rasSize_) {
        ras_.pop_front();
      }
      ras_.push_back(target);
    } else {
      // If history entry belongs to a branch-and-link instruction, pop target
      // off of stack
      if (ras_.size()) {
        ras_.pop_back();
      }
    }
    rasHistory_.erase(it);
  }
}

int64_t PerceptronPredictor::getDotProduct(
    const std::vector<int8_t>& perceptron, uint64_t history) {
  int64_t Pout = perceptron[globalHistoryLength_];
  for (uint64_t i = 0; i < globalHistoryLength_; i++) {
    // Get branch direction for ith entry in the history
    bool historyTaken =
        ((history & (1 << ((globalHistoryLength_ - 1) - i))) != 0);
    Pout += historyTaken ? perceptron[i] : (0 - perceptron[i]);
  }
  return Pout;
}

}  // namespace simeng
