#include "simeng/PerceptronPredictor.hh"

// ToDo -- remove this include
#include <iostream>

namespace simeng {

PerceptronPredictor::PerceptronPredictor(ryml::ConstNodeRef config)
    : btbBits_(config["Branch-Predictor"]["BTB-Tag-Bits"].as<uint64_t>()),
      globalHistoryLength_(
          config["Branch-Predictor"]["Global-History-Length"].as<uint64_t>()),
      rasSize_(config["Branch-Predictor"]["RAS-entries"].as<uint64_t>()) {
  // Build BTB based on config options
  btb_.resize(1 << (btbBits_));
  for (int i = 0; i < (1 << (btbBits_)); i++) {
    btb_[i].first.assign(globalHistoryLength_, 0);
    btb_[i].first.push_back(1);
    btb_[i].second = 0;
  }

  // Set up training threshold according to empirically determined formula
  trainingThreshold_ = (int)((1.93 * (globalHistoryLength_)) + 14);

  // ToDo -- remove print statement
  std::cout << "Making Perceptron Predictor" << std::endl;
}

PerceptronPredictor::~PerceptronPredictor() {
  ras_.clear();
  rasHistory_.clear();
}

BranchPrediction PerceptronPredictor::predict(uint64_t address, BranchType type,
                                           int64_t knownOffset) {
  // Get index via an XOR hash between the global history and the lower btbBits_
  // bits of the instruction address
  uint64_t hashedIndex = ((address >> 2) ^ globalHistory_) & ((1 << btbBits_) - 1);

  // Store the global history for correct hashing in update() --
  // needs to be global history and not the hashed index as hashing looses information at longer
  // global history lengths
  btbHistory_[address] = globalHistory_;

  // Retrieve the perceptron from the BTB
  std::vector<int8_t> perceptron = btb_[hashedIndex].first;

  // Determine direction prediction from perceptron, starting with the bias weight
  int64_t Pout = perceptron[globalHistoryLength_];
  for (int i = 0; i < globalHistoryLength_; i++) {
    bool historyTaken =
        ((globalHistory_ & (1 << ((globalHistoryLength_ - 1) - i))) != 0);
    Pout += historyTaken ? perceptron[i] : (0 - perceptron[i]);
  }
  bool direction = (Pout >= 0);
  // Retrieve target prediction

  uint64_t target =
      (knownOffset != 0) ? address + knownOffset : btb_[hashedIndex].second;

  BranchPrediction prediction = {direction, target};

  // Ammend prediction based on branch type
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
  uint64_t prevGlobalHistory = btbHistory_[address];
  uint64_t hashedIndex =
      ((address >> 2) ^ prevGlobalHistory) & ((1 << btbBits_) - 1);

  std::vector<int8_t> perceptron = btb_[hashedIndex].first;

  // Work out the most recent prediction
  int64_t Pout = perceptron[globalHistoryLength_];
  for (int i = 0; i < globalHistoryLength_; i++) {
    bool historyTaken =
        ((prevGlobalHistory & (1 << ((globalHistoryLength_ - 1) - i))) != 0);
    Pout += historyTaken ? perceptron[i] : (0 - perceptron[i]);
  }
  bool directionPrediction = (Pout >= 0);

  // Determine the magnitude of the dot product for training
  uint64_t magnitude = (Pout < 0) ? (0 - Pout) : Pout;

  // update the perceptron if the prediction was wrong, or the dot product's magnitude
  // was not greater than the training threshold
  if ((directionPrediction != taken) || (magnitude < trainingThreshold_)) {
    int8_t t = (taken) ? 1 : -1;

    for (int i = 0; i < globalHistoryLength_; i++) {
      int8_t xi =
          ((prevGlobalHistory & (1 << ((globalHistoryLength_ - 1) - i))) == 0) ? -1 : 1;
      int8_t product_xi_t = xi * t;
      // Make sure no overflow
      if ((product_xi_t > 0 && perceptron[i] < 127) || (product_xi_t < 0 && perceptron[i] > -127)) {
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

}  // namespace simeng
