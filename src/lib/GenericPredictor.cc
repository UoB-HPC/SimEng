#include "simeng/GenericPredictor.hh"

#include <iostream>

namespace simeng {

GenericPredictor::GenericPredictor(YAML::Node config)
    : btbBits_(config["Branch-Predictor"]["BTB-Tag-Bits"].as<uint64_t>()),
      btb_(1 << btbBits_,
           {config["Branch-Predictor"]["Fallback-Static-Predictor"]
                .as<uint16_t>(),
            0}),
      satCntBits_(
          config["Branch-Predictor"]["Saturating-Count-Bits"].as<uint64_t>()),
      globalHistoryLength_(
          config["Branch-Predictor"]["Global-History-Length"].as<uint64_t>()),
      rasSize_(config["Branch-Predictor"]["RAS-entries"].as<uint64_t>()) {
  // Alter globalHistoryLength_ value to better suit required format in update()
  globalHistoryLength_ = (1 << globalHistoryLength_) - 1;
}

GenericPredictor::~GenericPredictor() {
  btb_.clear();
  ras_.clear();
  rasHistory_.clear();
}

BranchPrediction GenericPredictor::predict(uint64_t address, BranchType type,
                                           uint64_t knownTarget) {
  // Get index via an XOR hash between the global history and the lower btbBits_
  // bits of the instruction address
  uint64_t hashedIndex = (address & ((1 << btbBits_) - 1)) ^ globalHistory_;
  btbHistory_[address] = hashedIndex;

  // Get prediction from BTB
  bool direction =
      btb_[hashedIndex].first < (1 << (satCntBits_ - 1)) ? false : true;
  uint64_t target =
      (knownTarget != 0) ? address + knownTarget : btb_[hashedIndex].second;
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

void GenericPredictor::update(uint64_t address, bool taken,
                              uint64_t targetAddress, BranchType type) {
  // Get previous index calculated for the instruction address supplied
  uint64_t hashedIndex = btbHistory_[address];

  // Calculate 2-bit saturating counter value
  uint8_t satCntVal = btb_[hashedIndex].first;
  // Only alter value if it would transition to a valid state
  if (!((satCntVal == (1 << satCntBits_) - 1) && taken) &&
      !(satCntVal == 0 && !taken)) {
    satCntVal += taken ? 1 : -1;
  }

  // Update BTB entry
  btb_[hashedIndex] = {satCntVal, targetAddress};

  // Update global history value with new direction
  globalHistory_ = ((globalHistory_ << 1) | taken) & globalHistoryLength_;
  return;
}

void GenericPredictor::flush(uint64_t address) {
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
