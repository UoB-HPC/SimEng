#include "simeng/GenericPredictor.hh"

#include <iostream>

namespace simeng {

GenericPredictor::GenericPredictor(ryml::ConstNodeRef config)
    : btbBits_(config["Branch-Predictor"]["BTB-Tag-Bits"].as<uint8_t>()),
      satCntBits_(
          config["Branch-Predictor"]["Saturating-Count-Bits"].as<uint8_t>()),
      globalHistoryLength_(
          config["Branch-Predictor"]["Global-History-Length"].as<uint16_t>()),
      rasSize_(config["Branch-Predictor"]["RAS-entries"].as<uint16_t>()) {
  // Calculate the saturation counter boundary between weakly isTaken and
  // not-isTaken. `(2 ^ num_sat_cnt_bits) / 2` gives the weakly isTaken state
  // value
  uint8_t weaklyTaken = 1 << (satCntBits_ - 1);
  uint8_t satCntVal = (config["Branch-Predictor"]["Fallback-Static-Predictor"]
                           .as<std::string>() == "Always-Taken")
                          ? weaklyTaken
                          : (weaklyTaken - 1);
  // Create branch prediction structures
  btb_ =
      std::vector<std::pair<uint8_t, uint64_t>>(1 << btbBits_, {satCntVal, 0});
  // Alter globalHistoryLength_ value to better suit required format in update()
  // Multiply original globalHistoryLength_ by two so that extra branch
  // outcomes are stored to allow rolling back the speculatively updated
  // global history in the event of a misprediction.
  globalHistoryMask_ = (1 << (globalHistoryLength_ * 2)) - 1;
}

GenericPredictor::~GenericPredictor() {
  btb_.clear();
  ras_.clear();
  rasHistory_.clear();
  ftq_.clear();
}

BranchPrediction GenericPredictor::predict(uint64_t address, BranchType type,
                                           int64_t knownOffset) {
  // Get index via an XOR hash between the global history and the instruction
  // address. This hash is then ANDed to keep it within bounds of the btb.
  // The address is shifted to remove the two least-significant bits as these
  // are always 0 in an ISA with 4-byte aligned instructions.
  uint64_t hashedIndex =
      ((address >> 2) ^ globalHistory_) & ((1 << btbBits_) - 1);

  // Get prediction from BTB
  bool direction = btb_[hashedIndex].first >= (1 << (satCntBits_ - 1));
  uint64_t target =
      (knownOffset != 0) ? address + knownOffset : btb_[hashedIndex].second;
  BranchPrediction prediction = {direction, target};

  // Amend prediction based on branch type
  if (type == BranchType::Unconditional) {
    prediction.isTaken = true;
  } else if (type == BranchType::Return) {
    prediction.isTaken = true;
    // Return branches can use the RAS if an entry is available
    if (ras_.size() > 0) {
      prediction.target = ras_.back();
      // Record top of RAS used for target prediction
      rasHistory_[address] = ras_.back();
      ras_.pop_back();
    }
  } else if (type == BranchType::SubroutineCall) {
    prediction.isTaken = true;
    // Subroutine call branches must push their associated return address to RAS
    if (ras_.size() >= rasSize_) {
      ras_.pop_front();
    }
    ras_.push_back(address + 4);
    // Record that this address is a branch-and-link instruction
    rasHistory_[address] = 0;
  } else if (type == BranchType::Conditional) {
    if (!prediction.isTaken) prediction.target = address + 4;
  }

  // Store the hashed index for correct hashing in update()
  ftq_.emplace_back(prediction.isTaken, hashedIndex);

  // Speculatively update the global history
  globalHistory_ =
      ((globalHistory_ << 1) | prediction.isTaken) & globalHistoryMask_;

  return prediction;
}

void GenericPredictor::update(uint64_t address, bool isTaken,
                              uint64_t targetAddress, BranchType type) {
  // Get previous prediction and index calculated from the FTQ
  bool prevPrediction = ftq_.front().first;
  uint64_t hashedIndex = ftq_.front().second;
  ftq_.pop_front();

  // Calculate 2-bit saturating counter value
  uint8_t satCntVal = btb_[hashedIndex].first;
  // Only alter value if it would transition to a valid state
  if (!((satCntVal == (1 << satCntBits_) - 1) && isTaken) &&
      !(satCntVal == 0 && !isTaken)) {
    satCntVal += isTaken ? 1 : -1;
  }

  // Update BTB entry
  btb_[hashedIndex] = {satCntVal, targetAddress};

  // Update global history if prediction was incorrect
  if (prevPrediction != isTaken) {
    // Bit-flip the global history bit corresponding to this prediction
    // We know how many predictions there have since been by the size of the FTQ
    globalHistory_ ^= (1 << (ftq_.size()));
  }
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

  // If possible, pop instruction from FTQ
  ftq_.pop_back();

  // Roll back global history
  globalHistory_ >>= 1;
}

void GenericPredictor::addToFTQ(uint64_t address, bool isTaken) {
  // Make the hashed index and add it to the FTQ
  uint64_t hashedIndex = ((address >> 2) ^ globalHistory_) & ((1 << btbBits_)
                                                              - 1);
  ftq_.emplace_back(isTaken, hashedIndex);
  // Speculatively update the global history
  globalHistory_ = ((globalHistory_ << 1) | isTaken) & globalHistoryMask_;
}

}  // namespace simeng
