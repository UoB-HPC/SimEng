#include "simeng/pipeline_hi/StaticPredictor.hh"

#include <cassert>

namespace simeng {
namespace pipeline_hi {
//TODO: temp for get rid of yaml, delete it later
StaticPredictor::StaticPredictor(uint8_t sType)
    : staticType_(sType) {}

StaticPredictor::StaticPredictor(YAML::Node config)
    : staticType_(config["Branch-Predictor"]["Static-Type"].as<uint8_t>()),
      rasSize_(config["Branch-Predictor"]["RAS-entries"].as<uint64_t>()){}

StaticPredictor::~StaticPredictor() {
  ras_.clear();
  rasHistory_.clear();
}

BranchPrediction StaticPredictor::predict(uint64_t address, BranchType type,
                                          uint64_t knownOffset,
                                          uint8_t byteLength) {
  int64_t offset = knownOffset;
  uint64_t predict_target = (knownOffset) ? knownOffset + address : 0;
  BranchPrediction prediction = {false, 0};

  assert(byteLength > 1 && "byteLength <= 1");

  if (type == BranchType::Unconditional) {
    prediction = { true, predict_target};
  } else if (type == BranchType::Return) {
    if (ras_.size() > 0) {
      predict_target = ras_.back();
      // Record top of RAS used for target prediction
      rasHistory_[address] = ras_.back();
      ras_.pop_back();
    }
    prediction = {true, predict_target};
  } else if (type == BranchType::SubroutineCall) { //JAL and JALR
    if (ras_.size() >= rasSize_) {
      ras_.pop_front();
    }
    ras_.push_back(address + byteLength);
    // Record that this address is a branch-and-link instruction
    rasHistory_[address] = 0;
    prediction = {true, predict_target};
  } else if (type == BranchType::Conditional) {
    switch (staticType_) {
      case 0: //always-taken
        prediction = {true, predict_target};
        break;

      case 1: //always-not-taken;
        prediction = {false, 0};
        break;

      case 2: //Backward Taken, Forward Not Taken
      {
        if (offset >= 0) {
          //not taken
          prediction = {false, address+byteLength};
        } else {
          prediction = {true, predict_target};
        }
        break;
      }

      case 3: //Forward Taken, Backward Not Taken
      {
        if (offset <= 0) {
          //not taken
          prediction = {false, address+byteLength};
        } else {
          prediction = {true, predict_target};
        }
        break;
      }

      default:
        assert(staticType_ < 4 && "Non-supported type for static predictor");
        break;
    }
  }

  return prediction;
}

void StaticPredictor::update(uint64_t address, bool taken,
                             uint64_t targetAddress, BranchType type) {}

void StaticPredictor::flush(uint64_t address) {
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
BranchPrediction StaticPredictor::predict(uint64_t address, BranchType type,
                                          uint64_t knownTarget) {
  printf("StaticPredictor::predict(), This is overloaded and deprecated! \n");
  return predict(address, type, knownTarget, 4);
}

}  // namespace pipeline_hi
}  // namespace simeng
