#include "simeng/branchpredictors/PerceptronPredictor.hh"

namespace simeng {

PerceptronPredictor::PerceptronPredictor(ryml::ConstNodeRef config)
    : btbBits_(config["Branch-Predictor"]["BTB-Tag-Bits"].as<uint64_t>()),
      globalHistoryLength_(
          config["Branch-Predictor"]["Global-History-Length"].as<uint64_t>()),
      rasSize_(config["Branch-Predictor"]["RAS-entries"].as<uint64_t>()) {
  // Build BTB based on config options
  uint32_t btbSize = (1ul << btbBits_);
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

  // Generate a bitmask that is used to ensure only the relevant number of
  // bits are stored in the global history. This is two times the
  // globalHistoryLength_ to allow rolling back of the speculatively updated
  // global history in the event of a misprediction.
  globalHistoryMask_ = (1ull << (globalHistoryLength_ * 2)) - 1;
}

PerceptronPredictor::~PerceptronPredictor() {
  ras_.clear();
  rasHistory_.clear();
  ftq_.clear();
}

BranchPrediction PerceptronPredictor::predict(uint64_t address, BranchType type,
                                              int64_t knownOffset) {
  // Get the hashed index for the prediction table.  XOR the global history with
  // the non-zero bits of the address, and then keep only the btbBits_ bits of
  // the output to keep it in bounds of the prediction table.
  // The address is shifted to remove the two least-significant bits as these
  // are always 0 in an ISA with 4-byte aligned instructions.
  uint64_t hashedIndex =
      ((address >> 2) ^ globalHistory_) & ((1ull << btbBits_) - 1);

  // Retrieve the perceptron from the BTB
  std::vector<int8_t> perceptron = btb_[hashedIndex].first;

  // Get dot product of perceptron and history
  int64_t Pout = getDotProduct(perceptron, globalHistory_);

  // Determine direction prediction based on its sign
  bool direction = (Pout >= 0);

  // If there is a known offset then calculate target accordingly, otherwise
  // retrieve the target prediction from the btb.
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

  // Store the Pout and global history for correct update() --
  // needs to be global history and not the hashed index as hashing loses
  // information and the global history is required for updating perceptrons.
  ftq_.emplace_back(Pout, globalHistory_);

  // Speculatively update the global history based on the direction
  // prediction being made
  globalHistory_ =
      ((globalHistory_ << 1) | prediction.isTaken) & globalHistoryMask_;

  return prediction;
}

void PerceptronPredictor::update(uint64_t address, bool isTaken,
                                 uint64_t targetAddress, BranchType type,
                                 uint64_t instructionId) {
  // Make sure that this function is called in program order; and then update
  // the lastUpdatedInstructionId variable
  assert(instructionId >= lastUpdatedInstructionId_ &&
         (lastUpdatedInstructionId_ = instructionId) >= 0 &&
         "Update not called on branch instructions in program order");

  // Retrieve the previous global history and branch direction prediction from
  // the front of the ftq (assumes branches are updated in program order).
  int64_t prevPout = ftq_.front().first;
  uint64_t prevGlobalHistory = ftq_.front().second;
  ftq_.pop_front();

  // Work out hashed index
  uint64_t hashedIndex =
      ((address >> 2) ^ prevGlobalHistory) & ((1ull << btbBits_) - 1);

  std::vector<int8_t> perceptron = btb_[hashedIndex].first;

  // Work out the most recent prediction
  bool directionPrediction = (prevPout >= 0);

  // Update the perceptron if the prediction was wrong, or the dot product's
  // magnitude was not greater than the training threshold
  if ((directionPrediction != isTaken) ||
      (static_cast<uint64_t>(std::abs(prevPout)) < trainingThreshold_)) {
    int8_t t = (isTaken) ? 1 : -1;

    for (uint64_t i = 0; i < globalHistoryLength_; i++) {
      int8_t xi = ((prevGlobalHistory &
                    (1ull << ((globalHistoryLength_ - 1) - i))) == 0)
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
  if (isTaken) {
    btb_[hashedIndex].second = targetAddress;
  }

  // Update global history if prediction was incorrect
  // Bit-flip the global history bit corresponding to this prediction
  // We know how many predictions there have since been by the size of the FTQ
  if (directionPrediction != isTaken) globalHistory_ ^= (1ull << (ftq_.size()));
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

  assert((ftq_.size() > 0) &&
         "Cannot flush instruction from Branch Predictor "
         "when the ftq is empty");
  ftq_.pop_back();

  // Roll back global history
  globalHistory_ >>= 1;
}

int64_t PerceptronPredictor::getDotProduct(
    const std::vector<int8_t>& perceptron, uint64_t history) {
  int64_t Pout = perceptron[globalHistoryLength_];
  for (uint64_t i = 0; i < globalHistoryLength_; i++) {
    // Get branch direction for ith entry in the history
    bool historyTaken =
        ((history & (1ull << ((globalHistoryLength_ - 1) - i))) != 0);
    Pout += historyTaken ? perceptron[i] : (0 - perceptron[i]);
  }
  return Pout;
}

}  // namespace simeng
