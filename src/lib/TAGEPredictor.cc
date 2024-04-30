#include "simeng/TAGEPredictor.hh"

namespace simeng {

TAGEPredictor::TAGEPredictor(ryml::ConstNodeRef config)
  : rasSize_(config["Branch-Predictor"]["RAS-entries"].as<uint64_t>()) {
  // Initialise the predictor tables to be weakly taken and not useful
  for (int i = 0; i < numTables_; i++) {
    taggedPredictors_.push_back(std::array<predictorEntry, 1024>());
    for (int ent = 0; ent < taggedEntries_; ent++) {
      taggedPredictors_[i][ent] = {0, 0, 2, 0};
    }
  }

  for (int ent = 0; ent < T0Entries_; ent++) {
    T0Predictor_[ent] = {0, 0, 2, 0};
  }
}

TAGEPredictor::~TAGEPredictor() {
  ras_.clear();
  taggedPredictors_.clear();
}

BranchPrediction TAGEPredictor::predict(uint64_t address, BranchType type,
                                        int64_t knownOffset) {
  bool taggedTaken = false;
  bool altTaken = false;
  uint64_t taggedTarget = 0;
  int8_t provider = -1;

  uint64_t tag = getTagHash(address, globalHistory_);

  for (int8_t table = 0; table < numTables_; table++) {
    uint32_t index = getIndex(address, globalHistory_, table);
    if (taggedPredictors_[table][index].tag == tag) {
      altTaken = taggedTaken;
      provider = table;
      taggedTaken = (taggedPredictors_[table][index].counter >=
                                   2);
      taggedTarget = taggedPredictors_[table][index].target;
    }
  }

  BranchPrediction prediction = {taggedTaken, taggedTarget};

  // Replace prediction with default prediction if none of the tagged
  // predictors have an entry matching this branch
  if (provider == -1) {
    prediction = getDefaultPrediction(address);
  }

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

  // store state information in FTQ
  ftqEntry state = {prediction.taken, prediction.target, altTaken,
                    globalHistory_, provider};
  ftq_.push_back(state);

  // Speculatively update the global history on the basis of this prediction
  globalHistory_ = (globalHistory_ << 1) | prediction.taken;

  // ToDo -- implement periodic reset of usefulness bits

  return prediction;
}

void TAGEPredictor::update(uint64_t address, bool taken, uint64_t targetAddress,
                           simeng::BranchType type) {
  // Get previous state from FTQ
  ftqEntry prevState = ftq_.front();
  ftq_.pop_front();

  // Get a pointer to the provider entry
  predictorEntry* providerEntry = (prevState.provider != -1) ?
      &taggedPredictors_[prevState.provider][getIndex(address,
                                                      prevState.history,
                                                      prevState.provider)] :
      &T0Predictor_[(address >> 2) & 4095];

  // Update the usefulness counter
  // If both provider and altPred are tagged predictors, and made different
  // predictions, increment/decrement usefulness counter of predictor on the
  // basis of the correctness of the prediction
  if (prevState.provider != -1 &&
      (prevState.taken != prevState.altPrediction)) {
    if (!((prevState.taken == taken) && (prevState.target == targetAddress)) &&
        (providerEntry->usefulness > 0)) {
      providerEntry->usefulness--;
    } else if ((prevState.taken == taken) &&
               (prevState.target == targetAddress) &&
               (providerEntry->usefulness < 3)) {
      providerEntry->usefulness++;
    }
  }

  // Update counter of provider based on outcome of branch
  if ((providerEntry->counter < 3) && taken) {
    providerEntry->counter++;
  } else if ((providerEntry->counter > 0) && !taken) {
    providerEntry->counter--;
  }

  // If predictor is using the longest possible history length, we try to
  // allocate an entry for the branch in a higher-order tagged predictor table
  // ToDo -- implement probabilistic allocation if more than one are available
  if (prevState.provider < (numTables_ - 1)) {
    for (int8_t table = prevState.provider + 1; table < numTables_; table++) {
      predictorEntry* tableEntry =
          &taggedPredictors_[table][getIndex(address,
                                             prevState.history,
                                             table)];
      if (tableEntry->usefulness == 0) {
        tableEntry->counter = (taken) ? 2 : 1; // Todo -- The paper says
                                               // always set to 2, but this
                                               // seems more sensible to me.
                                               // Investigate
        tableEntry->usefulness = 0;
        tableEntry->target = targetAddress;
        tableEntry->tag = getTagHash(address, prevState.history);
        break;
      }
    }
  }

  if (prevState.taken != taken) globalHistory_ ^= (1 << (ftq_.size()));
}

void TAGEPredictor::flush(uint64_t address) {
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

  ftq_.pop_back();

  // Roll back global history
  globalHistory_ >>= 1;
}

void TAGEPredictor::addToFTQ(uint64_t address, bool taken) {
  // Add instruction to the FTQ in event of reused prediction
  // Set FTQ entry to say that the prediction was on the bases of the default
  // predictor table, as this means less info needs to be remembered and
  // passed down.
  // ToDo -- think if there is a more elegant way of implementing this to
  //  retain more info from the base prediction
  ftqEntry newEntry = {taken, 0, false, globalHistory_, -1};
  ftq_.push_back(newEntry);
  globalHistory_ = (globalHistory_ << 1) | taken;
}

BranchPrediction TAGEPredictor::getDefaultPrediction(uint64_t address) {
  uint64_t index = (address >> 2) & 4095;
  return {((T0Predictor_[index].counter & 2) > 0),
          T0Predictor_[index].target};
}

uint64_t TAGEPredictor::getTagHash(uint64_t address, uint64_t history) {
  return address;
}

uint64_t TAGEPredictor::getIndex(uint64_t address, uint64_t history,
                                 int8_t predictor) {
  return (((address >> 2) ^ (history & (1 << (predictor + 1)) - 1)) & 1023);
}

} // namespace simeng