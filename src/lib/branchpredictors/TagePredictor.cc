#include "simeng/branchpredictors/TagePredictor.hh"

#include <iostream>

namespace simeng {

TagePredictor::TagePredictor(ryml::ConstNodeRef config)
    : btbBits_(config["Branch-Predictor"]["BTB-Tag-Bits"].as<uint8_t>()),
      satCntBits_(
          config["Branch-Predictor"]["Saturating-Count-Bits"].as<uint8_t>()),
      globalHistoryLength_(
          config["Branch-Predictor"]["Global-History-Length"].as<uint16_t>()),
      rasSize_(config["Branch-Predictor"]["RAS-entries"].as<uint16_t>()),
      globalHistory_(1 << (numTageTables_ + 1)) {
  // Calculate the saturation counter boundary between weakly taken and
  // not-taken. `(2 ^ num_sat_cnt_bits) / 2` gives the weakly taken state
  // value
  uint8_t weaklyTaken = 1 << (satCntBits_ - 1);
  uint8_t satCntVal = (config["Branch-Predictor"]["Fallback-Static-Predictor"]
                           .as<std::string>() == "Always-Taken")
                          ? weaklyTaken
                          : (weaklyTaken - 1);
  // Create branch prediction structures
  btb_ =
      std::vector<std::pair<uint8_t, uint64_t>>(1 << btbBits_, {satCntVal, 0});

  // Set up Tagged tables
  for (uint32_t i = 0; i < numTageTables_; i++) {
    std::vector<TageEntry> newTable;
    for (uint32_t j = 0; j < (1 << tageTableBits_); j++) {
      TageEntry newEntry = {2, 0, 1, 0};
      newTable.push_back(newEntry);
    }
    tageTables_.push_back(newTable);
  }
}

TagePredictor::~TagePredictor() {
  btb_.clear();
  ras_.clear();
  rasHistory_.clear();
  ftq_.clear();
}

BranchPrediction TagePredictor::predict(uint64_t address, BranchType type,
                                        int64_t knownOffset) {
//  std::cout << "Predicting" << std::endl;
  BranchPrediction prediction;
  BranchPrediction altPrediction;
  uint8_t predTable;
  std::vector<uint64_t> indices;
  std::vector<uint64_t> tags;
  getTaggedPrediction(address, &prediction, &altPrediction, &predTable,
                      &indices, &tags);

  if (knownOffset != 0) prediction.target = address + knownOffset;

  // Amend prediction based on branch type
  if (type == BranchType::Unconditional) {
    prediction.isTaken = true;
    predTable = 0;
  } else if (type == BranchType::Return) {
    prediction.isTaken = true;
    // Return branches can use the RAS if an entry is available
    if (ras_.size() > 0) {
      prediction.target = ras_.back();
      // Record top of RAS used for target prediction
      rasHistory_[address] = ras_.back();
      ras_.pop_back();
    }
    predTable = 0;
  } else if (type == BranchType::SubroutineCall) {
    prediction.isTaken = true;
    // Subroutine call branches must push their associated return address to RAS
    if (ras_.size() >= rasSize_) {
      ras_.pop_front();
    }
    ras_.push_back(address + 4);
    // Record that this address is a branch-and-link instruction
    rasHistory_[address] = 0;
    predTable = 0;
  } else if (type == BranchType::Conditional) {
    if (!prediction.isTaken) prediction.target = address + 4;
  }

  // Store the hashed index for correct hashing in update()
  ftqEntry newEntry = {predTable, indices, tags, prediction, altPrediction};
  ftq_.push_back(newEntry);

  // Speculatively update the global history
  globalHistory_.addHistory(prediction.isTaken);
  return prediction;
}

void TagePredictor::update(uint64_t address, bool isTaken,
                           uint64_t targetAddress,
                           simeng::BranchType type, uint64_t instructionId) {
//  std::cout << "Updating" << std::endl;
  // Make sure that this function is called in program order; and then update
  // the lastUpdatedInstructionId variable
  assert(instructionId >= lastUpdatedInstructionId &&
         (lastUpdatedInstructionId = instructionId) >= 0 &&
         "Update not called on branch instructions in program order");

  updateBtb(address, isTaken, targetAddress);

  updateTaggedTables(address, isTaken, targetAddress);

  // Update global history if prediction was incorrect
  if (ftq_.front().prediction.isTaken != isTaken) {
    // Bit-flip the global history bit corresponding to this prediction
    // We know how many predictions there have since been by the size of the FTQ
    globalHistory_.updateHistory(isTaken, ftq_.size());
  }

  // Pop ftq entry from ftq
  ftq_.pop_front();
}

void TagePredictor::flush(uint64_t address) {
//  std::cout << "Flush" << std::endl;
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
  globalHistory_.rollBack();

}

BranchPrediction TagePredictor::getBtbPrediction(uint64_t address) {
//  std::cout << "Getting BTB" << std::endl;
  // Get prediction from BTB
  uint64_t index = (address >> 2) & ((1 << btbBits_) - 1);
  bool direction = (btb_[index].first >= (1 << (satCntBits_ - 1)));
  uint64_t target = btb_[index].second;
  return {direction, target};
}

void TagePredictor::getTaggedPrediction(uint64_t address,
                                        BranchPrediction* prediction,
                                        BranchPrediction* altPrediction,
                                        uint8_t* predTable,
                                        std::vector<uint64_t>* indices,
                                        std::vector<uint64_t>* tags) {
//  std::cout << "Getting Prediction" << std::endl;
  // Get a basic prediction from the btb
  BranchPrediction basePrediction = getBtbPrediction(address);
  prediction->isTaken = basePrediction.isTaken;
  prediction->target = basePrediction.target;
  *predTable = 0;

  // Check each of the tagged predictor tables for an entry matching this
  // branch.  If found, update the best prediction.  The greater the table
  // number, the longer global history it has access to.  Therefore, the
  // greater the table number, the better the prediction.
  for (uint8_t table = 0; table < numTageTables_; table++) {
//    std::cout << "Checking table " << (table + 1) << std::endl;
    uint64_t index = getTaggedIndex(address, table);
    indices->push_back(index);
    uint64_t tag = getTag(address, table);
    tags->push_back(tag);
    if (tageTables_[table][index].tag == tag) {
//      std::cout << "Tag match -- " << std::endl;
      altPrediction->isTaken = prediction->isTaken;
      altPrediction->target = prediction->target;

      prediction->isTaken = (tageTables_[table][index].satCnt >= 2);
      prediction->target = tageTables_[table][index].target;
      *predTable = table;
    }
  }
}

uint64_t TagePredictor::getTaggedIndex(uint64_t address, uint8_t table) {
//  std::cout << "getting Index" << std::endl;
  // Hash function here is pretty arbitrary.
  uint64_t h1 = (address >> 2);
  uint64_t h2 = globalHistory_.getFolded(1 << (table + 1),
                                         (1 << tageTableBits_) - 1);
//  std::cout << "Index: h1=" << h1 << " h2=" << h2 << " final="
//            << ((h1 ^ h2) & ((1 << tageTableBits_) - 1)) << std::endl;
  return (h1 ^ h2) & ((1 << tageTableBits_) - 1);
}

uint64_t TagePredictor::getTag(uint64_t address, uint8_t table) {
//  std::cout << "getting Tag" << std::endl;
  // Hash function here is pretty arbitrary.
  uint64_t h1 = address;
  uint64_t h2 = globalHistory_.getFolded((1 << table),
                                         ((1 << tagLength_) - 1));
//  std::cout << "Tag: h1=" << h1 << " h2=" << h2 << " final="
//            << ((h1 ^ h2) & ((1 << tagLength_) - 1)) << std::endl;
  return (h1 ^ h2) & ((1 << tagLength_) - 1);
}


void TagePredictor::updateBtb(uint64_t address, bool isTaken,
                              uint64_t targetAddress) {
  // Calculate 2-bit saturating counter value
  uint8_t satCntVal = btb_[((address >> 2) & ((1 << btbBits_) - 1))].first;
  // Only alter value if it would transition to a valid state
  if (!((satCntVal == (1 << satCntBits_) - 1) && isTaken) &&
      !(satCntVal == 0 && !isTaken)) {
    satCntVal += isTaken ? 1 : -1;
  }

  // Update BTB entry
  btb_[((address >> 2) & ((1 << btbBits_) - 1))].first = satCntVal;
  if (isTaken) {
    btb_[((address >> 2) & ((1 << btbBits_) - 1))].second = targetAddress;
  }
}


void TagePredictor::updateTaggedTables(uint64_t address, bool isTaken,
                                       uint64_t target) {
  // Get stored information from the ftq
  uint8_t predTable = ftq_.front().predTable;
  std::vector<uint64_t> indices = ftq_.front().indices;
  std::vector<uint64_t> tags = ftq_.front().tags;
  BranchPrediction pred = ftq_.front().prediction;
  BranchPrediction altPred = ftq_.front().altPrediction;


  // Update the prediction counter
  uint64_t predIndex = indices[predTable];
  if (isTaken && (tageTables_[predTable][predIndex].satCnt < 3)) {
    (tageTables_[predTable][predIndex].satCnt)++;
  } else if (!isTaken && (tageTables_[predTable][predIndex].satCnt > 0)) {
    (tageTables_[predTable][predIndex].satCnt)--;
  }

  // Allocate new entry if prediction wrong and possible -- Check higher order
  // tagged predictor tables to see if there is a non-useful entry that can
  // be replaced
  if (isTaken != pred.isTaken || (isTaken && (target != pred.target))) {
    bool allocated = false;
    for (uint8_t table = predTable + 1; table < numTageTables_; table++) {
      if (!allocated && (tageTables_[table][indices[table]].u <= 1)) {
        tageTables_[table][indices[table]] = {((isTaken) ? (uint8_t)2 :
                                                         (uint8_t)1),
                                              tags[table], (uint8_t)2, target};
        allocated = true;
      }
    }
  }

  // Update the usefulness counters if prediction differs from alt-prediction
  if (pred.isTaken != altPred.isTaken ||
      (pred.isTaken && (pred.target != altPred.target))) {
    bool wasUseful = (pred.isTaken == isTaken);
    uint8_t currentU = tageTables_[predTable][indices[predTable]].u;
    if (wasUseful && currentU < 3) {
      (tageTables_[predTable][indices[predTable]].u)++;
    } if (!wasUseful && currentU > 0) {
      (tageTables_[predTable][indices[predTable]].u)--;
    }

  }
}

} // namespace simeng