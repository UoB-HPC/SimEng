#include "simeng/branchpredictors/TAGEPredictor.hh"

namespace simeng {

TAGEPredictor::TAGEPredictor(ryml::ConstNodeRef config)
    : btbBits_(config["Branch-Predictor"]["BTB-Tag-Bits"].as<uint8_t>()),
      TAGETableBits_(
          config["Branch-Predictor"]["TAGE-Table-Bits"].as<uint8_t>()),
      numTAGETables_(
          config["Branch-Predictor"]["Num-TAGE-Tables"].as<uint8_t>()),
      satCntBits_(
          config["Branch-Predictor"]["Saturating-Count-Bits"].as<uint8_t>()),
      globalHistoryLength_(
          config["Branch-Predictor"]["Global-History-Length"].as<uint16_t>()),
      rasSize_(config["Branch-Predictor"]["RAS-entries"].as<uint16_t>()),
      globalHistory_(1 << (numTAGETables_ + 1)),
      tagLength_(config["Branch-Predictor"]["Tag-Length"].as<uint8_t>()) {
  // Calculate the saturation counter boundary between weakly taken and
  // not-taken. `(2 ^ num_sat_cnt_bits) / 2` gives the weakly taken state
  // value
  uint8_t weaklyTaken = (uint8_t)1 << (satCntBits_ - 1);
  uint8_t satCntVal = (config["Branch-Predictor"]["Fallback-Static-Predictor"]
                           .as<std::string>() == "Always-Taken")
                          ? weaklyTaken
                          : (weaklyTaken - 1);

  // Set up non-tagged default prediction table
  btb_ = std::vector<std::pair<uint8_t, uint64_t>>(1ul << btbBits_,
                                                   {satCntVal, 0});

  // Set up tagged prediction tables
  for (uint32_t i = 0; i < numTAGETables_; i++) {
    std::vector<TAGEEntry> newTable;
    for (uint32_t j = 0; j < (1ul << TAGETableBits_); j++) {
      TAGEEntry newEntry = {satCntVal, 0, 1, 0};
      newTable.push_back(newEntry);
    }
    TAGETables_.push_back(newTable);
  }
}

TAGEPredictor::~TAGEPredictor() {
  btb_.clear();
  ras_.clear();
  rasHistory_.clear();
  ftq_.clear();
}

BranchPrediction TAGEPredictor::predict(uint64_t address, BranchType type,
                                        int64_t knownOffset) {
  BranchPrediction prediction;
  BranchPrediction altPrediction;
  int8_t predTable;
  std::shared_ptr<uint64_t[]> indices(new uint64_t[numTAGETables_]);
  std::shared_ptr<uint64_t[]> tags(new uint64_t[numTAGETables_]);
  getTaggedPrediction(address, &prediction, &altPrediction, &predTable, indices,
                      tags);

  // If known offset then overwrite predicted target with this
  if (knownOffset != 0) prediction.target = address + knownOffset;

  // Amend prediction based on branch type
  if (type == BranchType::Unconditional) {
    prediction.isTaken = true;
    predTable = -1;
  } else if (type == BranchType::Return) {
    prediction.isTaken = true;
    // Return branches can use the RAS if an entry is available
    if (ras_.size() > 0) {
      prediction.target = ras_.back();
      // Record top of RAS used for target prediction
      rasHistory_[address] = ras_.back();
      ras_.pop_back();
    }
    predTable = -1;
  } else if (type == BranchType::SubroutineCall) {
    prediction.isTaken = true;
    // Subroutine call branches must push their associated return address to RAS
    if (ras_.size() >= rasSize_) {
      ras_.pop_front();
    }
    ras_.push_back(address + 4);
    // Record that this address is a branch-and-link instruction
    rasHistory_[address] = 0;
    predTable = -1;
  } else if (type == BranchType::Conditional ||
             type == BranchType::LoopClosing) {
    if (!prediction.isTaken) prediction.target = address + 4;
  }

  // Store prediction data so that update() has the info it needs
  ftqEntry newEntry = {predTable, indices, tags, prediction, altPrediction};
  ftq_.push_back(newEntry);

  // Speculatively update the global history
  globalHistory_.addHistory(prediction.isTaken);
  return prediction;
}

void TAGEPredictor::update(uint64_t address, bool isTaken,
                           uint64_t targetAddress, simeng::BranchType type,
                           uint64_t instructionId) {
  // Make sure that this function is called in program order; and then update
  // the lastUpdatedInstructionId variable
  assert(instructionId >= lastUpdatedInstructionId &&
         (lastUpdatedInstructionId = instructionId) >= 0 &&
         "Update not called on branch instructions in program order");

  updateBtb(address, isTaken, targetAddress);

  updateTaggedTables(isTaken, targetAddress);

  // Update global history if prediction was incorrect
  if (ftq_.front().prediction.isTaken != isTaken) {
    // We know how many predictions there have since been by the size of the FTQ
    globalHistory_.updateHistory(isTaken, ftq_.size());
  }

  // Pop used ftq entry from ftq
  ftq_.pop_front();
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

  assert((ftq_.size() > 0) &&
         "Cannot flush instruction from Branch Predictor "
         "when the ftq is empty");
  ftq_.pop_back();

  // Roll back global history
  globalHistory_.rollBack();
}

void TAGEPredictor::getTaggedPrediction(uint64_t address,
                                        BranchPrediction* prediction,
                                        BranchPrediction* altPrediction,
                                        int8_t* predTable,
                                        std::shared_ptr<uint64_t[]> indices,
                                        std::shared_ptr<uint64_t[]> tags) {
  // Get a basic prediction from the btb
  BranchPrediction basePrediction = getBtbPrediction(address);
  prediction->isTaken = basePrediction.isTaken;
  prediction->target = basePrediction.target;
  *predTable = -1;

  // Check each of the tagged predictor tables for an entry matching this
  // branch.  If found, update the best prediction.  The greater the table
  // number, the longer global history it has access to.  Therefore, the
  // greater the table number, the better the prediction.
  for (int8_t table = 0; table < numTAGETables_; table++) {
    // Determine the index and tag for this table, as they vary depending on
    // the length of global history
    uint64_t index = getTaggedIndex(address, table);
    indices.get()[table] = index;
    uint64_t tag = getTag(address, table);
    tags.get()[table] = tag;

    // If tag matches, then use this prediction
    if (TAGETables_[table][index].tag == tag) {
      altPrediction->isTaken = prediction->isTaken;
      altPrediction->target = prediction->target;

      prediction->isTaken = (TAGETables_[table][index].satCnt >= 2);
      prediction->target = TAGETables_[table][index].target;
      *predTable = table;
    }
  }
}

BranchPrediction TAGEPredictor::getBtbPrediction(uint64_t address) {
  // Get prediction from BTB
  uint64_t index = (address >> 2) & ((1ull << btbBits_) - 1);
  bool direction = (btb_[index].first >= (1 << (satCntBits_ - 1)));
  uint64_t target = btb_[index].second;
  return {direction, target};
}

uint64_t TAGEPredictor::getTaggedIndex(uint64_t address, uint8_t table) {
  // Get the XOR of the address (sans two least-significant bits) and the
  // global history (folded onto itself to make it of the correct size).
  uint64_t h1 = (address >> 2);
  uint64_t h2 = globalHistory_.getFolded(1ull << (table + 1), TAGETableBits_);
  // Then truncate the XOR to make it fit the desired size of an index
  return (h1 ^ h2) & ((1 << TAGETableBits_) - 1);
}

uint64_t TAGEPredictor::getTag(uint64_t address, uint8_t table) {
  // Hash function here is pretty arbitrary
  uint64_t h1 = address;
  uint64_t h2 =
      globalHistory_.getFolded((1ull << table), ((1ull << tagLength_) - 1));
  return (h1 ^ h2) & ((1ull << tagLength_) - 1);
}

void TAGEPredictor::updateBtb(uint64_t address, bool isTaken,
                              uint64_t targetAddress) {
  // Calculate 2-bit saturating counter value
  uint8_t satCntVal = btb_[((address >> 2) & ((1ull << btbBits_) - 1))].first;
  // Only alter value if it would transition to a valid state
  // (i.e., avoid overflow)
  if (!((satCntVal == (1ull << satCntBits_) - 1) && isTaken) &&
      !(satCntVal == 0 && !isTaken)) {
    satCntVal += isTaken ? 1 : -1;
  }

  // Update BTB entry
  btb_[((address >> 2) & ((1ull << btbBits_) - 1))].first = satCntVal;
  if (isTaken) {
    btb_[((address >> 2) & ((1ull << btbBits_) - 1))].second = targetAddress;
  }
}

void TAGEPredictor::updateTaggedTables(bool isTaken, uint64_t target) {
  // Get stored information from the FTQ
  int8_t predTable = ftq_.front().predTable;
  std::shared_ptr<uint64_t[]> indices = ftq_.front().indices;
  std::shared_ptr<uint64_t[]> tags = ftq_.front().tags;
  BranchPrediction pred = ftq_.front().prediction;
  BranchPrediction altPred = ftq_.front().altPrediction;

  // Update the prediction counter if tagged prediction table was used
  if (predTable != -1) {
    uint64_t predIndex = indices.get()[predTable];
    if (isTaken && (TAGETables_[predTable][predIndex].satCnt < 3)) {
      (TAGETables_[predTable][predIndex].satCnt)++;
    } else if (!isTaken && (TAGETables_[predTable][predIndex].satCnt > 0)) {
      (TAGETables_[predTable][predIndex].satCnt)--;
    }
  }

  // Allocate new entry if prediction was wrong and space for a new entry is
  // available
  // -- Check higher order tagged predictor tables to see if there is a
  // non-useful entry that can be replaced
  if (isTaken != pred.isTaken || (isTaken && (target != pred.target))) {
    for (uint8_t table = predTable + 1; table < numTAGETables_; table++) {
      if (TAGETables_[table][indices.get()[table]].u <= 1) {
        TAGETables_[table][indices.get()[table]] = {
            (isTaken ? (uint8_t)2 : (uint8_t)1), tags.get()[table], (uint8_t)2,
            target};
        break;
      }
    }
  }

  // Update the usefulness counters if prediction is from a tagged prediction
  // table and differs from alt-prediction
  if ((predTable != -1) &&
      (pred.isTaken != altPred.isTaken ||
       (pred.isTaken && (pred.target != altPred.target)))) {
    bool wasUseful = (pred.isTaken == isTaken);
    uint8_t currentU = TAGETables_[predTable][indices.get()[predTable]].u;
    // Make sure that update is possible
    if (wasUseful && currentU < 3) {
      (TAGETables_[predTable][indices.get()[predTable]].u)++;
    }
    if (!wasUseful && currentU > 0) {
      (TAGETables_[predTable][indices.get()[predTable]].u)--;
    }
  }
}

}  // namespace simeng