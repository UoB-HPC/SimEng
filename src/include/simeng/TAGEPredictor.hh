#pragma once

#include <deque>
#include <map>
#include <vector>

#include "simeng/BranchPredictor.hh"
#include "simeng/config/SimInfo.hh"

namespace simeng {

struct predictorEntry {
  uint64_t target;
  uint64_t tag;
  uint8_t counter;
  uint8_t usefulness;
};

struct ftqEntry {
  bool taken;
  uint64_t target;
  bool altPrediction;
  uint64_t history;
  int8_t provider;
  int8_t altPred;
};

/**
 * ToDo -- DESCRIPTION OF TAGE PREDICTOR
 *
 */

class TAGEPredictor : public BranchPredictor {
 public:
  TAGEPredictor(ryml::ConstNodeRef config = config::SimInfo::getConfig());
  ~TAGEPredictor();

  BranchPrediction predict(uint64_t address, BranchType type,
                           int64_t knownOffset = 0) override;

  void update(uint64_t address, bool taken, uint64_t targetAddress, BranchType
                                                                     type)
      override;

  void flush(uint64_t address) override;

  void addToFTQ(uint64_t address, bool taken) override;

 private:
  /**
   * Gets the default prediction from the untagged predictor table T0
   */
  BranchPrediction getDefaultPrediction(uint64_t address);

  uint64_t getTagHash(uint64_t address, uint64_t history);

  uint64_t getIndex(uint64_t address, uint64_t history, int8_t predictor);

  /**
   * The number of tagged predictor tables in the ITTAGE predictor (i.e
   * . excluding the untagged T0 predictor table).  Hard coded to 4 for the
   * moment.
   * ToDo -- make this definable in the config file
   */
  uint32_t numTables_ = 4;

  /**
   * A history of the directions taken by the previous branches
   */
  uint64_t globalHistory_ = 0;

  /**
   * The untagged predictor table
   */
  std::array<predictorEntry, 4096> T0Predictor_ = std::array<predictorEntry,
                                                             4096>();
  uint32_t T0Entries_ = 4096;

  /**
   * A vector of the tagged predictors.  Each entry is a predictor table.  Each
   * predictor table contains n entries
   */
  std::vector<std::array<predictorEntry, 1024>> taggedPredictors_;
  uint32_t taggedEntries_ = 1024;

  /** Fetch Target Queue containing the state of the BP at the point of
   * prediction for the branches that are currently unresolved */
  std::deque<ftqEntry> ftq_;

  /** A return address stack. */
  std::deque<uint64_t> ras_;

  /** RAS history with instruction address as the keys. A non-zero value
   * represents the target prediction for a return instruction and a 0 entry for
   * a branch-and-link instruction. */
  std::map<uint64_t, uint64_t> rasHistory_;

  /** The size of the RAS. */
  uint64_t rasSize_;
};

} // namespace simeng