#pragma once

#include <cassert>
#include <deque>
#include <map>
#include <vector>
#include <algorithm>

#include "simeng/branchpredictors/BranchPredictor.hh"
#include "simeng/branchpredictors/BranchHistory.hh"
#include "simeng/config/SimInfo.hh"

namespace simeng {

struct TageEntry {
  uint8_t satCnt;
  uint64_t tag;
  uint8_t u; // usefulness counter
  uint64_t target;
};

struct ftqEntry {
  uint8_t predTable;
  std::vector<uint64_t> indices;
  std::vector<uint64_t> tags;
  BranchPrediction prediction;
  BranchPrediction altPrediction;
};

/** ToDo -- Explain TAGE */

class TagePredictor : public BranchPredictor {
 public:
  /** Initialise predictor models. */
  TagePredictor(ryml::ConstNodeRef config = config::SimInfo::getConfig());
  ~TagePredictor();

  /** Generate a branch prediction for the supplied instruction address, a
   * branch type, and a known branch offset; defaults to 0 meaning offset is not
   * known. Returns a branch direction and branch target address. */
  BranchPrediction predict(uint64_t address, BranchType type,
                           int64_t knownOffset = 0) override;

  /** Updates appropriate predictor model objects based on the address, type and
   * outcome of the branch instruction.  Update must be called on
   * branches in program order.  To check this, instructionId is also passed
   * to this function. */
  void update(uint64_t address, bool isTaken, uint64_t targetAddress,
              BranchType type, uint64_t instructionId) override;

  /** Provides flushing behaviour for the implemented branch prediction schemes
   * via the instruction address.  Branches must be flushed in reverse
   * program order (though, if a block of n instructions is being flushed at
   * once, the exact order that the individual instructions within this block
   * are flushed does not matter so long as they are all flushed). */
  void flush(uint64_t address) override;

 private:
  /** Returns a btb prediction for this branch */
  BranchPrediction getBtbPrediction(uint64_t address);

  /** Todo */
  void getTaggedPrediction(uint64_t address, BranchPrediction* prediction,
                           BranchPrediction* altPrediction,
                           uint8_t* predTable,
                           std::vector<uint64_t>* indices,
                           std::vector<uint64_t>* tags);

  /** Get the index of a branch for a given address and table */
  uint64_t getTaggedIndex(uint64_t address, uint8_t table);

  /** Return a hash of the address and the global history that is then trimmed
    * to the length of the tags.  The tag varies depending on
    * the table that is being accessed */
  uint64_t getTag(uint64_t address, uint8_t table);

  void updateBtb(uint64_t address, bool isTaken, uint64_t target);

  void updateTaggedTables(uint64_t address, bool isTaken, uint64_t target);

  /** The bitlength of the BTB index; BTB will have 2^bits entries. */
  uint8_t btbBits_;

  /** A 2^bits length vector of pairs containing a satCntBits_-bit saturating
   * counter and a branch target. */
  std::vector<std::pair<uint8_t, uint64_t>> btb_;

  uint64_t tageTableBits_ = 12;
  uint8_t numTageTables_ = 6;

  std::vector<std::vector<TageEntry>> tageTables_;

  /** Fetch Target Queue containing the direction prediction and previous global
   * history state of branches that are currently unresolved */
  std::deque<ftqEntry> ftq_;

  /** The number of bits used to form the saturating counter in a BTB entry. */
  uint8_t satCntBits_;

  /** The number of previous branch directions recorded globally. */
  uint16_t globalHistoryLength_;

  /** A return address stack. */
  std::deque<uint64_t> ras_;

  /** RAS history with instruction address as the keys. A non-zero value
   * represents the target prediction for a return instruction and a 0 entry for
   * a branch-and-link instruction. */
  std::map<uint64_t, uint64_t> rasHistory_;

  /** The size of the RAS. */
  uint16_t rasSize_;

  /** An n-bit history of previous branch directions where n is equal to
   * globalHistoryLength_.  Each bit represents a branch taken (1) or not
   * taken (0), with the most recent branch being the least-significant-bit */
  BranchHistory globalHistory_;

  uint8_t tagLength_ = 8;

  // This variable is used only in debug mode -- therefore hide behind ifdef
#ifndef NDEBUG
  /** The Id of the last instruction that update was called on -- used to
   * ensure that update is called in program order. */
  uint64_t lastUpdatedInstructionId = 0;
#endif
};

}  // namespace simeng
