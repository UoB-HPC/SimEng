#pragma once

#include "simeng/BranchPredictor.hh"

#include <vector>
#include <stack>
#include <deque>
#include <tuple>

namespace simeng {

/** A Branch Target Buffer based branch predictor. Keeps an internal BTB with
 * previously seen branch target buffer addresses. */
class BTB_BTWPredictor : public BranchPredictor {
 public:
  /** Construct a BTB/BTW predictor, with 2^bits entries. */
  BTB_BTWPredictor(uint8_t bits, uint8_t associative);

  /** Generate a branch prediction for the supplied instruction address. Finds
   * the corresponding BTB entry and returns a "taken" prediction with the
   * stored target. If no entry is found, predicts "not taken". */
  BranchPrediction predict(std::shared_ptr<Instruction> uop) override;

  /** Update the BTB entry for the supplied instruction address with the taken
   * state and targt address. */
  void update(std::shared_ptr<Instruction> uop, bool taken,
              uint64_t targetAddress) override;

 private:
  /** The bitlength of the BTB index; BTB will have 2^bits entries. */
  uint8_t bits;

  /** The width of each entry */
  uint8_t width;

  /** Mask for truncating values to desired number of bits. */
  uint64_t mask;  

  /** An x-way associative 2^bits length vector used for storing branch targets. */
  std::vector<std::vector<std::tuple<uint64_t, uint64_t, int64_t>>> btb;

  /** A 2^bits length vector storing a presence. */
   std::vector<std::vector<int8_t>> hasValue;

  /** The pattern history table. */
  std::vector<uint8_t> pht;

  /** A target history for the BTB */
  uint64_t thr;

  /** A global history of branch directions in unsigned format {0|1}. */
  uint64_t ghrUnsigned;

  /** A global history of branch directions in signed format {-1|1}. */
  std::deque<int64_t> ghrSigned;

  /** A global table of branch weightings. */
  std::deque<int64_t> bwt;

  /** A return address stack */
  std::stack<uint64_t> ras;

  /** Generate a BTB lookup hash for the specified address by trimming the
   * lowest `bits` bits. */
  uint64_t hash(uint64_t instructionAddress) const;
};

}  // namespace simeng
