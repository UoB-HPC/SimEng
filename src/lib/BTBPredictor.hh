#pragma once

#include "BranchPredictor.hh"

#include <vector>

namespace simeng {

/** A Branch Target Buffer based branch predictor. Keeps an internal BTB with
 * previously seen branch target buffer addresses. */
class BTBPredictor : public BranchPredictor {
 public:
  /** Construct a BTB predictor, with 2^bits BTB entries. */
  BTBPredictor(uint8_t bits);

  /** Generate a branch prediction for the supplied instruction address. Finds
   * the corresponding BTB entry and returns a "taken" prediction with the
   * stored target. If no entry is found, predicts "not taken". */
  BranchPrediction predict(uint64_t instructionAddress) override;

  /** Update the BTB entry for the supplied instruction address with the taken
   * state and targt address. */
  void update(uint64_t instructionAddress, bool taken,
              uint64_t targetAddress) override;

 private:
  /** The bitlength of the BTB index; BTB will have 2^bits entries. */
  uint8_t bits;

  /** A 2^bits length vector used for storing branch targets. */
  std::vector<uint64_t> btb;

  /** A 2^bits length vector storing a presence. */
  std::vector<bool> hasValue;

  /** Generate a BTB lookup hash for the specified address by trimming the
   * lowest `bits` bits. */
  uint64_t hash(uint64_t instructionAddress) const;
};

}  // namespace simeng
