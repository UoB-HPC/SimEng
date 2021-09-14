#pragma once

#include <deque>
#include <stack>
#include <tuple>
#include <unordered_map>
#include <vector>

#include "simeng/BranchPredictor.hh"

namespace simeng {

/** An A64FX based branch predictor containing a Branch Target Buffer,
 * a Branch Weight Table, and a Return Address Stack implementation. */
class BTB_BWTPredictor : public BranchPredictor {
 public:
  /** Construct a BTB/BWT predictor, with 2^bits rows and a
   * number of entires per row defined by associative. */
  BTB_BWTPredictor(uint8_t bits, uint8_t associative);

  /** Generate a branch prediction for the supplied instruction address.
   * Use a combination of a BTB entry, a global history, and an agreement
   * policy. */
  BranchPrediction predict(std::shared_ptr<Instruction>& uop) override;

  /** Update the BTB entry for the supplied instruction address with the taken
   * state and targt address. Also update the global state of the predictor*/
  void update(std::shared_ptr<Instruction>& uop, bool taken,
              uint64_t targetAddress) override;

 private:
  /** The bitlength of the BTB index; BTB will have 2^bits entries. */
  uint8_t bits;

  /** The width of each entry */
  uint8_t width;

  /** Mask for truncating values to desired number of bits. */
  uint64_t mask;

  /** An x-way associative 2^bits length vector used for storing branch targets.
   */
  std::vector<std::vector<std::tuple<uint64_t, uint64_t, int64_t>>> btb;

  /** The pattern history table. */
  std::vector<uint8_t> pht;

  /** A target history for the BTB */
  uint64_t thr;

  /** A global history of branch directions in unsigned format {0|1}. */
  uint64_t ghrUnsigned;

  /** A return address stack */
  std::stack<uint64_t> ras;

  /** Records occupied entries in BTB. */
  std::vector<std::vector<uint64_t>> touched;

  /** Records latest used associative entry of a giving BTB row. */
  std::vector<uint8_t> associativeIndex;

  /** Records mapping between an instruction and a BTB entry. */
  std::unordered_map<uint64_t, std::pair<uint64_t, uint8_t>> mappings;

  /** Generate a BTB lookup hash for the specified address by trimming the
   * lowest `bits` bits. */
  uint64_t hash(uint64_t instructionAddress) const;
};

}  // namespace simeng
