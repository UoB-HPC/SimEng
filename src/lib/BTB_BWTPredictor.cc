#include "simeng/BTB_BWTPredictor.hh"

#include <cassert>

namespace simeng {

BTB_BWTPredictor::BTB_BWTPredictor(uint8_t bits, uint8_t associative)
    : bits(bits),
      width(associative),
      mask((1 << bits) - 1),
      btb(1 << bits, *(new std::vector<std::tuple<uint64_t, uint64_t, int64_t>>(
                         associative))),
      pht(1 << bits, 1),
      touched(std::vector<std::vector<uint64_t>>(
          1 << bits, *(new std::vector<uint64_t>(associative)))),
      associativeIndex(1 << 11, 0) {
  thr = 0;
  ghrUnsigned = 0;
}

BranchPrediction BTB_BWTPredictor::predict(std::shared_ptr<Instruction>& uop) {
  auto instructionAddress = uop->getInstructionAddress();
  std::pair<uint64_t, uint8_t>& btbIndex = mappings[instructionAddress];

  BranchPrediction prediction;
  // Provide new BTB entry if the branch doesn't have one or it's
  // previous allocation has been replaced.
  if (touched[btbIndex.first][btbIndex.second] != instructionAddress) {
    auto addressHash = hash(instructionAddress);
    btbIndex.first = addressHash;
    // Increment secondary index for oldest-replacement scheme
    btbIndex.second = (++associativeIndex[addressHash]) % width;
    mappings[instructionAddress] = btbIndex;
    touched[btbIndex.first][btbIndex.second] = instructionAddress;
    std::get<2>(btb[btbIndex.first][btbIndex.second]) = -1;
  }

  // If the branch is a subroutine return then try and use return address stack
  if (uop->isRET() && ras.size() > 0) {
    uint64_t target = ras.top();
    ras.pop();
    prediction = {true, target};
  } else {
    uint64_t phtIndex = ghrUnsigned ^ (instructionAddress & mask);
    std::get<1>(btb[btbIndex.first][btbIndex.second]) = phtIndex;

    uint8_t agreement = pht[phtIndex] / 2;
    if (std::get<2>(btb[btbIndex.first][btbIndex.second]) ==
        -1) {  // Static prediction
      prediction.taken = 0;
    } else if (agreement) {
      prediction.taken = std::get<2>(btb[btbIndex.first][btbIndex.second]);
    } else {
      prediction.taken = !std::get<2>(btb[btbIndex.first][btbIndex.second]);
    }
    prediction.target = std::get<0>(btb[btbIndex.first][btbIndex.second]);
  }

  // If appropiate branch type, add to return address stack.
  if (uop->isBL()) {
    ras.push(instructionAddress + 4);
  }

  return prediction;
}

void BTB_BWTPredictor::update(std::shared_ptr<Instruction>& uop, bool taken,
                              uint64_t targetAddress) {
  auto instructionAddress = uop->getInstructionAddress();
  std::pair<uint64_t, uint8_t>& btbIndex = mappings[instructionAddress];

  // Update btb entry
  if (taken) std::get<0>(btb[btbIndex.first][btbIndex.second]) = targetAddress;
  if (std::get<2>(btb[btbIndex.first][btbIndex.second]) == -1) {
    std::get<2>(btb[btbIndex.first][btbIndex.second]) = taken;
  }

  // Update pattern history table.
  uint64_t phtIndex = std::get<1>(btb[btbIndex.first][btbIndex.second]);
  if (std::get<2>(btb[btbIndex.first][btbIndex.second]) == taken) {
    pht[phtIndex] = pht[phtIndex] == 4 ? 4 : pht[phtIndex] + 1;
  } else {
    pht[phtIndex] = pht[phtIndex] == 0 ? 0 : pht[phtIndex] - 1;
  }

  // Update bitlength history registers.
  thr = targetAddress & mask;
  ghrUnsigned = ((ghrUnsigned << 1) | taken) & mask;
}

uint64_t BTB_BWTPredictor::hash(uint64_t instructionAddress) const {
  uint64_t combination = thr ^ ghrUnsigned;
  return combination ^ (instructionAddress & mask);
}

}  // namespace simeng
