#include "simeng/BTBPredictor.hh"

namespace simeng {

BTBPredictor::BTBPredictor(uint8_t bits)
    : bits(bits), btb(1 << bits), hasValue(1 << bits, false) {}

BranchPrediction BTBPredictor::predict(uint64_t instructionAddress) {
  // Simple hash; lowest `bits` bits of address
  auto addressHash = hash(instructionAddress);

  return {hasValue[addressHash], btb[addressHash]};
}

void BTBPredictor::update(uint64_t instructionAddress, bool taken,
                          uint64_t targetAddress) {
  auto addressHash = hash(instructionAddress);

  hasValue[addressHash] = taken;
  btb[addressHash] = targetAddress;
}

uint64_t BTBPredictor::hash(uint64_t instructionAddress) const {
  uint64_t mask = (1 << bits) - 1;
  return instructionAddress & mask;
}

}  // namespace simeng
