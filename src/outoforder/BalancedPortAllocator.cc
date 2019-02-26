#include "BalancedPortAllocator.hh"

#include <limits>

namespace simeng {
namespace outoforder {

BalancedPortAllocator::BalancedPortAllocator(
    std::vector<std::vector<uint16_t>> portArrangement)
    : weights(portArrangement.size(), 0) {
  for (size_t portIndex = 0; portIndex < portArrangement.size(); portIndex++) {
    const auto& groups = portArrangement[portIndex];
    for (const auto& group : groups) {
      if (group >= supportMatrix.size()) {
        supportMatrix.resize(group + 1);
      }
      supportMatrix[group].push_back(portIndex);
    }
  }
}

uint8_t BalancedPortAllocator::allocate(uint16_t instructionGroup) {
  const auto& available = supportMatrix[instructionGroup];

  uint16_t bestWeight = std::numeric_limits<uint16_t>::max();
  uint8_t bestPort = 0;
  for (const auto& portIndex : available) {
    if (weights[portIndex] < bestWeight) {
      bestPort = portIndex;
    }
  }

  weights[bestPort]++;
  return bestPort;
}

void BalancedPortAllocator::issued(uint8_t port) { weights[port]--; }

}  // namespace outoforder
}  // namespace simeng
