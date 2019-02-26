#include "BalancedPortAllocator.hh"

#include <cassert>

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

  bool foundPort = false;
  uint16_t bestWeight;
  uint8_t bestPort = 0;
  for (const auto& portIndex : available) {
    if (!foundPort || weights[portIndex] < bestWeight) {
      foundPort = true;
      bestWeight = weights[portIndex];
      bestPort = portIndex;
    }
  }

  assert(foundPort && "Unsupported group; cannot allocate a port");

  weights[bestPort]++;
  return bestPort;
}

void BalancedPortAllocator::issued(uint8_t port) { weights[port]--; }

}  // namespace outoforder
}  // namespace simeng
