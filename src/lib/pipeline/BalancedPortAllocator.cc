#include "simeng/pipeline/BalancedPortAllocator.hh"

#include <cassert>

namespace simeng {
namespace pipeline {

BalancedPortAllocator::BalancedPortAllocator(
    std::vector<std::vector<uint16_t>> portArrangement)
    : weights(portArrangement.size(), 0) {
  // Construct the  support matrix
  for (size_t portIndex = 0; portIndex < portArrangement.size(); portIndex++) {
    const auto& groups = portArrangement[portIndex];
    // Add this port to the matrix entry for each group it supports
    for (const auto& group : groups) {
      if (group >= supportMatrix.size()) {
        // New highest group ID; expand matrix
        supportMatrix.resize(group + 1);
      }
      supportMatrix[group].push_back(portIndex);
    }
  }
}

uint8_t BalancedPortAllocator::allocate(uint16_t instructionGroup) {
  // Find the list of ports that support this instruction group
  assert(instructionGroup < supportMatrix.size() &&
         "instruction group not covered by port allocator");
  const auto& available = supportMatrix[instructionGroup];

  bool foundPort = false;
  uint16_t bestWeight;
  uint8_t bestPort = 0;
  for (const auto& portIndex : available) {
    // Search for the lowest-weighted port available
    if (!foundPort || weights[portIndex] < bestWeight) {
      foundPort = true;
      bestWeight = weights[portIndex];
      bestPort = portIndex;
    }
  }

  assert(foundPort && "Unsupported group; cannot allocate a port");

  // Increment the weight of the allocated port
  weights[bestPort]++;
  return bestPort;
}

void BalancedPortAllocator::issued(uint8_t port) { weights[port]--; }
void BalancedPortAllocator::deallocate(uint8_t port) { issued(port); };

}  // namespace pipeline
}  // namespace simeng
