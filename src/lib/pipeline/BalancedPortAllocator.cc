#include "simeng/pipeline/BalancedPortAllocator.hh"

#include <cassert>

namespace simeng {
namespace pipeline {

BalancedPortAllocator::BalancedPortAllocator(
    const std::vector<std::vector<uint16_t>>& portArrangement)
    : weights(portArrangement.size(), 0) {}

uint16_t BalancedPortAllocator::allocate(const std::vector<uint16_t>& ports) {
  assert(ports.size() &&
         "No supported ports supplied; cannot allocate from a empty set");
  bool foundPort = false;
  uint16_t bestWeight = 0xFFFF;
  uint16_t bestPort = 0;
  for (const auto& portIndex : ports) {
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

void BalancedPortAllocator::issued(uint16_t port) {
  assert(weights[port] > 0);
  weights[port]--;
}
void BalancedPortAllocator::deallocate(uint16_t port) { issued(port); }

void BalancedPortAllocator::setRSSizeGetter(
    std::function<void(std::vector<uint32_t>&)> rsSizes) {
  rsSizes_ = rsSizes;
}

void BalancedPortAllocator::tick() {}

}  // namespace pipeline
}  // namespace simeng
