#include "simeng/pipeline/M1PortAllocator.hh"

#include <cassert>
#include <cstdint>
#include <vector>

// TODO REMOVE
#include "stdio.h"

namespace simeng {
namespace pipeline {

M1PortAllocator::M1PortAllocator(
    const std::vector<std::vector<uint16_t>>& portArrangement,
    std::vector<std::pair<uint8_t, uint64_t>> rsArrangement)
    : weights(portArrangement.size(), 0), rsArrangement_(rsArrangement) {}

uint8_t M1PortAllocator::allocate(const std::vector<uint8_t>& ports) {
  assert(ports.size() &&
         "No supported ports supplied; cannot allocate from a empty set");
  bool foundPort = false;
  uint16_t bestWeight = 0xFFFF;
  uint8_t bestPort = 0;
  std::vector<uint64_t> rsFreeSpaces;
  rsSizes_(rsFreeSpaces);

  for (const auto& portIndex : ports) {
    auto rsIndex = rsArrangement_[portIndex].first;
    auto rsSize = rsArrangement_[portIndex].second;
    auto rsFreeSpace = rsFreeSpaces[rsIndex];
    float biasedWeight =
        (float)weights[portIndex] * (float)rsFreeSpace / (float)rsSize;
    // printf("RS Index: %d\tRS Size: %lu\nRS Free Space: %lu\tweight:
    // %d\tbiasedWeight:
    // %f\n",rsIndex,rsSize,rsFreeSpace,weights[portIndex],biasedWeight);
    // Search for the lowest-weighted port available
    if (!foundPort || biasedWeight < bestWeight) {
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

void M1PortAllocator::issued(uint8_t port) {
  assert(weights[port] > 0);
  weights[port]--;
}

void M1PortAllocator::deallocate(uint8_t port) { issued(port); };

void M1PortAllocator::setRSSizeGetter(
    std::function<void(std::vector<uint64_t>&)> rsSizes) {
  rsSizes_ = rsSizes;
}

void M1PortAllocator::tick() {}
}  // namespace pipeline
}  // namespace simeng
