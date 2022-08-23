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
  //printf("--- Allocating --- \n");
  assert(ports.size() &&
         "No supported ports supplied; cannot allocate from a empty set");
  bool foundPort = false;
  uint8_t bestPort = 0;
  uint16_t bestWeight = 0xFFFF;

  uint16_t bestRSQueueSize = 0xFFFF;
  bool foundRS = false;
  std::vector<uint64_t> rsFreeSpaces;
  rsSizes_(rsFreeSpaces);

  for (const auto& portIndex : ports) {
    auto rsIndex = rsArrangement_[portIndex].first;
    auto rsSize = rsArrangement_[portIndex].second;
    auto rsFreeSpace = rsFreeSpaces[rsIndex];
    auto rsQueueSize = (rsSize - rsFreeSpace);

    // printf("n_RS: %d\tPort Index %d\tRS Index: %d\tRS Size: %lu\tRS Free
    // Space: %lu\tqueuesize: %d\tWeight: %f\tbestWeight:
    // %f\n",rsFreeSpaces.size(),portIndex,
    // rsIndex,rsSize,rsFreeSpace,rsQueueSize,weights[portIndex], bestWeight);
    if (rsQueueSize < bestRSQueueSize) {
      bestRSQueueSize = rsQueueSize;
      foundRS = true;

      // Search for the lowest-weighted port available
      if (!foundPort || weights[portIndex] < bestWeight) {
        // printf("Using RS %d\n",rsIndex);
        foundPort = true;
        bestWeight = weights[portIndex];  // weights[portIndex];
        bestPort = portIndex;
      }
    }
  }

  assert(foundPort && foundRS && "Unsupported group; cannot allocate a port");

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
