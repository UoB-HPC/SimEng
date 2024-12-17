#include "simeng/pipeline/M1PortAllocator.hh"

#include <cassert>
#include <cstdint>
#include <vector>

namespace simeng {
namespace pipeline {

M1PortAllocator::M1PortAllocator(
    const std::vector<std::vector<uint16_t>>& portArrangement,
    std::vector<std::pair<uint16_t, uint64_t>> rsArrangement)
    : weights(portArrangement.size(), 0), rsArrangement_(rsArrangement) {}

uint16_t M1PortAllocator::allocate(const std::vector<uint16_t>& ports) {
  assert(ports.size() &&
         "No supported ports supplied; cannot allocate from a empty set");
  bool foundPort = false;
  uint16_t bestPort = 0;
  uint16_t bestWeight = 0xFFFF;

  uint16_t bestRSQueueSize = 0xFFFF;
  // Only used in assertions so produces warning in release mode
  [[maybe_unused]] bool foundRS = false;

  // Update the reference for number of free spaces in the reservation
  // stations
  rsFreeSpaces.clear();
  rsSizes_(rsFreeSpaces);

  for (const auto& portIndex : ports) {
    auto rsIndex = rsArrangement_[portIndex].first;
    auto rsSize = rsArrangement_[portIndex].second;
    auto rsFreeSpace = rsFreeSpaces[rsIndex];
    auto rsQueueSize = (rsSize - rsFreeSpace);

    if (rsQueueSize < bestRSQueueSize) {
      bestRSQueueSize = rsQueueSize;
      foundRS = true;

      // Search for the lowest-weighted port available
      if (!foundPort || weights[portIndex] < bestWeight) {
        foundPort = true;
        bestWeight = weights[portIndex];
        bestPort = portIndex;
      }
    }
  }

  assert(foundPort && foundRS && "Unsupported group; cannot allocate a port");

  // Increment the weight of the allocated port
  weights[bestPort]++;
  return bestPort;
}

void M1PortAllocator::issued(uint16_t port) {
  assert(weights[port] > 0);
  weights[port]--;
}

void M1PortAllocator::deallocate(uint16_t port) { issued(port); }

void M1PortAllocator::setRSSizeGetter(
    std::function<void(std::vector<uint32_t>&)> rsSizes) {
  rsSizes_ = rsSizes;
}

void M1PortAllocator::tick() {}
}  // namespace pipeline
}  // namespace simeng
