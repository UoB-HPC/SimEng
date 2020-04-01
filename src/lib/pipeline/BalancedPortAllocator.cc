#include "simeng/pipeline/BalancedPortAllocator.hh"

#include <cassert>

namespace simeng {
namespace pipeline {

BalancedPortAllocator::BalancedPortAllocator(
    std::vector<std::vector<std::vector<std::pair<uint16_t, uint8_t>>>> portArrangement)
    : weights(portArrangement.size(), 0) {
  // Construct the  support matrix
  for (size_t portIndex = 0; portIndex < portArrangement.size(); portIndex++) {
    const auto& port = portArrangement[portIndex];
    uint8_t id = 0;
    // Add this port to the matrix entry for each group it supports
    for (const auto& set : port) {
      std::vector<uint8_t> acceptedSelection;
      uint8_t compulsoryGroups = 0;
      std::vector<uint8_t> optionalGroups;
      for (const auto& group : set) {
        assert(group.second < 2 && "port type not supported");
        if (group.second == PortType::COMPULSORY) {
          // This group is compulsory
          // Add group to bit representation
          compulsoryGroups |= (1 << group.first);
          id |= (1 << group.first);
        } else if (group.second == PortType::OPTIONAL) {
          // This group is optional
          // Add group bit representation
          optionalGroups.push_back((1 << group.first));
          id |= (1 << group.first);
        }
      }

      
      acceptedSelection.push_back(compulsoryGroups);
      if (compulsoryGroups >= supportMatrix.size()) {
        // New highest group ID; expand matrix
        supportMatrix.resize(compulsoryGroups + 1);
      }
      supportMatrix[compulsoryGroups].push_back(portIndex);
      int n = 0;
      while (n < optionalGroups.size()) {
          std::vector<uint8_t> temp = acceptedSelection;
          for (const auto& entry : temp) {
            uint8_t groupSet = entry | optionalGroups[n];
            acceptedSelection.push_back(groupSet);
            if (groupSet >= supportMatrix.size()) {
              // New highest group ID; expand matrix
              supportMatrix.resize(groupSet + 1);
            }
            supportMatrix[groupSet].push_back(portIndex);
          }
          n++;
      }     
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

void BalancedPortAllocator::issued(uint8_t port) {
  assert(weights[port] > 0);
  weights[port]--;
}
void BalancedPortAllocator::deallocate(uint8_t port) { issued(port); };

}  // namespace pipeline
}  // namespace simeng
