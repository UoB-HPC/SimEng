#include "simeng/pipeline/A64FXPortAllocator.hh"

#include <cassert>
#include <algorithm>
#include <cmath>
#include <iostream>

namespace simeng {
namespace pipeline {

A64FXPortAllocator::A64FXPortAllocator(
    std::vector<std::vector<std::vector<std::pair<uint16_t, uint8_t>>>> portArrangement) {
  // Construct the  support matrix
  for (size_t portIndex = 0; portIndex < portArrangement.size(); portIndex++) {
    const auto& port = portArrangement[portIndex];
    uint16_t id = 0;
    // Add this port to the matrix entry for each group it supports
    for (const auto& set : port) {
      std::vector<uint16_t> acceptedSelection;
      uint16_t compulsoryGroups = 0;
      std::vector<uint16_t> optionalGroups;
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
        // New highest group ID; expand matrices
        supportMatrix.resize(compulsoryGroups + 1);
        attributeMatrix.resize(compulsoryGroups + 1);
      }
      supportMatrix[compulsoryGroups].push_back(portIndex);
      attributeMatrix[compulsoryGroups] = attributeMapping(compulsoryGroups);

      int n = 0;
      while (n < optionalGroups.size()) {
          std::vector<uint16_t> temp = acceptedSelection;
          for (const auto& entry : temp) {
            uint16_t groupSet = entry | optionalGroups[n];
            acceptedSelection.push_back(groupSet);
            if (groupSet >= supportMatrix.size()) {
              // New highest group ID; expand matrices
              supportMatrix.resize(groupSet + 1);
              attributeMatrix.resize(groupSet + 1);
            }
            supportMatrix[groupSet].push_back(portIndex);
            attributeMatrix[groupSet] = attributeMapping(groupSet);
          }
          n++;
      }
    }
  }
  // Initialise rowSelection vector
  rowSelection = std::vector<uint8_t>(6, 0);
  // Initiliase reservation station to port mapping
  rsToPort_ = {{0,1,2},{3,4},{5},{6},{7}};
}

uint8_t A64FXPortAllocator::allocate(uint16_t instructionGroup) {
  // Find the list of ports that support this instruction group
  assert(instructionGroup < supportMatrix.size() &&
         "instruction group not covered by port allocator");
  const auto& available = supportMatrix[instructionGroup];
  const uint8_t attribute = attributeMatrix[instructionGroup];

  uint8_t rs = 0;
  uint8_t port = 0;
  bool foundRS = false;
  bool foundPort = false;

  // TODO: remove first if statement
  // if ((instructionGroup & 64) > 0) { // Ensure store foes to EAGB
  //   rs = 3;
  //   foundRS = true;
  if(attribute == InstructionAttribute::RSX) {
    // Get difference betwwen free entries of RSE{0|1} and RSA{0|1}
    int difference = (freeEntries_[0] + freeEntries_[1]) - (freeEntries_[2] + freeEntries_[3]);
    // Set threshold values
    int thresholdA = 0;
    int thresholdB = 4;
    int thresholdC = 0;
    if ((freeEntries_[0] > 0) && (freeEntries_[1] > 0) && (freeEntries_[2] == 0) && (freeEntries_[3] == 0)) {
      if (abs(freeEntries_[0] - freeEntries_[1]) >= 0) {
        rs = freeEntries_[0] >= freeEntries_[1] ? 0 : 1;  // Table 1
        foundRS = true;
      } else {
        switch (rowSelection[1] % 2) { // Table 2
          case 0: {
            rs = freeEntries_[0] >= freeEntries_[1] ? 0 : 1;
            foundRS = true;
            break;
          }
          case 1: {
            rs = freeEntries_[1] <= freeEntries_[0] ? 1 : 0;
            foundRS = true;
            break;
          }
          default:
            rowSelection[1]--;
            break;
        }
        rowSelection[1]++;
      }
    } else if ((freeEntries_[2] > 0) && (freeEntries_[3] > 0) && (freeEntries_[0] == 0) && (freeEntries_[1] == 0)) {
      switch (rowSelection[2] % 2) { // Table 3
          case 0: { 
            rs = freeEntries_[2] >= freeEntries_[3] ? 2 : 3;
            foundRS = true;
            break;
          }
          case 1: { 
            rs = freeEntries_[3] <= freeEntries_[2] ? 3 : 2;
            foundRS = true;
            break;
          }
          default:
            rowSelection[2]--;
            break;
      }
      rowSelection[2]++;
    } else {
      // Determine if RSE{0|1} has the most free entries excluding RSBR
      if((std::max_element(freeEntries_.begin(), freeEntries_.end()-1) - freeEntries_.begin()) < 2) {
        switch (rowSelection[3] % 4) { // Table 4
          case 0: {
            rs = freeEntries_[0] >= freeEntries_[1] ? 0 : 1;
            foundRS = true;
            break;
          }
          case 1: { 
            rs = freeEntries_[1] <= freeEntries_[0] ? 1 : 0;
            foundRS = true;
            break;
          }
          case 2: { 
            rs = freeEntries_[2] >= freeEntries_[3] ? 2 : 3;
            foundRS = true;
            break;
          }
          case 3: { 
            rs = freeEntries_[3] <= freeEntries_[2] ? 3 : 2;
            foundRS = true;
            break;
          }
          default:
            rowSelection[3]--;
            break;
        }
        rowSelection[3]++;
      } else {
        switch (rowSelection[4] % 4) { // Table 5
          case 0: { 
            rs = freeEntries_[2] >= freeEntries_[3] ? 2 : 3;
            foundRS = true;
            break;
          }
          case 1: { 
            rs = freeEntries_[3] <= freeEntries_[2] ? 3 : 2;
            foundRS = true;
            break;
          }
          case 2: { 
            rs = freeEntries_[0] >= freeEntries_[1] ? 0 : 1;
            foundRS = true;
            break;
          }
          case 3: { 
            rs = freeEntries_[1] <= freeEntries_[0] ? 1 : 0;
            foundRS = true;
            break;
          }
          default:
            rowSelection[4]--;
            break;
        }
        rowSelection[4]++;
      }
    }  
  } else if (attribute == InstructionAttribute::RSE || attribute == InstructionAttribute::RSA) {
    uint8_t A = 0;
    uint8_t B = 1;
    if(attribute == InstructionAttribute::RSA) {
      A = 2;
      B = 3;
    }
    if ((freeEntries_[A] > freeEntries_[B]) && (freeEntries_[B] == 0)) { // Table 5
      rs = A;
      foundRS = true;
    } else if ((freeEntries_[B] > freeEntries_[A]) && (freeEntries_[A] == 0)) { // Table 5
      rs = B;
      foundRS = true;
    } else {
      switch (rowSelection[5] % 2) { // Table 6
          case 0: {
            rs = A;
            foundRS = true;
            break;
          }
          case 1: { 
            rs = B;
            foundRS = true;
            break;
          }
          default:
            rowSelection[5]--;
            break;
      }
      rowSelection[5]++;
    }
  } else if (attribute == InstructionAttribute::RSE0) {
    rs = 0;
    foundRS = true; 
  } else if (attribute == InstructionAttribute::RSE1) {
    rs = 1;
    foundRS = true; 
  } else if (attribute == InstructionAttribute::BR) {
    rs = 4;
    foundRS = true; 
  }

  assert(foundRS && "Unsupported group; cannot allocate reservation station");

  for(auto option : available) {
    if(std::find(rsToPort_[rs].begin(), rsToPort_[rs].end(), option) != rsToPort_[rs].end()){
      port = option;
      foundPort = true;
      break;
    }
  }

  assert(foundPort && "Unsupported group; cannot allocate a port");
  return port;
}

void A64FXPortAllocator::issued(uint8_t port) {}
void A64FXPortAllocator::deallocate(uint8_t port) { issued(port); };

uint8_t A64FXPortAllocator::attributeMapping(uint16_t group) {
  uint8_t attribute = 0;
  bool foundAttribute = false;
  if (group == 1) {
    attribute = 0; // RSX
    foundAttribute = true;
  } else if (group == 3) {
    attribute = 1; // RSE
    foundAttribute = true;
  } else if (group == 16) {
    attribute = 1; // RSE
    foundAttribute = true;
  } else if (group == 18) {
    attribute = 1; // RSE
    foundAttribute = true;
  } else if (group == 20) {
    attribute = 1; // RSE
    foundAttribute = true;
  } else if (group == 22) {
    attribute = 1; // RSE
    foundAttribute = true;
  } else if (group > 31 && group < 83) {
    attribute = 2; // RSA
    foundAttribute = true;
  } else if ((group & 24) == 24 || (group & 5) == 5) {
    attribute = 3; // RSE0
    foundAttribute = true;
  } else if ((group & 9) == 9) {
    attribute = 4; // RSE1
    foundAttribute = true;
  } else if (group == 128) {
    attribute = 5; // BR
    foundAttribute = true;
  } else if (group > 255) {
    attribute = 3; // RSE0
    foundAttribute = true;
  }

  assert(foundAttribute && "Unsupported group; cannot allocate an attribute");
  return attribute;
}

void A64FXPortAllocator::setRSSizeGetter(
  std::function<void(std::vector<uint64_t>&)> rsSizes) { rsSizes_ = rsSizes; }

void A64FXPortAllocator::tick() {
  freeEntries_.clear();
  rsSizes_(freeEntries_);
}

}  // namespace pipeline
}  // namespace simeng
