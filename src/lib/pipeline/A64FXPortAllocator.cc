#include "simeng/pipeline/A64FXPortAllocator.hh"

#include <algorithm>
#include <cassert>
#include <cmath>

namespace simeng {
namespace pipeline {

A64FXPortAllocator::A64FXPortAllocator(
    const std::vector<std::vector<uint16_t>>& portArrangement)
    :  // Initiliase reservation station to port mapping
      rsToPort_({{0, 1, 2}, {3, 4}, {5}, {6}, {7}}) {}

uint8_t A64FXPortAllocator::allocate(std::vector<uint8_t> ports) {
  assert(ports.size() &&
         "No supported ports supplied; cannot allocate from a empty set");
  const uint8_t attribute = attributeMapping(ports);

  uint8_t rs = 0;
  uint8_t port = 0;
  bool foundRS = false;
  bool foundPort = false;

  if (attribute == InstructionAttribute::RSX) {
    // Get difference between free entries of RSE{0|1} and RSA{0|1}
    int diffRSE = (freeEntries_[0] + freeEntries_[1]) -
                  (freeEntries_[2] + freeEntries_[3]);
    int diffRSA = (freeEntries_[2] + freeEntries_[3]) -
                  (freeEntries_[0] + freeEntries_[1]);
    // Set threshold values
    int thresholdA = 4;
    int thresholdB = 4;
    int thresholdC = 4;

    if (diffRSE >= thresholdA) {
      if ((freeEntries_[0] - freeEntries_[1]) >= thresholdB) {
        rs = RSEm_;  // Table 1
      } else {
        rs = dispatchSlot_ % 2 == 0 ? RSEm_ : RSEf_;  // Table 2
      }
      foundRS = true;
    } else if (diffRSA >= thresholdC) {
      rs = dispatchSlot_ % 2 == 0 ? RSAm_ : RSAf_;  // Table 3
      foundRS = true;
    } else {
      // Determine if RSE{0|1} has the most free entries excluding RSBR
      if ((std::max_element(freeEntries_.begin(), freeEntries_.end() - 1) -
           freeEntries_.begin()) < 2) {
        switch (dispatchSlot_ % 4) {  // Table 4
          case 0: {
            rs = RSEm_;
            break;
          }
          case 1: {
            rs = RSEf_;
            break;
          }
          case 2: {
            rs = RSAm_;
            break;
          }
          case 3: {
            rs = RSAf_;
            break;
          }
        }
        foundRS = true;
      } else {
        switch (dispatchSlot_ % 4) {  // Table 5
          case 0: {
            rs = RSAm_;
            break;
          }
          case 1: {
            rs = RSAf_;
            break;
          }
          case 2: {
            rs = RSEm_;
            break;
          }
          case 3: {
            rs = RSEf_;
            break;
          }
        }
        foundRS = true;
      }
    }
  } else if (attribute == InstructionAttribute::RSE ||
             attribute == InstructionAttribute::RSA) {
    uint8_t A = 0;
    uint8_t B = 1;
    if (attribute == InstructionAttribute::RSA) {
      A = 2;
      B = 3;
    }
    if ((freeEntries_[A] > freeEntries_[B]) &&
        (freeEntries_[B] == 0)) {  // Table 6
      rs = A;
      foundRS = true;
    } else if ((freeEntries_[B] > freeEntries_[A]) &&
               (freeEntries_[A] == 0)) {  // Table 6
      rs = B;
      foundRS = true;
    } else {
      switch (dispatchSlot_ % 2) {  // Table 7
        case 0: {
          rs = A;
          break;
        }
        case 1: {
          rs = B;
          break;
        }
      }
      foundRS = true;
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
  dispatchSlot_++;

  for (auto option : ports) {
    if (std::find(rsToPort_[rs].begin(), rsToPort_[rs].end(), option) !=
        rsToPort_[rs].end()) {
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

uint8_t A64FXPortAllocator::attributeMapping(
    const std::vector<uint8_t>& ports) {
  uint8_t attribute = 0;
  bool foundAttribute = false;
  if (ports == std::vector<uint8_t>({2, 4, 5, 6})) {  // EXA,EXB,EAGA,EAGB
    attribute = InstructionAttribute::RSX;
    foundAttribute = true;
  } else if (ports == std::vector<uint8_t>({2, 4}) ||
             ports == std::vector<uint8_t>({0, 3})) {  // EXA,EXB|FLA,FLB
    attribute = InstructionAttribute::RSE;
    foundAttribute = true;
  } else if (ports == std::vector<uint8_t>({5, 6})) {  // EAGA,EAGB
    attribute = InstructionAttribute::RSA;
    foundAttribute = true;
  } else if (ports == std::vector<uint8_t>({0}) ||
             ports == std::vector<uint8_t>({1}) ||
             ports == std::vector<uint8_t>({2})) {  // EXA|FLA|PR
    attribute = InstructionAttribute::RSE0;
    foundAttribute = true;
  } else if (ports == std::vector<uint8_t>({3}) ||
             ports == std::vector<uint8_t>({4})) {  // EXB|FLB
    attribute = InstructionAttribute::RSE1;
    foundAttribute = true;
  } else if (ports == std::vector<uint8_t>({7})) {  // BR
    attribute = InstructionAttribute::BR;
    foundAttribute = true;
  }

  assert(foundAttribute && "Unsupported group; cannot allocate an attribute");
  return attribute;
}

void A64FXPortAllocator::setRSSizeGetter(
    std::function<void(std::vector<uint64_t>&)> rsSizes) {
  rsSizes_ = rsSizes;
}

void A64FXPortAllocator::tick() {
  freeEntries_.clear();
  rsSizes_(freeEntries_);

  RSEm_ = freeEntries_[0] >= freeEntries_[1] ? 0 : 1;
  RSEf_ = RSEm_ == 0 ? 1 : 0;
  RSAm_ = freeEntries_[2] >= freeEntries_[3] ? 2 : 3;
  RSAf_ = RSAm_ == 2 ? 3 : 2;

  dispatchSlot_ = 0;
}

}  // namespace pipeline
}  // namespace simeng
