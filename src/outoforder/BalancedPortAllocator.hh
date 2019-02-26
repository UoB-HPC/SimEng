#pragma once

#include "PortAllocator.hh"

#include <vector>

namespace simeng {
namespace outoforder {

class BalancedPortAllocator : public PortAllocator {
 public:
  BalancedPortAllocator(std::vector<std::vector<uint16_t>> portArrangement);

  uint8_t allocate(uint16_t instructionGroup) override;
  void issued(uint8_t port) override;

 private:
  std::vector<std::vector<uint8_t>> supportMatrix;
  std::vector<uint16_t> weights;
};

}  // namespace outoforder
}  // namespace simeng
