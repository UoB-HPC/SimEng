#pragma once

#include <cstdint>

namespace simeng {
namespace outoforder {

class PortAllocator {
 public:
  virtual ~PortAllocator(){};

  virtual uint8_t allocate(uint16_t instructionGroup) = 0;
  virtual void issued(uint8_t port) = 0;
};

}  // namespace outoforder
}  // namespace simeng
