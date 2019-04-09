#pragma once

#include <cstdint>

namespace simeng {
namespace pipeline {

/** An abstract execution port allocator interface. */
class PortAllocator {
 public:
  virtual ~PortAllocator(){};

  /** Allocate a port for the specified instruction group; returns the allocated
   * port. */
  virtual uint8_t allocate(uint16_t instructionGroup) = 0;

  /** Inform the allocator that an instruction was issued to the specified port.
   */
  virtual void issued(uint8_t port) = 0;

  /** Inform the allocator that an instruction will not issue to its
   * allocated port. */
  virtual void deallocate(uint8_t port) = 0;
};

}  // namespace pipeline
}  // namespace simeng
