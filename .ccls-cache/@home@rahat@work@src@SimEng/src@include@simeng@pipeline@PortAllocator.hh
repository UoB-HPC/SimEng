#pragma once

#include <cstdint>
#include <functional>

namespace simeng {
namespace pipeline {

namespace PortType {
/** Instructions have to match the exact group(s) in set. */
const uint8_t COMPULSORY = 0;
/** Instructions can optional match group(s) in set. */
const uint8_t OPTIONAL = 1;
}  // namespace PortType

/** An abstract execution port allocator interface. */
class PortAllocator {
 public:
  virtual ~PortAllocator(){};

  /** Allocate a port for the specified instruction group; returns the allocated
   * port. */
  virtual uint16_t allocate(const std::vector<uint16_t>& ports) = 0;

  /** Inform the allocator that an instruction was issued to the specified port.
   */
  virtual void issued(uint16_t port) = 0;

  /** Inform the allocator that an instruction will not issue to its
   * allocated port. */
  virtual void deallocate(uint16_t port) = 0;

  /** Set function from DispatchIssueUnit to retrieve reservation
   * station sizes during execution. */
  virtual void setRSSizeGetter(
      std::function<void(std::vector<uint64_t>&)> rsSizes) = 0;

  /** Tick the port allocator to allow it to process internal tasks. */
  virtual void tick() = 0;
};

}  // namespace pipeline
}  // namespace simeng
