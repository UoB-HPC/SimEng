#pragma once

#include "simeng/pipeline/PortAllocator.hh"

#include <vector>

namespace simeng {
namespace pipeline {

/** A load-balancing port allocator implementation. Maintains demand weightings
 * for each port, and allocates instructions to the suitable port with the
 * lowest weighting. */
class BalancedPortAllocator : public PortAllocator {
 public:
  /** Construct a load-balancing port allocator, providing a port arrangement
   * specification. Each element of the port arrangement should represent a
   * port, and contain a list of the instruction groups that port supports. */
  BalancedPortAllocator(std::vector<std::vector<uint16_t>> portArrangement);

  /** Allocate the lowest weighted port available for the specified instruction
   * group. Returns the allocated port, and increases the weight of the port.
   */
  uint8_t allocate(uint16_t instructionGroup) override;

  /** Decrease the weight for the specified port. */
  void issued(uint8_t port) override;

  /** Decrease the weight for the specified port. */
  void deallocate(uint8_t port) override;

 private:
  /** The instruction group support matrix. An instruction-group-indexed map
   * containing lists of the ports that support each instruction group. */
  std::vector<std::vector<uint8_t>> supportMatrix;

  /** The port weighting map. Each element corresponds to a port, and contains a
   * weighting representing the number of in-flight instructions allocated to
   * that port. */
  std::vector<uint16_t> weights;
};

}  // namespace pipeline
}  // namespace simeng
